package proxy

// Connected-account capabilities stay in sealed's memory. The agent can use
// an installed operation over the private Unix socket, but neither that tool
// nor owner inventory reads return credentials. OAuth tokens stay at the
// account provider boundary in the engine; these are narrow, revocable grants.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxConnectionBody = 1_048_576

var connectionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var connectionCapability = regexp.MustCompile(`^acap_[A-Za-z0-9_-]{20,240}$`)
var (
	errConnectionInput       = errors.New("invalid_connection_request")
	errConnectionMissing     = errors.New("connection_not_installed")
	errConnectionLimit       = errors.New("connection_limit")
	errConnectionDenied      = errors.New("connection_access_denied")
	errConnectionRefreshing  = errors.New("connection_refresh_in_progress")
	errConnectionUnavailable = errors.New("connection_unavailable")
)

type connectionInstall struct {
	EngineOrigin string `json:"engine_origin"`
	Capability   string `json:"capability"`
	Operation    string `json:"operation"`
}
type connectionSummary struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
}
type connectionCall struct {
	GrantID      string          `json:"grant_id"`
	InvocationID string          `json:"invocation_id"`
	Input        json.RawMessage `json:"input"`
}
type connectionHub struct {
	mu     sync.RWMutex
	grants map[string]connectionInstall
	client *http.Client
}

func newConnectionHub() *connectionHub {
	return &connectionHub{grants: make(map[string]connectionInstall), client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DialContext: dialConnection, TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4},
	}}
}

// Resolve and dial the checked address directly. Re-resolving a hostname after
// validation would allow DNS rebinding to reach the container's private APIs.
func dialConnection(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errConnectionInput
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errConnectionUnavailable
	}
	for _, ip := range ips {
		if !publicConnectionIP(ip.IP) {
			return nil, errConnectionInput
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errConnectionUnavailable
}

var connectionSpecialNetworks = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
}

func publicConnectionIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range connectionSpecialNetworks {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func connectionOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errConnectionInput
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return "", errConnectionInput
	}
	if ip := net.ParseIP(host); ip != nil && !publicConnectionIP(ip) {
		return "", errConnectionInput
	}
	if u.Port() != "" && u.Port() != "443" {
		return "", errConnectionInput
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (h *connectionHub) install(id string, grant connectionInstall) error {
	if !connectionID.MatchString(id) || !connectionCapability.MatchString(grant.Capability) ||
		(grant.Operation != "calendar.check_availability" && grant.Operation != "notion.search_shared_titles") {
		return errConnectionInput
	}
	origin, err := connectionOrigin(grant.EngineOrigin)
	if err != nil {
		return err
	}
	grant.EngineOrigin = origin
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.grants[id]; !exists && len(h.grants) >= 50 {
		return errConnectionLimit
	}
	h.grants[id] = grant
	return nil
}

func (h *connectionHub) list() []connectionSummary {
	h.mu.RLock()
	defer h.mu.RUnlock()
	items := make([]connectionSummary, 0, len(h.grants))
	for id, grant := range h.grants {
		items = append(items, connectionSummary{ID: id, Operation: grant.Operation})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}
func (h *connectionHub) remove(id string) { h.mu.Lock(); defer h.mu.Unlock(); delete(h.grants, id) }

func (h *connectionHub) invoke(ctx context.Context, call connectionCall) (json.RawMessage, error) {
	if !connectionID.MatchString(call.GrantID) || !connectionID.MatchString(call.InvocationID) || len(call.Input) == 0 || len(call.Input) > maxConnectionBody || !json.Valid(call.Input) {
		return nil, errConnectionInput
	}
	h.mu.RLock()
	grant, ok := h.grants[call.GrantID]
	h.mu.RUnlock()
	if !ok {
		return nil, errConnectionMissing
	}
	body, err := json.Marshal(struct {
		InvocationID string          `json:"invocationId"`
		Input        json.RawMessage `json:"input"`
	}{call.InvocationID, call.Input})
	if err != nil {
		return nil, errConnectionInput
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, grant.EngineOrigin+"/connections/runtime/agent-grants/"+call.GrantID+"/invoke", bytes.NewReader(body))
	if err != nil {
		return nil, errConnectionInput
	}
	r.Header.Set("Authorization", "Capability "+grant.Capability)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, err := h.client.Do(r)
	if err != nil {
		return nil, errConnectionUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusServiceUnavailable {
		content, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		var result struct {
			Code  string `json:"code"`
			Retry bool   `json:"retryWithNewInvocationId"`
		}
		// Only this response proves no provider tool call began. Transport
		// failures and other errors must never authorize a fresh invocation.
		if readErr == nil && len(content) <= 4096 && json.Unmarshal(content, &result) == nil &&
			result.Code == "connection_refresh_in_progress" && result.Retry {
			return nil, errConnectionRefreshing
		}
		return nil, errConnectionUnavailable
	}
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 || response.StatusCode == 409 {
		return nil, errConnectionDenied
	}
	if response.StatusCode != http.StatusOK {
		return nil, errConnectionUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxConnectionBody+1))
	if err != nil || len(content) > maxConnectionBody {
		return nil, errConnectionUnavailable
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(content, &result) != nil || len(result) != 1 || result["result"] == nil {
		return nil, errConnectionUnavailable
	}
	return content, nil
}

func decodeConnectionBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxConnectionBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		connectionError(w, errConnectionInput)
		return false
	}
	return true
}

func connectionError(w http.ResponseWriter, err error) {
	if err == errConnectionRefreshing {
		w.Header().Set("Retry-After", "1")
		writeSynthJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":                    map[string]string{"code": errConnectionRefreshing.Error()},
			"retryWithNewInvocationId": true,
		})
		return
	}
	status := http.StatusBadGateway
	switch err {
	case errConnectionInput:
		status = http.StatusBadRequest
	case errConnectionLimit:
		status = http.StatusConflict
	case errConnectionMissing:
		status = http.StatusNotFound
	case errConnectionDenied:
		status = http.StatusForbidden
	}
	// Never forward transport/provider error text; it can contain credentials.
	code := errConnectionUnavailable.Error()
	if err == errConnectionInput || err == errConnectionLimit || err == errConnectionMissing || err == errConnectionDenied {
		code = err.Error()
	}
	writeSynthJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}

func (s *Server) handleStudioConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	if !s.requireStudioOwner(w, r) {
		return
	}
	const prefix = "/_seal/studio/connections"
	if r.URL.Path == prefix && r.Method == http.MethodGet {
		writeSynthJSON(w, http.StatusOK, map[string]any{"connections": s.connections.list()})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix+"/")
	if !connectionID.MatchString(id) {
		connectionError(w, errConnectionInput)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var grant connectionInstall
		if !decodeConnectionBody(w, r, &grant) {
			return
		}
		if err := s.connections.install(id, grant); err != nil {
			connectionError(w, err)
			return
		}
		writeSynthJSON(w, http.StatusOK, map[string]any{"id": id, "operation": grant.Operation})
	case http.MethodDelete:
		s.connections.remove(id)
		writeSynthJSON(w, http.StatusOK, map[string]any{"removed": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Registered only on the agent-private Unix socket, never on the public mux.
func (s *Server) handleAgentConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/connections" && r.Method == http.MethodGet {
		writeSynthJSON(w, http.StatusOK, map[string]any{"connections": s.connections.list()})
		return
	}
	if r.URL.Path != "/connections/invoke" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var call connectionCall
	if !decodeConnectionBody(w, r, &call) {
		return
	}
	result, err := s.connections.invoke(r.Context(), call)
	if err != nil {
		connectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}
