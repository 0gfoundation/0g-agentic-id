package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/credentials"
)

// CredentialService is the credential store the owner manages through
// /_seal/credentials* (internal/credentials.Store).
type CredentialService interface {
	Load(ctx context.Context, doc credentials.Document, ownerEpoch uint64) (*credentials.Opened, error)
	Version() uint64
	List() []credentials.EntryInfo
	PendingList() []credentials.Pending
	Decide(ctx context.Context, authReqID, decision string, a *credentials.Approval, sig string) error
	AuditSince(after int64) []credentials.AuditRecord
	StartLogin(ctx context.Context, name, redirectURI string) (string, error)
	FinishLogin(ctx context.Context, state, code, oauthError, iss string) (string, error)
	Disconnect(ctx context.Context, name string) (revoked bool, note string, err error)
	// BeginOwnerLookup and ObserveOwnerLookup record the owner a request
	// was signed by, the live on-chain owner, in the order the lookups
	// began: a new owner's first request clears the previous owner's state
	// before anything of it is read or used.
	BeginOwnerLookup() credentials.OwnerLookup
	ObserveOwnerLookup(l credentials.OwnerLookup, owner common.Address) bool
}

// Scrubber replaces the credential values sealed holds with their
// placeholders (credproxy.Registry).
type Scrubber interface {
	Scrub(b []byte) []byte
	ScrubReader(src io.Reader) io.Reader
	// NameHoldsValue reports whether a header name holds a value, in any
	// letter case.
	NameHoldsValue(name string) bool
}

// SetScrubber installs what the proxy scrubs agent responses with.
func (s *Server) SetScrubber(sc Scrubber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scrubber = sc
}

// scrubBytes replaces credential values in b; b itself when there is no
// scrubber.
func (s *Server) scrubBytes(b []byte) []byte {
	s.mu.RLock()
	sc := s.scrubber
	s.mu.RUnlock()
	if sc == nil {
		return b
	}
	return sc.Scrub(b)
}

// nameHoldsValue reports whether a header name holds a credential value, in
// any letter case: Go's client and HTTP/2 change the case of header names.
// False when there is no scrubber.
func (s *Server) nameHoldsValue(name string) bool {
	s.mu.RLock()
	sc := s.scrubber
	s.mu.RUnlock()
	return sc != nil && sc.NameHoldsValue(name)
}

// scrubResponse replaces credential values in resp's headers (dropping a
// header whose name holds one) and, as it is read, its body.
func (s *Server) scrubResponse(resp *http.Response) {
	s.mu.RLock()
	sc := s.scrubber
	s.mu.RUnlock()
	if sc == nil {
		return
	}
	for k, vs := range resp.Header {
		if sc.NameHoldsValue(k) {
			delete(resp.Header, k)
			continue
		}
		for i, v := range vs {
			vs[i] = string(sc.Scrub([]byte(v)))
		}
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{sc.ScrubReader(resp.Body), resp.Body}
}

// maxCredentialBody bounds a credential set push: definitions and sealed
// values for every entry.
const maxCredentialBody = 256 << 10

// SetCredentials installs the credential store behind the owner routes.
func (s *Server) SetCredentials(c CredentialService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials = c
}

func (s *Server) credentialService(w http.ResponseWriter) (CredentialService, string, string, bool) {
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return nil, "", "", false
	}
	s.mu.RLock()
	c := s.credentials
	s.mu.RUnlock()
	if c == nil {
		http.Error(w, "credentials not ready", http.StatusServiceUnavailable)
		return nil, "", "", false
	}
	return c, sealID, owner, true
}

// verifyCredOwner checks an owner-signed credential request (digest is the
// body's, or "" for a read) and records its signer as the owner.
func (s *Server) verifyCredOwner(w http.ResponseWriter, r *http.Request, c CredentialService, tag, sealID, owner, digest string) bool {
	l := c.BeginOwnerLookup() // before the signature check looks the owner up
	_, signer, ok := s.verifyOwnerSigAs(w, r, tag, sealID, owner, digest)
	if !ok {
		return false
	}
	// An answer a later lookup overtook, naming someone else, confirms
	// nothing: the request is not served on it.
	if !c.ObserveOwnerLookup(l, common.HexToAddress(signer)) {
		http.Error(w, "owner lookup unavailable, retry", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func readSignedBody(w http.ResponseWriter, r *http.Request, s *Server, tag, sealID, owner string) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCredentialBody+1))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if len(body) > maxCredentialBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	sum := sha256.Sum256(body)
	s.mu.RLock()
	c := s.credentials
	s.mu.RUnlock()
	if !s.verifyCredOwner(w, r, c, tag, sealID, owner, hex.EncodeToString(sum[:])) {
		return nil, false
	}
	// A signed request is taken once: replayed within its freshness window
	// (a login started again, a decision sent again) it is refused. Keyed on
	// the signed message, as compaction's guard is (compact.go says why).
	used := sha256.Sum256([]byte(r.Header.Get("X-Auth-Message")))
	if !s.credUsed.take(hex.EncodeToString(used[:])) {
		http.Error(w, "this signed request was already used; sign a fresh one", http.StatusConflict)
		return nil, false
	}
	return body, true
}

// usedMessages remembers accepted signed messages for as long as their
// timestamp could still pass verifyOwnerSig.
type usedMessages struct {
	mu   sync.Mutex
	used map[string]int64
}

// take records key and reports whether it was new. A message older than
// 2×window can no longer pass verifyOwnerSig, so it is forgotten then.
func (u *usedMessages) take(key string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now().Unix()
	if u.used == nil {
		u.used = map[string]int64{}
	}
	for k, at := range u.used {
		if now-at > 2*authWindowSec {
			delete(u.used, k)
		}
	}
	if _, seen := u.used[key]; seen {
		return false
	}
	u.used[key] = now
	return true
}

// handleCredentials: GET lists the loaded entries (never values); POST loads
// a credential set the owner signed. The request signature proves who pushes;
// the set's EIP-712 signature, checked again inside, is what makes the
// entries the owner's.
func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.verifyCredOwner(w, r, c, "0GSealCredentials", sealID, owner, "") {
			return
		}
		entries := c.List()
		if entries == nil {
			entries = []credentials.EntryInfo{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"version": c.Version(), "entries": entries})
	case http.MethodPost:
		body, ok := readSignedBody(w, r, s, "0GSealCredentials", sealID, owner)
		if !ok {
			return
		}
		var doc credentials.Document
		if err := json.Unmarshal(body, &doc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": "invalid credential set document"})
			return
		}
		opened, err := c.Load(r.Context(), doc, 0)
		switch {
		case errors.Is(err, credentials.ErrStale):
			writeJSON(w, http.StatusConflict, map[string]any{"code": "stale_version", "message": err.Error(), "version": c.Version()})
			return
		case errors.Is(err, credentials.ErrOwnerLookup):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "owner_unknown", "message": "the agent's owner could not be looked up; retry"})
			return
		case err != nil:
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_set", "message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"version": opened.Set.Version, "skipped": opened.Skipped})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCredentialPending(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCredOwner(w, r, c, "0GSealCredPending", sealID, owner, "") {
		return
	}
	list := c.PendingList()
	if list == nil {
		list = []credentials.Pending{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCredentialDecide(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, ok := readSignedBody(w, r, s, "0GSealCredDecide", sealID, owner)
	if !ok {
		return
	}
	var in struct {
		AuthReqID string                `json:"auth_req_id"`
		Decision  string                `json:"decision"`
		Approval  *credentials.Approval `json:"approval,omitempty"`
		Signature string                `json:"signature,omitempty"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": "invalid decision"})
		return
	}
	if err := c.Decide(r.Context(), in.AuthReqID, in.Decision, in.Approval, in.Signature); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, credentials.ErrUnknownRequest) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"code": "invalid_decision", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCredentialAudit(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCredOwner(w, r, c, "0GSealCredAudit", sealID, owner, "") {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	recs := c.AuditSince(after)
	if recs == nil {
		recs = []credentials.AuditRecord{}
	}
	writeJSON(w, http.StatusOK, recs)
}

// handleCredentialDisconnect ends a login entry's login: the server is asked
// to revoke the tokens when it can be, and sealed forgets them. Owner-signed.
func (s *Server) handleCredentialDisconnect(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, ok := readSignedBody(w, r, s, "0GSealCredDisconnect", sealID, owner)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": "give the entry name"})
		return
	}
	revoked, note, err := c.Disconnect(r.Context(), in.Name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked, "note": note})
}

// oauthCallbackPath is where an authorization server returns the owner
// after a login: this agent's public address, so the code reaches sealed
// and nothing else.
const oauthCallbackPath = "/_seal/oauth/callback"

// handleCredentialLogin starts the owner's login to a login entry's MCP
// server and returns the URL the owner opens. Owner-signed: the login gives
// the agent the owner's account at that server.
func (s *Server) handleCredentialLogin(w http.ResponseWriter, r *http.Request) {
	c, sealID, owner, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, ok := readSignedBody(w, r, s, "0GSealCredLogin", sealID, owner)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": "give the entry name"})
		return
	}
	if s.publicURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "no_public_url", "message": "this agent has no public address for the login to return to"})
		return
	}
	u, err := c.StartLogin(r.Context(), in.Name, strings.TrimRight(s.publicURL, "/")+oauthCallbackPath)
	if err != nil {
		var le *credentials.LoginError
		status := http.StatusBadGateway
		if errors.As(err, &le) && strings.HasPrefix(le.Reason, "no login entry") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"code": "login_failed", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": u})
}

// handleOAuthCallback is where the owner's browser lands after consenting.
// It carries no owner signature: the one-time state, known only to sealed
// and to the authorization server it sent the owner to, is what binds the
// code to the login the owner started.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	c, _, _, ok := s.credentialService(w)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	name, err := c.FinishLogin(r.Context(), q.Get("state"), q.Get("code"), q.Get("error"), q.Get("iss"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "<!doctype html><title>Login failed</title><p>Login failed: "+html.EscapeString(err.Error())+"</p>")
		return
	}
	_, _ = io.WriteString(w, "<!doctype html><title>Logged in</title><p>The agent is logged in for "+html.EscapeString(name)+". You can close this page.</p>")
}
