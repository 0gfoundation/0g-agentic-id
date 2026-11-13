// Package inferproxy is sealed's inference route for a framework that calls
// its model through sealed (sealed/LAYERS.md §4.2): the framework's model
// base URL is this proxy, on loopback, and each request goes on to the
// owner's route with
//
//   - the model name the owner's settings pin, whatever the framework asked
//     for;
//   - the platform text (the agent doc: identity, doctrine, environment)
//     at the end of its system prompt, so code the framework runs cannot
//     leave it out;
//   - the route's credential headers in place of whatever the framework
//     sent: the key, or the placeholder the credential proxy fills on its
//     way out (then Upstream is the credential proxy's form of the route).
//
// Only model calls pass, by their exact paths under the route's base URL:
// POST chat/completions, messages and responses, and GET models, each with
// or without a leading /v1 (an OpenAI-wire client's base URL ends in /v1, an
// Anthropic-wire one's does not). Responses stream back as they arrive.
package inferproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"seal-verify/internal/logger"
)

// maxRequestBytes bounds a model request body the proxy rewrites.
const maxRequestBytes = 64 << 20

// Route is where the proxy sends requests and how it rewrites them.
type Route struct {
	// Upstream is the base URL a request's path (after the proxy's own
	// prefix) is appended to.
	Upstream string
	// Headers are set on every request sent upstream; the framework's own
	// values of these headers are dropped.
	Headers map[string]string
	// Model is the model name every request names.
	Model string
	// System is appended to every model request's system prompt.
	System string
}

// Server is the proxy. One per sealed process; Route changes as the
// owner's settings do (SetRoute).
type Server struct {
	token  string
	base   string
	client *http.Client

	mu    sync.RWMutex
	route *Route
}

// Start listens on a loopback port and serves the proxy.
func Start() (*Server, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{
		token: hex.EncodeToString(b[:]),
		// No overall timeout: a streamed answer takes as long as it takes;
		// the framework's request context ends it.
		client: &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}},
	}
	s.base = fmt.Sprintf("http://%s/%s", l.Addr().String(), s.token)
	go func() { _ = http.Serve(l, s) }()
	logger.Logf("inference proxy listening on %s", l.Addr().String())
	return s, nil
}

// BaseURL is the base URL the framework is given: loopback, and a
// per-process path token.
func (s *Server) BaseURL() string { return s.base }

// SetRoute sets where requests go from now on.
func (s *Server) SetRoute(r Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.route = &r
}

func (s *Server) current() *Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.route
}

// endpoints are the model calls the proxy forwards: method and exact path
// under the route's base URL, to the kind Rewrite takes.
var endpoints = map[string]string{
	"POST /chat/completions": "chat",
	"POST /messages":         "messages",
	"POST /responses":        "responses",
	"GET /models":            "models",
}

// endpoint names the model call a request path is, "" for anything else:
// one of endpoints, with or without a leading /v1. A path that only ends like
// one (an Assistants API /threads/<id>/messages, say) is not a model call.
func endpoint(method, path string) string {
	if kind, ok := endpoints[method+" "+path]; ok {
		return kind
	}
	if rest, ok := strings.CutPrefix(path, "/v1"); ok {
		return endpoints[method+" "+rest]
	}
	return ""
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+s.token)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		http.NotFound(w, r)
		return
	}
	route := s.current()
	if route == nil {
		http.Error(w, "no inference route set", http.StatusServiceUnavailable)
		return
	}
	kind := endpoint(r.Method, rest)
	if kind == "" {
		http.Error(w, "only model calls pass the inference route", http.StatusNotFound)
		return
	}

	var body io.Reader = http.NoBody
	length := int64(0)
	if kind != "models" {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
		if err != nil {
			http.Error(w, "read request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(raw) > maxRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		out, err := Rewrite(kind, raw, route.Model, route.System)
		if err != nil {
			http.Error(w, "rewrite request: "+err.Error(), http.StatusBadRequest)
			return
		}
		body, length = bytes.NewReader(out), int64(len(out))
	}

	target := strings.TrimRight(route.Upstream, "/") + rest
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		http.Error(w, "build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	up.ContentLength = length
	for k, vs := range r.Header {
		if hopHeader(k) || strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "X-Api-Key") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Host") {
			continue
		}
		if _, set := headerValue(route.Headers, k); set {
			continue
		}
		up.Header[k] = vs
	}
	for k, v := range route.Headers {
		up.Header.Set(k, v)
	}
	resp, err := s.client.Do(up)
	if err != nil {
		if r.Context().Err() != nil {
			return // the framework went away
		}
		http.Error(w, "inference route: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if hopHeader(k) || strings.EqualFold(k, "Content-Length") {
			continue
		}
		w.Header()[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	flushCopy(w, resp.Body)
}

// headerValue looks a header up by name in any case.
func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func hopHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

// flushCopy streams src to w, flushing after every read so an event stream
// reaches the framework as it arrives.
func flushCopy(w http.ResponseWriter, src io.Reader) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// Rewrite sets the model and appends system to the system prompt of one
// model request: kind "chat" (OpenAI chat/completions: the first system or
// developer message, or a new system message first), "messages"
// (Anthropic: the system field) or "responses" (OpenAI Responses: the
// instructions field). Every other field is kept. Empty model or system
// leaves that part as it is.
func Rewrite(kind string, body []byte, model, system string) ([]byte, error) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if req == nil {
		return nil, errors.New("not a JSON object")
	}
	if model != "" {
		req["model"] = mustJSON(model)
	}
	if system != "" {
		var err error
		switch kind {
		case "chat":
			err = appendChatSystem(req, system)
		case "messages":
			req["system"], err = appendSystemField(req["system"], system)
		case "responses":
			req["instructions"], err = appendStringField(req["instructions"], system)
		}
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(req)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// appendChatSystem appends system to the first system or developer message,
// or puts a system message first when there is none.
func appendChatSystem(req map[string]json.RawMessage, system string) error {
	var messages []map[string]json.RawMessage
	if raw, ok := req["messages"]; ok {
		if err := json.Unmarshal(raw, &messages); err != nil {
			return fmt.Errorf("messages: %w", err)
		}
	}
	for _, m := range messages {
		var role string
		_ = json.Unmarshal(m["role"], &role)
		if role != "system" && role != "developer" {
			continue
		}
		content, err := appendContent(m["content"], system)
		if err != nil {
			return fmt.Errorf("system message: %w", err)
		}
		m["content"] = content
		req["messages"] = mustJSON(messages)
		return nil
	}
	first := map[string]json.RawMessage{"role": mustJSON("system"), "content": mustJSON(system)}
	req["messages"] = mustJSON(append([]map[string]json.RawMessage{first}, messages...))
	return nil
}

// appendContent appends text to a chat message's content: a string, or an
// array of parts (a text part is added).
func appendContent(raw json.RawMessage, text string) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return mustJSON(text), nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return mustJSON(s + "\n\n" + text), nil
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, errors.New("content is neither a string nor an array")
	}
	return mustJSON(append(parts, mustJSON(map[string]string{"type": "text", "text": text}))), nil
}

// appendSystemField appends text to Anthropic's system field: a string, or
// an array of text blocks (a block is added).
func appendSystemField(raw json.RawMessage, text string) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return mustJSON(text), nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return mustJSON(s + "\n\n" + text), nil
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, errors.New("system is neither a string nor an array")
	}
	return mustJSON(append(blocks, mustJSON(map[string]string{"type": "text", "text": text}))), nil
}

// appendStringField appends text to a string field.
func appendStringField(raw json.RawMessage, text string) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return mustJSON(text), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("not a string")
	}
	return mustJSON(s + "\n\n" + text), nil
}
