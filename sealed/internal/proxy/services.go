package proxy

// Agent-declared external service registry.
//
// An agent exposes a service by running the backend itself — a loopback
// HTTP server inside this sandbox — and registering it here over the
// agent-only sign socket (POST /services). sealed's :8080 proxy then
// routes the public path to that backend and signs the response, so every
// externally-visible service leaves through the one attributed surface.
// This lifts service exposure OUT of the orchestration framework (it used
// to be openclaw's in-process handlers + ~/.openclaw/services.json) and
// into sealed, so it's framework-agnostic.
//
// This file is step 1: the registry + registration endpoint only. Routing
// (:8080 dispatch) and /hello wiring land in later steps; nothing here
// changes existing request handling yet.
//
// Registration is runtime state — the agent re-posts on each boot; it is
// not chain-anchored (durable capability is still the tracked-skill path).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"seal-verify/internal/logger"
	"seal-verify/internal/report"
)

// ServiceEntry is one agent-declared external service.
type ServiceEntry struct {
	Path         string `json:"path"`                    // public path, must start with /api/
	Method       string `json:"method"`                  // uppercase HTTP verb
	Description  string `json:"description,omitempty"`   // one short sentence
	InputExample string `json:"input_example,omitempty"` // literal JSON body, if any
	Backend      string `json:"backend"`                 // loopback upstream: http://127.0.0.1:<port>
}

// reservedPrefixes are platform-owned paths an agent service may not shadow.
// Agent paths must already be under /api/, so this is belt-and-suspenders
// against a future /api/-reserved path or a validation slip.
var reservedPrefixes = []string{"/hello", "/healthz", "/log", "/_seal/", "/admin/"}

var validMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true,
}

// validateServices checks the agent-supplied list as a whole. Any violation
// rejects the ENTIRE POST (all-or-nothing) so a bad entry can't partially
// land. Returns normalized entries (method upper-cased) or an error.
func validateServices(in []ServiceEntry) ([]ServiceEntry, error) {
	seen := make(map[string]bool, len(in))
	out := make([]ServiceEntry, 0, len(in))
	for i, e := range in {
		if !strings.HasPrefix(e.Path, "/api/") || len(e.Path) <= len("/api/") {
			return nil, fmt.Errorf("services[%d].path %q must start with /api/ and name something after it", i, e.Path)
		}
		for _, p := range reservedPrefixes {
			if e.Path == p || strings.HasPrefix(e.Path, p) {
				return nil, fmt.Errorf("services[%d].path %q is platform-reserved", i, e.Path)
			}
		}
		if seen[e.Path] {
			return nil, fmt.Errorf("services[%d].path %q declared more than once", i, e.Path)
		}
		seen[e.Path] = true

		m := strings.ToUpper(strings.TrimSpace(e.Method))
		if !validMethods[m] {
			return nil, fmt.Errorf("services[%d].method %q is not a valid HTTP verb", i, e.Method)
		}
		e.Method = m

		if err := validateLoopbackBackend(e.Backend); err != nil {
			return nil, fmt.Errorf("services[%d].backend %q: %w", i, e.Backend, err)
		}
		if e.InputExample != "" && !json.Valid([]byte(e.InputExample)) {
			return nil, fmt.Errorf("services[%d].input_example is not valid JSON", i)
		}
		out = append(out, e)
	}
	return out, nil
}

// validateLoopbackBackend enforces that a backend points only at the agent's
// own loopback. An agent must not register a backend that reaches off-box —
// that would let it front an unattributable external target through sealed's
// signed surface. Loopback-only means every registered service is genuinely
// served from inside this sandbox.
func validateLoopbackBackend(backend string) error {
	if backend == "" {
		return fmt.Errorf("required")
	}
	u, err := url.Parse(backend)
	if err != nil {
		return fmt.Errorf("unparseable: %w", err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("scheme must be http, got %q", u.Scheme)
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "localhost" {
		return fmt.Errorf("host must be 127.0.0.1 or localhost, got %q", h)
	}
	if u.Port() == "" {
		return fmt.Errorf("must include a port")
	}
	return nil
}

// getServices returns a copy of the current agent-registered services.
func (s *Server) getServices() []ServiceEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ServiceEntry, len(s.services))
	copy(out, s.services)
	return out
}

// servicesForHello maps the internal registry entries to the public /hello
// shape, dropping the internal loopback backend — external callers reach a
// service through :8080, never its backend port directly.
func servicesForHello(entries []ServiceEntry) []report.Service {
	out := make([]report.Service, 0, len(entries))
	for _, e := range entries {
		out = append(out, report.Service{
			Path:         e.Path,
			Method:       e.Method,
			Description:  e.Description,
			InputExample: e.InputExample,
		})
	}
	return out
}

// helloSelfEntry is service #0: /hello advertises itself. Always present,
// so the service list is never empty and the always-on signed endpoint is
// visible as the worked example of the mechanism. Backed by sealed itself
// (not an agent loopback), so it needs no registration.
func helloSelfEntry() report.Service {
	return report.Service{
		Path:        "/hello",
		Method:      "GET",
		Description: "Signed self-introduction — this agent's identity, on-chain data hashes, and its declared services.",
	}
}

// helloServiceList is the array /hello advertises: entry #0 (/hello itself)
// followed by the agent-registered services.
func (s *Server) helloServiceList() []report.Service {
	return append([]report.Service{helloSelfEntry()}, servicesForHello(s.getServices())...)
}

// matchService returns the registered service whose path exactly equals the
// request path (query string excluded by the caller). Exact match for now;
// subpath/prefix routing is a later refinement.
func (s *Server) matchService(path string) (ServiceEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.services {
		if e.Path == path {
			return e, true
		}
	}
	return ServiceEntry{}, false
}

// handleServices serves the agent-only registry on the internal sign socket:
//
//	POST /services  — replace the whole agent-registered set (overwrite
//	                  semantics; the complete list every time).
//	GET  /services  — read the current set back.
//
// /hello (the sealed-owned default service) is never part of this set.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"services": s.getServices()})
	case http.MethodPost:
		var body struct {
			Services []ServiceEntry `json:"services"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeSignError(w, http.StatusBadRequest, "decode body: "+err.Error())
			return
		}
		entries, err := validateServices(body.Services)
		if err != nil {
			writeSignError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.mu.Lock()
		s.services = entries
		s.mu.Unlock()
		logger.Logf("services: registered %d agent service(s)", len(entries))
		writeJSON(w, http.StatusOK, map[string]any{"services": entries})
	default:
		writeSignError(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}
