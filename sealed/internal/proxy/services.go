package proxy

// Agent interfaces: the services an agent serves itself.
//
// An agent exposes a service by running the backend itself — a loopback
// HTTP server inside this sandbox — and registering it here over the
// agent-only sign socket (POST /services). sealed's :8080 proxy then
// routes the public path to that backend and signs the response, so every
// externally visible service leaves through the one attributed surface,
// whatever the framework. sealed keeps the registered list across restarts
// of the container and can run the backends itself (agentservices.go); it
// is not chain-anchored, so a capability that must survive a reset or a
// transfer lives in the agent's tracked data, which registers it again.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/report"
	"seal-verify/internal/servicehost"
)

// ServiceEntry is one agent-declared external service.
type ServiceEntry struct {
	Path         string `json:"path"`                    // public path, must start with /api/
	Method       string `json:"method"`                  // uppercase HTTP verb
	Description  string `json:"description,omitempty"`   // one short sentence
	InputExample string `json:"input_example,omitempty"` // literal JSON body, if any
	Backend      string `json:"backend"`                 // loopback upstream: http://127.0.0.1:<port>
	// Transport marks plain HTTP or an MCP Streamable HTTP endpoint. MCP
	// registrations name POST; the proxy also relays GET/DELETE and lets
	// the backend return 405 when an optional method is unsupported.
	Transport string `json:"transport,omitempty"` // "" (plain HTTP) | "mcp"
	// Start, when set, has sealed run the backend itself and keep it
	// running, across restarts too (agentservices.go). Never shown in /hello.
	Start *ServiceStart `json:"start,omitempty"`
}

// reservedPrefixes are platform-owned paths an agent service may not shadow.
// Agent paths must already be under /api/, so this is belt-and-suspenders
// against a future /api/-reserved path or a validation slip.
var reservedPrefixes = []string{"/hello", "/healthz", "/log", "/_seal/", "/admin/"}

var validMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true,
}

// fieldLimits bound a registration's description and input example, in
// bytes, for adapters that declare them (framework.ServiceFieldLimiter);
// zero leaves a field unbounded.
type fieldLimits struct {
	description, inputExample int
	managedNamespace          bool
}

// validateServices checks the agent-supplied list as a whole. Any violation
// rejects the ENTIRE POST (all-or-nothing) so a bad entry can't partially
// land. Returns normalized entries (method upper-cased) or an error.
func validateServices(in []ServiceEntry, limits fieldLimits) ([]ServiceEntry, error) {
	seen := make(map[string]bool, len(in))
	out := make([]ServiceEntry, 0, len(in))
	for i, e := range in {
		if limits.description > 0 && len(e.Description) > limits.description {
			return nil, fmt.Errorf("services[%d].description is %d bytes, over the %d allowed", i, len(e.Description), limits.description)
		}
		if limits.inputExample > 0 && len(e.InputExample) > limits.inputExample {
			return nil, fmt.Errorf("services[%d].input_example is %d bytes, over the %d allowed", i, len(e.InputExample), limits.inputExample)
		}
		if !strings.HasPrefix(e.Path, "/api/") || len(e.Path) <= len("/api/") {
			return nil, fmt.Errorf("services[%d].path %q must start with /api/ and name something after it", i, e.Path)
		}
		for _, p := range reservedPrefixes {
			if e.Path == p || strings.HasPrefix(e.Path, p) {
				return nil, fmt.Errorf("services[%d].path %q is platform-reserved", i, e.Path)
			}
		}
		if limits.managedNamespace && managedServicePath(e.Path) {
			return nil, fmt.Errorf("services[%d].path %q belongs to isolated service hosting; use seal_service_publish", i, e.Path)
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
		if err := validateStart(e.Start); err != nil {
			return nil, fmt.Errorf("services[%d].%w", i, err)
		}
		switch e.Transport {
		case "":
		case "mcp":
			// The one-method-per-path pin meets MCP's POST workhorse: a
			// non-POST MCP route would be unauditable on arrival (405 on
			// every JSON-RPC request).
			if m != http.MethodPost {
				return nil, fmt.Errorf("services[%d].transport %q requires method POST, got %q", i, e.Transport, m)
			}
		default:
			return nil, fmt.Errorf("services[%d].transport %q is not a known transport (\"\" or \"mcp\")", i, e.Transport)
		}
		out = append(out, e)
	}
	if err := checkSharedStarts(out); err != nil {
		return nil, err
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
	// Host:port ONLY — no path/query/fragment. The proxy forwards to
	// `backend + request.RequestURI` (see proxy.go), so any path here
	// double-prefixes the request (e.g. backend ".../api/x" + request
	// "/api/x" → ".../api/x/api/x"), which the loopback backend then 404s.
	// Reject at registration so the agent fails fast instead of silently
	// serving 404/502.
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("must be host:port only, no path (got %q) — sealed appends the request path when forwarding", u.Path)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be host:port only, no query or fragment")
	}
	return nil
}

// visibleServices is what callers can reach: a copy of the agent's
// registered interfaces (without the paths isolated hosting owns, under that
// policy) and, under that policy, the hosted programs.
func (s *Server) visibleServices() ([]ServiceEntry, []servicehost.Status) {
	strict := s.isolatedServicePolicy()
	s.mu.RLock()
	agent := make([]ServiceEntry, 0, len(s.services))
	for _, e := range s.services {
		if !strict || !managedServicePath(e.Path) {
			agent = append(agent, e)
		}
	}
	host := s.serviceHost
	s.mu.RUnlock()
	if !strict || host == nil {
		return agent, nil
	}
	return agent, host.List()
}

// getServices returns the services callers can reach, hosted programs as
// entries too.
func (s *Server) getServices() []ServiceEntry {
	out, hosted := s.visibleServices()
	for _, svc := range hosted {
		out = append(out, ServiceEntry{Path: svc.Path, Method: "POST", Backend: "http://localhost", Transport: "mcp", Description: svc.Description})
	}
	return out
}

// servicesForHello maps the agent's registered interfaces to the public
// /hello shape, dropping the internal loopback backend and start command —
// external callers reach a service through :8080, never its backend port
// directly.
func servicesForHello(entries []ServiceEntry) []report.Service {
	out := make([]report.Service, 0, len(entries))
	for _, e := range entries {
		out = append(out, report.Service{
			Path:         e.Path,
			Method:       e.Method,
			Description:  e.Description,
			InputExample: e.InputExample,
			Transport:    e.Transport,
			Kind:         report.ServiceKindAgent,
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
		Kind:        report.ServiceKindRuntime,
	}
}

// helloServiceList is the array /hello advertises: entry #0 (/hello itself),
// the agent's registered interfaces, then its hosted programs with the
// release each one runs and where to audit it.
func (s *Server) helloServiceList() []report.Service {
	agent, hosted := s.visibleServices()
	out := append([]report.Service{helloSelfEntry()}, servicesForHello(agent)...)
	for _, svc := range hosted {
		out = append(out, report.Service{
			Path: svc.Path, Method: "POST", Description: svc.Description, Transport: "mcp",
			Kind: report.ServiceKindHosted, Version: svc.Version, Release: svc.Path + "?sealed-release=1",
		})
	}
	return out
}

// matchService returns the registered service whose path exactly equals the
// request path (query string excluded by the caller). Exact match for now;
// subpath/prefix routing is a later refinement.
func (s *Server) matchService(path string) (ServiceEntry, bool) {
	if s.isolatedServicePolicy() && managedServicePath(path) {
		if host := s.getServiceHost(); host != nil {
			if svc, ok := host.Match(path); ok {
				return ServiceEntry{Path: svc.Path, Method: "POST", Backend: "http://localhost", Transport: "mcp", Description: svc.Description}, true
			}
		}
		return ServiceEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.services {
		if e.Path == path {
			return e, true
		}
	}
	return ServiceEntry{}, false
}

// serviceLimits are the registration rules of this runtime and framework.
func (s *Server) serviceLimits() fieldLimits {
	limits := fieldLimits{managedNamespace: s.isolatedServicePolicy()}
	if l, ok := s.getAdapter().(framework.ServiceFieldLimiter); ok {
		limits.description, limits.inputExample = l.ServiceFieldLimits()
	}
	return limits
}

// handleServices serves the agent-only registry on the internal sign socket:
//
//	POST /services  — replace the whole agent-registered set (overwrite
//	                  semantics; the complete list every time).
//	GET  /services  — read the current set back, with how each backend
//	                  sealed runs is doing (agentservices.go).
//
// /hello (the sealed-owned default service) is never part of this set.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out := map[string]any{"services": s.getServices()}
		if b := s.backendStatuses(); len(b) > 0 {
			out["backends"] = b
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var body struct {
			Services []ServiceEntry `json:"services"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeSignError(w, http.StatusBadRequest, "decode body: "+err.Error())
			return
		}
		entries, err := validateServices(body.Services, s.serviceLimits())
		if err != nil {
			writeSignError(w, http.StatusBadRequest, err.Error())
			return
		}
		// One registration at a time, so the list kept on disk and the
		// backends sealed runs always match the one in effect.
		s.keeper.post.Lock()
		defer s.keeper.post.Unlock()
		s.mu.Lock()
		s.services = entries
		s.mu.Unlock()
		logger.Logf("services: registered %d agent service(s)", len(entries))
		out := map[string]any{"services": entries}
		if err := s.keepAgentServices(entries); err != nil {
			logger.Logf("services: cannot keep the agent's interfaces across a restart: %v", err)
			out["warning"] = "registered, but not kept across a restart: " + err.Error()
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeSignError(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}
