package proxy

import (
	"encoding/json"
	"net/http"

	"seal-verify/internal/sealmcp"
	"seal-verify/internal/servicehost"
)

func (s *Server) SetServiceHost(m *servicehost.Manager) {
	if m != nil {
		m.SetExecutionAttestor(s.signExecutionReceipt)
	}
	s.mu.Lock()
	s.serviceHost = m
	s.mu.Unlock()
}
func (s *Server) getServiceHost() *servicehost.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serviceHost
}

// This gate follows the selected runtime, not only manager availability. A
// failed service-host bootstrap must never reopen legacy loopback forwarding.
func (s *Server) isolatedServicePolicy() bool {
	s.mu.RLock()
	strict, host := s.strictServices, s.serviceHost
	s.mu.RUnlock()
	return host != nil || strict
}

// This handler is reachable only through the owner agent's socket. Published
// sandboxes never receive that socket, the reveal socket or a signing tool.
func (s *Server) handleServiceHost(w http.ResponseWriter, r *http.Request) {
	m := s.getServiceHost()
	if m == nil {
		writeSignError(w, 503, "service hosting unavailable")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"services": m.List()})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeSignError(w, 405, "GET or POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 24<<20)
	var req struct {
		Action   string                `json:"action"`
		ID       string                `json:"id"`
		Manifest *servicehost.Manifest `json:"manifest,omitempty"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		writeSignError(w, 400, "invalid service request: "+err.Error())
		return
	}
	var out any
	var err error
	switch req.Action {
	case "publish":
		if req.Manifest == nil {
			writeSignError(w, 400, "give manifest")
			return
		}
		out, err = m.Publish(*req.Manifest)
	case "start":
		out, err = m.Start(req.ID)
	case "stop":
		out, err = m.Stop(req.ID)
	case "logs":
		var text string
		text, err = m.Logs(req.ID)
		out = map[string]string{"logs": text}
	default:
		writeSignError(w, 400, "action must be publish, start, stop or logs")
		return
	}
	if err != nil {
		writeSignError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) serviceHostTools() []sealmcp.Tool {
	if s.getServiceHost() == nil {
		return nil
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	obj := func(props map[string]any, req ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(req) > 0 {
			m["required"] = req
		}
		return m
	}
	manifest := obj(map[string]any{
		"id":                      str("Lowercase service name, up to 32 characters; public endpoint /api/mcp/<id>."),
		"command":                 str("Trusted image interpreter name, e.g. node. Runs inside a sandbox, never as sealed."),
		"args":                    map[string]any{"type": "array", "items": str("Interpreter argument, e.g. /app/server.mjs.")},
		"files":                   map[string]any{"type": "array", "items": obj(map[string]any{"path": str("Relative release file path."), "data": str("Standard base64 file bytes.")}, "path", "data")},
		"description":             str("Short public service description."),
		"env":                     map[string]any{"type": "object", "additionalProperties": true, "description": "Non-secret program configuration; string values. Never put credentials in tool arguments."},
		"worker":                  obj(map[string]any{"command": str("Trusted image interpreter for isolated task execution."), "args": map[string]any{"type": "array", "items": str("Worker interpreter argument.")}}, "command", "args"),
		"network":                 map[string]any{"type": "string", "enum": []string{"none", "egress"}, "description": "Programs always have private networking. egress permits only public destinations in egress_hosts through a restricted Unix proxy."},
		"egress_hosts":            map[string]any{"type": "array", "maxItems": 32, "items": str("Explicit allowed host:port, for example api.example:443. Private/loopback addresses remain blocked.")},
		"memory_mb":               map[string]any{"type": "integer", "description": "Per-process virtual address-space limit, default 8192 MiB; 128..16384."},
		"processes":               map[string]any{"type": "integer", "description": "Per-service UID process limit, default 64; 1..256."},
		"request_timeout_seconds": map[string]any{"type": "integer", "description": "Whole isolated task-worker lifetime, default 300 seconds; 1..3600. Task workers never resume."},
	}, "id", "command", "args", "files")
	tools := []sealmcp.Tool{{Name: "seal_service_list", Description: "List hosted MCP services, versions, desired state and request admission status.", Schema: obj(map[string]any{}), Method: http.MethodGet, Path: "/service-host"}}
	tools = append(tools, sealmcp.Tool{Name: "seal_service_publish", Description: "Publish a stopped service's immutable release. Files are base64. Without worker, each POST starts an isolated temporary server. With worker, an isolated coordinator handles MCP and starts only separately isolated temporary task processes through its service-scoped control socket. /app is read-only; only coordinator /work is durable. Stop before updating. No employer credential custody.", Schema: obj(map[string]any{"manifest": manifest}, "manifest"), Method: http.MethodPost, Path: "/service-host", Prepare: func(args map[string]any) (any, error) {
		if err := sealmcp.Allow(args, "manifest"); err != nil {
			return nil, err
		}
		if err := sealmcp.Require(args, "manifest"); err != nil {
			return nil, err
		}
		return map[string]any{"action": "publish", "manifest": args["manifest"]}, nil
	}})
	for _, action := range []string{"start", "stop", "logs"} {
		a := action
		tools = append(tools, sealmcp.Tool{Name: "seal_service_" + a, Description: map[string]string{"start": "Enable a published MCP service. With worker, start its isolated coordinator; each task runs in a separate temporary process. Otherwise each POST starts a temporary server. Verify real business health.", "stop": "Disable new requests and terminate the coordinator and all active workers for this service. Remains stopped after reboot.", "logs": "Request-worker stdout/stderr is discarded; this returns an empty log."}[a], Schema: obj(map[string]any{"id": str("Published service id.")}, "id"), Method: http.MethodPost, Path: "/service-host", Prepare: func(args map[string]any) (any, error) {
			if err := sealmcp.Allow(args, "id"); err != nil {
				return nil, err
			}
			if err := sealmcp.Require(args, "id"); err != nil {
				return nil, err
			}
			return map[string]any{"action": a, "id": args["id"]}, nil
		}})
	}
	return tools
}
