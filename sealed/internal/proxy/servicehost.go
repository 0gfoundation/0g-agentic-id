package proxy

import (
	"encoding/json"
	"net/http"

	"seal-verify/internal/sealmcp"
	"seal-verify/internal/servicehost"
)

func (s *Server) SetServiceHost(m *servicehost.Manager) {
	s.mu.Lock()
	s.serviceHost = m
	s.mu.Unlock()
}
func (s *Server) getServiceHost() *servicehost.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serviceHost
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
		"network":                 map[string]any{"type": "string", "enum": []string{"none", "host"}, "description": "Default none. host explicitly grants the container network including loopback; no tenant network isolation."},
		"memory_mb":               map[string]any{"type": "integer", "description": "Per-process virtual address-space limit, default 8192 MiB; 128..16384."},
		"processes":               map[string]any{"type": "integer", "description": "Per-service UID process limit, default 64; 1..256."},
		"request_timeout_seconds": map[string]any{"type": "integer", "description": "Whole isolated worker lifetime, default 300 seconds; 1..3600. Every MCP POST uses a fresh UID/sandbox; no task resume."},
	}, "id", "command", "args", "files")
	tools := []sealmcp.Tool{{Name: "seal_service_list", Description: "List hosted MCP services, versions, desired state and request admission status.", Schema: obj(map[string]any{}), Method: http.MethodGet, Path: "/service-host"}}
	tools = append(tools, sealmcp.Tool{Name: "seal_service_publish", Description: "Publish a stopped service's immutable release. Files are base64. Every MCP POST runs in a fresh isolated process listening on $MCP_SOCKET; /app is read-only, /work and /tmp are temporary. Stop before updating. No employer credential custody.", Schema: obj(map[string]any{"manifest": manifest}, "manifest"), Method: http.MethodPost, Path: "/service-host", Prepare: func(args map[string]any) (any, error) {
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
		tools = append(tools, sealmcp.Tool{Name: "seal_service_" + a, Description: map[string]string{"start": "Enable requests to a published MCP service. Each POST starts a fresh isolated worker; running indicates admission, not business health.", "stop": "Disable new requests and terminate all active workers for this service. Remains stopped after reboot.", "logs": "Request-worker stdout/stderr is discarded; this returns an empty log."}[a], Schema: obj(map[string]any{"id": str("Published service id.")}, "id"), Method: http.MethodPost, Path: "/service-host", Prepare: func(args map[string]any) (any, error) {
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
