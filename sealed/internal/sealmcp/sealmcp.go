// Package sealmcp serves one of sealed's agent sockets as an MCP server
// (Model Context Protocol over streamable HTTP, stateless, JSON responses):
// POST /mcp on the socket lists the socket's endpoints as tools, and runs a
// tool by sending the request to the socket's own handler. A tool therefore
// does exactly what its endpoint does, with the same checks and the same
// record, and nothing more; the socket file stays the only credential.
//
// The tool definitions live in sealed, next to the endpoints they describe,
// so they follow the sealed version that serves them. The framework mounts
// the server directly over the socket (0g-harness's seal-tools plugin), for
// an adapter that declares framework.RuntimeTools.
package sealmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Tool is one endpoint of the socket, offered as an MCP tool.
type Tool struct {
	Name        string
	Description string
	// Schema is the JSON schema of the tool's arguments (an object schema).
	Schema map[string]any
	// Method and Path name the endpoint. A path segment written {arg} is
	// taken from that argument, which is then not sent in the body.
	Method string
	Path   string
	// Prepare, when set, checks the arguments and returns the request body
	// (nil: none). Without it, a GET has no body and any other method sends
	// the arguments as the JSON body. Numbers in args are json.Number.
	Prepare func(args map[string]any) (body any, err error)
	// Handler, when set, serves the tool instead of the server's Handler:
	// a tool of another socket that this server also lists.
	Handler http.Handler
}

// Server is the MCP server for one socket.
type Server struct {
	Name         string
	Version      string
	Instructions string
	// Tools lists the tools at the moment of the call: a tool whose endpoint
	// is not wired in this runtime is left out.
	Tools func() []Tool
	// Handler is the socket's own handler; tool calls are served by it
	// unless the tool names another.
	Handler http.Handler
}

// Protocol versions this server speaks; the first is offered when the client
// asks for one not listed.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const (
	maxRequestBytes = 1 << 20
	maxResultBytes  = 1 << 20
)

// JSON-RPC 2.0 error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// ServeHTTP answers POST with JSON. There is no server-to-client stream, so
// GET (and DELETE, which ends a session this server never keeps) is 405.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	out, ok := s.handle(r.Context(), body)
	if !ok {
		// Notifications only: nothing to answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// handle answers one message or a batch; ok is false when nothing needs an
// answer.
func (s *Server) handle(ctx context.Context, body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
			return mustJSON(errorResponse(nil, codeParse, "invalid JSON")), true
		}
		var out []rpcResponse
		for _, m := range batch {
			if resp, ok := s.one(ctx, m); ok {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return mustJSON(out), true
	}
	resp, ok := s.one(ctx, trimmed)
	if !ok {
		return nil, false
	}
	return mustJSON(resp), true
}

func (s *Server) one(ctx context.Context, raw json.RawMessage) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return errorResponse(nil, codeParse, "invalid JSON"), true
	}
	notification := len(req.ID) == 0 || string(req.ID) == "null"
	if req.JSONRPC != "2.0" || req.Method == "" {
		if notification {
			return rpcResponse{}, false
		}
		return errorResponse(req.ID, codeInvalidRequest, "not a JSON-RPC 2.0 request"), true
	}
	if notification {
		// notifications/initialized, notifications/cancelled and the like:
		// a stateless server has nothing to do with them.
		return rpcResponse{}, false
	}
	switch req.Method {
	case "initialize":
		return result(req.ID, s.initialize(req.Params)), true
	case "ping":
		return result(req.ID, map[string]any{}), true
	case "tools/list":
		return result(req.ID, map[string]any{"tools": s.list()}), true
	case "tools/call":
		res, rerr := s.call(ctx, req.Params)
		if rerr != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr}, true
		}
		return result(req.ID, res), true
	default:
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method), true
	}
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := protocolVersions[0]
	for _, v := range protocolVersions {
		if v == p.ProtocolVersion {
			version = v
		}
	}
	out := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
	}
	if s.Instructions != "" {
		out["instructions"] = s.Instructions
	}
	return out
}

func (s *Server) tools() []Tool {
	if s.Tools == nil {
		return nil
	}
	return s.Tools()
}

func (s *Server) list() []map[string]any {
	tools := s.tools()
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		schema := t.Schema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
	}
	return out
}

// call runs a tool. A request the tool's endpoint refuses is a tool result
// with isError, as MCP has it; only a call that names no tool is a
// protocol error.
func (s *Server) call(ctx context.Context, params json.RawMessage) (map[string]any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "tools/call needs a tool name"}
	}
	var tool *Tool
	for _, t := range s.tools() {
		if t.Name == p.Name {
			t := t
			tool = &t
			break
		}
	}
	if tool == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + p.Name}
	}
	args := map[string]any{}
	if len(bytes.TrimSpace(p.Arguments)) > 0 && string(bytes.TrimSpace(p.Arguments)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(p.Arguments))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return toolError("arguments must be a JSON object: " + err.Error()), nil
		}
	}
	status, text, err := s.run(ctx, *tool, args)
	if err != nil {
		return toolError(err.Error()), nil
	}
	if status >= 300 {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("HTTP %d: %s", status, text)}}, "isError": true}, nil
	}
	if text == "" {
		text = fmt.Sprintf("HTTP %d", status)
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false}, nil
}

// run sends the tool's request to the socket's handler and returns the
// status and the body.
func (s *Server) run(ctx context.Context, t Tool, args map[string]any) (int, string, error) {
	path, err := fillPath(t.Path, args)
	if err != nil {
		return 0, "", err
	}
	var body any
	switch {
	case t.Prepare != nil:
		if body, err = t.Prepare(args); err != nil {
			return 0, "", err
		}
	case t.Method != http.MethodGet:
		body = args
	}
	var reader io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", fmt.Errorf("encode the request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, t.Method, "http://localhost"+path, reader)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	h := s.Handler
	if t.Handler != nil {
		h = t.Handler
	}
	rec := &recorder{header: http.Header{}}
	h.ServeHTTP(rec, req)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	text := strings.TrimSpace(rec.body.String())
	if rec.truncated {
		text += "\n[truncated]"
	}
	return rec.status, text, nil
}

// fillPath replaces each {arg} segment with that argument, which is then
// removed from args.
func fillPath(pattern string, args map[string]any) (string, error) {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := seg[1 : len(seg)-1]
		v, _ := args[name].(string)
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("give %s", name)
		}
		segs[i] = url.PathEscape(v)
		delete(args, name)
	}
	return strings.Join(segs, "/"), nil
}

func toolError(msg string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}
}

func result(id json.RawMessage, v any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: v}
}

func errorResponse(id json.RawMessage, code int, msg string) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(errorResponse(nil, -32603, "encode the answer"))
	}
	return b
}

// recorder collects a handler's answer, up to maxResultBytes of body.
type recorder struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	truncated bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	room := maxResultBytes - r.body.Len()
	if room <= 0 {
		r.truncated = true
		return len(b), nil
	}
	if len(b) > room {
		r.truncated = true
		r.body.Write(b[:room])
		return len(b), nil
	}
	return r.body.Write(b)
}

// Helpers for Prepare functions.

// Require reports the first of names that args lacks.
func Require(args map[string]any, names ...string) error {
	for _, n := range names {
		if v, ok := args[n]; !ok || v == nil {
			return fmt.Errorf("give %s", n)
		}
	}
	return nil
}

// Allow refuses an argument the tool does not take: a misspelt field would
// otherwise be dropped without a word.
func Allow(args map[string]any, names ...string) error {
	for k := range args {
		known := false
		for _, n := range names {
			if k == n {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("unknown argument %q (takes %s)", k, strings.Join(names, ", "))
		}
	}
	return nil
}

// CheckSchema reports a construct outside the JSON Schema subset every
// client the runtime's tools are mounted in takes: one string `type`, object
// `properties` with `required` among them and a boolean
// `additionalProperties`, array `items`, scalar `enum`, and `description`.
func CheckSchema(schema map[string]any) error {
	return checkSchema(schema, "schema")
}

func checkSchema(n map[string]any, path string) error {
	for k, v := range n {
		switch k {
		case "type":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s.type: one type, as a string", path)
			}
		case "description":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s.description: a string", path)
			}
		case "additionalProperties":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("%s.additionalProperties: a boolean", path)
			}
		case "enum":
			if _, ok := v.([]string); !ok {
				return fmt.Errorf("%s.enum: strings", path)
			}
		case "required":
			req, ok := v.([]string)
			if !ok {
				return fmt.Errorf("%s.required: strings", path)
			}
			props, _ := n["properties"].(map[string]any)
			for _, r := range req {
				if _, ok := props[r]; !ok {
					return fmt.Errorf("%s.required: %q is not a property", path, r)
				}
			}
		case "properties":
			props, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.properties: an object", path)
			}
			for name, p := range props {
				pm, ok := p.(map[string]any)
				if !ok {
					return fmt.Errorf("%s.properties.%s: a schema", path, name)
				}
				if err := checkSchema(pm, path+".properties."+name); err != nil {
					return err
				}
			}
		case "items":
			im, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.items: a schema", path)
			}
			if err := checkSchema(im, path+".items"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %q is outside the subset", path, k)
		}
	}
	return nil
}
