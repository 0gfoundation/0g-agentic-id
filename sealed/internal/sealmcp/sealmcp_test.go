package sealmcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echo is a socket handler that answers with what it got.
func echo() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/thing/{name}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "name": r.PathValue("name"), "body": string(b)})
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"nope"}`, http.StatusForbidden)
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return mux
}

func testServer() *Server {
	return &Server{
		Name: "t", Version: "1", Instructions: "use it",
		Handler: echo(),
		Tools: func() []Tool {
			return []Tool{
				{Name: "post", Description: "d", Method: http.MethodPost, Path: "/thing/{name}"},
				{Name: "get", Method: http.MethodGet, Path: "/thing/{name}"},
				{Name: "fail", Method: http.MethodPost, Path: "/fail"},
				{Name: "empty", Method: http.MethodDelete, Path: "/empty", Prepare: func(map[string]any) (any, error) { return nil, nil }},
				{Name: "strict", Method: http.MethodPost, Path: "/thing/x", Prepare: func(args map[string]any) (any, error) {
					return args, Allow(args, "a")
				}},
			}
		},
	}
}

func rpc(t *testing.T, s *Server, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	var out map[string]any
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("answer is not JSON: %s", w.Body)
		}
	}
	return w, out
}

func TestInitialize_NegotiatesVersion(t *testing.T) {
	s := testServer()
	for asked, want := range map[string]string{"2025-03-26": "2025-03-26", "2025-11-25": "2025-11-25", "2099-01-01": "2025-11-25", "": "2025-11-25"} {
		_, out := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+asked+`","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
		res := out["result"].(map[string]any)
		if res["protocolVersion"] != want {
			t.Errorf("asked %q: got %v, want %s", asked, res["protocolVersion"], want)
		}
		if res["instructions"] != "use it" || res["serverInfo"].(map[string]any)["name"] != "t" {
			t.Errorf("initialize result: %v", res)
		}
		if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
			t.Errorf("no tools capability: %v", res)
		}
	}
}

func TestNotificationsGetNoAnswer(t *testing.T) {
	s := testServer()
	w, _ := rpc(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("notification: %d %q", w.Code, w.Body)
	}
}

func TestToolsList(t *testing.T) {
	_, out := rpc(t, testServer(), `{"jsonrpc":"2.0","id":"a","method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 5 {
		t.Fatalf("tools: %v", tools)
	}
	first := tools[0].(map[string]any)
	if first["name"] != "post" || first["description"] != "d" || first["inputSchema"].(map[string]any)["type"] != "object" {
		t.Fatalf("tool: %v", first)
	}
	if out["id"] != "a" {
		t.Fatalf("id not echoed: %v", out)
	}
}

func call(t *testing.T, s *Server, name, args string) (text string, isError bool) {
	t.Helper()
	_, out := rpc(t, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no result: %v", name, out)
	}
	content := res["content"].([]any)[0].(map[string]any)
	return content["text"].(string), res["isError"].(bool)
}

func TestToolsCall_RunsTheEndpoint(t *testing.T) {
	s := testServer()
	text, isErr := call(t, s, "post", `{"name":"n1","x":12345678901234567890}`)
	var got map[string]string
	if isErr || json.Unmarshal([]byte(text), &got) != nil {
		t.Fatalf("post: %v %s", isErr, text)
	}
	// The path argument leaves the body; numbers keep every digit.
	if got["method"] != "POST" || got["name"] != "n1" || got["body"] != `{"x":12345678901234567890}` {
		t.Fatalf("post reached the endpoint as %v", got)
	}
	text, _ = call(t, s, "get", `{"name":"a/b"}`)
	_ = json.Unmarshal([]byte(text), &got)
	if got["method"] != "GET" || got["body"] != "" {
		t.Fatalf("get: %v", got)
	}
	if text, isErr := call(t, s, "fail", `{}`); !isErr || !strings.Contains(text, "HTTP 403") || !strings.Contains(text, "nope") {
		t.Fatalf("a refused request is a tool error: %v %s", isErr, text)
	}
	if text, isErr := call(t, s, "empty", `null`); isErr || text != "HTTP 204" {
		t.Fatalf("empty answer: %v %q", isErr, text)
	}
	if text, isErr := call(t, s, "post", `{}`); !isErr || !strings.Contains(text, "give name") {
		t.Fatalf("missing path argument: %v %s", isErr, text)
	}
	if text, isErr := call(t, s, "strict", `{"b":1}`); !isErr || !strings.Contains(text, `unknown argument "b"`) {
		t.Fatalf("Allow: %v %s", isErr, text)
	}
	if text, isErr := call(t, s, "post", `[1]`); !isErr || !strings.Contains(text, "JSON object") {
		t.Fatalf("arguments that are not an object: %v %s", isErr, text)
	}
}

func TestProtocolErrors(t *testing.T) {
	s := testServer()
	_, out := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`)
	if out["error"].(map[string]any)["code"].(float64) != codeInvalidParams {
		t.Fatalf("unknown tool: %v", out)
	}
	_, out = rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if out["error"].(map[string]any)["code"].(float64) != codeMethodNotFound {
		t.Fatalf("unknown method: %v", out)
	}
	_, out = rpc(t, s, `{not json`)
	if out["error"].(map[string]any)["code"].(float64) != codeParse || out["id"] != nil {
		t.Fatalf("parse error: %v", out)
	}
	_, out = rpc(t, s, `{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	if _, ok := out["result"].(map[string]any); !ok {
		t.Fatalf("ping: %v", out)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
}

func TestBatch(t *testing.T) {
	w := httptest.NewRecorder()
	testServer().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`)))
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) != 2 {
		t.Fatalf("batch: %s", w.Body)
	}
}

func TestToolResultIsBounded(t *testing.T) {
	big := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResultBytes+10)))
	})
	s := &Server{Handler: big, Tools: func() []Tool { return []Tool{{Name: "big", Method: http.MethodGet, Path: "/"}} }}
	text, _ := call(t, s, "big", `{}`)
	if len(text) > maxResultBytes+20 || !strings.HasSuffix(text, "[truncated]") {
		t.Fatalf("result of %d bytes", len(text))
	}
}
