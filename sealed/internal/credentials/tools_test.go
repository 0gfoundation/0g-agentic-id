package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"seal-verify/internal/sealmcp"
)

func mcpCall(t *testing.T, h http.Handler, body string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("/mcp: %d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out["result"].(map[string]any)
}

func toolNames(t *testing.T, h http.Handler) []string {
	t.Helper()
	var names []string
	for _, tool := range mcpCall(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	sort.Strings(names)
	return names
}

// The credential socket's endpoints are tools the sign socket's server lists
// (Tools); reveal is served by the reveal socket alone.
func TestMCP_ToolsAndTheRevealSocket(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	var names []string
	for _, tool := range s.Tools() {
		if tool.Handler == nil {
			t.Fatalf("%s is not served by the credential socket's handler", tool.Name)
		}
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "seal_credential_delete,seal_credential_request,seal_credential_sign,seal_credential_token,seal_credentials" {
		t.Fatalf("credential tools: %s", got)
	}
	rec := httptest.NewRecorder()
	s.RevealHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the reveal socket's tool is off until turned on: %d", rec.Code)
	}
	s.ServeRevealTool()
	if got := strings.Join(toolNames(t, s.RevealHandler()), ","); got != "seal_credential_reveal" {
		t.Fatalf("reveal socket tools: %s", got)
	}
	rec = httptest.NewRecorder()
	s.HarnessHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the credential socket serves no MCP of its own: %d", rec.Code)
	}
}

// A tool answers what its endpoint answers: the list without values, and a
// reveal that waits for the owner.
func TestMCP_ToolsAnswerAsTheEndpoints(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	_, _ = s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_secretvalue"}), 0)

	server := &sealmcp.Server{Tools: s.Tools}
	res := mcpCall(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"seal_credentials","arguments":{}}}`)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != false || !strings.Contains(text, `"github"`) || strings.Contains(text, "ghp_secretvalue") {
		t.Fatalf("seal_credentials: %v", res)
	}

	s.ServeRevealTool()
	res = mcpCall(t, s.RevealHandler(), `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"seal_credential_reveal","arguments":{"name":"github","reason":"a tool needs it"}}}`)
	text = res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != true || !strings.Contains(text, "HTTP 403") || !strings.Contains(text, "auth_req_id") || strings.Contains(text, "ghp_secretvalue") {
		t.Fatalf("seal_credential_reveal: %v", res)
	}

	res = mcpCall(t, server, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"seal_credential_request","arguments":{"op":"add","name":"x"}}}`)
	if res["isError"] != true || !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "give reason") {
		t.Fatalf("a request without a reason: %v", res)
	}
}

// Every tool's argument schema stays in the subset every mounting client
// takes.
func TestMCP_SchemasInTheCommonSubset(t *testing.T) {
	for _, tool := range append(harnessTools(), revealTools()...) {
		if err := sealmcp.CheckSchema(tool.Schema); err != nil {
			t.Errorf("%s: %v", tool.Name, err)
		}
	}
}
