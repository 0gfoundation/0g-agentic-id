package proxy

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

func signMCP(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	mux, _ := s.signSocketMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("/mcp: %d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func signTool(t *testing.T, s *Server, name, args string) (string, bool) {
	t.Helper()
	res := signMCP(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)["result"].(map[string]any)
	return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"].(bool)
}

// The sign socket lists its endpoints as tools; restarting the harness only
// where the runtime can.
func TestSignMCP_ListsTheSocketsEndpoints(t *testing.T) {
	s, _ := rulesServer(t)
	names := func() string {
		var n []string
		for _, tool := range signMCP(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)["result"].(map[string]any)["tools"].([]any) {
			n = append(n, tool.(map[string]any)["name"].(string))
		}
		sort.Strings(n)
		return strings.Join(n, ",")
	}
	const base = "seal_register_service,seal_services,seal_set_thinking,seal_settings,seal_sign,seal_sign_transaction,seal_sign_typed_data"
	if got := names(); got != base {
		t.Fatalf("tools: %s", got)
	}
	s.SetHarnessRestart(func(context.Context) error { return nil })
	if got := names(); got != "seal_register_service,seal_restart_harness,seal_services,seal_set_thinking,seal_settings,seal_sign,seal_sign_transaction,seal_sign_typed_data" {
		t.Fatalf("tools with a harness restart: %s", got)
	}
}

// /mcp is served only for a framework that mounts the runtime's tools.
func TestSignMCP_OnlyWhereDeclared(t *testing.T) {
	s, _ := signServer(t)
	mux, _ := s.signSocketMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/mcp for an undeclared framework: %d", rec.Code)
	}
}

// A tool signs through the socket's route: same signature, same record.
func TestSignMCP_SignsAndRecords(t *testing.T) {
	s, addr := rulesServer(t)
	text, isErr := signTool(t, s, "seal_sign", `{"message":"from a tool"}`)
	if isErr || !strings.Contains(text, addr.Hex()) {
		t.Fatalf("seal_sign: %v %s", isErr, text)
	}
	if r := lastRecord(t, s); r.Kind != "personal_sign" || r.Text != "from a tool" {
		t.Fatalf("record: %+v", r)
	}

	// The domain's own type may be left out.
	text, isErr = signTool(t, s, "seal_sign_typed_data", `{"domain":{"name":"T","chainId":1},"types":{"M":[{"name":"n","type":"uint256"}]},"primaryType":"M","message":{"n":5}}`)
	if isErr || !strings.Contains(text, "digest") {
		t.Fatalf("seal_sign_typed_data: %v %s", isErr, text)
	}
}

func TestSignMCP_TransactionArguments(t *testing.T) {
	s, _ := rulesServer(t)
	s.SetAgenticID(testAgenticID)
	const fees = `"gas_limit":21000,"max_fee_per_gas":"2","max_priority_fee_per_gas":"1"`
	for name, tc := range map[string]struct {
		args string
		ok   bool
		want string
	}{
		"plain":                 {`{"chain_id":16602,"nonce":0,"to":"0x0000000000000000000000000000000000000002","value":"1000",` + fees + `}`, true, "raw_tx"},
		"no to":                 {`{"chain_id":"16602","nonce":0,` + fees + `}`, false, "give to"},
		"explicit creation":     {`{"chain_id":"16602","nonce":0,"to":"","data":"0x6000",` + fees + `}`, true, "raw_tx"},
		"rounded amount":        {`{"chain_id":"16602","nonce":0,"to":"0x0000000000000000000000000000000000000002","value":1500000000000000000,` + fees + `}`, false, "2^53"},
		"misspelt field":        {`{"chain_id":"16602","nonce":0,"to":"","gasLimit":1,` + fees + `}`, false, `unknown argument "gasLimit"`},
		"nonce as a string":     {`{"chain_id":"16602","nonce":"3","to":"0x0000000000000000000000000000000000000002",` + fees + `}`, true, "raw_tx"},
		"AgenticID iData write": {`{"chain_id":"16602","nonce":0,"to":"` + testAgenticID + `","data":"` + iDataCall(t, "update") + `",` + fees + `}`, false, "HTTP 403"},
	} {
		text, isErr := signTool(t, s, "seal_sign_transaction", tc.args)
		if isErr == tc.ok || !strings.Contains(text, tc.want) {
			t.Errorf("%s: isError=%v %s", name, isErr, text)
		}
	}
	creations := 0
	for _, r := range s.signLog.since(-1) {
		if r.Create {
			creations++
		}
	}
	if creations != 1 {
		t.Errorf("the explicit creation is recorded as one: %+v", s.signLog.since(-1))
	}
	text, isErr := signTool(t, s, "seal_sign_typed_data", `{"domain":{"name":"T"},"types":{"M":[{"name":"n","type":"uint256"}]},"primaryType":"M","message":{"n":12345678901234567890}}`)
	if !isErr || !strings.Contains(text, "message.n") {
		t.Errorf("a typed-data integer a client may have rounded: %v %s", isErr, text)
	}
}

// Every tool's argument schema stays in the subset every mounting client
// takes (DSH, openclaw, hermes, prime-agent).
func TestSignMCP_SchemasInTheCommonSubset(t *testing.T) {
	s, _ := rulesServer(t)
	s.SetHarnessRestart(func(context.Context) error { return nil })
	for _, tool := range s.signTools() {
		schema := tool.Schema
		if schema == nil {
			continue
		}
		if err := sealmcp.CheckSchema(schema); err != nil {
			t.Errorf("%s: %v", tool.Name, err)
		}
	}
}
