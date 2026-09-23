package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type connectionTransport func(*http.Request) (*http.Response, error)

func (f connectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const testConnectionID = "12345678-1234-4123-8123-123456789abc"
const testCapability = "acap_abcdefghijklmnopqrstuvwxyz0123456789ABCDE12"
const testInvocationID = "87654321-4321-4321-8321-cba987654321"

func TestConnectionsForwardOneGrantWithoutExposingCredential(t *testing.T) {
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "calendar.check_availability"}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(h.list(true))
	if strings.Contains(string(wire), testCapability) || strings.Contains(string(wire), "engine.example") {
		t.Fatalf("private routing data in list: %s", wire)
	}
	h.client.Transport = connectionTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://engine.example/connections/runtime/agent-grants/"+testConnectionID+"/invoke" {
			t.Fatalf("wrong route: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Capability "+testCapability {
			t.Fatal("missing narrow credential")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 2 || string(body["invocationId"]) != `"turn-1"` || string(body["input"]) != `{"start":"today"}` {
			t.Fatalf("unexpected request: %s", body)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"result":{"available":true}}`))}, nil
	})
	got, err := h.invoke(context.Background(), connectionCall{GrantID: testConnectionID, InvocationID: "turn-1", Input: json.RawMessage(`{"start":"today"}`)})
	if err != nil || string(got) != `{"result":{"available":true}}` {
		t.Fatalf("result %s: %v", got, err)
	}
	h.remove(testConnectionID)
	if _, err := h.invoke(context.Background(), connectionCall{GrantID: testConnectionID, InvocationID: "turn-2", Input: json.RawMessage(`{}`)}); err != errConnectionMissing {
		t.Fatalf("removed grant accepted: %v", err)
	}
}

func TestConnectionsRouteAPIGrantWithoutForwardingDestinationControls(t *testing.T) {
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{
		EngineOrigin: "https://engine.example",
		Capability:   testCapability,
		Operation:    "api.request",
		Label:        "CRM records",
		SkillID:      "crm_lookup",
	}); err != nil {
		t.Fatal(err)
	}
	h.client.Transport = connectionTransport(func(r *http.Request) (*http.Response, error) {
		if got, want := r.URL.String(), "https://engine.example/connections/runtime/api-grants/"+testConnectionID+"/invoke"; got != want {
			t.Fatalf("wrong API grant route: got %s want %s", got, want)
		}
		if r.Header.Get("Authorization") != "Capability "+testCapability {
			t.Fatal("missing narrow credential")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 2 || string(body["invocationId"]) != `"`+testInvocationID+`"` || string(body["input"]) != `{"query":{"customer":"42"},"body":{"active":true}}` {
			t.Fatalf("unexpected request: %s", body)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"result":{"status":"ok"}}`))}, nil
	})

	got, err := h.invoke(context.Background(), connectionCall{
		GrantID:      testConnectionID,
		Operation:    "api.request",
		InvocationID: testInvocationID,
		Input:        json.RawMessage(`{"query":{"customer":"42"},"body":{"active":true}}`),
	})
	if err != nil || string(got) != `{"result":{"status":"ok"}}` {
		t.Fatalf("result %s: %v", got, err)
	}
}

func TestConnectionsRejectAPIGrantOverridesAndOperationMismatch(t *testing.T) {
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "api.request"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []connectionCall{
		{GrantID: testConnectionID, InvocationID: "missing-op", Input: json.RawMessage(`{}`)},
		{GrantID: testConnectionID, Operation: "calendar.check_availability", InvocationID: testInvocationID, Input: json.RawMessage(`{}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: "not-a-uuid", Input: json.RawMessage(`{}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: "00000000-0000-0000-0000-000000000000", Input: json.RawMessage(`{}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: testInvocationID, Input: json.RawMessage(`{"url":"https://attacker.example"}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: testInvocationID, Input: json.RawMessage(`{"method":"DELETE"}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: testInvocationID, Input: json.RawMessage(`{"headers":{"Authorization":"secret"}}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: testInvocationID, Input: json.RawMessage(`{"query":{"page":2}}`)},
		{GrantID: testConnectionID, Operation: "api.request", InvocationID: testInvocationID, Input: json.RawMessage(`{"query":null}`)},
	} {
		if _, err := h.invoke(context.Background(), call); err != errConnectionInput {
			t.Errorf("accepted invalid API call %+v: %v", call, err)
		}
	}
}

func TestConnectionsMatchAPIInputLimits(t *testing.T) {
	cases := []struct {
		name  string
		input any
	}{
		{name: "too many query entries", input: apiInputWithQuery(51, "name", "value")},
		{name: "empty query name", input: map[string]any{"query": map[string]string{"": "value"}}},
		{name: "long query name", input: map[string]any{"query": map[string]string{strings.Repeat("n", 129): "value"}}},
		{name: "long query value", input: map[string]any{"query": map[string]string{"name": strings.Repeat("v", 2049)}}},
		{name: "oversized input", input: map[string]any{"body": strings.Repeat("x", 64*1024)}},
	}
	for _, tc := range cases {
		raw, err := json.Marshal(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		if validAPIRequestInput(raw) {
			t.Errorf("accepted %s (%d bytes)", tc.name, len(raw))
		}
	}
	validQuery := make(map[string]string, 50)
	for i := 0; i < 49; i++ {
		validQuery[fmt.Sprintf("name%d", i)] = "value"
	}
	validQuery[strings.Repeat("n", 128)] = strings.Repeat("v", 2048)
	valid, err := json.Marshal(map[string]any{"query": validQuery})
	if err != nil || !validAPIRequestInput(valid) {
		t.Fatalf("rejected valid API boundary input: %v", err)
	}
	maxBody, err := json.Marshal(map[string]any{"body": strings.Repeat("x", maxAPIRequestBody-len(`{"body":""}`))})
	if err != nil || len(maxBody) != maxAPIRequestBody || !validAPIRequestInput(maxBody) {
		t.Fatalf("rejected %d-byte API input: %v", len(maxBody), err)
	}
}

func apiInputWithQuery(count int, name, value string) map[string]any {
	query := make(map[string]string, count)
	for i := 0; i < count; i++ {
		query[fmt.Sprintf("%s%d", name, i)] = value
	}
	return map[string]any{"query": query}
}

func TestConnectionsExposeSupportedOperationsAndSafeMetadata(t *testing.T) {
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{
		EngineOrigin: "https://engine.example",
		Capability:   testCapability,
		Operation:    "api.request",
		Label:        "CRM records",
		SkillID:      "crm_lookup",
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := h.operations(), []string{"api.request", "calendar.check_availability", "notion.search_shared_titles"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("operations=%v want %v", got, want)
	}
	if got, want := h.list(false), []connectionSummary{{ID: testConnectionID, Operation: "api.request", Label: "CRM records"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("agent list=%#v want %#v", got, want)
	}
	if got, want := h.list(true), []connectionSummary{{ID: testConnectionID, Operation: "api.request", Label: "CRM records", SkillID: "crm_lookup"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("owner list=%#v want %#v", got, want)
	}
}

func TestConnectionsRejectUnsafeInstallAndInput(t *testing.T) {
	for _, origin := range []string{"http://engine.example", "https://localhost", "https://127.0.0.1", "https://[::1]", "https://10.0.0.1", "https://engine.example/path", "https://a:b@engine.example", "https://engine.example?secret=1"} {
		h := newConnectionHub()
		if err := h.install(testConnectionID, connectionInstall{EngineOrigin: origin, Capability: testCapability, Operation: "notion.search_shared_titles"}); err == nil {
			t.Errorf("accepted %s", origin)
		}
	}
	for _, id := range []string{"../x", "x/y", "x?y", ""} {
		if err := newConnectionHub().install(id, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "notion.search_shared_titles"}); err == nil {
			t.Errorf("accepted ID %q", id)
		}
	}
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "gmail.send"}); err == nil {
		t.Fatal("accepted unsupported operation")
	}
	for _, grant := range []connectionInstall{
		{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "api.request", Label: strings.Repeat("x", 129)},
		{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "api.request", Label: string([]byte{0xff})},
		{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "api.request", SkillID: "unsafe/id"},
	} {
		if err := h.install(testConnectionID, grant); err == nil {
			t.Fatalf("accepted unsafe metadata: %+v", grant)
		}
	}
	if err := h.install("emoji-label", connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "api.request", Label: strings.Repeat("😀", 40)}); err != nil {
		t.Fatalf("rejected valid multibyte label: %v", err)
	}
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: "provider-oauth-token", Operation: "notion.search_shared_titles"}); err == nil {
		t.Fatal("accepted provider credential")
	}
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "notion.search_shared_titles"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.invoke(context.Background(), connectionCall{GrantID: testConnectionID, InvocationID: "", Input: json.RawMessage(`{}`)}); err != errConnectionInput {
		t.Fatalf("empty invocation accepted: %v", err)
	}
}

func TestConnectionsRejectRedirectAndBoundProviderResponse(t *testing.T) {
	h := newConnectionHub()
	_ = h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "notion.search_shared_titles"})
	for _, response := range []struct {
		status int
		body   string
	}{{302, `{"result":{}}`}, {200, `{"token":"secret"}`}, {200, strings.Repeat("x", maxConnectionBody+1)}, {401, `{"error":"revoked"}`}} {
		h.client.Transport = connectionTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: response.status, Header: http.Header{"Location": []string{"https://other.example"}}, Body: io.NopCloser(strings.NewReader(response.body))}, nil
		})
		if _, err := h.invoke(context.Background(), connectionCall{GrantID: testConnectionID, InvocationID: "id", Input: json.RawMessage(`{}`)}); err == nil {
			t.Errorf("accepted response status=%d size=%d", response.status, len(response.body))
		}
	}
}

func TestConnectionsRejectPrivateResolvedAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "0.0.0.0", "100.64.0.1", "198.18.0.1"} {
		if publicConnectionIP(net.ParseIP(address)) {
			t.Errorf("allowed %s", address)
		}
	}
	if !publicConnectionIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public destination rejected")
	}
}

func TestConnectionsPreserveOnlyProvenRefreshRetry(t *testing.T) {
	h := newConnectionHub()
	_ = h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "notion.search_shared_titles"})
	for _, tc := range []struct {
		body  string
		retry bool
	}{
		{`{"error":"connection_refresh_in_progress","code":"connection_refresh_in_progress","retryWithNewInvocationId":true}`, true},
		{`{"code":"connection_refresh_in_progress","retryWithNewInvocationId":false}`, false},
		{`{"code":"provider_timeout","retryWithNewInvocationId":true}`, false},
		{`not JSON`, false},
	} {
		h.client.Transport = connectionTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})
		server := &Server{connections: h}
		recorder := httptest.NewRecorder()
		server.handleAgentConnections(recorder, httptest.NewRequest(http.MethodPost, "/connections/invoke", strings.NewReader(`{"grant_id":"`+testConnectionID+`","invocation_id":"retry-test","input":{}}`)))
		var result struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
			Retry bool `json:"retryWithNewInvocationId"`
		}
		if json.Unmarshal(recorder.Body.Bytes(), &result) != nil {
			t.Fatal("invalid error response")
		}
		if result.Retry != tc.retry {
			t.Fatalf("retry=%v want %v: %s", result.Retry, tc.retry, recorder.Body.String())
		}
		if tc.retry && (recorder.Code != 503 || recorder.Header().Get("Retry-After") != "1" || result.Error.Code != "connection_refresh_in_progress") {
			t.Fatalf("lost refresh contract: %d %s", recorder.Code, recorder.Body.String())
		}
	}
}
