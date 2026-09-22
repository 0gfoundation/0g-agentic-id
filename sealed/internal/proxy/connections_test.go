package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type connectionTransport func(*http.Request) (*http.Response, error)

func (f connectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const testConnectionID = "12345678-1234-4123-8123-123456789abc"
const testCapability = "acap_abcdefghijklmnopqrstuvwxyz0123456789ABCDE12"

func TestConnectionsForwardOneGrantWithoutExposingCredential(t *testing.T) {
	h := newConnectionHub()
	if err := h.install(testConnectionID, connectionInstall{EngineOrigin: "https://engine.example", Capability: testCapability, Operation: "calendar.check_availability"}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(h.list())
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
