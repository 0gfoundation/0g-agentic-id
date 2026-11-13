package harness

import (
	"context"
	"testing"

	"seal-verify/internal/framework"
)

// The routes /hello advertises: the chat and responses surfaces, and one kind
// per harness capability. A client enables a feature only on the kinds an
// agent declares, so every route must share the one upstream and the bearer
// token, and none may be signed (the owner's steering channel never is).
func TestFrameworkRoutesAdvertiseTheHarnessSurface(t *testing.T) {
	want := map[string]string{
		"/v1/":          "chat",
		"/v1/responses": "responses",
		"/v1/inbox":     "inbox",
		"/v1/events":    "events",
		"/v1/tasks":     "tasks",
		"/v1/schedules": "schedules",
	}
	routes := New().FrameworkRoutes()
	if len(routes) != len(want) {
		t.Fatalf("got %d routes, want %d: %+v", len(routes), len(want), routes)
	}
	for _, r := range routes {
		kind, ok := want[r.Prefix]
		if !ok {
			t.Errorf("unexpected route %s", r.Prefix)
			continue
		}
		if r.Kind != kind {
			t.Errorf("%s kind = %q, want %q", r.Prefix, r.Kind, kind)
		}
		if r.Backend != routes[0].Backend || r.Auth != "bearer" || r.Signed {
			t.Errorf("%s: backend %q auth %q signed %v — every route shares the harness upstream and the bearer token, unsigned", r.Prefix, r.Backend, r.Auth, r.Signed)
		}
		if r.Description == "" {
			t.Errorf("%s has no description", r.Prefix)
		}
	}
}

// Each route forwards the requests docs/PROTOCOL.md (protocol 1) lists and
// nothing else under its prefix.
func TestFrameworkRoutesListTheProtocolEndpoints(t *testing.T) {
	routes := map[string]framework.Route{}
	for _, r := range New().FrameworkRoutes() {
		routes[r.Prefix] = r
	}
	forwarded := []struct{ prefix, method, path string }{
		{"/v1/", "GET", "/v1/harness"},
		{"/v1/", "POST", "/v1/chat/completions"},
		{"/v1/", "POST", "/v1/interrupt"},
		{"/v1/", "POST", "/v1/compact"},
		{"/v1/responses", "POST", "/v1/responses"},
		{"/v1/responses", "GET", "/v1/responses/resp_1"},
		{"/v1/responses", "POST", "/v1/responses/resp_1/cancel"},
		{"/v1/inbox", "GET", "/v1/inbox"},
		{"/v1/inbox", "POST", "/v1/inbox/ack"},
		{"/v1/events", "GET", "/v1/events"},
		{"/v1/tasks", "GET", "/v1/tasks"},
		{"/v1/tasks", "GET", "/v1/tasks/bash-1"},
		{"/v1/tasks", "POST", "/v1/tasks/all/cancel"},
		{"/v1/schedules", "GET", "/v1/schedules"},
		{"/v1/schedules", "DELETE", "/v1/schedules/s1"},
		{"/v1/", "OPTIONS", "/v1/chat/completions"},
	}
	for _, f := range forwarded {
		if ok, _ := routes[f.prefix].Allows(f.method, f.path); !ok {
			t.Errorf("%s %s is not forwarded", f.method, f.path)
		}
	}
	refused := []struct{ prefix, method, path string }{
		{"/v1/", "GET", "/v1/models"},
		{"/v1/", "POST", "/v1/export"},
		{"/v1/", "GET", "/v1/chat/completions"},
		{"/v1/responses", "DELETE", "/v1/responses/resp_1"},
		{"/v1/tasks", "POST", "/v1/tasks/a/b/cancel"},
		{"/v1/tasks", "GET", "/v1/tasks/"},
		{"/v1/inbox", "GET", "/v1/inbox/all"},
	}
	for _, f := range refused {
		if ok, _ := routes[f.prefix].Allows(f.method, f.path); ok {
			t.Errorf("%s %s is forwarded", f.method, f.path)
		}
	}
}

// The owner's token is not the harness's: the owner gets one, the proxy
// swaps it for the other, and nothing else is swapped.
func TestOwnerTokenIsNotTheHarnessToken(t *testing.T) {
	a := New()
	a.bridgeToken, a.ownerToken = "harness-token", "owner-token"
	resp, err := a.AuthResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.(map[string]any)["token"]; got != "owner-token" {
		t.Fatalf("AuthResponse handed out %v", got)
	}
	if got, ok := a.TranslateBearer("owner-token"); !ok || got != "harness-token" {
		t.Fatalf("TranslateBearer(owner) = %q, %v", got, ok)
	}
	for _, bad := range []string{"harness-token", "", "owner-toke", "owner-token "} {
		if _, ok := a.TranslateBearer(bad); ok {
			t.Errorf("TranslateBearer(%q) accepted", bad)
		}
	}
}
