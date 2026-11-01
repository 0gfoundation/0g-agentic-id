package harness

import "testing"

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
