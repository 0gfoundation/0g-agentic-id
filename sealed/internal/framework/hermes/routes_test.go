package hermes

import (
	"context"
	"testing"

	"seal-verify/internal/framework"
)

// The adapter must satisfy framework.RouteProvider so the proxy stops
// blind-forwarding and signs per-route.
var _ framework.RouteProvider = (*Adapter)(nil)

// hermes exposes ONLY the chat route (/v1/). The dashboard is deliberately
// not declared (it embeds a terminal + file browser — a shell/file backdoor
// if proxied); this test guards against it being re-added.
func TestFrameworkRoutes(t *testing.T) {
	routes := (&Adapter{}).FrameworkRoutes()
	if len(routes) != 1 {
		t.Fatalf("want exactly one route (chat), got %d: %+v", len(routes), routes)
	}
	chat := routes[0]
	if chat.Prefix != "/v1/" || chat.Kind != "chat" || chat.Auth != "bearer" || !chat.Signed {
		t.Errorf("chat route: want prefix=/v1/ kind=chat auth=bearer signed=true, got %+v", chat)
	}
	for _, r := range routes {
		if r.Kind == "dashboard" || r.Prefix == "/" {
			t.Error("dashboard/root route must NOT be declared — it exposes the terminal + file-browser backdoor")
		}
	}
}

// AuthResponse returns only the credential — where/how to use it lives in
// FrameworkRoutes / /hello, not in the auth payload (chat_path is gone).
func TestAuthResponse_TokenOnly(t *testing.T) {
	a := &Adapter{apiServerKey: "deadbeef"}
	payload, err := a.AuthResponse(context.Background())
	if err != nil {
		t.Fatalf("AuthResponse: %v", err)
	}
	m, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("payload is not a map: %T", payload)
	}
	if m["token"] != "deadbeef" {
		t.Errorf("token = %v, want deadbeef", m["token"])
	}
	if _, present := m["chat_path"]; present {
		t.Error("chat_path must no longer be in the auth payload (superseded by FrameworkRoutes)")
	}
	if len(m) != 1 {
		t.Errorf("auth payload should carry only the token, got %+v", m)
	}
}
