package proxy

import (
	"testing"

	"seal-verify/internal/framework"
)

// A framework that owns the root ("/") plus a scoped API prefix — the openclaw
// shape. Longest-prefix wins, so /v1/* is the API route and everything else is
// the dashboard; nothing 404s because "/" catches all.
func TestMatchFrameworkRoute_LongestPrefixWins(t *testing.T) {
	s := &Server{fwRoutes: []framework.Route{
		{Prefix: "/v1/", Kind: "chat", Auth: "bearer", Signed: true},
		{Prefix: "/", Kind: "dashboard", Auth: "token-fragment", Signed: false},
	}}
	if !s.hasFrameworkRoutes() {
		t.Fatal("hasFrameworkRoutes should be true once routes are declared")
	}
	rt, ok := s.matchFrameworkRoute("/v1/chat/completions")
	if !ok || rt.Kind != "chat" || !rt.Signed {
		t.Fatalf("/v1/* should match the signed chat route, got ok=%v %+v", ok, rt)
	}
	rt, ok = s.matchFrameworkRoute("/assets/app.js")
	if !ok || rt.Kind != "dashboard" || rt.Signed {
		t.Fatalf("non-/v1 path should fall to the unsigned dashboard route, got ok=%v %+v", ok, rt)
	}
}

// A headless framework that does NOT own the root — the hermes shape. Paths
// outside its declared prefixes don't match, so handleProxy 404s them instead
// of blind-forwarding (the 収口).
func TestMatchFrameworkRoute_NoMatchWhenNoRootRoute(t *testing.T) {
	s := &Server{fwRoutes: []framework.Route{
		{Prefix: "/v1/", Kind: "chat", Auth: "bearer", Signed: true},
	}}
	if _, ok := s.matchFrameworkRoute("/v1/models"); !ok {
		t.Error("/v1/models should match the declared API route")
	}
	if _, ok := s.matchFrameworkRoute("/"); ok {
		t.Error("root should NOT match when no root route is declared")
	}
	if _, ok := s.matchFrameworkRoute("/wp-admin"); ok {
		t.Error("an undeclared path should not match (handleProxy 404s it)")
	}
}

// Legacy fallback: an adapter that never declared routes leaves fwRoutes nil,
// and hasFrameworkRoutes reports false so handleProxy keeps forwarding+signing
// every path.
func TestHasFrameworkRoutes_NilIsLegacy(t *testing.T) {
	if (&Server{}).hasFrameworkRoutes() {
		t.Error("a Server with no declared routes must be legacy (forward-all)")
	}
}

func TestFrameworkRoutesForHello_Maps(t *testing.T) {
	s := &Server{fwRoutes: []framework.Route{
		{Prefix: "/v1/", Kind: "chat", Auth: "bearer", Signed: true, Description: "api"},
	}}
	out := s.frameworkRoutesForHello()
	if len(out) != 1 {
		t.Fatalf("want 1 route, got %d", len(out))
	}
	got := out[0]
	if got.Prefix != "/v1/" || got.Kind != "chat" || got.Auth != "bearer" || !got.Signed || got.Description != "api" {
		t.Errorf("route mapping wrong: %+v", got)
	}
}
