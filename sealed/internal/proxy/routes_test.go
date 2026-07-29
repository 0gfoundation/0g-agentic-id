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

// An adapter that declared no routes leaves fwRoutes nil: nothing matches, so
// handleProxy 404s every framework path (fail-closed — the old forward-all
// "legacy" fallback was removed). Agent /api/* services are matched earlier
// and are unaffected.
func TestMatchFrameworkRoute_NoRoutesMatchesNothing(t *testing.T) {
	s := &Server{}
	if _, ok := s.matchFrameworkRoute("/"); ok {
		t.Error("no declared routes must match nothing (fail-closed)")
	}
	if _, ok := s.matchFrameworkRoute("/v1/chat/completions"); ok {
		t.Error("no declared routes must match nothing (fail-closed)")
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
	// Signed is forced false for framework routes regardless of the declared
	// value — the proxy never signs them, so /hello must not claim otherwise.
	if got.Prefix != "/v1/" || got.Kind != "chat" || got.Auth != "bearer" || got.Signed || got.Description != "api" {
		t.Errorf("route mapping wrong: %+v", got)
	}
}
