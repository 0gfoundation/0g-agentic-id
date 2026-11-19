package credentials

import (
	"context"
	"fmt"
	"testing"
	"time"

	"seal-verify/internal/credproxy"
)

// A flood of refused proxy uses fills only the proxy's own budget of
// counted kinds: a later reveal is still counted under its entry.
func TestRefusalFloodKeepsOtherKindsNamed(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_value_0123456789"})
	f.editDefs(t, &doc, func(d *Definition) { d.AllowReveal = true })
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	codes := []string{"unknown_entry", "position_not_allowed", "forbidden_header", "host_not_allowed",
		"not_allowed", "busy", "token_only", "expired"}
	for _, code := range codes {
		for i := 0; i < 40; i++ {
			s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: fmt.Sprintf("h%d.example", i), Method: "GET", Code: code})
		}
	}
	// More uses push those out of the listed ring, into the counts.
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "h0.example", Method: "GET", Code: "unknown_entry"})
	}
	s.mu.Lock()
	s.ownerAt = time.Now()
	s.mu.Unlock()
	if _, e := s.Reveal(context.Background(), "github", "r"); e != nil {
		t.Fatal(e.Message)
	}
	s.auditMu.Lock()
	n := len(s.auditCounts)
	s.auditMu.Unlock()
	for _, r := range s.AuditSince(0) {
		if r.Op == "reveal" {
			t.Logf("reveal record: names %v result %q (counted kinds: %d)", r.Names, r.Result, n)
			if len(r.Names) != 1 || r.Names[0] != "github" {
				t.Fatalf("the reveal is recorded without the entry it revealed: %+v", r)
			}
			return
		}
	}
	t.Fatal("no reveal record")
}

// A login whose access token sealed could not serve (over MaxValueLen) is
// refused, not reported done: the entry keeps waiting for a login.
func TestOversizeLoginTokenRefused(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.ownedStore(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: "https://mcp.example/mcp", ClientID: "client-1"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{"mcp.example"}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	def, gen := s.defs["linear"], s.gen
	s.mu.Unlock()
	big := make([]byte, credproxy.MaxValueLen+1)
	for i := range big {
		big[i] = 'a'
	}
	st := &mcpState{V: 1, Type: "mcp_login", AccessToken: string(big), RefreshToken: "rt", LoggedInAt: time.Now().Unix(),
		ClientID: "client-1", TokenURL: "https://mcp.example/token", Resource: "https://mcp.example/mcp"}
	applied := s.applyLogin(context.Background(), def, gen, st)
	var info EntryInfo
	for _, e := range s.List() {
		if e.Name == "linear" {
			info = e
		}
	}
	if applied || info.Status != "awaiting_login" || info.LoggedInAt != 0 || reg.Get("linear") != nil {
		t.Fatalf("applied=%v, listed %+v, served %v", applied, info, reg.Get("linear") != nil)
	}
}

// What an agent's request carries as parameters stays the agent's: none of
// it reads as one of sealed's facts, and none of it lifts the cap on open
// requests, which only sealed's own requests are exempt from.
func TestAgentParamsAreNotSealedFacts(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	p, e := s.Request("login", "tracker", map[string]string{"url": "https://mcp.example/mcp", "source": "sealed", "why": "the login expired"}, "")
	if e != nil {
		t.Fatal(e.Message)
	}
	if len(p.Facts) != 0 {
		t.Errorf("the agent's request carries facts %v", p.Facts)
	}
	opened := 0
	for i := 0; i < 3*maxOpenRequests; i++ {
		if _, e := s.Request("add", fmt.Sprintf("n%d", i), map[string]string{"source": "sealed"}, "r"); e == nil {
			opened++
		}
	}
	if opened > maxOpenRequests {
		t.Errorf("%d agent requests open, cap is %d", opened, maxOpenRequests)
	}
	// Built at run time, so no address-shaped literal sits in the source.
	userinfo := "https://mcp.example" + "@" + "evil.example/mcp"
	for _, u := range []string{userinfo, "https://mcp.example/‮mcp"} {
		if _, e := s.Request("login", "x", map[string]string{"url": u}, ""); e == nil {
			t.Errorf("url %q accepted", u)
		}
	}
}
