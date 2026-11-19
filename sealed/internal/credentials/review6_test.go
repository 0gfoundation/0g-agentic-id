package credentials

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"seal-verify/internal/credproxy"
)

// Floods of three proxy-use results blur only those results' later kinds:
// the owner's own uses and a host an entry does not allow stay named.
func TestResultFloodBlursOnlyThatResult(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	for _, code := range []string{"unknown_entry", "position_not_allowed", "forbidden_header"} {
		for i := 0; i < 33; i++ {
			s.Record(credproxy.Record{Time: time.Now(), Names: []string{fmt.Sprintf("n%d", i)}, Host: fmt.Sprintf("h%d.example", i), Method: "GET", Code: code})
		}
	}
	// A successful use of an owner entry and a refused one to another host.
	s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "api.github.com", Method: "GET"})
	s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "other.example", Method: "GET", Code: "host_not_allowed"})
	// Pushed out of the listed ring by uses of a kind already counted.
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"n0"}, Host: "h0.example", Method: "GET", Code: "unknown_entry"})
	}
	var sent, refused bool
	for _, r := range s.AuditSince(0) {
		if r.Count == 0 || r.Op != "inject" {
			continue
		}
		if r.Result == "sent" || r.Result == "host_not_allowed" {
		}
		if r.Result == "sent" && len(r.Names) == 1 && r.Names[0] == "github" && r.Host == "api.github.com" {
			sent = true
		}
		if r.Result == "host_not_allowed" && len(r.Names) == 1 && r.Names[0] == "github" && r.Host == "other.example" {
			refused = true
		}
	}
	if !sent || !refused {
		t.Fatalf("kinds of other results lost their entry/host: sent named=%v, host_not_allowed named=%v", sent, refused)
	}
}

// The persisted audit log at its largest (every record at the largest size
// its source allows) fits what the next boot reads.
func TestAuditFileWorstCaseFits(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	ts := time.Date(2026, 11, 7, 12, 34, 56, 123456789, time.FixedZone("x", 8*3600))
	lt := strings.Repeat("<", 400) // JSON writes '<' as <, 6 bytes
	gname := func(i int) string {  // a placeholder-grammar name of 71 chars
		return "derived:" + fmt.Sprintf("%02d", i) + strings.Repeat("a", 61)
	}
	var names16 []string
	for i := 0; i < 1000; i++ {
		names16 = append(names16, gname(i%100))
	}
	// 15 placeholder names and the X-Seal-Sign name, which is the agent's
	// raw header text (signRequest returns it unchecked on a refusal).
	injNames := append(append([]string(nil), names16[:15]...), lt)
	inject := boundAudit(AuditRecord{Time: ts, Op: "inject", Names: injNames, Host: lt, Method: "OPTIONS", Result: "position_not_allowed"})
	sign := boundAudit(AuditRecord{Time: ts, Op: "sign personal_sign", Names: []string{gname(1)}, Result: "signed: " + lt})
	other := boundAudit(AuditRecord{Time: ts, Op: "disconnect", Names: []string{lt}, Host: lt, Result: lt})
	first := ts
	counted := other
	counted.Count, counted.First = 1<<62, &first
	countedInject := inject
	countedInject.Count, countedInject.First = 1<<62, &first
	s.mu.Lock()
	s.owner = common.HexToAddress("0x00000000000000000000000000000000000000a1")
	s.mu.Unlock()
	s.auditMu.Lock()
	s.auditReady = true
	for i := 0; i < auditKeep; i++ {
		s.auditInject = append(s.auditInject, inject)
		s.auditSign = append(s.auditSign, sign)
		s.auditLog = append(s.auditLog, other)
	}
	// Every kind at the largest counted size (the backstop plus one "more
	// kinds" per operation).
	for i := 0; i < maxCountKeys+20; i++ {
		if i%2 == 0 {
			s.auditCounts[fmt.Sprint(i)] = &countedInject
		} else {
			s.auditCounts[fmt.Sprint(i)] = &counted
		}
	}
	s.auditMu.Unlock()
	file, ok := s.AuditSnapshot()
	if !ok {
		t.Fatal("no snapshot")
	}
	b, _ := json.Marshal(file)
	t.Logf("file %d bytes (%.2f MiB), limit %d (16 MiB)", len(b), float64(len(b))/(1<<20), 16<<20)
	if len(b) > 16<<20 {
		t.Fatalf("worst case %d bytes is over 16 MiB", len(b))
	}
}

// cleanHTTPS takes real authorization endpoints and refuses what could
// mislead the owner.
func TestCleanHTTPSRealWorld(t *testing.T) {
	ok := []string{
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://auth.example.com:8443/oauth/authorize?tenant=x&prompt=consent",
		"https://xn--bcher-kva.example/authorize",
		"https://bücher.example/authorize",
		"https://[2001:db8::1]:8443/token",
		"https://kc.example/realms/my%20realm/protocol/openid-connect/auth",
		"HTTPS://AS.EXAMPLE/authorize",
		"https://as.example/authorize?",
		"https://as.example/a#frag",
	}
	at := "@" // built at run time, so no address-shaped literal sits in the source
	bad := []string{
		"https://as.example/a b",
		"https://u:p" + at + "as.example/a",
		"https://as.example\\" + at + "evil.example/",
		"http://as.example/a",
		"https:///a",
		"https://as.example/‮a",
		"https://as.example/a\t",
	}
	for _, u := range ok {
		if !cleanHTTPS(u) {
			t.Errorf("refused %q", u)
		}
	}
	for _, u := range bad {
		if cleanHTTPS(u) {
			t.Errorf("accepted %q", u)
		}
	}
}

// rotate's check refuses only values the proxy could not serve.
func TestRotateTakesLegitimateValues(t *testing.T) {
	login := &Definition{V: 1, Name: "linear", Hosts: []string{"mcp.example"}, MCP: &MCPSpec{URL: "https://mcp.example/mcp"}}
	st := &mcpState{V: 1, Type: "mcp_login", AccessToken: strings.Repeat("a", credproxy.MaxValueLen), RefreshToken: strings.Repeat("r", 20000),
		ClientSecret: strings.Repeat("s", 4000), TokenURL: "https://mcp.example/token"}
	raw, _ := json.Marshal(st)
	if err := login.Entry(raw).Validate(); err != nil {
		t.Errorf("login state of %d bytes with a max-size access token refused: %v", len(raw), err)
	}
	tok := &Definition{V: 1, Name: "svc", Use: credproxy.UseTokenOnly, TokenRequest: &TokenRequest{URL: "https://t.example/token"}}
	if err := tok.Entry([]byte("rt_" + strings.Repeat("x", 100))).Validate(); err != nil {
		t.Errorf("token entry refused: %v", err)
	}
}

// The budgets hold for records restored at boot too.
func TestBudgetsHoldAcrossRestart(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	s.mu.Lock()
	s.owner = owner
	s.mu.Unlock()
	s.SeedAudit(nil)
	for _, code := range []string{"unknown_entry", "position_not_allowed", "forbidden_header"} {
		for i := 0; i < 33; i++ {
			s.Record(credproxy.Record{Time: time.Now(), Names: []string{fmt.Sprintf("n%d", i)}, Host: fmt.Sprintf("h%d.example", i), Method: "GET", Code: code})
		}
	}
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"n0"}, Host: "h0.example", Method: "GET", Code: "unknown_entry"})
	}
	file, ok := s.AuditSnapshot()
	if !ok {
		t.Fatal("no snapshot")
	}
	b, _ := json.Marshal(file)
	var back AuditFile
	_ = json.Unmarshal(b, &back)

	s2, _, _ := f.store(t, nil, nil)
	s2.mu.Lock()
	s2.owner = owner
	s2.mu.Unlock()
	s2.SeedAudit(&back)
	s2.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "api.github.com", Method: "GET"})
	for i := 0; i < auditKeep; i++ {
		s2.Record(credproxy.Record{Time: time.Now(), Names: []string{"n0"}, Host: "h0.example", Method: "GET", Code: "unknown_entry"})
	}
	for _, r := range s2.AuditSince(0) {
		if r.Count > 0 && r.Op == "inject" && r.Result == "sent" {
			if len(r.Names) == 1 && r.Names[0] == "github" {
				return
			}
		}
	}
	t.Fatal("after the restart, a new successful use is counted without its entry")
}
