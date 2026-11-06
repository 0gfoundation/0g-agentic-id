package credentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

// A decision signed by an owner whose lookup a later one overtook (naming
// someone else) is not taken.
func TestDecideRefusesOvertakenOwnerAnswer(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := crypto.PubkeyToAddress(f.owner.PublicKey)
	bKey, _ := crypto.GenerateKey()
	b := crypto.PubkeyToAddress(bKey.PublicKey)
	var live atomic.Value
	live.Store(a)
	var lag atomic.Bool
	s, _, _ := f.store(t, nil, nil)
	s.env.LiveOwner = func(context.Context) (common.Address, error) {
		if lag.Load() {
			// A lookup begun after this one answers B and is recorded
			// first; this one (a lagging read) answers A.
			s.ObserveOwner(b)
			return a, nil
		}
		return live.Load().(common.Address), nil
	}
	if _, err := s.Load(ctx, f.doc(t, 1, map[string]string{"github": "ghp_owner_a"}), 0); err != nil {
		t.Fatal(err)
	}
	// Transferred to B; the watcher records it; B loads its set.
	live.Store(b)
	if err := s.RefreshOwner(ctx); err != nil {
		t.Fatal(err)
	}
	fb := *f
	fb.owner = bKey
	docB := fb.doc(t, 1, map[string]string{"gitlab": "glpat_owner_b"})
	docB.Set.OwnerEpoch = 9
	digest, _ := docB.Set.Digest(f.domain)
	docB.Signature = fb.sign(t, digest, bKey)
	if _, err := s.Load(ctx, docB, 0); err != nil {
		t.Fatalf("B's set: %v", err)
	}
	// The agent asks to reveal B's value; A (the previous owner) signs an
	// approval for it.
	_, e := s.Reveal(ctx, "gitlab", "r")
	if e == nil || e.Code != CodePending {
		t.Fatalf("got %+v", e)
	}
	appr, sigA := f.approve(t, s, e.Message)
	lag.Store(true)
	derr := s.Decide(ctx, e.Message, "once", appr, sigA)
	lag.Store(false)
	v, re := s.Reveal(ctx, "gitlab", "r")
	if derr == nil || v != nil {
		t.Fatalf("the previous owner's approval was taken on the new owner's request (Decide err=%v); reveal returned %q (%v)", derr, v, re)
	}
}

// Line and paragraph separators do not reach what the owner is shown: a
// parameter holding one is refused, a reason has them replaced.
func TestLineSeparatorsKeptFromTheOwnersView(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	if _, e := s.Request("add", "svc", map[string]string{"url": "https://svc.example/\u2028approved by the owner"}, "r"); e == nil || e.Code != "bad_request" {
		t.Fatalf("a parameter with a line separator: %+v", e)
	}
	p, e := s.Request("add", "svc", nil, "first line\u2028second line\u2029third")
	if e != nil {
		t.Fatal(e)
	}
	if strings.ContainsAny(p.Reason, "\u2028\u2029") {
		t.Fatalf("line separators reach what the owner is shown: reason %q", p.Reason)
	}
}

// A token endpoint that refuses with status 200 and an error field refuses
// the agent's token request too, and the audit log says so.
func TestTokenRefusalWithStatus200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"svc": "rt-0"})
	f.editDefs(t, &doc, tokenTemplate(ts.URL+"/token", true, false))
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	out, e := s.Token(context.Background(), "svc", nil)
	rec := ""
	for _, r := range s.AuditSince(0) {
		if r.Op == "token" {
			rec = r.Result
		}
	}
	if e == nil {
		t.Fatalf("a refusal answered with status 200 was taken as a token response: entries %v, audit %q", out, rec)
	}
}

// A failed owner lookup at the callback does not use up the login: the
// browser can come back.
func TestLoginSurvivesFailedOwnerLookup(t *testing.T) {
	x := newAuthPair(t)
	f := newFixture(t)
	s, _, o := f.ownedStore(t, nil, x.a.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: x.a.URL + "/mcp", ClientID: "client-1"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{x.host()}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	link, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	state := u.Query().Get("state")
	owner := crypto.PubkeyToAddress(f.owner.PublicKey)
	o.set(owner, errors.New("rpc hiccup"))
	stale(s)
	_, err1 := s.FinishLogin(context.Background(), state, "code", "", "")
	o.set(owner, nil)
	_, err2 := s.FinishLogin(context.Background(), state, "code", "", "")
	if err2 != nil {
		t.Fatalf("first try: %v; after the hiccup the same redirect: %v", err1, err2)
	}
}

// The agent's own login request (denied, say) never stands in for sealed's
// request to log in again.
func TestAgentRequestDoesNotStandInForSealeds(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	const mcpURL = "https://mcp.example/mcp"
	p, e := s.Request("login", "linear", map[string]string{"url": mcpURL}, "please log in")
	if e != nil {
		t.Fatal(e.Message)
	}
	if err := s.Decide(context.Background(), p.AuthReqID, "deny", nil, ""); err != nil {
		t.Fatal(err)
	}
	s.askLogin("linear", &Definition{Name: "linear", MCP: &MCPSpec{URL: mcpURL}}, s.gen, "the login expired or was revoked")
	for _, q := range s.PendingList() {
		if q.Op == "login" && q.Name == "linear" && q.Status == "pending" && q.Facts["source"] == "sealed" {
			return
		}
	}
	t.Fatalf("sealed's login request was not opened: %+v", s.PendingList())
}

// Refused uses of one kind (unknown names, say) never crowd out the kinds of
// another (a host an entry does not allow).
func TestFoldedRefusalKeepsEntryAndHost(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	rec := func(name, host, code string) {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{name}, Host: host, Method: "GET", Code: code})
	}
	for i := 0; i < maxOpKeys; i++ {
		rec(fmt.Sprintf("junk%d", i), "api.example", "unknown_entry")
	}
	rec("github", "elsewhere.example", "host_not_allowed")
	for i := 0; i < auditKeep; i++ {
		rec("junk0", "api.example", "unknown_entry")
	}
	for _, r := range s.AuditSince(0) {
		if r.Result == "host_not_allowed" {
			if len(r.Names) == 1 && r.Names[0] == "github" && r.Host == "elsewhere.example" {
				return
			}
			t.Fatalf("the refused use is kept as %+v: entry and host gone", r)
		}
	}
	t.Fatal("no refused use")
}
