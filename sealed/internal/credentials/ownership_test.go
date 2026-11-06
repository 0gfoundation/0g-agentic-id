package credentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

// chainOwner is the agent's on-chain owner, which a test can transfer or
// make unreachable.
type chainOwner struct {
	mu   sync.Mutex
	addr common.Address
	err  error
}

func (o *chainOwner) get(context.Context) (common.Address, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.addr, o.err
}

func (o *chainOwner) set(a common.Address, err error) {
	o.mu.Lock()
	o.addr, o.err = a, err
	o.mu.Unlock()
}

// ownedStore is f.store with an owner the test controls.
func (f *fixture) ownedStore(t *testing.T, wb func(context.Context, string, Writeback) error, client *http.Client) (*Store, *credproxy.Registry, *chainOwner) {
	t.Helper()
	o := &chainOwner{addr: crypto.PubkeyToAddress(f.owner.PublicKey)}
	reg := credproxy.NewRegistry()
	s := NewStore(Env{
		Domain: f.domain, SealID: testSeal, AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey), AgentSealPriv: crypto.FromECDSA(f.seal),
		BootID: "boot-1", LiveOwner: o.get, Persist: &memPersist{}, Writeback: wb, HTTPClient: client,
	}, reg)
	return s, reg, o
}

// stale makes the store look the owner up again before its next use.
func stale(s *Store) {
	s.mu.Lock()
	s.ownerAt = time.Time{}
	s.mu.Unlock()
}

// tokenTemplate makes an entry a token_only entry with a template on url.
func tokenTemplate(url string, rotate, writeback bool, params ...string) func(*Definition) {
	return func(d *Definition) {
		d.Use, d.Positions, d.Writeback = credproxy.UseTokenOnly, nil, writeback
		d.TokenRequest = &TokenRequest{URL: url, Fields: map[string]string{"refresh_token": "{v}"}, Params: params,
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"api.example"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}}}
		if rotate {
			d.TokenRequest.RotateField = "refresh_token"
		}
	}
}

// approve signs the owner's one-time approval of the open request id.
func (f *fixture) approve(t *testing.T, s *Store, id string) (*Approval, string) {
	t.Helper()
	var p *Pending
	for _, q := range s.PendingList() {
		if q.AuthReqID == id {
			q := q
			p = &q
		}
	}
	if p == nil {
		t.Fatalf("no pending request %s", id)
	}
	a := &Approval{SealID: testSeal, BootID: p.BootID, AuthReqID: id, RequestDigest: p.RequestDigest, ExpiresAt: uint64(time.Now().Add(time.Hour).Unix())}
	digest, _ := a.Digest(f.domain)
	return a, f.sign(t, digest, f.owner)
}

// A value a token endpoint returns is used as it is: a rotated value that
// reads like {cred:<name>} does not pull another entry into the next request.
func TestTemplateExpandsOnce(t *testing.T) {
	var mu sync.Mutex
	var forms []string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.PostForm.Encode())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"{cred:github}"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"svc": "rt_old", "github": "ghp_other_secret"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "svc" {
			tokenTemplate(ts.URL+"/token", true, false)(d)
		}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, e := s.Token(context.Background(), "svc", nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(forms) != 2 || strings.Contains(forms[1], "ghp_other_secret") {
		t.Fatalf("forms sent: %v", forms)
	}
}

// A token request that returns after the owner changed keeps nothing.
func TestTokenAcrossOwnerChangeKeepsNothing(t *testing.T) {
	release, arrived := make(chan struct{}), make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_old_owner","refresh_token":"rt_rotated"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, reg, o := f.ownedStore(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"gcp": "rt"})
	f.editDefs(t, &doc, tokenTemplate(ts.URL+"/token", true, false))
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan *credproxy.Error)
	go func() { _, e := s.Token(context.Background(), "gcp", nil); done <- e }()
	<-arrived
	other, _ := crypto.GenerateKey()
	o.set(crypto.PubkeyToAddress(other.PublicKey), nil)
	s.ObserveOwner(crypto.PubkeyToAddress(other.PublicKey))
	close(release)
	if e := <-done; e == nil || e.Code != "changed" {
		t.Fatalf("token result after the owner changed: %+v", e)
	}
	if len(reg.Names()) != 0 || len(s.List()) != 0 {
		t.Fatalf("kept after the owner changed: %v", reg.Names())
	}
}

// A rotation that returns after the owner gave the entry a new value is
// dropped: the owner's new value stands, and nothing is written back.
func TestRotationAcrossNewValueIsDropped(t *testing.T) {
	release, arrived := make(chan struct{}), make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt_from_the_old_value"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	var wrote atomic.Int32
	s, reg, _ := f.store(t, func(context.Context, string, Writeback) error { wrote.Add(1); return nil }, ts.Client())
	mk := func(v uint64, val string) Document {
		doc := f.doc(t, v, map[string]string{"gcp": val})
		f.editDefs(t, &doc, tokenTemplate(ts.URL+"/token", true, true))
		return doc
	}
	if _, err := s.Load(context.Background(), mk(1, "rt_first"), 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = s.Token(context.Background(), "gcp", nil); close(done) }()
	<-arrived
	if _, err := s.Load(context.Background(), mk(2, "rt_new_from_owner"), 0); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if e := reg.Get("gcp"); e == nil || string(e.Value) != "rt_new_from_owner" || wrote.Load() != 0 {
		t.Fatalf("value %q, writebacks %d", e.Value, wrote.Load())
	}
}

// A token that lives a minute is refreshed about halfway, not at once and
// again and again.
func TestShortLivedLoginRefreshIsPaced(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":60}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, func(context.Context, string, Writeback) error { return nil }, ts.Client())
	doc := f.doc(t, 1, map[string]string{"m": "x"})
	f.editDefs(t, &doc, func(d *Definition) { d.MCP, d.Writeback, d.ValueHash = &MCPSpec{URL: ts.URL + "/mcp"}, true, "" })
	delete(doc.Values, "m")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	s.applyLogin(context.Background(), s.defs["m"], s.gen, &mcpState{V: 1, Type: "mcp_login", AccessToken: "a0", RefreshToken: "r0",
		ExpiresAt: time.Now().Unix() + 60, ClientID: "c", TokenURL: ts.URL + "/token", Resource: "r"})
	time.Sleep(time.Second)
	s.Clear()
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d refreshes in a second", n)
	}
}

// A new owner's first set loads after the previous owner's later versions:
// the anti-rollback mark is (owner epoch, version).
func TestNewOwnerFirstSetLoads(t *testing.T) {
	f := newFixture(t)
	s, _, o := f.ownedStore(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 5, map[string]string{"github": "ghp_a"}), 0); err != nil {
		t.Fatal(err)
	}
	next, _ := crypto.GenerateKey()
	o.set(crypto.PubkeyToAddress(next.PublicKey), nil)
	f.owner = next
	doc := f.doc(t, 1, map[string]string{"github": "ghp_b"})
	doc.Set.OwnerEpoch = 8
	digest, _ := doc.Set.Digest(f.domain)
	doc.Signature = f.sign(t, digest, next)
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatalf("the new owner's first set: %v", err)
	}
	if e := s.reg.Get("github"); e == nil || string(e.Value) != "ghp_b" {
		t.Fatalf("serving %v", e)
	}
}

// After a transfer the new owner cannot approve a reveal of what the
// previous owner's set holds, and the request is gone with the set.
func TestNewOwnerCannotApprovePreviousOwnersValue(t *testing.T) {
	f := newFixture(t)
	s, _, o := f.ownedStore(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_previous"}), 0); err != nil {
		t.Fatal(err)
	}
	_, e := s.Reveal(context.Background(), "github", "")
	if e == nil || e.Code != CodePending {
		t.Fatalf("got %+v", e)
	}
	next, _ := crypto.GenerateKey()
	o.set(crypto.PubkeyToAddress(next.PublicKey), nil) // transferred; the watcher has not run
	a, _ := f.approve(t, s, e.Message)
	digest, _ := a.Digest(f.domain)
	if err := s.Decide(context.Background(), e.Message, "once", a, f.sign(t, digest, next)); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("the new owner decided on the previous owner's request: %v", err)
	}
	if v, e := s.Reveal(context.Background(), "github", ""); v != nil || e == nil || e.Code != "unknown_entry" {
		t.Fatalf("after the transfer: %q %+v", v, e)
	}
}

// A reveal, a token request and a wallet signature go ahead only on an owner
// sealed could confirm.
func TestOwnerLookupFailureRefuses(t *testing.T) {
	f := newFixture(t)
	s, _, o := f.ownedStore(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_x"})
	f.editDefs(t, &doc, func(d *Definition) { d.AllowReveal = true })
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	o.set(crypto.PubkeyToAddress(f.owner.PublicKey), errors.New("rpc down"))
	stale(s)
	if v, e := s.Reveal(context.Background(), "github", ""); v != nil || e == nil || e.Code != "owner_unknown" {
		t.Fatalf("reveal: %q %+v", v, e)
	}
	if _, e := s.Token(context.Background(), "github", nil); e == nil || e.Code != "owner_unknown" {
		t.Fatalf("token: %+v", e)
	}
	if _, e := s.WalletSign(context.Background(), SignRequest{Name: "github"}); e == nil || e.Code != "owner_unknown" {
		t.Fatalf("sign: %+v", e)
	}
}

// An approval to reveal a derived token is for that token: a token obtained
// after it (here with a broader scope) is asked for again.
func TestRevealApprovalBoundToValue(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + r.PostForm.Get("scope") + `"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"g": "secret"})
	f.editDefs(t, &doc, tokenTemplate(ts.URL+"/token", false, false, "scope"))
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, e := s.Token(context.Background(), "g", map[string]string{"scope": "read"}); e != nil {
		t.Fatal(e)
	}
	_, e := s.Reveal(context.Background(), "derived:g.access_token", "")
	a, sig := f.approve(t, s, e.Message)
	if err := s.Decide(context.Background(), e.Message, "once", a, sig); err != nil {
		t.Fatal(err)
	}
	if _, e := s.Token(context.Background(), "g", map[string]string{"scope": "admin"}); e != nil {
		t.Fatal(e)
	}
	if v, e := s.Reveal(context.Background(), "derived:g.access_token", ""); v != nil || e == nil || e.Code != CodePending {
		t.Fatalf("the read-token approval revealed %q (%+v)", v, e)
	}
}

// Two refreshes scheduled for the same token: the second finds it already
// refreshed and sends nothing, so a rotating refresh token is used once.
func TestConcurrentRefreshUsesTokenOnce(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	gate := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		seen = append(seen, r.PostForm.Get("refresh_token"))
		first := len(seen) == 1
		mu.Unlock()
		if first {
			<-gate
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a1","refresh_token":"r1","expires_in":3600}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"m": "x"})
	f.editDefs(t, &doc, func(d *Definition) { d.MCP, d.Writeback, d.ValueHash = &MCPSpec{URL: ts.URL + "/mcp"}, true, "" })
	delete(doc.Values, "m")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	s.applyLogin(context.Background(), s.defs["m"], s.gen, &mcpState{V: 1, Type: "mcp_login", AccessToken: "a0", RefreshToken: "r0",
		ClientID: "c", TokenURL: ts.URL + "/token", Resource: "r"})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.refreshLogin("m", "a0", 0) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	s.Clear()
	if len(seen) != 1 || seen[0] != "r0" {
		t.Fatalf("refresh tokens sent: %v", seen)
	}
}

// A login entry the proxy could not serve is skipped when the set loads, so
// a later login cannot keep the proxy from taking the owner's next set.
func TestInvalidLoginEntrySkippedAtLoad(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_x", "m": "x"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "m" {
			d.MCP, d.Writeback, d.ValueHash = &MCPSpec{URL: "https://mcp.example/mcp"}, true, ""
			d.Positions = []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Cookie", Template: "s={v}"}}
		}
	})
	delete(doc.Values, "m")
	o, err := s.Load(context.Background(), doc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if o.Skipped["m"] == "" || reg.Get("github") == nil {
		t.Fatalf("skipped %v, serving %v", o.Skipped, reg.Names())
	}
	if _, err := s.Load(context.Background(), f.doc(t, 2, map[string]string{"gitlab": "glpat_x"}), 0); err != nil {
		t.Fatal(err)
	}
	if reg.Get("github") != nil || reg.Get("gitlab") == nil {
		t.Fatalf("serving %v", reg.Names())
	}
}

// One approval sent twice at once is taken once.
func TestDecideTakesOneApprovalOnce(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0); err != nil {
		t.Fatal(err)
	}
	_, e := s.Reveal(context.Background(), "github", "")
	a, sig := f.approve(t, s, e.Message)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Decide(context.Background(), e.Message, "once", a, sig) }()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrUnknownRequest) {
			t.Fatal(err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d decisions taken", ok)
	}
}

// A signing key signs and is never revealed, even if the owner allowed
// reveals of the entry.
func TestSigningKeyNeverRevealed(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"hmac": "k_secret_123"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Positions, d.AllowReveal = credproxy.UseSign, nil, true
		d.Signer = &credproxy.Signer{Method: credproxy.SignHMAC, Header: "X-Sig", Message: "{method} {path}"}
	})
	if o, err := s.Load(context.Background(), doc, 0); err != nil || len(o.Skipped) != 0 {
		t.Fatalf("%v %v", err, o.Skipped)
	}
	if v, e := s.Reveal(context.Background(), "hmac", ""); v != nil || e == nil || e.Code != "not_allowed" {
		t.Fatalf("revealed %q (%+v)", v, e)
	}
}

// A wallet entry may not hold the owner's own key: the agent could sign as
// its owner.
func TestOwnersOwnWalletRefused(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"w": fmt.Sprintf("0x%x", crypto.FromECDSA(f.owner))})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Positions, d.Hosts = credproxy.UseSign, nil, nil
		d.Signer = &credproxy.Signer{Method: credproxy.SignWallet}
	})
	o, err := s.Load(context.Background(), doc, 0)
	if err != nil || !strings.Contains(o.Skipped["w"], "owner's own key") || reg.Get("w") != nil {
		t.Fatalf("%v %v %v", err, o.Skipped, reg.Names())
	}
}

// A login entry's value is its login state, so it takes no token template.
func TestLoginEntryWithTemplateSkipped(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"m": "x"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP, d.ValueHash = &MCPSpec{URL: "https://mcp.example/mcp"}, ""
		tokenTemplate("https://auth.example/token", false, false)(d)
	})
	delete(doc.Values, "m")
	if o, err := s.Load(context.Background(), doc, 0); err != nil || o.Skipped["m"] == "" {
		t.Fatalf("%v %v", err, o.Skipped)
	}
}

// Editing a login entry's description keeps the login: the writeback is
// bound to the login (server, client, scopes), not to the whole definition.
func TestLoginSurvivesDescriptionEdit(t *testing.T) {
	auth := newFakeAuth(t)
	f := newFixture(t)
	s, reg := loginLinear(t, f, auth)
	doc := f.doc(t, 2, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(auth.ts.URL, "https://")}
		d.Description, d.AllowReveal = "Linear, edited", true
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if e := reg.Get("linear"); e == nil || string(e.Value) != "at-1" {
		t.Fatalf("the login was lost: %v", e)
	}
	// A different server is a different login.
	doc = f.doc(t, 3, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp", Scopes: []string{"write"}}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(auth.ts.URL, "https://")}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if reg.Get("linear") != nil {
		t.Fatal("a login was kept for other scopes")
	}
}

// The client secret entry goes to the token endpoint only if its own hosts
// allow it: the endpoint comes from the server's metadata.
func TestClientSecretOnlyToItsHosts(t *testing.T) {
	auth := newFakeAuth(t)
	f := newFixture(t)
	s, _, _ := f.store(t, nil, auth.ts.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused", "linear-secret": "cs_123"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "linear" {
			d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp", ClientID: "client-1", ClientSecretEntry: "linear-secret"}
			d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(auth.ts.URL, "https://")}
		} else {
			d.Use, d.Positions, d.Hosts = credproxy.UseTokenOnly, nil, []string{"auth.elsewhere.example"}
		}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	_, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
	if err == nil || !strings.Contains(err.Error(), "does not allow the token endpoint's host") {
		t.Fatalf("got %v", err)
	}
}

// Bounds on what the harness can make sealed keep: open requests, reasons,
// parameters, and audit records (proxy uses never push the rest out).
func TestHarnessBounds(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	for i := 0; i < maxOpenRequests; i++ {
		if _, e := s.Request("add", fmt.Sprintf("n%d", i), nil, strings.Repeat("r", 2*maxReason)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.Request("add", "one-more", nil, ""); e == nil || e.Code != "too_many_requests" {
		t.Fatalf("got %+v", e)
	}
	if l := s.PendingList(); len([]rune(l[0].Reason)) != maxReason {
		t.Fatalf("reason kept at %d", len([]rune(l[0].Reason)))
	}
	if _, e := s.Request("add", "x", map[string]string{"preset": strings.Repeat("p", maxParam+1)}, ""); e == nil || e.Code != "bad_request" {
		t.Fatalf("a long parameter: %+v", e)
	}
	s.Note("load", "github", "skipped: test")
	for i := 0; i < 2*auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "api.github.com", Method: "x\nINJECTED"})
	}
	recs := s.AuditSince(0)
	if recs[0].Op != "load" || len(recs) != auditKeep+1 || recs[1].Method != "OTHER" {
		t.Fatalf("%d records; first %+v; method %q", len(recs), recs[0], recs[1].Method)
	}
}

// What an earlier boot persisted is restored for the owner who wrote it, not
// for a new owner.
func TestAuditRestoredForItsOwnerOnly(t *testing.T) {
	f := newFixture(t)
	owner := crypto.PubkeyToAddress(f.owner.PublicKey)
	old := []AuditRecord{{Time: time.Unix(1_800_000_000, 0), Op: "reveal", Names: []string{"github"}, Result: "approved once"}}

	s, _, _ := f.store(t, nil, nil)
	s.SeedAudit(&AuditFile{Owner: owner, Records: old})
	if _, ok := s.AuditSnapshot(); ok {
		t.Fatal("persisting began before the owner was known")
	}
	s.ObserveOwner(owner)
	if f, ok := s.AuditSnapshot(); !ok || f.Owner != owner || len(f.Records) != 1 {
		t.Fatalf("restored %+v %v", f, ok)
	}

	s2, _, _ := f.store(t, nil, nil)
	other, _ := crypto.GenerateKey()
	s2.ObserveOwner(crypto.PubkeyToAddress(other.PublicKey))
	s2.SeedAudit(&AuditFile{Owner: owner, Records: old})
	if recs := s2.AuditSince(0); len(recs) != 0 {
		t.Fatalf("a previous owner's records were restored: %+v", recs)
	}
}
