package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

type memPersist struct{ v Mark }

func (m *memPersist) LoadHighest() (Mark, error) { return m.v, nil }
func (m *memPersist) SaveHighest(v Mark) error   { m.v = v; return nil }

func (f *fixture) store(t *testing.T, wb func(context.Context, string, Writeback) error, client *http.Client) (*Store, *credproxy.Registry, *memPersist) {
	t.Helper()
	reg := credproxy.NewRegistry()
	p := &memPersist{}
	owner := crypto.PubkeyToAddress(f.owner.PublicKey)
	s := NewStore(Env{
		Domain: f.domain, SealID: testSeal, AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey), AgentSealPriv: crypto.FromECDSA(f.seal),
		BootID: "boot-1", LiveOwner: func(context.Context) (common.Address, error) { return owner, nil },
		Persist: p, Writeback: wb, HTTPClient: client,
	}, reg)
	return s, reg, p
}

// editDefs rewrites definitions in doc and re-signs it.
func (f *fixture) editDefs(t *testing.T, doc *Document, edit func(*Definition)) {
	t.Helper()
	for i, e := range doc.Set.Entries {
		raw, _ := base64.StdEncoding.DecodeString(doc.Defs[e.Name])
		var d Definition
		_ = json.Unmarshal(raw, &d)
		edit(&d)
		raw, _ = json.Marshal(d)
		doc.Defs[e.Name] = base64.StdEncoding.EncodeToString(raw)
		doc.Set.Entries[i].DefHash = crypto.Keccak256Hash(raw).Hex()
	}
	digest, _ := doc.Set.Digest(f.domain)
	doc.Signature = f.sign(t, digest, f.owner)
}

func TestLoadListAndAntiRollback(t *testing.T) {
	f := newFixture(t)
	s, reg, p := f.store(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 2, map[string]string{"github": "ghp_x"}), 0); err != nil {
		t.Fatal(err)
	}
	if !p.v.Same(Mark{Epoch: 7, Version: 2}) || p.v.Digest == "" || reg.Get("github") == nil {
		t.Fatalf("persisted %+v, registry %v", p.v, reg.Names())
	}
	list := s.List()
	if len(list) != 1 || list[0].Placeholder != "[[credential:github]]" {
		t.Fatalf("list %+v", list)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "ghp_x") {
		t.Fatal("list leaked a value")
	}
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_old"}), 0); err != ErrStale {
		t.Fatalf("an older set was accepted: %v", err)
	}
}

func TestTokenRequestRotatesAndWritesBack(t *testing.T) {
	var gotForm string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm.Encode()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_123","expires_in":3600,"refresh_token":"rt_new","token_type":"Bearer"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	var wbMu sync.Mutex
	var wrote []Writeback
	s, reg, _ := f.store(t, func(_ context.Context, name string, w Writeback) error {
		wbMu.Lock()
		wrote = append(wrote, w)
		wbMu.Unlock()
		return nil
	}, ts.Client())
	doc := f.doc(t, 1, map[string]string{"gcp": "rt_old"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Writeback, d.Positions = credproxy.UseTokenOnly, true, nil
		d.TokenRequest = &TokenRequest{URL: ts.URL + "/token", Fields: map[string]string{"grant_type": "refresh_token", "refresh_token": "{v}", "client_id": "cid"},
			Params: []string{"scope"}, RotateField: "refresh_token",
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"cloudresourcemanager.googleapis.com"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, ExpiresInField: "expires_in"}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	out, cerr := s.Token(context.Background(), "gcp", map[string]string{"scope": "openid"})
	if cerr != nil {
		t.Fatal(cerr)
	}
	if len(out) != 1 || out[0].Name != "derived:gcp.access_token" || out[0].ExpiresAt == 0 {
		t.Fatalf("token result %+v", out)
	}
	if !strings.Contains(gotForm, "refresh_token=rt_old") || !strings.Contains(gotForm, "scope=openid") {
		t.Fatalf("token endpoint got %s", gotForm)
	}
	if e := reg.Get("derived:gcp.access_token"); e == nil || string(e.Value) != "at_123" {
		t.Fatal("access token not stored as a derived entry")
	}
	if e := reg.Get("gcp"); e == nil || string(e.Value) != "rt_new" {
		t.Fatal("refresh token not rotated")
	}
	if len(wrote) != 1 || wrote[0].Binding != s.defs["gcp"].Binding() || !strings.HasPrefix(wrote[0].Binding, "value:0x") {
		t.Fatalf("writebacks %+v", wrote)
	}
	// The written-back value opens at the next boot.
	doc.Writebacks = map[string]Writeback{"gcp": wrote[0]}
	o, err := Open(doc, f.check())
	if err != nil || string(o.Values["gcp"]) != "rt_new" {
		t.Fatalf("writeback did not survive a reload: %v %q", err, o.Values["gcp"])
	}
	if _, cerr := s.Token(context.Background(), "gcp", map[string]string{"audience": "x"}); cerr == nil || cerr.Code != "not_allowed" {
		t.Fatalf("a parameter outside the allowlist was accepted: %v", cerr)
	}
}

func TestTokenRequestErrorHidesBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"token rt_old revoked"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"gcp": "rt_old"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.TokenRequest = &TokenRequest{URL: ts.URL, Fields: map[string]string{"refresh_token": "{v}"}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	_, cerr := s.Token(context.Background(), "gcp", nil)
	if cerr == nil || cerr.Code != "token_request_failed" || !strings.Contains(cerr.Message, "invalid_grant") || strings.Contains(cerr.Message, "rt_old") {
		t.Fatalf("got %+v", cerr)
	}
}

func TestRevealNeedsApproval(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0); err != nil {
		t.Fatal(err)
	}
	_, cerr := s.Reveal(context.Background(), "github", "gh needs it")
	if cerr == nil || cerr.Code != CodePending {
		t.Fatalf("got %+v", cerr)
	}
	id := cerr.Message
	pending := s.PendingList()
	if len(pending) != 1 || pending[0].AuthReqID != id || pending[0].Reason != "gh needs it" || s.PendingCount() != 1 {
		t.Fatalf("pending %+v", pending)
	}
	// Asking again reports the same request.
	if _, again := s.Reveal(context.Background(), "github", "again"); again.Message != id {
		t.Fatal("a repeated request opened a second pending item")
	}
	p := pending[0]
	a := &Approval{SealID: testSeal, BootID: p.BootID, AuthReqID: id, RequestDigest: p.RequestDigest, ExpiresAt: uint64(time.Now().Add(time.Hour).Unix())}
	digest, _ := a.Digest(f.domain)
	other, _ := crypto.GenerateKey()
	if err := s.Decide(context.Background(), id, "once", a, f.sign(t, digest, other)); err != ErrWrongSigner {
		t.Fatalf("approval by a stranger: %v", err)
	}
	if err := s.Decide(context.Background(), id, "once", a, f.sign(t, digest, f.owner)); err != nil {
		t.Fatal(err)
	}
	if ev := s.Events(context.Background(), 0, 0); len(ev) == 0 || ev[len(ev)-1].Type != "pending_decided" {
		t.Fatalf("events %+v", ev)
	}
	v, cerr := s.Reveal(context.Background(), "github", "")
	if cerr != nil || string(v) != "ghp_x" {
		t.Fatalf("approved reveal: %v %q", cerr, v)
	}
	// The same signed approval sent again, right after its use, is refused:
	// its request is decided.
	if err := s.Decide(context.Background(), id, "once", a, f.sign(t, digest, f.owner)); err != ErrUnknownRequest {
		t.Fatalf("a used approval was accepted again: %v", err)
	}
	// The approval is single-use.
	if _, cerr := s.Reveal(context.Background(), "github", ""); cerr == nil || cerr.Code != CodePending {
		t.Fatalf("approval reused: %+v", cerr)
	}
}

// An expired credential is not revealed (not even allowed in advance) and
// not used in a token request, as the proxy does not fill or sign with it.
func TestExpiredEntryNotRevealedOrUsed(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_x"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.ExpiresAt = time.Now().Add(-time.Hour).Unix()
		d.AllowReveal = true
		d.TokenRequest = &TokenRequest{URL: "https://auth.example/token", Fields: map[string]string{"refresh_token": "{v}"},
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"api.github.com"}, Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if v, cerr := s.Reveal(context.Background(), "github", ""); cerr == nil || cerr.Code != "expired" || v != nil {
		t.Fatalf("reveal of an expired entry: %v %+v", v, cerr)
	}
	if _, cerr := s.Token(context.Background(), "github", nil); cerr == nil || cerr.Code != "expired" {
		t.Fatalf("token request with an expired entry: %+v", cerr)
	}
}

func TestRevealDenied(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	_, _ = s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0)
	_, cerr := s.Reveal(context.Background(), "github", "")
	if err := s.Decide(context.Background(), cerr.Message, "deny", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Reveal(context.Background(), "github", ""); cerr == nil || cerr.Code != CodeDenied {
		t.Fatalf("got %+v", cerr)
	}
	recs := s.AuditSince(0)
	if last := recs[len(recs)-1]; last.Op != "reveal" || last.Result != "refused by the owner" {
		t.Fatalf("the refusal is not in the owner's audit log: %+v", recs)
	}
}

func TestRevealAllowedInAdvance(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_x"})
	f.editDefs(t, &doc, func(d *Definition) { d.AllowReveal = true })
	_, _ = s.Load(context.Background(), doc, 0)
	if v, cerr := s.Reveal(context.Background(), "github", ""); cerr != nil || string(v) != "ghp_x" {
		t.Fatalf("got %v %q", cerr, v)
	}
	if len(s.AuditSince(0)) != 1 {
		t.Fatal("reveal not audited")
	}
}

func TestAddRequestClosesWhenOwnerAddsEntry(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	p, cerr := s.Request("add", "notion", map[string]string{"preset": "notion"}, "need notion")
	if cerr != nil {
		t.Fatal(cerr)
	}
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"notion": "secret_n"}), 0); err != nil {
		t.Fatal(err)
	}
	for _, q := range s.PendingList() {
		if q.AuthReqID == p.AuthReqID && q.Status != "approved" {
			t.Fatalf("status %s", q.Status)
		}
	}
}

func TestClearDropsEverything(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	_, _ = s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0)
	_, _ = s.Reveal(context.Background(), "github", "")
	s.Clear()
	if len(reg.Names()) != 0 || len(s.List()) != 0 || len(s.PendingList()) != 0 {
		t.Fatal("clear left state behind")
	}
	// The new owner's audit log starts with the clear, nothing of the old one.
	recs := s.AuditSince(0)
	if len(recs) != 1 || recs[0].Op != "clear" || len(recs[0].Names) != 0 {
		t.Fatalf("audit after clear: %+v", recs)
	}
}

// A used approval closes its request: asking again opens a new one the owner
// can see and decide, instead of answering with the old id forever.
func TestRevealAgainAfterApprovalOpensNewRequest(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	_, _ = s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0)
	_, e1 := s.Reveal(context.Background(), "github", "first")
	s.mu.Lock()
	p := s.pending[e1.Message]
	p.Status = "approved"
	s.approvals[p.RequestDigest] = Approval{ExpiresAt: uint64(s.now().Unix()) + 60}
	s.mu.Unlock()
	if v, err := s.Reveal(context.Background(), "github", "first"); err != nil || string(v) != "ghp_x" {
		t.Fatalf("the approval was not honoured: %v", err)
	}
	_, e2 := s.Reveal(context.Background(), "github", "second")
	if e2 == nil || e2.Code != CodePending || e2.Message == e1.Message {
		t.Fatalf("asking again: %+v (first id %s)", e2, e1.Message)
	}
	open := 0
	for _, q := range s.PendingList() {
		if q.Status == "pending" && q.AuthReqID == e2.Message {
			open++
		}
	}
	if open != 1 {
		t.Fatalf("the new request is not waiting for the owner: %+v", s.PendingList())
	}
}

// What sealed supplies itself is used on every model call: its successful
// uses become one counted record, failures stay listed, and the owner's own
// records are never pushed out by them.
func TestAuditCountsSealedEntries(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	t0 := time.Unix(1_800_000_000, 0)
	s.Record(credproxy.Record{Time: t0.Add(-time.Second), Names: []string{"github"}, Host: "api.github.com", Method: "GET"})
	for i := 0; i < auditKeep+50; i++ {
		s.Record(credproxy.Record{Time: t0.Add(time.Duration(i) * time.Second), Names: []string{"sealed:inference"}, Host: "router.example", Method: "POST"})
	}
	s.Record(credproxy.Record{Time: t0.Add(2 * time.Hour), Names: []string{"sealed:inference"}, Host: "router.example", Method: "POST", Code: "upstream_error"})
	recs := s.AuditSince(0)
	if len(recs) != 3 {
		t.Fatalf("records: %+v", recs)
	}
	if recs[0].Names[0] != "github" {
		t.Fatalf("the owner's record was pushed out: %+v", recs[0])
	}
	c := recs[1]
	if c.Count != auditKeep+50 || !c.First.Equal(t0) || !c.Time.Equal(t0.Add(time.Duration(auditKeep+49)*time.Second)) {
		t.Fatalf("counted record: %+v", c)
	}
	if recs[2].Result != "upstream_error" || recs[2].Count != 0 {
		t.Fatalf("a failure is listed on its own: %+v", recs[2])
	}
	// Persisted and loaded again (stop/start), the count carries on.
	s2, _, _ := f.store(t, nil, nil)
	s2.ObserveOwner(crypto.PubkeyToAddress(f.owner.PublicKey))
	s2.SeedAudit(&AuditFile{Owner: crypto.PubkeyToAddress(f.owner.PublicKey), Records: recs})
	s2.Record(credproxy.Record{Time: t0.Add(3 * time.Hour), Names: []string{"sealed:inference"}, Host: "router.example", Method: "POST"})
	again := s2.AuditSince(0)
	if len(again) != 3 || again[2].Count != auditKeep+51 {
		t.Fatalf("after reload: %+v", again)
	}
}

// Which entries were skipped and why is the owner's to read, never the
// public log's.
func TestSkippedEntryNamedInAuditOnly(t *testing.T) {
	f := newFixture(t)
	reg := credproxy.NewRegistry()
	var logged []string
	owner := crypto.PubkeyToAddress(f.owner.PublicKey)
	s := NewStore(Env{
		Domain: f.domain, SealID: testSeal, AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey), AgentSealPriv: crypto.FromECDSA(f.seal),
		BootID: "boot-1", LiveOwner: func(context.Context) (common.Address, error) { return owner, nil }, Persist: &memPersist{},
		Logf: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}, reg)
	doc := f.doc(t, 1, map[string]string{"secretname": "v-123456"})
	f.editDefs(t, &doc, func(d *Definition) { // a credential in the Host header: skipped
		d.Positions = []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Host", Template: "{v}"}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	for _, l := range logged {
		if strings.Contains(l, "secretname") {
			t.Fatalf("the public log names an entry: %q", l)
		}
	}
	var found bool
	for _, r := range s.AuditSince(0) {
		if r.Op == "load" && len(r.Names) == 1 && r.Names[0] == "secretname" && strings.HasPrefix(r.Result, "skipped: ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the skipped entry is not in the audit log: %+v", s.AuditSince(0))
	}
}

func TestHandlersNeverReturnValues(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	_, _ = s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_secretvalue"}), 0)
	h := s.HarnessHandler()
	for _, path := range []string{"/credentials", "/events?wait=0"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "ghp_secretvalue") {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	s.RevealHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/credentials/reveal", strings.NewReader(`{"name":"github","reason":"x"}`)))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"auth_req_id"`) || strings.Contains(rec.Body.String(), "ghp_secretvalue") {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body.String())
	}
}

// A new set that leaves a rotated entry's definition as it was keeps the
// rotated value; one that changes the definition takes the owner's value.
func TestRotatedValueSurvivesUnrelatedChange(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt_rotated"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, reg, _ := f.store(t, func(context.Context, string, Writeback) error { return nil }, ts.Client())
	mk := func(version uint64, values map[string]string, desc string) Document {
		doc := f.doc(t, version, values)
		f.editDefs(t, &doc, func(d *Definition) {
			if d.Name == "gcp" {
				d.Use, d.Writeback, d.Positions, d.Description = credproxy.UseTokenOnly, true, nil, desc
				d.TokenRequest = &TokenRequest{URL: ts.URL, Fields: map[string]string{"refresh_token": "{v}"}, RotateField: "refresh_token"}
			}
		})
		return doc
	}
	first := mk(1, map[string]string{"gcp": "rt_owner"}, "a")
	if _, err := s.Load(context.Background(), first, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "gcp", nil); cerr != nil {
		t.Fatal(cerr)
	}
	// The owner adds another entry; gcp's definition and value bytes are
	// carried over as they were, as the SDK does for an entry left alone.
	v2 := f.doc(t, 2, map[string]string{"github": "ghp_value_0123"})
	v2.Defs["gcp"], v2.Values["gcp"] = first.Defs["gcp"], first.Values["gcp"]
	v2.Set.Entries = append(v2.Set.Entries, first.Set.Entries[0])
	digest, _ := v2.Set.Digest(f.domain)
	v2.Signature = f.sign(t, digest, f.owner)
	if _, err := s.Load(context.Background(), v2, 0); err != nil {
		t.Fatal(err)
	}
	if e := reg.Get("gcp"); e == nil || string(e.Value) != "rt_rotated" {
		t.Fatalf("rotated value lost: %v", e)
	}
	// The owner changes gcp itself: their value wins.
	if _, err := s.Load(context.Background(), mk(3, map[string]string{"gcp": "rt_owner_new"}, "b"), 0); err != nil {
		t.Fatal(err)
	}
	if e := reg.Get("gcp"); e == nil || string(e.Value) != "rt_owner_new" {
		t.Fatalf("got %v", e)
	}
}

// git's helper gets the placeholder for a host whose entry allows Basic.
func TestGitCredentialHelperRoute(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"gh": "ghp_value_0123"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Hosts = []string{"github.com"}
		d.Positions = []credproxy.Position{{Kind: credproxy.PosBasic, Username: "x-access-token"}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	h := s.HarnessHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/credentials/git?host=github.com", nil))
	if w.Code != http.StatusOK || w.Body.String() != "username=x-access-token\npassword=[[credential:gh]]\n" {
		t.Fatalf("HTTP %d: %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/credentials/git?host=gitlab.com", nil))
	if w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("another host got %d %q", w.Code, w.Body.String())
	}
}
