package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"seal-verify/internal/credproxy"
)

// authPair: server A is the MCP server and its authorization server; server B is
// another https host (a second authorization server, a revocation endpoint).
type authPair struct {
	a, b        *httptest.Server
	mu          sync.Mutex
	prmResource string // "" = A/mcp
	prmIssuer   string // "" = A/auth
	revA        string // A's metadata revocation_endpoint ("" = none)
	tokenForms  []url.Values
	bForms      []url.Values
	issued      int
}

func newAuthPair(t *testing.T) *authPair {
	x := &authPair{}
	ma, mb := http.NewServeMux(), http.NewServeMux()
	x.a, x.b = httptest.NewTLSServer(ma), httptest.NewTLSServer(mb)
	t.Cleanup(x.a.Close)
	t.Cleanup(x.b.Close)
	A, B := x.a.URL, x.b.URL
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	ma.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+A+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(401)
	})
	ma.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		x.mu.Lock()
		res, iss := x.prmResource, x.prmIssuer
		x.mu.Unlock()
		if res == "" {
			res = A + "/mcp"
		}
		if iss == "" {
			iss = A + "/auth"
		}
		j(w, map[string]any{"resource": res, "authorization_servers": []string{iss}})
	})
	ma.HandleFunc("/.well-known/oauth-authorization-server/auth", func(w http.ResponseWriter, r *http.Request) {
		m := map[string]any{"authorization_endpoint": A + "/auth/authorize", "token_endpoint": A + "/auth/token",
			"code_challenge_methods_supported": []string{"S256"}}
		x.mu.Lock()
		if x.revA != "" {
			m["revocation_endpoint"] = x.revA
		}
		x.mu.Unlock()
		j(w, m)
	})
	ma.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		x.mu.Lock()
		x.tokenForms = append(x.tokenForms, r.PostForm)
		x.issued++
		n := string(rune('0' + x.issued))
		x.mu.Unlock()
		j(w, map[string]any{"access_token": "at-" + n, "refresh_token": "rt-" + n, "expires_in": 3600})
	})
	mb.HandleFunc("/.well-known/oauth-authorization-server/auth2", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"authorization_endpoint": B + "/auth2/authorize", "token_endpoint": B + "/auth2/token",
			"revocation_endpoint": B + "/revoke", "registration_endpoint": B + "/register"})
	})
	mb.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		j(w, map[string]any{"client_id": "b-client"})
	})
	mb.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		x.mu.Lock()
		x.bForms = append(x.bForms, r.PostForm)
		x.mu.Unlock()
	})
	return x
}

func (x *authPair) host() string { return strings.TrimPrefix(x.a.URL, "https://") }

// loginPair loads a login entry "linear" (client_id + client_secret_entry
// "linear-secret", whose hosts are A only) and completes the login.
func loginPair(t *testing.T, f *fixture, x *authPair) *Store {
	t.Helper()
	s, _, _ := f.store(t, nil, x.a.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused", "linear-secret": "cs_123"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "linear" {
			d.MCP = &MCPSpec{URL: x.a.URL + "/mcp", ClientID: "client-1", ClientSecretEntry: "linear-secret"}
			d.ValueHash, d.Writeback, d.Hosts = "", true, []string{x.host()}
		} else {
			d.Use, d.Positions, d.Hosts = credproxy.UseTokenOnly, nil, []string{x.host()}
		}
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
	if _, err := s.FinishLogin(context.Background(), u.Query().Get("state"), "code", ""); err != nil {
		t.Fatal(err)
	}
	return s
}

func secretsIn(forms []url.Values) []string {
	var out []string
	for _, f := range forms {
		if v := f.Get("client_secret"); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// A revocation endpoint on another host than the token endpoint is not
// asked: the client secret and the tokens go to the token endpoint's host only.
func TestRevocationOnlyOnTokenHost(t *testing.T) {
	x := newAuthPair(t)
	x.revA = x.b.URL + "/revoke" // B is not in linear-secret's hosts
	s := loginPair(t, newFixture(t), x)
	if _, _, err := s.Disconnect(context.Background(), "linear"); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if got := secretsIn(x.bForms); len(got) > 0 {
		t.Fatalf("client secret sent to the revocation host %s, not in its entry's hosts: %v", x.b.URL, got)
	}
}

// A login made where the authorization server offered no revocation: a
// disconnect does not discover again, so nothing goes where the server's
// metadata points to today.
func TestDisconnectDoesNotDiscoverAgain(t *testing.T) {
	x := newAuthPair(t)
	s := loginPair(t, newFixture(t), x) // no revocation endpoint at login
	x.mu.Lock()
	x.prmIssuer = x.b.URL + "/auth2" // the resource server now names another AS
	x.mu.Unlock()
	if _, _, err := s.Disconnect(context.Background(), "linear"); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, f := range x.bForms {
		t.Errorf("sent to an authorization server that never issued the tokens: token_type_hint=%s token=%s client_secret=%s",
			f.Get("token_type_hint"), f.Get("token"), f.Get("client_secret"))
	}
}

// The login keeps no copy of the client secret: once the owner's entry has
// expired, or is gone, refreshes send none.
func TestRefreshReadsClientSecretEntryAgain(t *testing.T) {
	x := newAuthPair(t)
	f := newFixture(t)
	s := loginPair(t, f, x)
	access := func() string {
		s.mu.Lock()
		defer s.mu.Unlock()
		st, _ := parseMCPState(s.values["linear"])
		return st.AccessToken
	}
	loginDef := func(d *Definition) {
		d.MCP = &MCPSpec{URL: x.a.URL + "/mcp", ClientID: "client-1", ClientSecretEntry: "linear-secret"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{x.host()}
	}
	// v2: the secret entry has expired.
	doc := f.doc(t, 2, map[string]string{"linear": "unused", "linear-secret": "cs_123"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "linear" {
			loginDef(d)
		} else {
			d.Use, d.Positions, d.Hosts, d.ExpiresAt = credproxy.UseTokenOnly, nil, []string{x.host()}, time.Now().Add(-time.Hour).Unix()
		}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	x.tokenForms = nil
	x.mu.Unlock()
	s.refreshLogin("linear", access(), 0)
	x.mu.Lock()
	expired := secretsIn(x.tokenForms)
	x.tokenForms = nil
	x.mu.Unlock()
	// v3: the secret entry is gone.
	doc = f.doc(t, 3, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, loginDef)
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	s.refreshLogin("linear", access(), 0)
	x.mu.Lock()
	removed := secretsIn(x.tokenForms)
	x.mu.Unlock()
	if len(expired) > 0 || len(removed) > 0 {
		t.Fatalf("refresh sent the client secret after its entry expired %v / was removed %v", expired, removed)
	}
}

// RFC 9728 §3.3: the resource in the metadata must be the server the login
// is for.
func TestResourceMetadataMustNameTheServer(t *testing.T) {
	x := newAuthPair(t)
	x.prmResource = "https://other-resource.example/api"
	f := newFixture(t)
	s, _, _ := f.store(t, nil, x.a.Client())
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
	if err == nil {
		u, _ := url.Parse(link)
		t.Fatalf("a login for resource %q was started for the MCP server %s/mcp", u.Query().Get("resource"), x.a.URL)
	}
}

// resource_metadata over plain http is not followed.
func TestResourceMetadataOnlyOverHTTPS(t *testing.T) {
	x := newAuthPair(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": x.a.URL + "/mcp", "authorization_servers": []string{x.b.URL + "/auth2"}})
	}))
	defer plain.Close()
	mcp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+plain.URL+`/prm"`)
		w.WriteHeader(401)
	}))
	defer mcp.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, x.a.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: mcp.URL + "/mcp", ClientID: "client-1"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(mcp.URL, "https://")}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	link, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
	if err == nil {
		t.Fatalf("metadata fetched over http steered the login to %s", link)
	}
}

// A field the owner's template sets (scope=read) is not the agent's to
// replace, even when the template lists it among the params.
func TestParamCannotReplaceOwnerField(t *testing.T) {
	var got url.Values
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_x","expires_in":3600}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"svc": "client-secret-value"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Positions = credproxy.UseTokenOnly, nil
		// What the CLI's preset=oauth2-client scope=read builds.
		d.TokenRequest = &TokenRequest{URL: ts.URL + "/token", Encoding: "form",
			Fields: map[string]string{"grant_type": "client_credentials", "client_id": "cid", "client_secret": "{v}", "scope": "read"},
			Params: []string{"scope"},
			Take: []TokenTake{{Field: "access_token", Name: "svc", Hosts: []string{"api.example"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, ExpiresInField: "expires_in"}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "svc", map[string]string{"scope": "admin write"}); cerr == nil || cerr.Code != "not_allowed" || got != nil {
		t.Fatalf("the agent's scope replaced the owner's: %+v, sent %v", cerr, got)
	}
}

// The owner deciding a reveal of a derived token is shown where the token
// goes and what it was obtained with.
func TestDerivedRevealFactsAreTheTokens(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_derived_value","expires_in":3600}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"gcp": "rt_old"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Positions, d.Hosts = credproxy.UseTokenOnly, nil, []string{"oauth2.googleapis.com"}
		d.TokenRequest = &TokenRequest{URL: ts.URL + "/token", Fields: map[string]string{"refresh_token": "{v}"}, Params: []string{"scope"},
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"storage.googleapis.com"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "gcp", map[string]string{"scope": "devstorage.full_control"}); cerr != nil {
		t.Fatal(cerr)
	}
	if _, cerr := s.Reveal(context.Background(), "derived:gcp.access_token", ""); cerr == nil || cerr.Code != CodePending {
		t.Fatalf("got %+v", cerr)
	}
	p := s.PendingList()[0]
	b, _ := json.Marshal(p.Facts)
	if !strings.Contains(string(b), "storage.googleapis.com") || !strings.Contains(string(b), "scope") {
		t.Fatalf("the owner is asked to reveal derived:gcp.access_token with facts %s (not its hosts, nor the scope it was obtained with)", b)
	}
}

// A derived token expires with its source entry, whatever the response says.
func TestDerivedExpiresWithSource(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_long_lived_value"}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, ts.Client())
	start := time.Now()
	doc := f.doc(t, 1, map[string]string{"svc": "client-secret-value"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Positions, d.AllowReveal, d.ExpiresAt = credproxy.UseTokenOnly, nil, true, start.Add(time.Minute).Unix()
		d.TokenRequest = &TokenRequest{URL: ts.URL + "/token", Fields: map[string]string{"client_secret": "{v}"},
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"api.example"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, ExpiresInField: "expires_in"}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "svc", nil); cerr != nil {
		t.Fatal(cerr)
	}
	s.now = func() time.Time { return start.Add(time.Hour) }
	if _, cerr := s.Reveal(context.Background(), "svc", ""); cerr == nil || cerr.Code != "expired" {
		t.Fatalf("source: %+v", cerr)
	}
	e := reg.Get("derived:svc.access_token")
	v, cerr := s.Reveal(context.Background(), "derived:svc.access_token", "")
	if cerr == nil || (e != nil && e.ExpiresAt.IsZero()) {
		t.Fatalf("an hour after the source expired, its derived token still reveals (%q) and fills (expiry %v)", v, e.ExpiresAt)
	}
}

// An approval whose expiry does not fit int64 is past its request's expiry,
// and refused.
func TestApprovalExpiryBeyondInt64Refused(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_value_0123"}), 0); err != nil {
		t.Fatal(err)
	}
	_, cerr := s.Reveal(context.Background(), "github", "")
	if cerr == nil || cerr.Code != CodePending {
		t.Fatalf("%+v", cerr)
	}
	p := s.PendingList()[0]
	a := &Approval{SealID: testSeal, BootID: p.BootID, AuthReqID: p.AuthReqID, RequestDigest: p.RequestDigest, ExpiresAt: ^uint64(0)}
	dg, _ := a.Digest(f.domain)
	if err := s.Decide(context.Background(), p.AuthReqID, "once", a, f.sign(t, dg, f.owner)); err == nil {
		s.now = func() time.Time { return time.Now().Add(10 * 365 * 24 * time.Hour) }
		_, cerr := s.Reveal(context.Background(), "github", "")
		t.Fatalf("an approval with expires_at 2^64-1 (request expires %d) was taken; ten years on the reveal answers %v", p.ExpiresAt, cerr)
	}
}

// A disconnect is written back: the next boot finds the entry waiting for a
// login, not the login the attestor held.
func TestDisconnectSurvivesRestart(t *testing.T) {
	auth := newFakeAuth(t)
	f := newFixture(t)
	var mu sync.Mutex
	var last Writeback
	s, _, _ := f.store(t, func(_ context.Context, _ string, w Writeback) error {
		mu.Lock()
		last = w
		mu.Unlock()
		return nil
	}, auth.ts.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(auth.ts.URL, "https://")}
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
	auth.mu.Lock()
	auth.challenge = u.Query().Get("code_challenge")
	auth.mu.Unlock()
	if _, err := s.FinishLogin(context.Background(), u.Query().Get("state"), "the-code", ""); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	doc.Writebacks = map[string]Writeback{"linear": last}
	mu.Unlock()
	if o, err := Open(doc, f.check()); err != nil || o.Values["linear"] == nil {
		t.Fatalf("the login was not written back: %v", err)
	}
	if _, _, err := s.Disconnect(context.Background(), "linear"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	doc.Writebacks = map[string]Writeback{"linear": last}
	mu.Unlock()
	o, err := Open(doc, f.check())
	if err != nil || o.Defs["linear"] == nil || o.Values["linear"] != nil {
		t.Fatalf("after a disconnect the next boot has %v (%v)", o.Values["linear"], err)
	}
}
