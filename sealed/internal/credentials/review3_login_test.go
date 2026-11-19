package credentials

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/credproxy"
)

// The client secret entry is read again at the code exchange: a login
// started while it allowed the token endpoint, finished after the owner's
// next set removed, expired or narrowed it, sends no secret.
func TestCodeExchangeRereadsClientSecret(t *testing.T) {
	cases := map[string]func(x *authPair, d *Definition) (keep bool){
		"removed": func(x *authPair, d *Definition) bool { return false },
		"expired": func(x *authPair, d *Definition) bool {
			d.Use, d.Positions, d.Hosts, d.ExpiresAt = credproxy.UseTokenOnly, nil, []string{x.host()}, time.Now().Add(-time.Hour).Unix()
			return true
		},
		"hosts narrowed": func(x *authPair, d *Definition) bool {
			d.Use, d.Positions, d.Hosts = credproxy.UseTokenOnly, nil, []string{"other.example"}
			return true
		},
	}
	for label, edit := range cases {
		t.Run(label, func(t *testing.T) {
			x := newAuthPair(t)
			f := newFixture(t)
			s, _, _ := f.store(t, nil, x.a.Client())
			loginDef := func(d *Definition) {
				d.MCP = &MCPSpec{URL: x.a.URL + "/mcp", ClientID: "client-1", ClientSecretEntry: "linear-secret"}
				d.ValueHash, d.Writeback, d.Hosts = "", true, []string{x.host()}
			}
			doc := f.doc(t, 1, map[string]string{"linear": "unused", "linear-secret": "cs_123"})
			f.editDefs(t, &doc, func(d *Definition) {
				if d.Name == "linear" {
					loginDef(d)
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
			// The owner's next set, before the browser comes back.
			vals := map[string]string{"linear": "unused", "linear-secret": "cs_123"}
			keep := edit(x, &Definition{})
			if !keep {
				delete(vals, "linear-secret")
			}
			doc2 := f.doc(t, 2, vals)
			f.editDefs(t, &doc2, func(d *Definition) {
				if d.Name == "linear" {
					loginDef(d)
				} else {
					edit(x, d)
				}
			})
			delete(doc2.Values, "linear")
			if _, err := s.Load(context.Background(), doc2, 0); err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(link)
			_, ferr := s.FinishLogin(context.Background(), u.Query().Get("state"), "code", "", "")
			x.mu.Lock()
			sent := secretsIn(x.tokenForms)
			x.mu.Unlock()
			if len(sent) > 0 {
				t.Fatalf("secret entry %s after StartLogin; the code exchange still sent client_secret=%v (FinishLogin err=%v)", label, sent, ferr)
			}
		})
	}
}

// The authorization server's redirect must name the server the owner was
// sent to when it names one (RFC 9207): a code from another server is never
// posted to this login's token endpoint.
func TestLoginRedirectFromAnotherIssuerRefused(t *testing.T) {
	x := newAuthPair(t)
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
	start := func() string {
		link, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(link)
		return u.Query().Get("state")
	}
	x.mu.Lock()
	x.tokenForms = nil
	x.mu.Unlock()
	if _, err := s.FinishLogin(context.Background(), start(), "code", "", x.b.URL+"/auth2"); err == nil {
		t.Fatal("a redirect naming another issuer was taken")
	}
	x.mu.Lock()
	sent := len(x.tokenForms)
	x.mu.Unlock()
	if sent != 0 {
		t.Fatal("the code was posted to the token endpoint")
	}
	if _, err := s.FinishLogin(context.Background(), start(), "code", "", x.a.URL+"/auth/"); err != nil {
		t.Fatalf("the redirect named the right issuer: %v", err)
	}
}

// An unknown state is refused before anything else: it costs no lookup of
// the owner on chain.
func TestUnknownLoginStateCostsNoLookup(t *testing.T) {
	f := newFixture(t)
	s, _, o := f.ownedStore(t, nil, nil)
	stale(s)
	var lookups atomic.Int32
	s.env.LiveOwner = func(ctx context.Context) (common.Address, error) { lookups.Add(1); return o.get(ctx) }
	if _, err := s.FinishLogin(context.Background(), "made-up", "code", "", ""); err == nil || lookups.Load() != 0 {
		t.Fatalf("err %v, %d lookups", err, lookups.Load())
	}
}

// A token endpoint that refuses a refresh with a 200 carrying an error ends
// the login like any refusal: the owner is asked to log in again.
func TestRefreshRefusedWithStatus200AsksLogin(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
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
	s.refreshLogin("m", "a0", 0)
	for _, p := range s.PendingList() {
		if p.Op == "login" && p.Name == "m" {
			return
		}
	}
	t.Fatal("the owner was not asked to log in again")
}
