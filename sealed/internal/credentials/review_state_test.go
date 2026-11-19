package credentials

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/evmsign"
)

// A token request for a name the owner never defined leaves nothing behind.
func TestUnknownTokenNamesKeepNoLock(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0); err != nil {
		t.Fatal(err)
	}
	h := s.HarnessHandler()
	long := strings.Repeat("z", 60<<10)
	for i := 0; i < 200; i++ {
		body, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("%s-%d", long, i)})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/credentials/token", strings.NewReader(string(body))))
		if w.Code != http.StatusNotFound {
			t.Fatalf("HTTP %d", w.Code)
		}
	}
	s.mu.Lock()
	n, bytes := len(s.tokenMu), 0
	for k := range s.tokenMu {
		bytes += len(k)
	}
	s.mu.Unlock()
	if n > 1 {
		t.Fatalf("unknown names are kept: %d keys, %d bytes", n, bytes)
	}
}

// Records whose host or names the harness chose stay small, so the persisted
// log always fits what the next boot reads (main's maxAuditFile, 8 MiB).
func TestAuditBoundedForPersistence(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	s.SeedAudit(nil)
	s.ObserveOwner(crypto.PubkeyToAddress(f.owner.PublicKey))
	host := strings.Repeat("a", 9<<10) + ".example"
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"nope"}, Host: host, Method: "GET", Code: "unknown_entry"})
	}
	snap, ok := s.AuditSnapshot()
	if !ok {
		t.Fatal("not ready")
	}
	b, _ := json.Marshal(snap)
	if len(b) > 8<<20 {
		t.Fatalf("audit file %d bytes exceeds what the next boot reads", len(b))
	}
}

// The owner's newer login stands over a refresh of the older one that was
// already running.
func TestNewerLoginWinsOverRefreshInFlight(t *testing.T) {
	refreshStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	base := ts.URL
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/auth"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/auth", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"authorization_endpoint": base + "/auth/authorize", "token_endpoint": base + "/auth/token",
			"registration_endpoint": base + "/auth/register", "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		j(w, map[string]any{"client_id": "client-1"})
	})
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			c := r.PostForm.Get("code") // code-A or code-B
			j(w, map[string]any{"access_token": "at-" + c, "refresh_token": "rt-" + c, "expires_in": 3600})
		case "refresh_token":
			once.Do(func() { close(refreshStarted) })
			<-release
			j(w, map[string]any{"access_token": "at-refreshed-" + r.PostForm.Get("refresh_token"), "refresh_token": "rt-2", "expires_in": 3600})
		}
	})

	f := newFixture(t)
	s, reg, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: base + "/mcp"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(base, "https://")}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	login := func(code string) {
		link, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(link)
		if _, err := s.FinishLogin(context.Background(), u.Query().Get("state"), code, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	login("code-A")
	if v := string(reg.Get("linear").Value); v != "at-code-A" {
		t.Fatalf("after login A: %q", v)
	}
	done := make(chan struct{})
	go func() { s.refreshLogin("linear", "at-code-A", 0); close(done) }()
	<-refreshStarted
	// The owner logs in again (say, to another account) while the refresh
	// runs: the new login waits for it, then stands.
	link, err := s.StartLogin(context.Background(), "linear", "https://agent.example/_seal/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	finished := make(chan error, 1)
	go func() {
		_, err := s.FinishLogin(context.Background(), u.Query().Get("state"), "code-B", "", "")
		finished <- err
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if v := string(reg.Get("linear").Value); v != "at-code-B" {
		t.Fatalf("the owner's newer login was replaced by the refreshed older one: %q", v)
	}
}

// Failed signature requests are counted, so they never push the record of a
// real signature out of the owner's audit log.
func TestFailedSignaturesDoNotEvictRecords(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	wallet, _ := crypto.GenerateKey()
	doc := f.doc(t, 1, map[string]string{"wallet": hex.EncodeToString(crypto.FromECDSA(wallet))})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use, d.Hosts, d.Positions = credproxy.UseSign, nil, nil
		d.Signer = &credproxy.Signer{Method: credproxy.SignWallet}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, e := s.WalletSign(context.Background(), SignRequest{Name: "wallet", Transaction: &evmsign.TransactionRequest{ChainID: "16602", Nonce: 1,
		To: "0x000000000000000000000000000000000000dEaD", Value: "1000", GasLimit: 21000, MaxFeePerGas: "2", MaxPriorityFeePerGas: "1"}}); e != nil {
		t.Fatal(e.Message)
	}
	for i := 0; i < auditKeep; i++ {
		_, _ = s.WalletSign(context.Background(), SignRequest{Name: "wallet", PersonalSign: &evmsign.PersonalSignRequest{MessageHex: "0xzz"}})
	}
	for _, r := range s.AuditSince(0) {
		if r.Op == "sign transaction" {
			return
		}
	}
	t.Fatal("the signed transaction is no longer in the owner's audit log")
}

// An owner lookup begun before a newer one was recorded does not undo it:
// answers arrive out of order.
func TestStaleOwnerLookupIgnored(t *testing.T) {
	f := newFixture(t)
	ownerA := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	ownerB := crypto.PubkeyToAddress(f.owner.PublicKey)
	gate, started := make(chan struct{}), make(chan struct{})
	var calls sync.Mutex
	n := 0
	reg := credproxy.NewRegistry()
	s := NewStore(Env{
		Domain: f.domain, SealID: testSeal, AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey), AgentSealPriv: crypto.FromECDSA(f.seal),
		BootID: "boot-1", Persist: &memPersist{},
		LiveOwner: func(context.Context) (common.Address, error) {
			calls.Lock()
			n++
			first := n == 1
			calls.Unlock()
			if first { // the watcher's lookup, answered from before the transfer
				close(started)
				<-gate
				return ownerA, nil
			}
			return ownerB, nil
		},
	}, reg)
	s.ObserveOwner(ownerA)
	done := make(chan struct{})
	go func() { _ = s.RefreshOwner(context.Background()); close(done) }()
	<-started
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_x"}), 0); err != nil {
		t.Fatal(err)
	}
	close(gate)
	<-done
	if reg.Get("github") == nil {
		t.Fatal("an owner lookup begun earlier cleared the current owner's set")
	}
}

// What the agent puts in a request's parameters is shown to the owner: text
// only, and a login's url is https.
func TestRequestParamsAreText(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	for _, u := range []string{"https://mcp.example/\x1b[1A\x1b[2K\rreveal", "https://mcp.example/\u009b2K", "http://mcp.example/mcp"} {
		if _, e := s.Request("login", "linear", map[string]string{"url": u}, "r"); e == nil || e.Code != "bad_request" {
			t.Fatalf("%q: %+v", u, e)
		}
	}
	p, e := s.Request("login", "linear", map[string]string{"url": "https://mcp.example/mcp"}, "line one\x1b[2K\nline two")
	if e != nil {
		t.Fatal(e)
	}
	if strings.ContainsAny(p.Reason, "\x1b\n") {
		t.Fatalf("reason kept control characters: %q", p.Reason)
	}
}
