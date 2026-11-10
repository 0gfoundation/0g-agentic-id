package credentials

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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

// Successful signatures, which the agent can make without the owner, never
// push a record out of the log without a trace: a signed transaction stays
// listed, or is counted.
func TestSignaturesDoNotEvictEarlierRecords(t *testing.T) {
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
		if _, e := s.WalletSign(context.Background(), SignRequest{Name: "wallet", PersonalSign: &evmsign.PersonalSignRequest{Message: "hi"}}); e != nil {
			t.Fatal(e.Message)
		}
	}
	for _, r := range s.AuditSince(0) {
		if r.Op == "sign transaction" {
			return
		}
	}
	t.Fatal("the signed transaction is no longer in the owner's audit log")
}

// Methods the agent makes up are recorded as OTHER, and one operation's
// counted kinds never crowd out another's.
func TestMethodsCannotFillCountKinds(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_x"})
	f.editDefs(t, &doc, func(d *Definition) { d.AllowReveal = true })
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCountKeys; i++ {
		m := fmt.Sprintf("X%c%c", 'A'+i/26, 'A'+i%26)
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"sealed:inference"}, Host: "api.example", Method: m})
	}
	if _, e := s.Reveal(context.Background(), "github", "r"); e != nil {
		t.Fatal(e.Message)
	}
	for _, r := range s.AuditSince(0) {
		if r.Op == "reveal" {
			if len(r.Names) != 1 || r.Names[0] != "github" {
				t.Fatalf("the reveal record no longer names the entry: %+v", r)
			}
			return
		}
	}
	t.Fatal("no reveal record")
}

// An owner answer from a lookup that began before a later one was recorded
// is not taken, and confirms nothing.
func TestRouteAnswerDoesNotOutrankLaterLookup(t *testing.T) {
	f := newFixture(t)
	ownerA := crypto.PubkeyToAddress(f.owner.PublicKey)
	ownerB := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	var mu sync.Mutex
	block := false
	started, gate := make(chan struct{}), make(chan struct{})
	reg := credproxy.NewRegistry()
	s := NewStore(Env{
		Domain: f.domain, SealID: testSeal, AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey), AgentSealPriv: crypto.FromECDSA(f.seal),
		BootID: "boot-1", Persist: &memPersist{},
		LiveOwner: func(context.Context) (common.Address, error) {
			mu.Lock()
			b := block
			mu.Unlock()
			if !b {
				return ownerA, nil
			}
			close(started)
			<-gate
			return ownerB, nil // the chain after the transfer
		},
	}, reg)
	doc := f.doc(t, 1, map[string]string{"github": "ghp_secret"})
	f.editDefs(t, &doc, func(d *Definition) { d.AllowReveal = true })
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	stale(s)
	mu.Lock()
	block = true
	mu.Unlock()
	type res struct {
		v []byte
		e *credproxy.Error
	}
	out := make(chan res, 1)
	go func() { v, e := s.Reveal(context.Background(), "github", "r"); out <- res{v, e} }()
	<-started
	// The previous owner's signed route request: its resolveOwner began before
	// the transfer and answers A now.
	s.ObserveOwner(ownerA)
	close(gate)
	r := <-out
	if r.e == nil {
		t.Fatalf("revealed %q although the only lookup begun after the transfer answered the new owner", r.v)
	}
}

// A retried login writeback and a disconnect are ordered by the entry's
// lock: the disconnect written back last is what the next boot finds.
func TestRetriedWritebackDoesNotOverwriteDisconnect(t *testing.T) {
	auth := newFakeAuth(t)
	auth.noRevocation = true
	f := newFixture(t)
	var mu sync.Mutex
	calls := 0
	var last Writeback
	retryIn, retryGo := make(chan struct{}), make(chan struct{})
	s, _, _ := f.store(t, func(_ context.Context, _ string, w Writeback) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch {
		case n <= 3: // the login's writeback: the attestor is down
			return errors.New("attestor unreachable")
		case n == 4: // the retry, 30 s later: checked, now posting
			close(retryIn)
			<-retryGo
		}
		mu.Lock()
		last = w
		mu.Unlock()
		return nil
	}, auth.ts.Client())
	s.retryUnit = time.Millisecond
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
	if _, err := s.FinishLogin(context.Background(), u.Query().Get("state"), "the-code", "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retryIn:
	case <-time.After(10 * time.Second):
		t.Fatal("no retry")
	}
	disconnected := make(chan error, 1)
	go func() { _, _, err := s.Disconnect(context.Background(), "linear"); disconnected <- err }()
	time.Sleep(50 * time.Millisecond)
	close(retryGo)
	if err := <-disconnected; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	doc.Writebacks = map[string]Writeback{"linear": last}
	mu.Unlock()
	o, err := Open(doc, f.check())
	if err != nil {
		t.Fatal(err)
	}
	if o.Values["linear"] != nil {
		t.Fatalf("after a disconnect the attestor's writeback restores the login: %s", o.Values["linear"])
	}
}

// Open agent requests at their cap do not stop sealed asking the owner to
// log in again.
func TestAgentRequestsDoNotBlockSealedsLoginRequest(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	for i := 0; i < maxOpenRequests; i++ {
		if _, e := s.Request("add", fmt.Sprintf("n%d", i), nil, "r"); e != nil {
			t.Fatal(e.Message)
		}
	}
	s.askLogin("linear", &Definition{Name: "linear", MCP: &MCPSpec{URL: "https://mcp.example/mcp"}}, s.gen, "the login expired or was revoked")
	for _, p := range s.PendingList() {
		if p.Op == "login" && p.Name == "linear" {
			return
		}
	}
	t.Fatal("sealed's login request for the owner was dropped")
}

// Allowed proxy uses never push an earlier refusal out without a trace.
func TestAllowedUsesDoNotEvictRefusal(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "elsewhere.example", Method: "POST", Code: "host_not_allowed"})
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "api.github.com", Method: "GET"})
	}
	for _, r := range s.AuditSince(0) {
		if r.Result == "host_not_allowed" {
			return
		}
	}
	t.Fatal("the refused use is no longer in the owner's audit log")
}

// A token request that waited for the entry confirms the owner again once
// it is its turn.
func TestQueuedTokenRequestConfirmsOwnerAgain(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	release := make(chan struct{})
	first := make(chan struct{})
	ts := httptestTLS(t, func(n int) {
		if n == 1 {
			close(first)
			<-release
		}
	}, &mu, &hits)
	f := newFixture(t)
	s, _, owner := f.ownedStore(t, nil, ts.Client())
	var clock sync.Mutex
	now := time.Now()
	s.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	doc := f.doc(t, 1, map[string]string{"svc": "rt-0"})
	f.editDefs(t, &doc, tokenTemplate(ts.URL+"/token", false, false))
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	done1 := make(chan struct{})
	go func() { _, _ = s.Token(context.Background(), "svc", nil); close(done1) }()
	<-first
	type res struct {
		out []EntryInfo
		e   *credproxy.Error
	}
	out := make(chan res, 1)
	go func() { o, e := s.Token(context.Background(), "svc", nil); out <- res{o, e} }()
	time.Sleep(200 * time.Millisecond) // the second request is waiting for the lock
	clock.Lock()
	now = now.Add(time.Minute)
	clock.Unlock()
	owner.set(common.Address{}, errors.New("rpc down"))
	close(release)
	<-done1
	r := <-out
	mu.Lock()
	n := hits
	mu.Unlock()
	if r.e == nil || n > 1 {
		t.Fatalf("the queued token request was sent (%d requests) on an owner confirmation a minute old", n)
	}
}

// A disconnect whose client gave up still asks the server to revoke the
// tokens it forgets.
func TestCancelledDisconnectStillRevokes(t *testing.T) {
	auth := newFakeAuth(t)
	s, _ := loginLinear(t, newFixture(t), auth)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, note1, err := s.Disconnect(ctx, "linear")
	if err != nil {
		t.Fatal(err)
	}
	revoked, note2, _ := s.Disconnect(context.Background(), "linear")
	auth.mu.Lock()
	seen := len(auth.revokedSeen)
	auth.mu.Unlock()
	if seen == 0 && !revoked {
		t.Fatalf("tokens forgotten, never revoked; first note %q, second note %q", note1, note2)
	}
}
