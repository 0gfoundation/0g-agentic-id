package attestorhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// tlsKey is one attestor TLS key and its self-signed certificate.
type tlsKey struct {
	cert tls.Certificate
	pin  string
}

func newTLSKey(t *testing.T) tlsKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tlsKey{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pin: spkiHash(leaf)}
}

// fakeAttestor serves the relayed statement and a business endpoint over
// TLS with a key that can be switched.
type fakeAttestor struct {
	t      *testing.T
	server *httptest.Server
	signer []byte

	mu   sync.Mutex
	key  tlsKey
	pins []string // nil: the current key's pin
	// lifetimes are successive statements' lease lengths; the last repeats.
	lifetimes []int64
	// issuedOffset shifts issued_at from the real clock.
	issuedOffset int64
	status       int

	statements atomic.Int64
	business   atomic.Int64
}

func newFakeAttestor(t *testing.T) *fakeAttestor {
	t.Helper()
	f := &fakeAttestor{t: t, signer: providerKey(t), key: newTLSKey(t), lifetimes: []int64{120}, status: http.StatusOK}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	// Asked on every handshake (GetCertificate is not, without SNI).
	f.server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return &tls.Config{Certificates: []tls.Certificate{f.key.cert}}, nil
	}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAttestor) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/attestor-tls":
		n := f.statements.Add(1)
		want := strings.ToLower(vectorAnchor(f.t).Provider.Hex())
		if got := r.URL.Query().Get("provider"); got != want {
			f.t.Errorf("statement requested for provider %q, want %q", got, want)
		}
		f.mu.Lock()
		status, pins := f.status, f.pins
		if pins == nil {
			pins = []string{f.key.pin}
		}
		lifetime := f.lifetimes[min(int(n)-1, len(f.lifetimes)-1)]
		issued := time.Now().Unix() + f.issuedOffset
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		sorted := append([]string(nil), pins...)
		sort.Strings(sorted)
		anchor := vectorAnchor(f.t)
		s := sign(f.t, f.signer, Statement{Version: 3, ChainID: anchor.ChainID, RegistryAddress: strings.ToLower(anchor.Registry.Hex()),
			TLSPins: sorted, IssuedAt: uint64(issued), ExpiresAt: uint64(issued + lifetime)})
		_ = json.NewEncoder(w).Encode(s)
	case "/provision":
		f.business.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && string(body) != "proof" {
			f.t.Errorf("business request body %q", body)
		}
		_, _ = io.WriteString(w, "ok")
	default:
		http.NotFound(w, r)
	}
}

// rotate switches the attestor to a new TLS key, as when it moves to another
// node, so r's next request opens a new connection.
func (f *fakeAttestor) rotate(t *testing.T, r *resolver) {
	f.mu.Lock()
	f.key = newTLSKey(t)
	f.mu.Unlock()
	r.mu.Lock()
	r.transport.CloseIdleConnections()
	r.mu.Unlock()
}

// client returns a pinned client and its resolver, on a clock offset from
// the real one by *skew seconds.
func (f *fakeAttestor) client(t *testing.T, skew *atomic.Int64) (*http.Client, *resolver) {
	t.Helper()
	client, err := New(f.server.URL, vectorAnchor(t))
	if err != nil {
		t.Fatal(err)
	}
	r := client.Transport.(*resolver)
	if skew != nil {
		r.now = func() time.Time { return time.Now().Add(time.Duration(skew.Load()) * time.Second) }
	}
	return client, r
}

func post(client *http.Client, url string) error {
	response, err := client.Post(url+"/provision", "application/json", strings.NewReader("proof"))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err == nil && (response.StatusCode != http.StatusOK || string(body) != "ok") {
		err = errors.New("unexpected business answer")
	}
	return err
}

func TestPinsAttestorToProviderSignedStatement(t *testing.T) {
	f := newFakeAttestor(t)
	client, _ := f.client(t, nil)
	for range 3 {
		if err := post(client, f.server.URL); err != nil {
			t.Fatal(err)
		}
	}
	if f.statements.Load() != 1 || f.business.Load() != 3 {
		t.Fatalf("statements %d business %d; one statement serves its whole lease", f.statements.Load(), f.business.Load())
	}
}

func TestRejectsStatementWithoutTheConnectionKey(t *testing.T) {
	f := newFakeAttestor(t)
	// Validly signed, but naming a key this connection did not present.
	f.pins = []string{strings.Repeat("ab", 32)}
	client, _ := f.client(t, nil)
	if err := post(client, f.server.URL); err == nil || !strings.Contains(err.Error(), "does not list the key of the connection") {
		t.Fatalf("accepted a statement that does not pin its own connection: %v", err)
	}
	if f.business.Load() != 0 {
		t.Fatal("a business request was sent without an accepted statement")
	}
}

func TestRejectsStatementFromAnotherSigner(t *testing.T) {
	f := newFakeAttestor(t)
	f.signer = crypto.Keccak256([]byte("not the provider"))
	client, _ := f.client(t, nil)
	if err := post(client, f.server.URL); err == nil || !strings.Contains(err.Error(), "not signed by this container's provider") {
		t.Fatalf("accepted a statement from another signer: %v", err)
	}
	if f.business.Load() != 0 {
		t.Fatal("a business request was sent without an accepted statement")
	}
}

func TestStatementFetchFailuresSendNothing(t *testing.T) {
	for name, status := range map[string]int{"unavailable": http.StatusServiceUnavailable, "unknown provider": http.StatusNotFound, "redirect": http.StatusFound} {
		t.Run(name, func(t *testing.T) {
			f := newFakeAttestor(t)
			f.status = status
			client, _ := f.client(t, nil)
			if err := post(client, f.server.URL); err == nil {
				t.Fatal("request succeeded without a statement")
			}
			if f.business.Load() != 0 {
				t.Fatal("a business request was sent without a statement")
			}
		})
	}
}

func TestRefreshesStatementBeforeExpiry(t *testing.T) {
	f := newFakeAttestor(t)
	f.lifetimes = []int64{60, 120}
	var skew atomic.Int64
	client, r := f.client(t, &skew)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	firstExpiry := r.expiresAt
	// Five seconds or less left on the held statement: refresh first.
	skew.Store(56)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if f.statements.Load() != 2 || r.expiresAt <= firstExpiry {
		t.Fatalf("statements %d, expiry %d after %d", f.statements.Load(), r.expiresAt, firstExpiry)
	}
}

func TestRefusesStatementRollback(t *testing.T) {
	f := newFakeAttestor(t)
	f.lifetimes = []int64{60, 120}
	var skew atomic.Int64
	client, _ := f.client(t, &skew)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	// The refresh returns a valid statement issued before the held one.
	f.issuedOffset = -10
	skew.Store(56)
	if err := post(client, f.server.URL); err == nil || !strings.Contains(err.Error(), "older than the one already held") {
		t.Fatalf("accepted an older statement: %v", err)
	}
	if f.business.Load() != 1 {
		t.Fatal("a business request was sent under a rolled-back statement")
	}
}

func TestPinMismatchRefreshesAtMostEveryThirtySeconds(t *testing.T) {
	f := newFakeAttestor(t)
	var skew atomic.Int64
	client, r := f.client(t, &skew)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	// The attestor moves to a key the held statement lacks: one refresh,
	// then the request is replayed (body included) under the new pins.
	f.rotate(t, r)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if f.statements.Load() != 2 || f.business.Load() != 2 {
		t.Fatalf("statements %d business %d", f.statements.Load(), f.business.Load())
	}
	// Another move within 30 s fails without a refresh.
	f.rotate(t, r)
	if err := post(client, f.server.URL); !errors.Is(err, errPinMismatch) {
		t.Fatalf("second mismatch within 30 s: %v", err)
	}
	if f.statements.Load() != 2 || f.business.Load() != 2 {
		t.Fatalf("refreshed again within 30 s: statements %d business %d", f.statements.Load(), f.business.Load())
	}
	skew.Store(31)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if f.statements.Load() != 3 || f.business.Load() != 3 {
		t.Fatalf("statements %d business %d", f.statements.Load(), f.business.Load())
	}
}

// Two requests in flight on the old transport when the attestor moves: the
// first refreshes; the second, failing within the 30 s throttle, replays on
// the transport the first installed instead of failing.
func TestPinMismatchOnAReplacedTransportReplaysOnTheCurrentOne(t *testing.T) {
	f := newFakeAttestor(t)
	var skew atomic.Int64
	client, r := f.client(t, &skew)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	replaced := r.transport
	r.mu.Unlock()
	f.rotate(t, r)
	if err := post(client, f.server.URL); err != nil {
		t.Fatal(err)
	}
	transport, expiry, err := r.refreshAfterMismatch(context.Background(), replaced)
	if err != nil {
		t.Fatalf("mismatch on a replaced transport: %v", err)
	}
	if transport == replaced || f.statements.Load() != 2 {
		t.Fatalf("statements %d; want the installed transport without a fetch", f.statements.Load())
	}
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/provision", strings.NewReader("proof"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := roundTripBefore(transport, req, time.Unix(expiry, 0))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if f.business.Load() != 3 {
		t.Fatalf("business %d", f.business.Load())
	}
	// A mismatch on the current transport is still throttled.
	f.rotate(t, r)
	if err := post(client, f.server.URL); !errors.Is(err, errPinMismatch) {
		t.Fatalf("second mismatch within 30 s: %v", err)
	}
	if f.statements.Load() != 2 {
		t.Fatalf("refreshed again within 30 s: statements %d", f.statements.Load())
	}
}

func TestClientNeedsAnchorOrDevFlag(t *testing.T) {
	clients.Lock()
	saved, savedValues := clients.anchor, clients.values
	clients.anchor, clients.values = nil, make(map[string]*http.Client)
	clients.Unlock()
	t.Cleanup(func() {
		clients.Lock()
		clients.anchor, clients.values = saved, savedValues
		clients.Unlock()
	})
	t.Setenv(DevEnv, "")
	if _, err := Client("https://attestor.invalid"); err == nil {
		t.Fatal("unpinned client without the development flag")
	}
	Configure(vectorAnchor(t))
	client, err := Client("https://attestor.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Transport.(*resolver); !ok {
		t.Fatal("production client is not pinned")
	}
	if _, err := Client("http://attestor.invalid"); err == nil {
		t.Fatal("accepted a plain-HTTP attestor URL")
	}
	t.Setenv(DevEnv, "true")
	client, err = Client("http://attestor.invalid")
	if err != nil || client.Transport != nil {
		t.Fatalf("development flag did not give a plain client: %v", err)
	}
}

func TestExcerptBoundsAttestorBodies(t *testing.T) {
	if got := Excerpt([]byte("{\"error\":\"no authorized boot; reset required\"}\n")); got != `{"error":"no authorized boot; reset required"}` {
		t.Fatalf("short body changed: %q", got)
	}
	long := strings.Repeat("a", 255) + "界" + strings.Repeat("b", 100)
	got := Excerpt([]byte(long))
	if got != strings.Repeat("a", 255)+" ..." {
		t.Fatalf("cut not on a character boundary: %q", got)
	}
	if got := Excerpt([]byte("line one\r\nFAIL forged\tline")); strings.ContainsAny(got, "\r\n\t") {
		t.Fatalf("excerpt spans lines: %q", got)
	}
}
