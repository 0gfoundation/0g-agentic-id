package attestorhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const testRegistry = "0x1111111111111111111111111111111111111111"

func appServer(t *testing.T, calls *atomic.Int64) (*httptest.Server, identity, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	hash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(hash[:])
	id := identity{Role: "tls", Algorithm: "ecdsa-p256", Source: "local", Derivation: "tapp-tls-v1-sha256", Encoding: "sec1-compressed",
		PublicKey: "0x" + hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y))}
	return server, id, pin
}

type fixture struct {
	descriptor   Descriptor
	tlsIdentity  identity
	nodeIdentity identity
	appIdentity  identity
	node         string
	mode         atomic.Value
	appCalls     atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	app, tlsIdentity, pin := appServer(t, &f.appCalls)
	f.tlsIdentity = tlsIdentity
	nodeKey, _ := crypto.ToECDSA(append(make([]byte, 31), 1))
	appKey, _ := crypto.ToECDSA(append(make([]byte, 31), 2))
	f.node = crypto.PubkeyToAddress(nodeKey.PublicKey).Hex()
	f.nodeIdentity = identity{Role: "node_signer", Algorithm: "ecdsa-secp256k1", Source: "local", Derivation: "tapp-app-signer-v1", Encoding: "sec1-compressed", PublicKey: "0x" + hex.EncodeToString(crypto.CompressPubkey(&nodeKey.PublicKey))}
	f.appIdentity = identity{Role: "app_signer", Algorithm: "ecdsa-secp256k1", Source: "kms", Derivation: "raw-scalar-v1", Encoding: "sec1-compressed", PublicKey: "0x" + hex.EncodeToString(crypto.CompressPubkey(&appKey.PublicKey)),
		KeyRef: &commitment{Scheme: "poseidon-bn254-4-v1", Material: "70726f7669646572", Commitment: "0x" + strings.Repeat("01", 32)}}
	f.mode.Store("")
	scan := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Unix()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.EscapedPath() {
		case "/net/api/health":
			json.NewEncoder(w).Encode(map[string]any{"chain_id": 16602, "contract": testRegistry, "refreshed_at": now, "scanned_to_block": 10})
		case "/net/api/apps/a%2Fb":
			json.NewEncoder(w).Encode(map[string]any{"app_id": "a/b", "current_signers": []string{f.node}})
		case "/net/api/verify":
			if r.Method != http.MethodPost {
				t.Error("verify did not POST")
			}
			v := f.verdict()
			switch f.mode.Load().(string) {
			case "epoch":
				v.Scope.Epoch++
			case "scope":
				v.Scope.ChainID++
			case "signer":
				v.Status.Attested.AppSigner = f.node
			case "expired":
				v.ExpiresAt = now - 1
			case "unverified":
				v.IdentitiesVerified = false
			case "pubkey":
				v.Status.Attested.Identities[1].PublicKey = f.nodeIdentity.PublicKey
			case "tls":
				v.Status.Attested.Identities[2].PublicKey = "0x036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
			case "redirect":
				w.Header().Set("Location", f.descriptor.URL+"/provision")
				w.WriteHeader(307)
				return
			}
			json.NewEncoder(w).Encode(v)
		default:
			t.Errorf("unexpected Scan path %s", r.URL.EscapedPath())
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(scan.Close)
	scanHash := sha256.Sum256(scan.Certificate().RawSubjectPublicKeyInfo)
	// Creation took longer than the initial lease: bootstrap must use pinned Scan,
	// never send business data through the expired descriptor's app pin.
	f.descriptor = Descriptor{Version: 1, ChainID: 16602, RegistryAddress: testRegistry, AppID: "a/b", RegisteredAt: 100,
		AppSigner: crypto.PubkeyToAddress(appKey.PublicKey).Hex(), URL: app.URL, ScanURL: scan.URL + "/net/",
		ScanPublicKey: hex.EncodeToString(scanHash[:]), TLSPins: []string{pin}, CheckedAt: time.Now().Unix() - 180, ExpiresAt: time.Now().Unix() - 120}
	return f
}

func (f *fixture) verdict() verdict {
	v := verdict{AppID: f.descriptor.AppID, Signer: f.node, Verified: true, IdentitiesVerified: true, CheckedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 60, ImageEnv: "prod"}
	v.Scope.ChainID = f.descriptor.ChainID
	v.Scope.Registry = f.descriptor.RegistryAddress
	v.Scope.AppID = v.AppID
	v.Scope.Epoch = f.descriptor.RegisteredAt
	v.Status.AppID = v.AppID
	v.Status.Signer = f.node
	v.Status.CheckedAt = v.CheckedAt
	v.Status.Epoch = v.Scope.Epoch
	v.Status.Error = json.RawMessage("null")
	a := &v.Status.Attested
	a.Signer = f.node
	a.SignerOK = true
	a.Fresh = true
	a.Replay = true
	debug := false
	a.Debug = &debug
	a.TCB = "UpToDate"
	a.TLS = "0x" + f.descriptor.TLSPins[0]
	a.AppSigner = f.descriptor.AppSigner
	a.Identities = []identity{f.nodeIdentity, f.appIdentity, f.tlsIdentity}
	a.Commitments = []commitment{*f.appIdentity.KeyRef}
	return v
}

func (f *fixture) client(t *testing.T) *http.Client {
	t.Helper()
	raw, _ := json.Marshal(f.descriptor)
	client, err := New(f.descriptor.URL, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPinnedScanRefreshAndBusinessTLS(t *testing.T) {
	f := newFixture(t)
	client := f.client(t)
	response, err := client.Get(f.descriptor.URL + "/provision")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || f.appCalls.Load() != 1 {
		t.Fatal("authenticated business request failed")
	}
	// A cached keep-alive connection cannot keep authority after lease expiry.
	r := client.Transport.(*resolver)
	r.mu.Lock()
	r.expiresAt = time.Now().Unix() - 1
	r.mu.Unlock()
	f.mode.Store("epoch")
	if response, err := client.Get(f.descriptor.URL + "/status"); err == nil {
		response.Body.Close()
		t.Fatal("reclaimed app inherited authority")
	}
	if f.appCalls.Load() != 1 {
		t.Fatal("expired authorization sent business data")
	}
}

func TestRejectsWrongScopeBindingsPinsAndRedirects(t *testing.T) {
	for _, mode := range []string{"epoch", "scope", "signer", "expired", "unverified", "pubkey", "tls", "redirect", "scan-pin", "business-pin"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.mode.Store(mode)
			if mode == "scan-pin" {
				f.descriptor.ScanPublicKey = strings.Repeat("01", 32)
			}
			if mode == "business-pin" {
				var unused atomic.Int64
				_, id, pin := appServer(t, &unused)
				f.tlsIdentity = id
				f.descriptor.TLSPins = []string{pin}
			}
			if response, err := f.client(t).Get(f.descriptor.URL + "/provision"); err == nil {
				response.Body.Close()
				t.Fatal("invalid discovery accepted")
			}
			if f.appCalls.Load() != 0 {
				t.Fatal("unauthenticated business request escaped")
			}
		})
	}
}

func TestProductionRequiresDescriptorAndHTTPS(t *testing.T) {
	if _, err := New("http://localhost:8080", ""); err == nil {
		t.Fatal("missing descriptor accepted")
	}
	f := newFixture(t)
	f.descriptor.URL = "http://localhost:8080"
	raw, _ := json.Marshal(f.descriptor)
	if _, err := New(f.descriptor.URL, string(raw)); err == nil {
		t.Fatal("plaintext business URL accepted")
	}
	t.Setenv(DescriptorEnv, "")
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "")
	if _, err := Client("http://localhost:8080"); err == nil {
		t.Fatal("implicit dev fallback")
	}
}

func TestSameCommitmentDoesNotAuthorizeDifferentKMSPublicKeys(t *testing.T) {
	f := newFixture(t)
	first := f.tlsIdentity
	first.Source, first.Derivation = "kms", "raw-scalar-v1"
	ref := *f.appIdentity.KeyRef
	ref.Material = "746c73"
	first.KeyRef = &ref
	seen := make(map[string]identity)
	if err := consistentKMSIdentities(seen, []identity{first}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.PublicKey = "0x036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	if err := consistentKMSIdentities(seen, []identity{second}); err == nil {
		t.Fatal("equal commitments were treated as proof of two different TLS keys")
	}
	second.Source, second.KeyRef = "local", nil
	if err := consistentKMSIdentities(seen, []identity{second}); err != nil {
		t.Fatal("per-node local TLS keys must remain independent")
	}
}

func TestScanPrefixesAndAppIDsPreserveEscaping(t *testing.T) {
	for base, expected := range map[string]string{
		"https://scan.example/pre%20fix/": "https://scan.example/pre%20fix/api/apps/a%2Fb%3Fx",
		"https://scan.example/net/api/":   "https://scan.example/net/api/apps/a%2Fb%3Fx",
	} {
		u, err := httpsURL(base)
		if err != nil {
			t.Fatal(err)
		}
		r := resolver{scan: u}
		if got := r.endpoint("apps", "a/b?x"); got != expected {
			t.Fatalf("URL = %s, want %s", got, expected)
		}
	}
}
