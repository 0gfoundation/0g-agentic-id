package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"seal-verify/internal/framework"
	"seal-verify/internal/servicehost"
)

func TestExecutionReceiptHasIndependentUnforgeableDomain(t *testing.T) {
	s, signer := armedProxy(t, "http://localhost", testValidator)
	code := 0
	status := servicehost.ExecutionStatus{Handle: strings.Repeat("a", 64), Service: "report", Version: strings.Repeat("b", 64), State: "exited", ExitCode: &code, UID: 210000, StartedAt: 1, FinishedAt: 2, OutputHash: strings.Repeat("c", 64), OutputBytes: 42, OutputAvailable: true}
	profile := servicehost.IsolationProfile{Driver: "bubblewrap-v1", PrivatePID: true, PrivateMounts: true, PrivateNetwork: true, ReadOnlyCode: true, TemporaryWork: true, Network: "none"}
	token, err := s.signExecutionReceipt(status, profile)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	sig, err := hex.DecodeString(strings.TrimPrefix(parts[0], "0x"))
	if err != nil {
		t.Fatal(err)
	}
	sig[64] -= 27
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var receipt executionReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Execution.OutputAvailable || receipt.Execution.Receipt != "" {
		t.Fatal("transient or recursive receipt fields were signed")
	}
	digest := executionReceiptDigest(common.HexToAddress(testValidator), raw)
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != signer {
		t.Fatal("receipt signer mismatch")
	}
	inner := crypto.Keccak256([]byte(executionReceiptTag), raw)
	if bytes.Equal(digest, accounts.TextHash(inner)) || bytes.Equal(digest, serveProofDigest(common.HexToAddress(testValidator), crypto.Keccak256(raw))) {
		t.Fatal("receipt signing domain overlaps owner signing or ServeProof")
	}
	for _, bad := range [][]byte{executionReceiptDigest(common.HexToAddress("0x00000000000000000000000000000000000000B8"), raw), executionReceiptDigest(common.HexToAddress(testValidator), append(bytes.Clone(raw), ' '))} {
		pub, err := crypto.SigToPub(bad, sig)
		if err == nil && crypto.PubkeyToAddress(*pub) == signer {
			t.Fatal("tampered receipt accepted")
		}
	}
	s, _ = armedProxy(t, "http://localhost", "")
	if _, err := s.signExecutionReceipt(status, profile); err == nil {
		t.Fatal("missing trust domain still signed")
	}
}

func TestHarnessServiceIngressFailsClosed(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer backend.Close()
	s, _ := armedProxy(t, backend.URL, testValidator)
	s.strictServices = true // Selected harness, even when manager initialization failed.
	s.fwRoutes = append(s.fwRoutes, framework.Route{Prefix: "/api/", Kind: "service"})
	out := httptest.NewRecorder()
	s.handleProxy(out, httptest.NewRequest("POST", "/api/x", nil))
	if out.Code != 503 || called {
		t.Fatal("missing manager reopened unmanaged backend")
	}
	if len(s.getServices()) != 0 {
		t.Fatal("discovery advertised unmanaged services")
	}
	out = httptest.NewRecorder()
	s.handleServices(out, httptest.NewRequest("POST", "/services", strings.NewReader(`[]`)))
	if out.Code != 403 {
		t.Fatalf("legacy publication accepted: %d", out.Code)
	}
}

func TestExecutionReceiptWaitsForKnownLayerHashes(t *testing.T) {
	s, _ := armedProxy(t, "http://localhost", testValidator)
	code := 0
	status := servicehost.ExecutionStatus{Service: "report", State: "exited", ExitCode: &code}
	ready := false
	layers := ProofLayers{SealedHash: "0x" + strings.Repeat("a", 64), HarnessHash: "0x" + strings.Repeat("b", 64)}
	s.SetProofLayers(func() (ProofLayers, bool) { return layers, ready })
	if token, err := s.signExecutionReceipt(status, servicehost.IsolationProfile{}); err == nil || token != "" {
		t.Fatal("execution receipt omitted unavailable layer identity")
	}
	ready = true
	token, err := s.signExecutionReceipt(status, servicehost.IsolationProfile{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var receipt executionReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SealedHash != layers.SealedHash || receipt.HarnessHash != layers.HarnessHash {
		t.Fatal("execution receipt lost the ready layer identity")
	}
}
