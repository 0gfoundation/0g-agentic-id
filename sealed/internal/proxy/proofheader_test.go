package proxy

import (
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

// upstreamProof is what a backend tries to pass off as the runtime's header.
const upstreamProof = "0xupstream.e30"

// proofBackend is a loopback backend that answers every request with the
// katTask* response and an X-Agent-Proof of its own — once under the
// canonical key and once under a lowercase one written straight into the
// header map, so both spellings reach the proxy.
func proofBackend(t *testing.T, contentType string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Agent-Proof", upstreamProof)
		w.Header()["x-agent-proof"] = []string{upstreamProof}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(katTaskStatus)
		_, _ = io.WriteString(w, katTaskResp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// armedProxy returns a Server armed as agent 30 whose framework upstream and
// /api/x service both point at backend, plus the agentSeal address.
func armedProxy(t *testing.T, backend, validator string) (*Server, common.Address) {
	t.Helper()
	priv, _ := crypto.GenerateKey()
	ag := state.New()
	ag.Set(crypto.FromECDSA(priv), backend, "deadbeef", "0x00000000000000000000000000000000000000E1",
		"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", validator)
	s := New(ag, "")
	s.services = []ServiceEntry{{Path: "/api/x", Method: http.MethodPost, Backend: backend}}
	s.fwRoutes = []framework.Route{{Prefix: "/v1/", Kind: "chat", Auth: "bearer"}}
	return s, crypto.PubkeyToAddress(priv.PublicKey)
}

func proofHeaders(rec *httptest.ResponseRecorder) []string {
	var out []string
	for k, vs := range rec.Header() {
		if strings.EqualFold(k, "X-Agent-Proof") {
			out = append(out, vs...)
		}
	}
	return out
}

// With no usable validator the registered service is served unsigned — and
// the backend's own X-Agent-Proof must not ride through in its place.
func TestHandleProxy_ServiceNoValidatorDropsUpstreamProof(t *testing.T) {
	backend := proofBackend(t, "application/json")
	s, _ := armedProxy(t, backend.URL, "")

	rec := httptest.NewRecorder()
	s.handleProxy(rec, httptest.NewRequest(katTaskMethod, katTaskURI, strings.NewReader(katTaskReq)))

	if rec.Code != katTaskStatus || rec.Body.String() != katTaskResp {
		t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), katTaskStatus, katTaskResp)
	}
	if h := proofHeaders(rec); len(h) != 0 {
		t.Fatalf("unsigned service response carries X-Agent-Proof %q", h)
	}
}

// A framework route is never signed; an upstream X-Agent-Proof is dropped on
// both the buffered and the streamed (SSE) relay.
func TestHandleProxy_FrameworkRouteDropsUpstreamProof(t *testing.T) {
	for _, ct := range []string{"application/json", "text/event-stream"} {
		backend := proofBackend(t, ct)
		s, _ := armedProxy(t, backend.URL, testValidator)

		rec := httptest.NewRecorder()
		s.handleProxy(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

		if rec.Code != katTaskStatus || rec.Body.String() != katTaskResp {
			t.Fatalf("%s: got %d %q, want %d %q", ct, rec.Code, rec.Body.String(), katTaskStatus, katTaskResp)
		}
		if h := proofHeaders(rec); len(h) != 0 {
			t.Fatalf("%s: framework route response carries X-Agent-Proof %q", ct, h)
		}
	}
}

// With a validator the registered service is signed, and the response carries
// exactly one X-Agent-Proof: the runtime's, recovering to the agentSeal over
// the katTask* transcript.
func TestHandleProxy_ServiceSignedCarriesOnlyGenuineProof(t *testing.T) {
	backend := proofBackend(t, "application/json")
	s, seal := armedProxy(t, backend.URL, testValidator)

	rec := httptest.NewRecorder()
	s.handleProxy(rec, httptest.NewRequest(katTaskMethod, katTaskURI, strings.NewReader(katTaskReq)))

	if rec.Code != katTaskStatus || rec.Body.String() != katTaskResp {
		t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), katTaskStatus, katTaskResp)
	}
	h := proofHeaders(rec)
	if len(h) != 1 || h[0] == upstreamProof {
		t.Fatalf("want exactly the runtime's proof, got %q", h)
	}
	sig, env := decodeProofHeader(t, h[0])
	if env.TaskHash != "0x"+katTaskHash {
		t.Fatalf("task_hash = %s, want 0x%s", env.TaskHash, katTaskHash)
	}
	taskHash, _ := hexToBytes32(env.TaskHash)
	fwBytes, _ := hexToBytes32(env.FrameworkHash)
	proofHash := serveProofHash(big.NewInt(16602), addrWord("0x00000000000000000000000000000000000000A9"),
		addrWord(env.Submitter), big.NewInt(30), env.Timestamp, env.Deadline, taskHash, nil, fwBytes)
	if got := recoverSigner(t, serveProofDigest(common.HexToAddress(testValidator), proofHash), sig); got != seal {
		t.Fatalf("proof recovers to %s, want agentSeal %s", got.Hex(), seal.Hex())
	}
}

// The WebSocket relay strips the header from the upgrade response too.
func TestWSReverseProxy_DropsUpstreamProof(t *testing.T) {
	resp := &http.Response{Header: http.Header{"X-Agent-Proof": {upstreamProof}}}
	if err := wsReverseProxy("http://127.0.0.1:1").ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	if v := resp.Header.Get("X-Agent-Proof"); v != "" {
		t.Fatalf("upgrade response keeps X-Agent-Proof %q", v)
	}
}

// writeServeProof's no-proof path clears an X-Agent-Proof already on w.
func TestWriteServeProof_NoProofClearsStaleHeader(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Agent-Proof", upstreamProof)
	if err := writeServeProof(rec, httptest.NewRequest(http.MethodGet, "/hello", nil), crypto.FromECDSA(priv),
		nil, []byte("x"), nil, 200, "30", "0x"+strings.Repeat("11", 32), "16602",
		"0x00000000000000000000000000000000000000A9", ""); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}
	if h := proofHeaders(rec); len(h) != 0 {
		t.Fatalf("no-proof path left X-Agent-Proof %q", h)
	}
}
