package proxy

import (
	"compress/gzip"
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
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{"X-Agent-Proof": {upstreamProof}, "x-agent-proof": {upstreamProof}}}
	if err := wsReverseProxy("http://127.0.0.1:1").ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	if h := proofHeaders(&httptest.ResponseRecorder{HeaderMap: resp.Header}); len(h) != 0 {
		t.Fatalf("upgrade response keeps X-Agent-Proof %q", h)
	}
}

// A WebSocket upgrade the upstream refuses (non-101, chunked body) is relayed
// as a normal response, trailers included. An upstream X-Agent-Proof trailer —
// announced or not — must not reach the client; other trailers still do.
func TestWSReverseProxy_DropsUpstreamProofTrailer(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Agent-Proof, X-Other")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "no upgrade")
		w.(http.Flusher).Flush() // force chunked encoding
		w.Header().Set("X-Agent-Proof", upstreamProof)
		w.Header().Set("X-Other", "kept")
		w.Header().Set(http.TrailerPrefix+"x-agent-proof", upstreamProof) // unannounced
	}))
	t.Cleanup(backend.Close)
	s, _ := armedProxy(t, backend.URL, testValidator)
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	t.Cleanup(front.Close)

	for path, method := range map[string]string{"/api/x": http.MethodPost, "/v1/ws": http.MethodGet} {
		req, _ := http.NewRequest(method, front.URL+path, nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || string(body) != "no upgrade" {
			t.Fatalf("%s: got %d %q", path, resp.StatusCode, body)
		}
		for _, h := range []http.Header{resp.Header, resp.Trailer} {
			for k, vs := range h {
				if isAgentProofHeader(k) || strings.Contains(strings.ToLower(strings.Join(vs, ",")), "x-agent-proof") {
					t.Fatalf("%s: relayed %s: %q", path, k, vs)
				}
			}
		}
		if got := resp.Trailer.Get("X-Other"); got != "kept" {
			t.Fatalf("%s: X-Other trailer = %q, want kept (trailers must still relay)", path, got)
		}
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

// A backend that compresses must not break per-exchange verification: the
// proxy drops the client's Accept-Encoding (Go's Transport then negotiates
// and decompresses on its own), so the bytes the serve-proof's taskHash
// covers equal the bytes delivered to the client. Forwarding the client's
// header instead (the old behavior) pins Accept-Encoding explicitly — the
// Transport skips its decompression, the hash covers the gzip bytes, and
// every exchange with a compressing backend fails verifyProof's taskMatches.
func TestProxy_CompressingBackendDeliversPlainBytes(t *testing.T) {
	plain := []byte("the plain body the taskHash must cover")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("X-Backend-Saw", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write(plain)
			_ = gz.Close()
			return
		}
		w.Header().Set("X-Backend-Saw", "identity")
		_, _ = w.Write(plain)
	}))
	t.Cleanup(backend.Close)
	s, _ := armedProxy(t, backend.URL, testValidator)
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	t.Cleanup(front.Close)

	// undici/browsers send this; an explicitly-set Accept-Encoding makes Go's
	// client skip its own decompression, so gzip bytes would surface as-is.
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/x", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding %q relayed to the client — the taskHash would cover compressed bytes", resp.Header.Get("Content-Encoding"))
	}
	if string(body) != string(plain) {
		t.Fatalf("client got %q (%d bytes), want the plain body — a compressing backend breaks per-exchange verification otherwise", body[:min(20, len(body))], len(body))
	}
}
