// Package proxy hosts the agent's external HTTP surface on :8080.
//
// Endpoints (in priority order, all served by the single mux):
//
//   GET  /healthz       - container liveness probe (always 200)
//   GET  /log           - bootstrap diagnostic log (plaintext, NOT signed)
//   GET  /log.html      - same log, color-coded HTML view for frontends
//   GET  /log/openclaw  - openclaw process log (plaintext, NOT signed)
//   GET  /log/openclaw.html - same log, color-coded HTML view
//   GET  /hello         - signed A2A self-introduction (returns 503 until armed)
//   POST /_seal/auth    - owner-only flow returning the framework auth token
//   *    /              - signed reverse proxy to agent upstream (returns 503 until armed)
//
// All signed responses (everything except /healthz, /log, /log/openclaw)
// carry an X-Agent-Proof header packing both an EIP-191 signature and the
// canonical envelope JSON. Callers verify with ethers.verifyMessage(envelope, sig).
package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/state"
)

const authWindowSec = 300

// Server wraps the HTTP server with references to the shared agent state and
// the framework adapter (consulted only by /_seal/auth for the framework-
// specific response payload).
type Server struct {
	agent     *state.Agent
	adapter   framework.Framework
	publicURL string // sandbox's externally-reachable URL prefix; empty in dev
}

// New constructs a proxy.Server backed by a state.Agent and a framework
// adapter. publicURL is the composed external URL ("http://8080-<id>.<domain>")
// that /hello surfaces for verifier cross-check; empty when
// SANDBOX_PROXY_DOMAIN is unset.
func New(agent *state.Agent, adapter framework.Framework, publicURL string) *Server {
	return &Server{agent: agent, adapter: adapter, publicURL: publicURL}
}

// Listen starts an HTTP server on :8080 in a goroutine. Errors are logged
// but never crash the process — bootstrap doesn't want a stray ListenAndServe
// failure to mask the actual fatal error.
func (s *Server) Listen() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/log", s.handleLog)
	mux.HandleFunc("/log.html", s.handleLogHTML)
	mux.HandleFunc("/log/openclaw", s.handleOpenclawLog)
	mux.HandleFunc("/log/openclaw.html", s.handleOpenclawLogHTML)
	mux.HandleFunc("/hello", s.handleHello)
	mux.HandleFunc("/_seal/auth", s.handleAuth)
	mux.HandleFunc("/", s.handleProxy)

	go func() {
		fmt.Println("Listening on :8080  GET /healthz | /log | /log/openclaw | /hello (signed) | /_seal/auth (owner-only) | /* (agent proxy)")
		_ = http.ListenAndServe(":8080", corsMiddleware(mux))
	}()
}

// ── Middleware ──────────────────────────────────────────────────────────────

// corsMiddleware adds the one CORS header the upstream proxy can't set: an
// explicit Access-Control-Expose-Headers entry for X-Agent-Proof so browsers
// surface it to JS. Specifically does NOT set Allow-Origin; the outer Daytona
// proxy already echoes Origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Expose-Headers", "X-Agent-Proof")
		next.ServeHTTP(w, r)
	})
}

// ── Bootstrap-owned endpoints ───────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, "ok")
}

func (s *Server) handleLog(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, logger.Snapshot())
}

func (s *Server) handleOpenclawLog(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	body, err := os.ReadFile("/tmp/openclaw.log")
	if err != nil {
		fmt.Fprintf(w, "openclaw log not available: %v\n", err)
		return
	}
	w.Write(body) //nolint:errcheck
}

// ── /hello ──────────────────────────────────────────────────────────────────

// handleHello returns the agent's signed A2A self-introduction.
//
//	{
//	  "agent":   "<agent ECDSA address>",
//	  "owner":   "<NFT owner address>",
//	  "message": "I am the agent of ...",
//	  "ts":      <unix>
//	}
//
// The X-Agent-Proof header signs (method, uri, req_body_hash, status,
// resp_body_hash, data_hashes, ts) so verifiers can confirm the response
// originated from this attested instance.
func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	priv, _, _, owner, dataHashes := s.agent.Snapshot()
	if priv == nil {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}

	agentAddr := ""
	if pk, err := crypto.ToECDSA(priv); err == nil {
		agentAddr = crypto.PubkeyToAddress(pk.PublicKey).Hex()
	}

	resp := map[string]any{
		"agent":      agentAddr,
		"owner":      owner,
		"public_url": s.publicURL, // empty when SANDBOX_PROXY_DOMAIN is unset
		"message":    fmt.Sprintf("I am the agent of %s, identified as %s. Services coming soon.", owner, agentAddr),
		"ts":         time.Now().Unix(),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := writeServeProof(w, r, priv, nil, body, dataHashes, http.StatusOK); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ── /_seal/auth ─────────────────────────────────────────────────────────────

// handleAuth hands the framework-specific control-UI credential (e.g. the
// openclaw gateway token) to a verified owner. Validates an EIP-191 signature
// over "0GSealAuth:0x<sealID>:<unix-ts>" and confirms the recovered signer
// equals the on-chain NFT owner cached at bootstrap.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	priv, _, sealID, owner, dataHashes := s.agent.Snapshot()
	if priv == nil || owner == "" {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}

	msg := r.Header.Get("X-Auth-Message")
	sigHex := r.Header.Get("X-Auth-Signature")
	if msg == "" || sigHex == "" {
		http.Error(w, "missing X-Auth-Message or X-Auth-Signature", http.StatusBadRequest)
		return
	}

	parts := strings.Split(msg, ":")
	if len(parts) != 3 || parts[0] != "0GSealAuth" {
		http.Error(w, "X-Auth-Message must be \"0GSealAuth:0x<sealID>:<ts>\"", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(parts[1], "0x"+sealID) {
		http.Error(w, "seal_id mismatch", http.StatusUnauthorized)
		return
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		http.Error(w, "bad timestamp in X-Auth-Message", http.StatusBadRequest)
		return
	}
	now := time.Now().Unix()
	if ts > now+authWindowSec || ts < now-authWindowSec {
		http.Error(w, "stale or future X-Auth-Message timestamp", http.StatusUnauthorized)
		return
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sigBytes) != 65 {
		http.Error(w, "X-Auth-Signature must be 65-byte hex", http.StatusBadRequest)
		return
	}
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	hash := crypto.Keccak256([]byte(prefix), []byte(msg))
	pub, err := crypto.SigToPub(hash, sigBytes)
	if err != nil {
		http.Error(w, "signature recover: "+err.Error(), http.StatusBadRequest)
		return
	}
	recovered := crypto.PubkeyToAddress(*pub).Hex()
	if !strings.EqualFold(recovered, owner) {
		http.Error(w, "signer is not the agent owner", http.StatusUnauthorized)
		return
	}

	if s.adapter == nil {
		http.Error(w, "framework adapter not wired", http.StatusServiceUnavailable)
		return
	}
	payload, err := s.adapter.AuthResponse(r.Context())
	if err != nil {
		http.Error(w, "auth response: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	envelope := map[string]any{}
	if m, ok := payload.(map[string]any); ok {
		for k, v := range m {
			envelope[k] = v
		}
	} else {
		envelope["payload"] = payload
	}
	envelope["ts"] = now

	body, err := json.Marshal(envelope)
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := writeServeProof(w, r, priv, nil, body, dataHashes, http.StatusOK); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ── Catch-all reverse proxy ─────────────────────────────────────────────────

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	priv, upstream, _, _, dataHashes := s.agent.Snapshot()
	if priv == nil || upstream == "" {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}

	// WS upgrades cannot be buffered + signed; hand off to httputil.
	if isWebSocketUpgrade(r) {
		wsReverseProxy(upstream).ServeHTTP(w, r)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.Body.Close()

	upstreamURL := upstream + r.URL.RequestURI()
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	upHost := ""
	if u, perr := url.Parse(upstream); perr == nil {
		upHost = u.Host
	}
	for k, vs := range r.Header {
		switch k {
		case "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate":
			continue
		case "Origin", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-Ip":
			continue
		}
		for _, v := range vs {
			upReq.Header.Add(k, v)
		}
	}
	if upHost != "" {
		upReq.Header.Set("Origin", "http://"+upHost)
	}

	resp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream body: "+err.Error(), http.StatusBadGateway)
		return
	}

	for k, vs := range resp.Header {
		// Skip Access-Control-* (corsMiddleware already set ours; duplicates
		// cause browsers to reject the response).
		if strings.HasPrefix(k, "Access-Control-") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if err := writeServeProof(w, r, priv, reqBody, respBody, dataHashes, resp.StatusCode); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ── WebSocket helpers ───────────────────────────────────────────────────────

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

func wsReverseProxy(upstream string) *httputil.ReverseProxy {
	target, err := url.Parse(upstream)
	if err != nil {
		return &httputil.ReverseProxy{
			Director: func(req *http.Request) {},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "bad upstream URL: "+err.Error(), http.StatusInternalServerError)
			},
		}
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header.Set("Origin", "http://"+target.Host)
			pr.Out.Header["X-Forwarded-For"] = nil
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Real-Ip")
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Access-Control-Allow-Origin")
			resp.Header.Del("Access-Control-Allow-Methods")
			resp.Header.Del("Access-Control-Allow-Headers")
			resp.Header.Del("Access-Control-Expose-Headers")
			return nil
		},
	}
}

// ── Serve-proof signing ─────────────────────────────────────────────────────

// serveProof is the canonical envelope signed by agent_seal_priv and packed
// into X-Agent-Proof. DataHashes keys every dim the agent currently tracks
// ("framework", "persona", "knowledge", "skills", "ops") -- including ones
// that have no chain pin yet -- so a verifier can do two independent
// checks per dim:
//
//	content_hash : sha256 of the local plaintext (always present). Commits
//	               the in-memory state including adapter defaults; lets a
//	               verifier with the same plaintext recompute and match.
//	data_hash    : 0g-storage root on chain. omitempty -- absent when the
//	               dim hasn't been uploaded yet, otherwise verifiers
//	               compare directly against AgenticID.intelligentDatasOf().
type serveProof struct {
	Method       string                     `json:"method"`
	URI          string                     `json:"uri"`
	ReqBodyHash  string                     `json:"req_body_hash"`
	Status       int                        `json:"status"`
	RespBodyHash string                     `json:"resp_body_hash"`
	DataHashes   map[string]state.DimHashes `json:"data_hashes"`
	Ts           int64                      `json:"ts"`
}

// writeServeProof signs the canonical envelope with agent_seal_priv and emits
// a single header packing the signature and base64-url envelope JSON, JWT-style:
//
//	X-Agent-Proof: 0x<65-byte sig hex>.<base64-url-encoded envelope JSON>
//
// Body is left untouched so verifiers recompute keccak256(body) and compare
// against proof.resp_body_hash.
func writeServeProof(w http.ResponseWriter, r *http.Request, priv, reqBody, body []byte, dataHashes map[string]state.DimHashes, statusCode int) error {
	proof := serveProof{
		Method:       r.Method,
		URI:          r.URL.RequestURI(),
		ReqBodyHash:  "0x" + hex.EncodeToString(crypto.Keccak256(reqBody)),
		Status:       statusCode,
		RespBodyHash: "0x" + hex.EncodeToString(crypto.Keccak256(body)),
		DataHashes:   dataHashes,
		Ts:           time.Now().Unix(),
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return fmt.Errorf("marshal serve-proof: %w", err)
	}

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(proofJSON))
	hash := crypto.Keccak256([]byte(prefix), proofJSON)

	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return fmt.Errorf("agent priv: %w", err)
	}
	sig, err := crypto.Sign(hash, privKey)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27

	w.Header().Set("X-Agent-Proof",
		"0x"+hex.EncodeToString(sig)+"."+base64.RawURLEncoding.EncodeToString(proofJSON))
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))

	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
	return nil
}
