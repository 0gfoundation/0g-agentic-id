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
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/report"
	"seal-verify/internal/state"
)

const authWindowSec = 300

// Server wraps the HTTP server with references to the shared agent state and
// the (late-bound) framework adapter.
type Server struct {
	agent     *state.Agent
	publicURL string // sandbox's externally-reachable URL prefix; empty in dev

	// The adapter is late-bound: sealed selects it from the on-chain
	// framework binding (end of Phase 2), which happens AFTER this server
	// must already be listening (/healthz + /log stay reachable while the
	// chain scan is in flight). Until SetAdapter runs, adapter-backed
	// endpoints degrade: /_seal/auth 503s, /hello omits services,
	// /log/agent reports unavailable.
	mu           sync.RWMutex
	adapter      framework.Framework
	servicesPath string         // agent-declared services manifest; empty disables /hello services field
	agentLogPath string         // adapter's subprocess log file; empty renders "not available"
	services     []ServiceEntry // agent-registered external services (see services.go); nil until first POST /services
}

// New constructs a proxy.Server backed by a state.Agent. publicURL is the
// composed external URL ("http://8080-<id>.<domain>") that /hello surfaces
// for verifier cross-check; empty when SANDBOX_PROXY_DOMAIN is unset.
//
// The framework adapter is attached later via SetAdapter, once the chain
// bootstrap has resolved which framework this agent is.
func New(agent *state.Agent, publicURL string) *Server {
	return &Server{agent: agent, publicURL: publicURL}
}

// SetAdapter late-binds the resolved framework adapter and derives the
// per-adapter optional paths from its capability interfaces:
//
//   - framework.ServicesManifestProvider → the services manifest /hello
//     embeds (e.g. ~/.openclaw/services.json)
//   - framework.SubprocessLogProvider → the log file /log/agent serves
//
// Called once by main after the on-chain framework binding names the
// adapter. Handlers read the trio under the lock.
func (s *Server) SetAdapter(fw framework.Framework) {
	servicesPath := ""
	if p, ok := fw.(framework.ServicesManifestProvider); ok {
		servicesPath = p.ServicesFilePath()
	}
	agentLogPath := ""
	if p, ok := fw.(framework.SubprocessLogProvider); ok {
		agentLogPath = p.SubprocessLogPath()
	}
	s.mu.Lock()
	s.adapter = fw
	s.servicesPath = servicesPath
	s.agentLogPath = agentLogPath
	s.mu.Unlock()
}

func (s *Server) getAdapter() framework.Framework {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adapter
}

func (s *Server) getServicesPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.servicesPath
}

func (s *Server) getAgentLogPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agentLogPath
}

// Listen starts an HTTP server on :8080 in a goroutine. Errors are logged
// but never crash the process — bootstrap doesn't want a stray ListenAndServe
// failure to mask the actual fatal error.
func (s *Server) Listen() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/log", s.handleLog)
	mux.HandleFunc("/log.html", s.handleLogHTML)
	mux.HandleFunc("/log/agent", s.handleAgentLog)
	mux.HandleFunc("/log/agent.html", s.handleAgentLogHTML)
	// Legacy aliases from when openclaw was the only framework; existing
	// frontends link these. Same handlers, adapter-resolved log path.
	mux.HandleFunc("/log/openclaw", s.handleAgentLog)
	mux.HandleFunc("/log/openclaw.html", s.handleAgentLogHTML)
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

func (s *Server) handleAgentLog(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	logPath := s.getAgentLogPath()
	if logPath == "" {
		fmt.Fprint(w, "agent log not available: framework adapter not resolved yet or no subprocess log path\n")
		return
	}
	body, err := os.ReadFile(logPath)
	if err != nil {
		fmt.Fprintf(w, "agent log not available: %v\n", err)
		return
	}
	w.Write(body) //nolint:errcheck
}

// ── /hello ──────────────────────────────────────────────────────────────────

// handleHello returns the agent's signed A2A self-introduction.
//
//	{
//	  "agent":      "<agent ECDSA address>",
//	  "owner":      "<NFT owner address>",
//	  "public_url": "<external URL prefix>",
//	  "message":    "I am the agent of ...",
//	  "services":   [{ path, method, description, ... }, ...],
//	  "ts":         <unix>
//	}
//
// The X-Agent-Proof header signs (method, uri, req_body_hash, status,
// resp_body_hash, data_hashes, ts) so verifiers can confirm the response
// originated from this attested instance.
//
// `services` is loaded from the adapter-designated manifest file
// (s.servicesPath) on each call — fresh per request, no caching. Read
// failures (file missing, parse error) collapse to an empty array; /hello
// itself always succeeds when the agent is armed, so verifier UX doesn't
// regress for agents that haven't declared anything yet.
func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	priv, _, _, owner, dataHashes := s.agent.Snapshot()
	agentID, frameworkHash := s.agent.ProofIdentity()
	if priv == nil {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}

	agentAddr := ""
	if pk, err := crypto.ToECDSA(priv); err == nil {
		agentAddr = crypto.PubkeyToAddress(pk.PublicKey).Hex()
	}

	// Fresh read on every /hello so verifiers see the agent's current
	// declared surface. The authoritative source is sealed's own service
	// registry (agent-registered via POST /services). During the transition
	// off per-framework manifests, we also merge any legacy adapter
	// services.json entries whose path the registry doesn't already cover
	// (step 5 retires that source). Empty slice (not nil) keeps the JSON
	// shape stable as `services: []`.
	services := servicesForHello(s.getServices())
	if servicesPath := s.getServicesPath(); servicesPath != "" {
		if loaded, err := report.LoadServices(servicesPath); err != nil {
			logger.Logf("handleHello: LoadServices(%s): %v (ignoring legacy manifest)", servicesPath, err)
		} else {
			seen := make(map[string]bool, len(services))
			for _, x := range services {
				seen[x.Path] = true
			}
			for _, x := range loaded {
				if !seen[x.Path] {
					services = append(services, x)
				}
			}
		}
	}

	// Message is the agent's self-introduction in its own voice. Reads
	// as 2 or 3 sentences: identity → owner → (if services present)
	// capability lead-in. Frontend renders the whole thing in a quote
	// bubble; the endpoint list flows directly underneath when present,
	// so all three sentences + the list scan as one continuous voice
	// rather than a verification panel followed by a separate catalog.
	helloMessage := fmt.Sprintf("I am %s. My owner is %s.", agentAddr, owner)
	if len(services) > 0 {
		helloMessage += " Here's what I can do for you:"
	}
	resp := map[string]any{
		"agent":      agentAddr,
		"owner":      owner,
		"public_url": s.publicURL, // empty when SANDBOX_PROXY_DOMAIN is unset
		"message":    helloMessage,
		"services":   services,
		"ts":         time.Now().Unix(),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := writeServeProof(w, r, priv, nil, body, dataHashes, http.StatusOK, agentID, frameworkHash); err != nil {
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
	agentID, frameworkHash := s.agent.ProofIdentity()
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

	adapter := s.getAdapter()
	if adapter == nil {
		http.Error(w, "framework adapter not resolved yet", http.StatusServiceUnavailable)
		return
	}
	payload, err := adapter.AuthResponse(r.Context())
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
	if err := writeServeProof(w, r, priv, nil, body, dataHashes, http.StatusOK, agentID, frameworkHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ── Catch-all reverse proxy ─────────────────────────────────────────────────

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	priv, upstream, _, _, dataHashes := s.agent.Snapshot()
	agentID, frameworkHash := s.agent.ProofIdentity()
	if priv == nil || upstream == "" {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}

	// A registered agent service takes precedence over the framework
	// upstream: a request whose path matches one is routed to that
	// service's loopback backend instead. Everything below (header copy,
	// forward, serve-proof signing) is identical either way — attribution
	// comes from leaving through :8080, not from which backend answered.
	if svc, ok := s.matchService(r.URL.Path); ok {
		if !strings.EqualFold(svc.Method, r.Method) {
			http.Error(w, "method not allowed for "+svc.Path, http.StatusMethodNotAllowed)
			return
		}
		upstream = svc.Backend
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
	if err := writeServeProof(w, r, priv, reqBody, respBody, dataHashes, resp.StatusCode, agentID, frameworkHash); err != nil {
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

// serveProofDeadlineWindow is how long (seconds) a serve-proof stays
// submittable on chain after issuance — the buyer must call giveFeedback
// before it lapses.
const serveProofDeadlineWindow = 3600

// serveProof is the canonical envelope signed by agent_seal_priv and packed
// into X-Agent-Proof. It mirrors the on-chain
// AgenticIDReputationRegistry.ServeProof tuple (minus the signature, which
// travels alongside in the header). There is NO client binding: attribution
// is via msg.sender at giveFeedback submission; the proof is a bearer
// attestation the consumer SDK submits from its own wallet.
//
//	agent_id       : on-chain token id (uint256 decimal string)
//	timestamp      : issuance unix time
//	deadline       : submission expiry
//	task_hash      : keccak256 over the request/response transcript — opaque to
//	                 the contract, kept so a buyer can audit *which* interaction
//	data_hashes    : the on-chain 0g-storage roots the TEE was running (compare
//	                 against AgenticID.intelligentDatasOf); dims not yet on chain
//	                 are omitted
//	framework_hash : the sealed image measurement (AgenticID Framework code)
type serveProof struct {
	AgentID       string   `json:"agent_id"`
	Timestamp     int64    `json:"timestamp"`
	Deadline      int64    `json:"deadline"`
	TaskHash      string   `json:"task_hash"`
	DataHashes    []string `json:"data_hashes"`
	FrameworkHash string   `json:"framework_hash"`
}

// writeServeProof signs the contract-shaped envelope with agent_seal_priv and
// emits a single header packing the signature and base64-url envelope JSON:
//
//	X-Agent-Proof: 0x<65-byte sig hex>.<base64-url-encoded envelope JSON>
//
// The signature is over keccak256(abi.encode(agentId, timestamp, deadline,
// taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash)), wrapped
// EIP-191 — exactly what AgenticIDReputationRegistry._verifyServeProof checks.
//
// When the agent has no on-chain identity yet (agentID/frameworkHash empty, e.g.
// local dev without a chain), the body is written without a proof header — a
// reputation proof would be meaningless.
func writeServeProof(w http.ResponseWriter, r *http.Request, priv, reqBody, body []byte, dataHashes map[string]state.DimHashes, statusCode int, agentID, frameworkHash string) error {
	agentIDBig, ok := new(big.Int).SetString(agentID, 10)
	fwBytes, fwErr := hexToBytes32(frameworkHash)
	if !ok || fwErr != nil || agentIDBig.Sign() == 0 {
		// No on-chain identity — serve the body without a serve-proof.
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(statusCode)
		_, _ = w.Write(body)
		return nil
	}

	// taskHash binds the exact request/response transcript. Opaque to the
	// contract; carried for the buyer to audit which interaction earned this.
	taskHash := crypto.Keccak256(
		[]byte(r.Method), []byte(r.URL.RequestURI()),
		crypto.Keccak256(reqBody), crypto.Keccak256(body),
		[]byte(strconv.Itoa(statusCode)),
	)

	// dataHashes → the on-chain roots, sorted by role for determinism; dims
	// without a chain pin (empty DataHash) are skipped.
	roles := make([]string, 0, len(dataHashes))
	for role := range dataHashes {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	dhHex := make([]string, 0, len(roles))
	var packed []byte // abi.encodePacked(bytes32[])
	for _, role := range roles {
		dh := dataHashes[role].DataHash
		if dh == "" {
			continue
		}
		b, err := hexToBytes32(dh)
		if err != nil {
			return fmt.Errorf("data_hash[%s]: %w", role, err)
		}
		dhHex = append(dhHex, "0x"+hex.EncodeToString(b))
		packed = append(packed, b...)
	}

	now := time.Now().Unix()
	deadline := now + serveProofDeadlineWindow

	env := serveProof{
		AgentID:       agentID,
		Timestamp:     now,
		Deadline:      deadline,
		TaskHash:      "0x" + hex.EncodeToString(taskHash),
		DataHashes:    dhHex,
		FrameworkHash: frameworkHash,
	}
	proofJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal serve-proof: %w", err)
	}

	// abi.encode of (uint256, uint256, uint256, bytes32, bytes32, bytes32) —
	// all static 32-byte words, so it's a plain concatenation.
	encoded := bytes.Join([][]byte{
		word256(agentIDBig),
		word256(big.NewInt(now)),
		word256(big.NewInt(deadline)),
		taskHash,
		crypto.Keccak256(packed),
		fwBytes,
	}, nil)
	proofHash := crypto.Keccak256(encoded)

	// EIP-191: keccak256("\x19Ethereum Signed Message:\n32" || proofHash),
	// matching OpenZeppelin MessageHashUtils.toEthSignedMessageHash(bytes32).
	ethHash := crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), proofHash)

	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return fmt.Errorf("agent priv: %w", err)
	}
	sig, err := crypto.Sign(ethHash, privKey)
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

// word256 left-pads a non-negative big.Int to a 32-byte big-endian word.
func word256(x *big.Int) []byte {
	out := make([]byte, 32)
	x.FillBytes(out)
	return out
}

// hexToBytes32 parses a "0x"-prefixed 32-byte hex string.
func hexToBytes32(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}
