// Agent-callable signing endpoint over a Unix domain socket.
//
// agent_seal_priv is provisioned via ECIES from the attestor and lives only
// inside the sealed Go process (state.Agent). The agent process (openclaw)
// runs in the same container but has no direct access to the priv. When the
// agent needs to sign as its attested identity — for contract calls where
// msg.sender must be the attested address, or for off-chain claims tied to
// the attestation — it calls this signer over a unix socket.
//
// Why a unix socket (not :8080 or a 0.0.0.0 port):
//   - :8080 is the public surface exposed by Daytona's port proxy. Any
//     endpoint added there is reachable by the sandbox owner from outside.
//   - 127.0.0.1 binds are also exposed by Daytona in some configurations.
//   - A unix socket is purely intra-container; fs permission is the ACL.
//
// Five routes (signSocketRoutes is the complete set; sign_test.go pins it):
//
//	POST     /sign/personal_sign  EIP-191 0x45 — body {"message": str} or {"message_hex": "0x..."}
//	POST     /sign/typed_data     EIP-712 (EIP-191 0x01) — body is the standard TypedData JSON
//	POST     /sign/transaction    raw RLP — body has chain_id, nonce, to, value, data,
//	                                        gas_limit, max_fee_per_gas, max_priority_fee_per_gas
//	GET/POST /services            agent service registry (services.go) — signs nothing
//	POST     /settings            agent half of the settings channel (settings.go) — signs nothing
//
// SIGNING-DOMAIN INVARIANT. Every signature this socket produces is over one
// of exactly three preimage shapes, each built here from the request:
//
//   - 0x19 0x45 ("\x19Ethereum Signed Message:\n<len>" ‖ msg)  — personal_sign
//   - 0x19 0x01 ‖ domainSeparator ‖ structHash                — typed_data
//   - a transaction signing payload (0x02 ‖ rlp(…) for EIP-1559, an RLP list
//     ≥ 0xc0 for legacy), built from the request fields via
//     types.LatestSignerForChainID                            — transaction
//
// It must NEVER offer raw-hash signing (sign an arbitrary caller-supplied
// 32 bytes, eth_sign-style) or EIP-191 version 0x00 ("data with intended
// validator") signing. ServeProofs live in the v0x00 domain, bound to the
// VerifiedFeedbackRegistry (proxy.serveProofDigest), and on-chain redemption
// never sees which channel a signature came from — so, with agent_seal_priv
// itself out of the agent's reach, this socket's inability to reach that
// domain is what stops the agent from forging ServeProof contents offline
// (audit FIND-01). Adding either path, here or in an adapter that bridges
// this socket, reopens it. (It does not stop the agent obtaining genuine
// proofs by calling its own proxy — see TRUST_MODEL.md.)
//
// Trust note: within those three shapes this is a fully general signer. If
// the agent forwards owner-controlled bytes through one of these endpoints it
// can manufacture a personal_sign / EIP-712 claim or a transaction that looks
// legitimate to whoever accepts that shape. The agent is the gatekeeper for
// those. See sealed/TRUST_MODEL.md.

package proxy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// ListenInternal binds a Unix domain socket and serves the agent-only sign
// mux. Idempotent w.r.t. a stale socket file from a previous run (removes
// then re-creates). Failures are logged and swallowed — the public :8080
// listener must still come up so bootstrap can report errors via /log.
func (s *Server) ListenInternal(sockPath string) {
	if sockPath == "" {
		logger.Logf("sign socket: path empty, skipping")
		return
	}
	// The socket's directory, the stale entry and the mode are handled
	// without following links (privsep fs helpers), like every other path
	// root touches.
	if err := privsep.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		logger.Logf("FAIL sign socket: mkdir %s: %v", filepath.Dir(sockPath), err)
		return
	}
	if err := privsep.Remove(sockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logger.Logf("FAIL sign socket: remove stale %s: %v", sockPath, err)
		return
	}
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		logger.Logf("FAIL sign socket: listen %s: %v", sockPath, err)
		return
	}
	// The framework subprocess runs as the low-privilege agent user
	// (internal/privsep), and this socket is its one legitimate channel to
	// its key — hand the file to that user, 0600 keeps everyone else out
	// (sealed is root and unaffected). Without the split (dev, legacy
	// image) OwnPath is a no-op and 0600 matches the single-uid reality.
	if err := privsep.Chmod(sockPath, 0o600); err != nil {
		logger.Logf("FAIL sign socket: chmod %s: %v", sockPath, err)
		l.Close()
		_ = privsep.Remove(sockPath)
		return
	}
	privsep.OwnPath(sockPath)

	mux, paths := s.signSocketMux()

	go func() {
		logger.Logf("OK   sign socket listening at unix://%s (%s)", sockPath, strings.Join(paths, " | "))
		_ = http.Serve(l, mux)
	}()
}

// signRoute is one path on the agent-only sign socket.
type signRoute struct {
	path    string
	handler http.HandlerFunc
}

// signSocketRoutes is the complete route set of the sign socket. Adding a
// signing route is a protocol change: it must stay within the signing-domain
// invariant in the file header (no raw-hash, no EIP-191 v0x00), and
// sign_test.go pins this list so the change can't land silently.
func (s *Server) signSocketRoutes() []signRoute {
	return []signRoute{
		{"/sign/personal_sign", s.handleSignPersonalSign},
		{"/sign/typed_data", s.handleSignTypedData},
		{"/sign/transaction", s.handleSignTransaction},
		{"/services", s.handleServices},
		{"/settings", s.handleAgentSettings},
	}
}

// signSocketMux builds the sign socket's mux from signSocketRoutes and
// returns the registered paths (for the startup log line).
func (s *Server) signSocketMux() (*http.ServeMux, []string) {
	mux := http.NewServeMux()
	routes := s.signSocketRoutes()
	paths := make([]string, 0, len(routes))
	for _, rt := range routes {
		mux.HandleFunc(rt.path, rt.handler)
		paths = append(paths, rt.path)
	}
	return mux, paths
}

// signPriv returns (priv, agentSealAddr) or an error if state isn't armed
// yet (provision hasn't completed).
func (s *Server) signPriv() ([]byte, string, error) {
	priv, _, _, _, _ := s.agent.Snapshot()
	if priv == nil {
		return nil, "", fmt.Errorf("agent not ready (provisioning incomplete)")
	}
	pk, err := crypto.ToECDSA(priv)
	if err != nil {
		return nil, "", fmt.Errorf("priv decode: %w", err)
	}
	return priv, crypto.PubkeyToAddress(pk.PublicKey).Hex(), nil
}

// ── /sign/personal_sign ─────────────────────────────────────────────────────

func (s *Server) handleSignPersonalSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSignError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		Message    string `json:"message"`
		MessageHex string `json:"message_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSignError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	var msg []byte
	switch {
	case req.MessageHex != "":
		b, err := hex.DecodeString(strings.TrimPrefix(req.MessageHex, "0x"))
		if err != nil {
			writeSignError(w, http.StatusBadRequest, "message_hex: "+err.Error())
			return
		}
		msg = b
	case req.Message != "":
		msg = []byte(req.Message)
	default:
		writeSignError(w, http.StatusBadRequest, "provide either message or message_hex")
		return
	}

	priv, addr, err := s.signPriv()
	if err != nil {
		writeSignError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	hash := crypto.Keccak256([]byte(prefix), msg)
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "priv: "+err.Error())
		return
	}
	sig, err := crypto.Sign(hash, privKey)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}
	sig[64] += 27

	writeJSON(w, http.StatusOK, map[string]any{
		"signature": "0x" + hex.EncodeToString(sig),
		"address":   addr,
		"msg_hash":  "0x" + hex.EncodeToString(hash),
	})
}

// ── /sign/typed_data ────────────────────────────────────────────────────────

func (s *Server) handleSignTypedData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSignError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var td apitypes.TypedData
	if err := json.NewDecoder(r.Body).Decode(&td); err != nil {
		writeSignError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if td.PrimaryType == "" {
		writeSignError(w, http.StatusBadRequest, "primaryType missing")
		return
	}

	domainHash, err := td.HashStruct("EIP712Domain", td.Domain.Map())
	if err != nil {
		writeSignError(w, http.StatusBadRequest, "hash domain: "+err.Error())
		return
	}
	msgHash, err := td.HashStruct(td.PrimaryType, td.Message)
	if err != nil {
		writeSignError(w, http.StatusBadRequest, "hash message: "+err.Error())
		return
	}
	digest := crypto.Keccak256([]byte{0x19, 0x01}, domainHash, msgHash)

	priv, addr, err := s.signPriv()
	if err != nil {
		writeSignError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "priv: "+err.Error())
		return
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}
	sig[64] += 27

	writeJSON(w, http.StatusOK, map[string]any{
		"signature": "0x" + hex.EncodeToString(sig),
		"address":   addr,
		"digest":    "0x" + hex.EncodeToString(digest),
	})
}

// ── /sign/transaction ───────────────────────────────────────────────────────

func (s *Server) handleSignTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSignError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		ChainID              string `json:"chain_id"` // decimal or 0x hex
		Nonce                uint64 `json:"nonce"`
		To                   string `json:"to"`    // empty = contract creation
		Value                string `json:"value"` // wei (decimal or 0x hex); default 0
		Data                 string `json:"data"`  // 0x hex
		GasLimit             uint64 `json:"gas_limit"`
		GasPrice             string `json:"gas_price"`                // legacy only
		MaxFeePerGas         string `json:"max_fee_per_gas"`          // dynamic (EIP-1559)
		MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"` // dynamic (EIP-1559)
		Type                 string `json:"type"`                     // "dynamic" (default) | "legacy"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSignError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	chainID, ok := parseBigInt(req.ChainID)
	if !ok {
		writeSignError(w, http.StatusBadRequest, "invalid or missing chain_id")
		return
	}
	// 0 or negative panics the geth signer (LatestSignerForChainID on a
	// zero/negative chain id); net/http would recover the panic, but the
	// caller would only see "socket hang up". Reject with a real error.
	// The upper bound is the same class as the amount checks: no real chain
	// id exceeds uint64, and an absurd one is a caller bug, not intent.
	if chainID.Sign() <= 0 {
		writeSignError(w, http.StatusBadRequest, "chain_id must be a positive integer")
		return
	}
	if chainID.BitLen() > 64 {
		writeSignError(w, http.StatusBadRequest, "chain_id: exceeds uint64")
		return
	}
	if req.GasLimit == 0 {
		writeSignError(w, http.StatusBadRequest, "gas_limit required")
		return
	}
	// An unparseable non-empty value would otherwise sign as 0 wei: "1.5"
	// and "1e18" both produce a valid-looking tx with the value silently
	// dropped. A negative amount parses fine (big.Int accepts a leading
	// "-") but is nonsense on the wire; 2^256 or more parses fine too but
	// overflows every uint256 field (the tx would serialize, but no node
	// accepts it — reject at the door with the same 400). Same for the
	// fee fields below.
	value, ok := parseBigInt(req.Value)
	if !ok && strings.TrimSpace(req.Value) != "" {
		writeSignError(w, http.StatusBadRequest, "value: not a decimal or 0x-hex integer")
		return
	}
	if msg := amountRangeErr(value, "value"); msg != "" {
		writeSignError(w, http.StatusBadRequest, msg)
		return
	}
	if value == nil {
		value = big.NewInt(0)
	}
	data, err := decodeHex(req.Data)
	if err != nil {
		writeSignError(w, http.StatusBadRequest, "data: "+err.Error())
		return
	}
	var toAddr *common.Address
	if req.To != "" {
		if !common.IsHexAddress(req.To) {
			writeSignError(w, http.StatusBadRequest, "to: not a hex address")
			return
		}
		a := common.HexToAddress(req.To)
		toAddr = &a
	}

	var tx *types.Transaction
	txType := strings.ToLower(req.Type)
	if txType == "" {
		txType = "dynamic"
	}
	switch txType {
	case "dynamic", "1559", "2", "eip1559":
		maxFee, _ := parseBigInt(req.MaxFeePerGas)
		tip, _ := parseBigInt(req.MaxPriorityFeePerGas)
		if maxFee == nil || tip == nil {
			writeSignError(w, http.StatusBadRequest,
				"dynamic tx requires max_fee_per_gas and max_priority_fee_per_gas")
			return
		}
		if msg := amountRangeErr(maxFee, "max_fee_per_gas"); msg != "" {
			writeSignError(w, http.StatusBadRequest, msg)
			return
		}
		if msg := amountRangeErr(tip, "max_priority_fee_per_gas"); msg != "" {
			writeSignError(w, http.StatusBadRequest, msg)
			return
		}
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     req.Nonce,
			GasTipCap: tip,
			GasFeeCap: maxFee,
			Gas:       req.GasLimit,
			To:        toAddr,
			Value:     value,
			Data:      data,
		})
	case "legacy", "0":
		gasPrice, _ := parseBigInt(req.GasPrice)
		if gasPrice == nil {
			writeSignError(w, http.StatusBadRequest, "legacy tx requires gas_price")
			return
		}
		if msg := amountRangeErr(gasPrice, "gas_price"); msg != "" {
			writeSignError(w, http.StatusBadRequest, msg)
			return
		}
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    req.Nonce,
			GasPrice: gasPrice,
			Gas:      req.GasLimit,
			To:       toAddr,
			Value:    value,
			Data:     data,
		})
	default:
		writeSignError(w, http.StatusBadRequest, "unsupported tx type: "+req.Type)
		return
	}

	priv, addr, err := s.signPriv()
	if err != nil {
		writeSignError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "priv: "+err.Error())
		return
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privKey)
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "sign tx: "+err.Error())
		return
	}
	rawBytes, err := signed.MarshalBinary()
	if err != nil {
		writeSignError(w, http.StatusInternalServerError, "marshal raw: "+err.Error())
		return
	}
	v, rSig, sSig := signed.RawSignatureValues()
	writeJSON(w, http.StatusOK, map[string]any{
		"raw_tx":  "0x" + hex.EncodeToString(rawBytes),
		"tx_hash": signed.Hash().Hex(),
		"address": addr,
		"signature": map[string]string{
			"v": "0x" + v.Text(16),
			"r": "0x" + rSig.Text(16),
			"s": "0x" + sSig.Text(16),
		},
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeSignError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// amountRangeErr returns the 400 message for an amount field that is
// negative or overflows uint256 (BitLen > 256), or "" when the amount is
// usable (nil — field absent — is fine: the caller defaults it).
func amountRangeErr(n *big.Int, field string) string {
	if n == nil {
		return ""
	}
	if n.Sign() < 0 {
		return field + ": negative"
	}
	if n.BitLen() > 256 {
		return field + ": exceeds uint256"
	}
	return ""
}

// parseBigInt accepts decimal ("123") or 0x-hex ("0x7b"). Empty → (nil, false).

func parseBigInt(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	n := new(big.Int)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if _, ok := n.SetString(s[2:], 16); !ok {
			return nil, false
		}
	} else {
		if _, ok := n.SetString(s, 10); !ok {
			return nil, false
		}
	}
	return n, true
}

// decodeHex accepts "0x..." or "..." or "". Empty → (nil, nil).
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
