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
// Three endpoints:
//
//	POST /sign/personal_sign  EIP-191 — body {"message": str} or {"message_hex": "0x..."}
//	POST /sign/typed_data     EIP-712 — body is the standard TypedData JSON
//	POST /sign/transaction    raw RLP — body has chain_id, nonce, to, value, data,
//	                                    gas_limit, max_fee_per_gas, max_priority_fee_per_gas
//
// Trust note: this is a fully general signer. If the agent forwards owner-
// controlled bytes through one of these endpoints it can manufacture a
// signature that looks like a legitimate serve-proof or contract claim. The
// agent is the gatekeeper. See sealed/TRUST_MODEL.md.

package proxy

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/logger"
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
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		logger.Logf("FAIL sign socket: mkdir %s: %v", filepath.Dir(sockPath), err)
		return
	}
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		logger.Logf("FAIL sign socket: remove stale %s: %v", sockPath, err)
		return
	}
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		logger.Logf("FAIL sign socket: listen %s: %v", sockPath, err)
		return
	}
	// Same uid as openclaw (single-container, same user); 0600 is enough.
	// If we ever split processes by uid, widen to 0660 and set group.
	if err := os.Chmod(sockPath, 0o600); err != nil {
		logger.Logf("warn sign socket: chmod %s: %v", sockPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sign/personal_sign", s.handleSignPersonalSign)
	mux.HandleFunc("/sign/typed_data", s.handleSignTypedData)
	mux.HandleFunc("/sign/transaction", s.handleSignTransaction)

	go func() {
		logger.Logf("OK   sign socket listening at unix://%s "+
			"(/sign/personal_sign | /sign/typed_data | /sign/transaction)", sockPath)
		_ = http.Serve(l, mux)
	}()
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
		GasPrice             string `json:"gas_price"`               // legacy only
		MaxFeePerGas         string `json:"max_fee_per_gas"`         // dynamic (EIP-1559)
		MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"` // dynamic (EIP-1559)
		Type                 string `json:"type"`                    // "dynamic" (default) | "legacy"
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
	if req.GasLimit == 0 {
		writeSignError(w, http.StatusBadRequest, "gas_limit required")
		return
	}
	value, _ := parseBigInt(req.Value)
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
