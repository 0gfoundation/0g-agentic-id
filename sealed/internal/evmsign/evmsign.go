// Package evmsign holds the three signing shapes sealed offers, for any
// secp256k1 key: an EIP-191 personal message, an EIP-712 digest, and a
// transaction it assembles from the request's fields. The agentSeal sign
// socket (internal/proxy/sign.go) and an owner's wallet credential
// (internal/credentials) both sign through it.
//
// It never signs a caller-supplied raw hash or an EIP-191 version 0x00
// message: see the signing-domain invariant in internal/proxy/sign.go.
package evmsign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// BadRequest is a request the caller must fix (HTTP 400).
type BadRequest struct{ msg string }

func (e *BadRequest) Error() string { return e.msg }

func bad(msg string) error { return &BadRequest{msg} }

// Unavailable is a key that cannot be had right now (HTTP 503).
type Unavailable struct{ Err error }

func (e *Unavailable) Error() string { return e.Err.Error() }

// KeyFunc returns the private key. It is called only once the request has
// been validated, so a malformed request is reported as such even while no
// key is available. Its error is reported as Unavailable.
type KeyFunc func() ([]byte, error)

// PersonalSignRequest is {"message": str} or {"message_hex": "0x..."}.
type PersonalSignRequest struct {
	Message    string `json:"message"`
	MessageHex string `json:"message_hex"`
}

// PersonalSign signs "\x19Ethereum Signed Message:\n<len>" ‖ msg.
func PersonalSign(req PersonalSignRequest, k KeyFunc) (map[string]any, error) {
	var msg []byte
	switch {
	case req.MessageHex != "":
		b, err := hex.DecodeString(strings.TrimPrefix(req.MessageHex, "0x"))
		if err != nil {
			return nil, bad("message_hex: " + err.Error())
		}
		msg = b
	case req.Message != "":
		msg = []byte(req.Message)
	default:
		return nil, bad("provide either message or message_hex")
	}
	priv, err := k()
	if err != nil {
		return nil, &Unavailable{err}
	}
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return nil, fmt.Errorf("priv: %w", err)
	}
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	hash := crypto.Keccak256([]byte(prefix), msg)
	sig, err := crypto.Sign(hash, privKey)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	return map[string]any{
		"signature": "0x" + hex.EncodeToString(sig),
		"address":   crypto.PubkeyToAddress(privKey.PublicKey).Hex(),
		"msg_hash":  "0x" + hex.EncodeToString(hash),
	}, nil
}

// TypedData signs 0x19 0x01 ‖ domainSeparator ‖ hashStruct(message).
func TypedData(td apitypes.TypedData, k KeyFunc) (map[string]any, error) {
	if td.PrimaryType == "" {
		return nil, bad("primaryType missing")
	}
	domainHash, msgHash, err := hashTypedData(td)
	if err != nil {
		return nil, err
	}
	digest := crypto.Keccak256([]byte{0x19, 0x01}, domainHash, msgHash)
	priv, err := k()
	if err != nil {
		return nil, &Unavailable{err}
	}
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return nil, fmt.Errorf("priv: %w", err)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	return map[string]any{
		"signature": "0x" + hex.EncodeToString(sig),
		"address":   crypto.PubkeyToAddress(privKey.PublicKey).Hex(),
		"digest":    "0x" + hex.EncodeToString(digest),
	}, nil
}

// TransactionRequest is the transaction to assemble and sign.
type TransactionRequest struct {
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

// Transaction assembles req and signs it for its chain.
func Transaction(req TransactionRequest, k KeyFunc) (map[string]any, error) {
	chainID, ok := parseBigInt(req.ChainID)
	if !ok {
		return nil, bad("invalid or missing chain_id")
	}
	// 0 or negative panics the geth signer (LatestSignerForChainID on a
	// zero/negative chain id); net/http would recover the panic, but the
	// caller would only see "socket hang up". Reject with a real error.
	// The upper bound is the same class as the amount checks: no real chain
	// id exceeds uint64, and an absurd one is a caller bug, not intent.
	if chainID.Sign() <= 0 {
		return nil, bad("chain_id must be a positive integer")
	}
	if chainID.BitLen() > 64 {
		return nil, bad("chain_id: exceeds uint64")
	}
	if req.GasLimit == 0 {
		return nil, bad("gas_limit required")
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
		return nil, bad("value: not a decimal or 0x-hex integer")
	}
	if msg := amountRangeErr(value, "value"); msg != "" {
		return nil, bad(msg)
	}
	if value == nil {
		value = big.NewInt(0)
	}
	data, err := decodeHex(req.Data)
	if err != nil {
		return nil, bad("data: " + err.Error())
	}
	var toAddr *common.Address
	if req.To != "" {
		if !common.IsHexAddress(req.To) {
			return nil, bad("to: not a hex address")
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
			return nil, bad("dynamic tx requires max_fee_per_gas and max_priority_fee_per_gas")
		}
		if msg := amountRangeErr(maxFee, "max_fee_per_gas"); msg != "" {
			return nil, bad(msg)
		}
		if msg := amountRangeErr(tip, "max_priority_fee_per_gas"); msg != "" {
			return nil, bad(msg)
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
			return nil, bad("legacy tx requires gas_price")
		}
		if msg := amountRangeErr(gasPrice, "gas_price"); msg != "" {
			return nil, bad(msg)
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
		return nil, bad("unsupported tx type: " + req.Type)
	}

	priv, err := k()
	if err != nil {
		return nil, &Unavailable{err}
	}
	privKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return nil, fmt.Errorf("priv: %w", err)
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privKey)
	if err != nil {
		return nil, fmt.Errorf("sign tx: %w", err)
	}
	rawBytes, err := signed.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal raw: %w", err)
	}
	v, rSig, sSig := signed.RawSignatureValues()
	return map[string]any{
		"raw_tx":  "0x" + hex.EncodeToString(rawBytes),
		"tx_hash": signed.Hash().Hex(),
		"address": crypto.PubkeyToAddress(privKey.PublicKey).Hex(),
		"signature": map[string]string{
			"v": "0x" + v.Text(16),
			"r": "0x" + rSig.Text(16),
			"s": "0x" + sSig.Text(16),
		},
	}, nil
}

// Status is the HTTP status for an error from this package.
func Status(err error) int {
	var b *BadRequest
	var u *Unavailable
	switch {
	case errors.As(err, &b):
		return 400
	case errors.As(err, &u):
		return 503
	}
	return 500
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

// hashTypedData hashes the domain and the message. go-ethereum panics on
// some malformed messages (a null inside an array of uint256): that is the
// caller's bad request, not a crash.
func hashTypedData(td apitypes.TypedData) (domainHash, msgHash []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = bad(fmt.Sprintf("typed data is malformed: %v", r))
		}
	}()
	if domainHash, err = td.HashStruct("EIP712Domain", td.Domain.Map()); err != nil {
		return nil, nil, bad("hash domain: " + err.Error())
	}
	if msgHash, err = td.HashStruct(td.PrimaryType, td.Message); err != nil {
		return nil, nil, bad("hash message: " + err.Error())
	}
	return domainHash, msgHash, nil
}
