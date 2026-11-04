package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/state"
)

// These tests pin the sign socket's signing-domain invariant (see the sign.go
// header): every signature it produces is over a 0x19 0x45 (personal_sign),
// 0x19 0x01 (EIP-712) or transaction preimage — never a raw caller-supplied
// hash, never EIP-191 version 0x00. ServeProofs live in the v0x00 domain, so
// this is what keeps the agent from forging them through the socket.

// signServer returns a Server armed with a fresh agent_seal key.
func signServer(t *testing.T) (*Server, common.Address) {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ag := state.New()
	ag.Set(crypto.FromECDSA(priv), "http://127.0.0.1:1", "deadbeef", "", "30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator)
	return &Server{agent: ag}, crypto.PubkeyToAddress(priv.PublicKey)
}

// callSign POSTs body to a sign handler and decodes the JSON reply.
func callSign(t *testing.T, h http.HandlerFunc, body any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return out
}

func mustHex(t *testing.T, v any) []byte {
	t.Helper()
	s, _ := v.(string)
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// The route set is exactly these five. A new signing route — a raw-hash /
// eth_sign / v0x00 endpoint above all — must fail this test and get a
// conscious review against the invariant, not slip in.
func TestSignSocket_RouteSetPinned(t *testing.T) {
	s, _ := signServer(t)
	mux, paths := s.signSocketMux()

	want := []string{"/sign/personal_sign", "/sign/typed_data", "/sign/transaction", "/services", "/settings"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("sign socket routes = %v, want exactly %v", paths, want)
	}
	for _, p := range want {
		if _, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, p, nil)); pattern != p {
			t.Errorf("%s: matched pattern %q", p, pattern)
		}
	}
	for _, p := range []string{
		"/sign", "/sign/", "/sign/hash", "/sign/raw", "/sign/digest", "/sign/eth_sign",
		"/sign/message", "/sign/data", "/sign/v0", "/sign/intended_validator",
		"/sign/validator", "/sign/serve_proof", "/sign/personal_sign/raw",
	} {
		if _, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, p, nil)); pattern != "" {
			t.Errorf("%s must not be routed, matched pattern %q", p, pattern)
		}
	}
}

// personal_sign signs keccak256 of the 0x19 0x45 preimage
// ("\x19Ethereum Signed Message:\n<len>" ‖ msg), for both input forms.
func TestSignPersonalSign_EIP191Prefix(t *testing.T) {
	s, agent := signServer(t)
	for name, tc := range map[string]struct {
		body any
		msg  []byte
	}{
		"message":     {map[string]string{"message": "hello"}, []byte("hello")},
		"message_hex": {map[string]string{"message_hex": "0xdeadbeef"}, []byte{0xde, 0xad, 0xbe, 0xef}},
	} {
		out := callSign(t, s.handleSignPersonalSign, tc.body)
		hash, preimage := accounts.TextAndHash(tc.msg)
		if !strings.HasPrefix(preimage, "\x19\x45") {
			t.Fatalf("%s: preimage starts %x, want 19 45", name, preimage[:2])
		}
		if got := mustHex(t, out["msg_hash"]); !bytes.Equal(got, hash) {
			t.Fatalf("%s: msg_hash = %x, want %x", name, got, hash)
		}
		if got := recoverSigner(t, hash, mustHex(t, out["signature"])); got != agent {
			t.Fatalf("%s: recovered %s, want %s", name, got.Hex(), agent.Hex())
		}
	}
}

// typed_data signs keccak256 of the 0x19 0x01 ‖ domainSeparator ‖ structHash
// preimage.
func TestSignTypedData_EIP712Prefix(t *testing.T) {
	s, agent := signServer(t)
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "chainId", Type: "uint256"}},
			"Note":         {{Name: "text", Type: "string"}},
		},
		PrimaryType: "Note",
		Domain:      apitypes.TypedDataDomain{Name: "test", ChainId: (*math.HexOrDecimal256)(big.NewInt(16602))},
		Message:     apitypes.TypedDataMessage{"text": "hi"},
	}
	out := callSign(t, s.handleSignTypedData, td)
	hash, preimage, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(preimage, "\x19\x01") {
		t.Fatalf("preimage starts %x, want 19 01", preimage[:2])
	}
	if got := mustHex(t, out["digest"]); !bytes.Equal(got, hash) {
		t.Fatalf("digest = %x, want %x", got, hash)
	}
	if got := recoverSigner(t, hash, mustHex(t, out["signature"])); got != agent {
		t.Fatalf("recovered %s, want %s", got.Hex(), agent.Hex())
	}
}

// transaction signs the geth signing hash for the chain
// (types.LatestSignerForChainID) of a tx the socket assembles from fields:
// 0x02 ‖ rlp(…) for EIP-1559, an RLP list (≥ 0xc0) for legacy — never 0x19.
func TestSignTransaction_ChainSignerHash(t *testing.T) {
	s, agent := signServer(t)
	for name, tc := range map[string]struct {
		body      map[string]any
		wantType  uint8
		firstByte func(byte) bool
	}{
		"dynamic": {
			map[string]any{"chain_id": "16602", "nonce": 7, "to": testValidator, "data": "0xabcd", "gas_limit": 50000,
				"max_fee_per_gas": "1000", "max_priority_fee_per_gas": "10"},
			types.DynamicFeeTxType, func(b byte) bool { return b == 0x02 },
		},
		"legacy": {
			map[string]any{"chain_id": "16602", "nonce": 7, "to": testValidator, "gas_limit": 50000,
				"gas_price": "1000", "type": "legacy"},
			types.LegacyTxType, func(b byte) bool { return b >= 0xc0 },
		},
	} {
		out := callSign(t, s.handleSignTransaction, tc.body)
		raw := mustHex(t, out["raw_tx"])
		if !tc.firstByte(raw[0]) {
			t.Fatalf("%s: raw tx starts 0x%02x", name, raw[0])
		}
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatalf("%s: decode raw tx: %v", name, err)
		}
		if tx.Type() != tc.wantType {
			t.Fatalf("%s: tx type %d, want %d", name, tx.Type(), tc.wantType)
		}
		if out["tx_hash"] != tx.Hash().Hex() {
			t.Fatalf("%s: tx_hash %v, want %s", name, out["tx_hash"], tx.Hash().Hex())
		}
		from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(16602)), &tx)
		if err != nil || from != agent {
			t.Fatalf("%s: sender %s (%v), want %s", name, from.Hex(), err, agent.Hex())
		}
	}
}

// The FIND-01 regression: nothing the agent can push through personal_sign —
// the proofHash itself, the v0x00 digest, or the v0x00 preimage with or
// without its 0x19 — yields a signature that verifies as a ServeProof (EIP-191
// v0x00 digest bound to the validator). Before the fix, a personal_sign over
// the 32-byte proofHash WAS the ServeProof signature.
func TestSignSocket_CannotProduceServeProofSignature(t *testing.T) {
	s, agent := signServer(t)
	proofHash, _ := hex.DecodeString(katProofHash)
	v0Digest, _ := hex.DecodeString(katV0Digest)
	validator := common.HexToAddress(testValidator).Bytes()

	// personal_sign over the 32-byte proofHash produces exactly the legacy
	// digest the registry now rejects.
	out := callSign(t, s.handleSignPersonalSign, map[string]string{"message_hex": "0x" + katProofHash})
	if got := hex.EncodeToString(mustHex(t, out["msg_hash"])); got != katLegacyDigest {
		t.Fatalf("personal_sign(proofHash) msg_hash = 0x%s, want legacy 0x%s", got, katLegacyDigest)
	}

	for name, msg := range map[string][]byte{
		"proofHash":           proofHash,
		"v0 digest":           v0Digest,
		"v0 preimage tail":    concat([]byte{0x00}, validator, proofHash),
		"v0 preimage (19 00)": concat([]byte{0x19, 0x00}, validator, proofHash),
	} {
		out := callSign(t, s.handleSignPersonalSign, map[string]string{"message_hex": "0x" + hex.EncodeToString(msg)})
		sig := mustHex(t, out["signature"])
		if got := recoverSigner(t, v0Digest, sig); got == agent {
			t.Fatalf("%s: personal_sign output verifies as a v0x00 ServeProof signature", name)
		}
	}
}
