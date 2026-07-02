package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/state"
)

// Rebuild the contract's signed proofHash from the envelope and recover the
// signer — it must equal the agentSeal address. This pins the Go signing to
// AgenticIDReputationRegistry._verifyServeProof's expectations:
// keccak256(abi.encode(agentId, timestamp, deadline, taskHash,
//   keccak256(abi.encodePacked(dataHashes)), frameworkHash)), EIP-191 wrapped.
func TestWriteServeProof_RecoversToAgentSeal(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	privBytes := crypto.FromECDSA(priv)
	wantSigner := crypto.PubkeyToAddress(priv.PublicKey)

	frameworkHash := "0x" + strings.Repeat("11", 32)
	dataHashes := map[string]state.DimHashes{
		"framework":     {ContentHash: "0xaa", DataHash: "0x" + strings.Repeat("22", 32)},
		"openclaw.json": {ContentHash: "0xbb", DataHash: "0x" + strings.Repeat("33", 32)},
		"workspace/":    {ContentHash: "0xcc", DataHash: ""}, // no chain pin → skipped
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/chat", strings.NewReader("hello"))
	body := []byte("world")
	if err := writeServeProof(rec, req, privBytes, []byte("hello"), body, dataHashes, 200, "30", frameworkHash); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}

	header := rec.Header().Get("X-Agent-Proof")
	if header == "" {
		t.Fatal("no X-Agent-Proof header")
	}
	sigHex, envB64, ok := strings.Cut(header, ".")
	if !ok {
		t.Fatal("malformed header (missing '.')")
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("bad sig: %v len=%d", err, len(sig))
	}
	envJSON, err := base64.RawURLEncoding.DecodeString(envB64)
	if err != nil {
		t.Fatalf("bad envelope b64: %v", err)
	}
	var env serveProof
	if err := json.Unmarshal(envJSON, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	// Envelope shape: dim without a chain pin must be excluded.
	if len(env.DataHashes) != 2 {
		t.Fatalf("expected 2 on-chain dataHashes, got %d", len(env.DataHashes))
	}
	if env.AgentID != "30" || env.FrameworkHash != frameworkHash {
		t.Fatalf("envelope identity mismatch: %+v", env)
	}
	if env.Deadline != env.Timestamp+serveProofDeadlineWindow {
		t.Fatalf("deadline window wrong: ts=%d deadline=%d", env.Timestamp, env.Deadline)
	}

	// Rebuild proofHash exactly as the contract does.
	var packed []byte
	for _, dh := range env.DataHashes {
		b, _ := hexToBytes32(dh)
		packed = append(packed, b...)
	}
	taskHash, _ := hexToBytes32(env.TaskHash)
	fwBytes, _ := hexToBytes32(env.FrameworkHash)
	agentIDBig, _ := new(big.Int).SetString(env.AgentID, 10)
	encoded := concat(
		word256(agentIDBig),
		word256(big.NewInt(env.Timestamp)),
		word256(big.NewInt(env.Deadline)),
		taskHash,
		crypto.Keccak256(packed),
		fwBytes,
	)
	proofHash := crypto.Keccak256(encoded)
	ethHash := crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), proofHash)

	// recover expects V in {0,1}.
	recSig := make([]byte, 65)
	copy(recSig, sig)
	recSig[64] -= 27
	pub, err := crypto.SigToPub(ethHash, recSig)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != wantSigner {
		t.Fatalf("recovered %s, want agentSeal %s", got.Hex(), wantSigner.Hex())
	}
}

func TestWriteServeProof_SkipsWhenNoIdentity(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	// agentID "" (unminted / dev) → body written, no proof header.
	if err := writeServeProof(rec, req, crypto.FromECDSA(priv), nil, []byte("x"), nil, 200, "", ""); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}
	if rec.Header().Get("X-Agent-Proof") != "" {
		t.Fatal("expected no proof header when identity is absent")
	}
	if rec.Body.String() != "x" {
		t.Fatalf("body = %q, want x", rec.Body.String())
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
