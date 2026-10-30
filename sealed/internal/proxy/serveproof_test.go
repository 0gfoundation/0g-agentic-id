package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/state"
)

// testValidator stands in for the VerifiedFeedbackRegistry proxy address.
const testValidator = "0x00000000000000000000000000000000000000B7"

// Cross-implementation known-answer vectors. katProofHash / katV0Digest /
// katLegacyDigest are also asserted in contracts/test,
// sdk/typescript/scripts/serveproof-kav.cjs and the SDK's
// test/serveproof*.test.mjs (inputs: the fixed tuple in
// TestServeProofDigest_KnownAnswerVector); katTaskHash in
// contracts/test/VerifiedFeedback.t.sol and sdk/typescript/test/taskhash.test.mjs;
// katTaskHashEdge and the requestURIForms table in that SDK test and in the
// attestor console's copy (test/serveproof-copies.test.mjs).
const (
	// keccak256(abi.encode(...)) — the inner ServeProof hash, unchanged by the
	// FIND-01 fix.
	katProofHash = "abfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b"
	// keccak256(0x19 ‖ 0x00 ‖ 0x…B7 ‖ katProofHash) — what agent_seal_priv signs.
	katV0Digest = "d496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b"
	// keccak256("\x19Ethereum Signed Message:\n32" ‖ katProofHash) — the legacy
	// wrap, which a personal_sign over katProofHash produces and the registry
	// now rejects.
	katLegacyDigest = "6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf"
	// keccak256("POST" ‖ "/api/x?q=1" ‖ keccak256(`{"q":"in"}`) ‖
	// keccak256(`{"a":"out"}`) ‖ "201") — the taskHash preimage that
	// attestFeedbackWithTask recomputes from a reveal. Also pinned (and
	// redeemed) in contracts/test/VerifiedFeedback.t.sol.
	katTaskHash = "6c37771076037daf6053adca6126264030e249e0c9a6fc0cc238c56509f842db"
)

// keccak256("GET" ‖ "/api/a%7Cb?" ‖ keccak256("") ‖ keccak256(`{"a":"out"}`) ‖
// "200") — a request sent as "/api/a|b?": Go re-escapes the '|' WHATWG URLs
// leave raw and keeps the bare trailing '?' (RequestURI with ForceQuery).
const katTaskHashEdge = "9e00c178e74e6acfb1c048af8be9a47f3d91adf60a02982ce15810ff452fc81b"

// requestURIForms maps a request target as sent on the wire to the
// r.URL.RequestURI() the proxy hashes. Mirrored verbatim by the SDK's
// requestUriOf and the console's goRequestURI.
var requestURIForms = [][2]string{
	{"/api/x?q=1", "/api/x?q=1"},
	{"/api/x?", "/api/x?"},
	{"/api/a|b", "/api/a%7Cb"},
	{"/api/a^b?x=|^", "/api/a%5Eb?x=|^"},
	{"/api/a|b?", "/api/a%7Cb?"},
	{"/api/a%2Fb|c", "/api/a/b%7Cc"},
	{"/api/a%7cb", "/api/a%7cb"},
	{"/api/a%41|", "/api/aA%7C"},
	{"/api/%C3%A9", "/api/%C3%A9"},
	{"/api/%C3%A9|", "/api/%C3%A9%7C"},
	{"/api/[x]!'()*,;=:@$&+", "/api/[x]!'()*,;=:@$&+"},
	{"/api/[x]|", "/api/%5Bx%5D%7C"},
	{"/api/a??b", "/api/a??b"},
}

// TestWriteServeProof_RequestURIForms pins the uri the taskHash commits to —
// Go's RequestURI of the received target — for the forms a client-side copy
// must reproduce, and katTaskHashEdge for one of them.
func TestWriteServeProof_RequestURIForms(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	respBody := []byte(katTaskResp)
	for _, f := range requestURIForms {
		req := httptest.NewRequest(http.MethodGet, f[0], nil)
		if got := req.URL.RequestURI(); got != f[1] {
			t.Fatalf("RequestURI(%q) = %q, want %q", f[0], got, f[1])
		}
		rec := httptest.NewRecorder()
		if err := writeServeProof(rec, req, crypto.FromECDSA(priv), nil, respBody, nil, http.StatusOK,
			"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator); err != nil {
			t.Fatalf("writeServeProof(%q): %v", f[0], err)
		}
		_, env := decodeProofHeader(t, rec.Header().Get("X-Agent-Proof"))
		var preimage []byte
		preimage = append(preimage, http.MethodGet...)
		preimage = append(preimage, f[1]...)
		preimage = append(preimage, crypto.Keccak256(nil)...)
		preimage = append(preimage, crypto.Keccak256(respBody)...)
		preimage = append(preimage, "200"...)
		if want := "0x" + hex.EncodeToString(crypto.Keccak256(preimage)); env.TaskHash != want {
			t.Fatalf("%q: task_hash = %s, want %s (uri %q)", f[0], env.TaskHash, want, f[1])
		}
		if f[0] == "/api/a|b?" && env.TaskHash != "0x"+katTaskHashEdge {
			t.Fatalf("task_hash drifted from katTaskHashEdge:\n got  %s\n want 0x%s", env.TaskHash, katTaskHashEdge)
		}
	}
}

// The fixed receipt materials behind katTaskHash.
const (
	katTaskMethod = "POST"
	katTaskURI    = "/api/x?q=1"
	katTaskReq    = `{"q":"in"}`
	katTaskResp   = `{"a":"out"}`
	katTaskStatus = 201
)

// TestWriteServeProof_TaskHashKnownAnswer pins the taskHash the runtime signs
// to the preimage VerifiedFeedbackRegistry.attestFeedbackWithTask rebuilds —
// abi.encodePacked(method, uri, keccak256(reqBody), keccak256(respBody),
// decimal statusCode), i.e. a plain concatenation — both against an
// independent rebuild here and against the cross-implementation constant.
// Drift in field order, the URI form (RequestURI, query included) or the
// status encoding would orphan every receipt-opened attest.
func TestWriteServeProof_TaskHashKnownAnswer(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	reqBody, respBody := []byte(katTaskReq), []byte(katTaskResp)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(katTaskMethod, katTaskURI, strings.NewReader(katTaskReq))
	if err := writeServeProof(rec, req, crypto.FromECDSA(priv), reqBody, respBody, nil, katTaskStatus,
		"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}
	if rec.Code != katTaskStatus || rec.Body.String() != katTaskResp {
		t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), katTaskStatus, katTaskResp)
	}
	_, env := decodeProofHeader(t, rec.Header().Get("X-Agent-Proof"))

	var preimage []byte
	preimage = append(preimage, katTaskMethod...)
	preimage = append(preimage, katTaskURI...)
	preimage = append(preimage, crypto.Keccak256(reqBody)...)
	preimage = append(preimage, crypto.Keccak256(respBody)...)
	preimage = append(preimage, strconv.Itoa(katTaskStatus)...)
	if want := "0x" + hex.EncodeToString(crypto.Keccak256(preimage)); env.TaskHash != want {
		t.Fatalf("task_hash = %s, want the independently rebuilt %s", env.TaskHash, want)
	}
	if env.TaskHash != "0x"+katTaskHash {
		t.Fatalf("task_hash drifted from the cross-impl vector:\n got  %s\n want 0x%s", env.TaskHash, katTaskHash)
	}
}

// Rebuild the contract's signed digest from the envelope — independently of
// serveProofHash / serveProofDigest, which the KAT below pins — and recover
// the signer: it must equal the agentSeal address. This pins the Go signing to
// VerifiedFeedbackRegistry._verifyServeProof's expectations:
//
//	proofHash = keccak256(abi.encode(chainId, identityRegistry, submitter,
//	            agentId, timestamp, deadline, taskHash,
//	            keccak256(abi.encodePacked(dataHashes)), frameworkHash))
//	digest    = keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)   (EIP-191 v0x00)
func TestWriteServeProof_RecoversToAgentSeal(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	privBytes := crypto.FromECDSA(priv)
	wantSigner := crypto.PubkeyToAddress(priv.PublicKey)

	frameworkHash := "0x" + strings.Repeat("11", 32)
	chainID := "16602"
	identityAddr := "0x00000000000000000000000000000000000000A9"
	submitter := "0x00000000000000000000000000000000000000c1"
	dataHashes := map[string]state.DimHashes{
		"framework":     {ContentHash: "0xaa", DataHash: "0x" + strings.Repeat("22", 32)},
		"openclaw.json": {ContentHash: "0xbb", DataHash: "0x" + strings.Repeat("33", 32)},
		"workspace/":    {ContentHash: "0xcc", DataHash: ""}, // no chain pin → skipped
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/chat", strings.NewReader("hello"))
	req.Header.Set(clientAddressHeader, submitter)
	body := []byte("world")
	if err := writeServeProof(rec, req, privBytes, []byte("hello"), body, dataHashes, 200, "30", frameworkHash, chainID, identityAddr, testValidator); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}

	sig, env := decodeProofHeader(t, rec.Header().Get("X-Agent-Proof"))

	// Envelope shape: dim without a chain pin must be excluded.
	if len(env.DataHashes) != 2 {
		t.Fatalf("expected 2 on-chain dataHashes, got %d", len(env.DataHashes))
	}
	if env.AgentID != "30" || env.FrameworkHash != frameworkHash {
		t.Fatalf("envelope identity mismatch: %+v", env)
	}
	if !strings.EqualFold(env.Submitter, submitter) {
		t.Fatalf("envelope submitter = %q, want %q", env.Submitter, submitter)
	}
	// validator is diagnostics-only, echoed in the same lowercase 0x-hex style
	// as submitter.
	if env.Validator != strings.ToLower(testValidator) {
		t.Fatalf("envelope validator = %q, want %q", env.Validator, strings.ToLower(testValidator))
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
	chainIDBig, _ := new(big.Int).SetString(chainID, 10)
	encoded := concat(
		word256(chainIDBig),
		addrWord(identityAddr),
		addrWord(env.Submitter),
		word256(agentIDBig),
		word256(big.NewInt(env.Timestamp)),
		word256(big.NewInt(env.Deadline)),
		taskHash,
		crypto.Keccak256(packed),
		fwBytes,
	)
	proofHash := crypto.Keccak256(encoded)
	validatorBytes := common.HexToAddress(testValidator).Bytes()
	digest := crypto.Keccak256([]byte{0x19, 0x00}, validatorBytes, proofHash)

	if got := recoverSigner(t, digest, sig); got != wantSigner {
		t.Fatalf("recovered %s, want agentSeal %s", got.Hex(), wantSigner.Hex())
	}

	// Negative: the legacy personal_sign wrap of the same proofHash must NOT
	// recover to agentSeal — sealed signs only the v0x00 digest, so nothing it
	// emits verifies under the scheme the registry dropped.
	legacy := crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), proofHash)
	if got := recoverSigner(t, legacy, sig); got == wantSigner {
		t.Fatal("signature also verifies under the legacy personal_sign wrap")
	}
	// Negative: bound to its validator — under any other registry address the
	// same signature recovers to someone else.
	other := crypto.Keccak256([]byte{0x19, 0x00}, common.HexToAddress("0x00000000000000000000000000000000000000B8").Bytes(), proofHash)
	if got := recoverSigner(t, other, sig); got == wantSigner {
		t.Fatal("signature verifies under a different validator")
	}
}

func TestWriteServeProof_SkipsWhenNoIdentity(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	// agentID "" (unminted / dev) → body written, no proof header.
	if err := writeServeProof(rec, req, crypto.FromECDSA(priv), nil, []byte("x"), nil, 200, "", "", "", "", testValidator); err != nil {
		t.Fatalf("writeServeProof: %v", err)
	}
	if rec.Header().Get("X-Agent-Proof") != "" {
		t.Fatal("expected no proof header when identity is absent")
	}
	if rec.Body.String() != "x" {
		t.Fatalf("body = %q, want x", rec.Body.String())
	}
}

// A fully-armed agent without a usable validator (VERIFIED_FEEDBACK_ADDR
// unset, malformed or zero) serves the body unsigned — the same path as "no
// chain identity". It must never fall back to the legacy personal_sign wrap.
func TestWriteServeProof_NoValidatorNoProof(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	for _, validator := range []string{
		"",
		"   ",
		"0x1234",
		"not-an-address",
		"0x0000000000000000000000000000000000000000",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/hello", nil)
		err := writeServeProof(rec, req, crypto.FromECDSA(priv), nil, []byte("x"), nil, 201,
			"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", validator)
		if err != nil {
			t.Fatalf("validator %q: writeServeProof: %v", validator, err)
		}
		if h := rec.Header().Get("X-Agent-Proof"); h != "" {
			t.Fatalf("validator %q: expected no proof header, got %q", validator, h)
		}
		if rec.Code != 201 || rec.Body.String() != "x" {
			t.Fatalf("validator %q: got %d %q, want 201 x", validator, rec.Code, rec.Body.String())
		}
	}
}

// X-Client-Address is client-controlled. Anything but a 20-byte hex address —
// including over-long values that used to panic word256 (> 32 bytes) or get
// signed as a non-address word (21–32 bytes) — means "no redeemer declared":
// the zero submitter, the same in the signed digest and in the envelope.
func TestWriteServeProof_MalformedClientAddressIsZero(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	wantSigner := crypto.PubkeyToAddress(priv.PublicKey)
	const identityAddr = "0x00000000000000000000000000000000000000A9"
	for _, addr := range []string{
		"0x" + strings.Repeat("ab", 33), // > 32 bytes: used to panic
		"0x" + strings.Repeat("ab", 21), // 21 bytes: used to sign a non-address word
		"0xC1",                          // short
		"not-an-address",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/hello", nil)
		req.Header.Set(clientAddressHeader, addr)
		if err := writeServeProof(rec, req, crypto.FromECDSA(priv), nil, []byte("x"), nil, 200,
			"30", "0x"+strings.Repeat("11", 32), "16602", identityAddr, testValidator); err != nil {
			t.Fatalf("%q: writeServeProof: %v", addr, err)
		}
		sig, env := decodeProofHeader(t, rec.Header().Get("X-Agent-Proof"))
		if env.Submitter != "0x0000000000000000000000000000000000000000" {
			t.Fatalf("%q: envelope submitter = %q, want the zero address", addr, env.Submitter)
		}
		taskHash, _ := hexToBytes32(env.TaskHash)
		fwBytes, _ := hexToBytes32(env.FrameworkHash)
		proofHash := serveProofHash(big.NewInt(16602), addrWord(identityAddr), make([]byte, 32),
			big.NewInt(30), env.Timestamp, env.Deadline, taskHash, nil, fwBytes)
		digest := serveProofDigest(common.HexToAddress(testValidator), proofHash)
		if got := recoverSigner(t, digest, sig); got != wantSigner {
			t.Fatalf("%q: signature is not over the zero-submitter digest (recovered %s)", addr, got.Hex())
		}
	}
}

// TestServeProofDigest_KnownAnswerVector drives the production serveProofHash
// and serveProofDigest with fixed inputs and pins both to the cross-
// implementation constants (see the const block above). Drift in field order,
// encoding, or the outer wrap fails here.
func TestServeProofDigest_KnownAnswerVector(t *testing.T) {
	taskHash, _ := hexToBytes32("0x" + strings.Repeat("11", 32))
	dh0, _ := hexToBytes32("0x" + strings.Repeat("22", 32))
	dh1, _ := hexToBytes32("0x" + strings.Repeat("33", 32))
	fwBytes, _ := hexToBytes32("0x" + strings.Repeat("44", 32))
	packed := append(append([]byte{}, dh0...), dh1...)

	proofHash := serveProofHash(
		big.NewInt(16602), // chainId
		addrWord("0x00000000000000000000000000000000000000A9"), // identityRegistry
		addrWord("0x00000000000000000000000000000000000000C1"), // submitter
		big.NewInt(42), // agentId
		1700000000,     // timestamp
		1700003600,     // deadline
		taskHash,
		packed,
		fwBytes,
	)
	if got := hex.EncodeToString(proofHash); got != katProofHash {
		t.Fatalf("serve-proof hash drifted from cross-impl vector:\n got  0x%s\n want 0x%s", got, katProofHash)
	}

	validator, ok := parseValidator(testValidator)
	if !ok {
		t.Fatalf("parseValidator(%s) rejected a valid address", testValidator)
	}
	digest := hex.EncodeToString(serveProofDigest(validator, proofHash))
	if digest != katV0Digest {
		t.Fatalf("serve-proof v0x00 digest drifted from cross-impl vector:\n got  0x%s\n want 0x%s", digest, katV0Digest)
	}
	// The legacy wrap is a different digest — pinned here so the "rejected"
	// vector stays the one the other implementations assert against.
	legacy := hex.EncodeToString(crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), proofHash))
	if legacy != katLegacyDigest {
		t.Fatalf("legacy digest vector drifted:\n got  0x%s\n want 0x%s", legacy, katLegacyDigest)
	}
	if digest == legacy {
		t.Fatal("v0x00 digest equals the legacy personal_sign digest")
	}
}

// decodeProofHeader splits X-Agent-Proof into its 65-byte signature and the
// decoded envelope.
func decodeProofHeader(t *testing.T, header string) ([]byte, serveProof) {
	t.Helper()
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
	return sig, env
}

// recoverSigner recovers the address behind a 65-byte {27,28}-V signature
// over a raw 32-byte digest.
func recoverSigner(t *testing.T, digest, sig []byte) common.Address {
	t.Helper()
	recSig := make([]byte, 65)
	copy(recSig, sig)
	recSig[64] -= 27 // recover expects V in {0,1}
	pub, err := crypto.SigToPub(digest, recSig)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	return crypto.PubkeyToAddress(*pub)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
