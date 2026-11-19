package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/state"
)

// ServeProof v2 known-answer vectors (sealed/LAYERS.md §7), computed
// independently with Foundry's cast (cast abi-encode + cast keccak; the same
// procedure reproduces katProofHash) from the v1 vector's fixed tuple plus
// sealedHash 0x55…55, harnessHash 0x66…66, inferenceURL
// "https://router.example/v1" and model "model-x". The other ServeProof
// implementations assert the same values.
const (
	katV2Tag        = "bb9f274649f44f7d428828efb016a5eec5ee4a38dda5d4ec21b530ccafeda1d3"
	katProofHashV2  = "dac99843c8993224fa49be6989ea6cb8fc3c5190e2d2e8be132e9d073ba73a73"
	katV0DigestV2   = "50f91a86a4e744dddd29bc16e936ab717a8c54074458e4332c5f43661538df4e"
	katInferenceURL = "https://router.example/v1"
	katModel        = "model-x"
)

func TestServeProofDigestV2_KnownAnswerVector(t *testing.T) {
	if got := hex.EncodeToString(serveProofV2Tag); got != katV2Tag {
		t.Fatalf("v2 tag = 0x%s, want 0x%s", got, katV2Tag)
	}
	taskHash, _ := hexToBytes32("0x" + strings.Repeat("11", 32))
	dh0, _ := hexToBytes32("0x" + strings.Repeat("22", 32))
	dh1, _ := hexToBytes32("0x" + strings.Repeat("33", 32))
	fwBytes, _ := hexToBytes32("0x" + strings.Repeat("44", 32))
	sealedBytes, _ := hexToBytes32("0x" + strings.Repeat("55", 32))
	harnessBytes, _ := hexToBytes32("0x" + strings.Repeat("66", 32))
	packed := append(append([]byte{}, dh0...), dh1...)

	proofHash := serveProofHashV2(
		big.NewInt(16602),
		addrWord("0x00000000000000000000000000000000000000A9"),
		addrWord("0x00000000000000000000000000000000000000C1"),
		big.NewInt(42),
		1700000000,
		1700003600,
		taskHash,
		packed,
		fwBytes,
		sealedBytes,
		harnessBytes,
		katInferenceURL,
		katModel,
	)
	if got := hex.EncodeToString(proofHash); got != katProofHashV2 {
		t.Fatalf("v2 serve-proof hash drifted from the cross-impl vector:\n got  0x%s\n want 0x%s", got, katProofHashV2)
	}
	validator, _ := parseValidator(testValidator)
	if got := hex.EncodeToString(serveProofDigest(validator, proofHash)); got != katV0DigestV2 {
		t.Fatalf("v2 serve-proof digest drifted from the cross-impl vector:\n got  0x%s\n want 0x%s", got, katV0DigestV2)
	}
	// The v1 hash of the same shared fields is a different value.
	if v1 := hex.EncodeToString(serveProofHash(big.NewInt(16602), addrWord("0x00000000000000000000000000000000000000A9"),
		addrWord("0x00000000000000000000000000000000000000C1"), big.NewInt(42), 1700000000, 1700003600,
		taskHash, packed, fwBytes)); v1 == katProofHashV2 {
		t.Fatal("v1 and v2 hashes coincide")
	}
}

// A v2 proof: the envelope carries version 2 and the four new fields, and
// the signature recovers to agentSeal over the digest rebuilt from the
// envelope (independently of serveProofHashV2), not over the v1 digest.
func TestWriteServeProofV2_RecoversToAgentSeal(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	wantSigner := crypto.PubkeyToAddress(priv.PublicKey)
	const (
		frameworkHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
		identityAddr  = "0x00000000000000000000000000000000000000A9"
	)
	layers := &ProofLayers{
		SealedHash:   "0x" + strings.Repeat("55", 32),
		HarnessHash:  "0x" + strings.Repeat("66", 32),
		InferenceURL: katInferenceURL,
		Model:        katModel,
	}
	dataHashes := map[string]state.DimHashes{
		"APPEND_SYSTEM.md": {ContentHash: "0xaa", DataHash: "0x" + strings.Repeat("22", 32)},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	if err := writeServeProofLayered(rec, req, crypto.FromECDSA(priv), nil, []byte("body"), dataHashes, http.StatusOK,
		"30", frameworkHash, "16602", identityAddr, testValidator, layers); err != nil {
		t.Fatalf("writeServeProofLayered: %v", err)
	}
	sig, env := decodeProofHeaderV2(t, rec.Header().Get("X-Agent-Proof"))
	if env.Version != 2 || env.SealedHash != layers.SealedHash || env.HarnessHash != layers.HarnessHash ||
		env.InferenceURL != katInferenceURL || env.Model != katModel || env.FrameworkHash != frameworkHash {
		t.Fatalf("v2 envelope = %+v", env)
	}

	var packed []byte
	for _, dh := range env.DataHashes {
		b, _ := hexToBytes32(dh)
		packed = append(packed, b...)
	}
	taskHash, _ := hexToBytes32(env.TaskHash)
	fwBytes, _ := hexToBytes32(env.FrameworkHash)
	sealedBytes, _ := hexToBytes32(env.SealedHash)
	harnessBytes, _ := hexToBytes32(env.HarnessHash)
	proofHash := crypto.Keccak256(concat(
		crypto.Keccak256([]byte("AgentDNA.ServeProof.v2")),
		word256(big.NewInt(16602)),
		addrWord(identityAddr),
		addrWord(env.Submitter),
		word256(big.NewInt(30)),
		word256(big.NewInt(env.Timestamp)),
		word256(big.NewInt(env.Deadline)),
		taskHash,
		crypto.Keccak256(packed),
		fwBytes,
		sealedBytes,
		harnessBytes,
		crypto.Keccak256([]byte(env.InferenceURL)),
		crypto.Keccak256([]byte(env.Model)),
	))
	digest := crypto.Keccak256([]byte{0x19, 0x00}, common.HexToAddress(testValidator).Bytes(), proofHash)
	if got := recoverSigner(t, digest, sig); got != wantSigner {
		t.Fatalf("recovered %s, want agentSeal %s", got.Hex(), wantSigner.Hex())
	}
	v1 := serveProofDigest(common.HexToAddress(testValidator), serveProofHash(big.NewInt(16602), addrWord(identityAddr),
		addrWord(env.Submitter), big.NewInt(30), env.Timestamp, env.Deadline, taskHash, packed, fwBytes))
	if got := recoverSigner(t, v1, sig); got == wantSigner {
		t.Fatal("a v2 signature verifies as a v1 proof")
	}
}

// A v1 proof stays exactly v1: no version field, no layer fields.
func TestWriteServeProof_V1EnvelopeUnchanged(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	rec := httptest.NewRecorder()
	if err := writeServeProofLayered(rec, httptest.NewRequest(http.MethodGet, "/hello", nil), crypto.FromECDSA(priv), nil, []byte("x"), nil, 200,
		"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator, nil); err != nil {
		t.Fatal(err)
	}
	_, envB64, _ := strings.Cut(rec.Header().Get("X-Agent-Proof"), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(envB64)
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "sealed_hash", "harness_hash", "inference_url", "model"} {
		if _, ok := fields[k]; ok {
			t.Fatalf("v1 envelope carries %q: %s", k, raw)
		}
	}
}

// A layer hash that is not 32 bytes of hex signs nothing: the body goes out
// without a proof rather than with a proof no verifier can rebuild.
func TestWriteServeProofV2_MalformedLayerHashNoProof(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	for _, l := range []*ProofLayers{
		{SealedHash: "", HarnessHash: "0x" + strings.Repeat("66", 32)},
		{SealedHash: "0x" + strings.Repeat("55", 32), HarnessHash: "0x1234"},
	} {
		rec := httptest.NewRecorder()
		if err := writeServeProofLayered(rec, httptest.NewRequest(http.MethodGet, "/hello", nil), crypto.FromECDSA(priv), nil, []byte("x"), nil, 200,
			"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator, l); err != nil {
			t.Fatal(err)
		}
		if h := rec.Header().Get("X-Agent-Proof"); h != "" {
			t.Fatalf("layers %+v: proof header %q, want none", l, h)
		}
		if rec.Body.String() != "x" {
			t.Fatalf("body = %q", rec.Body.String())
		}
	}
}

// layersForProof: nothing set means v1; set and not ok means no proof at all
// (never v1); ok signs what the provider names at that moment.
func TestServerLayersForProof(t *testing.T) {
	s := New(state.New(), "")
	if l, ok := s.layersForProof(); l != nil || !ok {
		t.Fatalf("without SetProofLayers: %+v %v, want a v1 proof", l, ok)
	}
	ready := false
	want := ProofLayers{SealedHash: "0xs", HarnessHash: "0xh", InferenceURL: katInferenceURL, Model: katModel}
	s.SetProofLayers(func() (ProofLayers, bool) { return want, ready })
	if l, ok := s.layersForProof(); l != nil || ok {
		t.Fatalf("while the layers are unknown: %+v %v, want no proof", l, ok)
	}
	ready = true
	if l, ok := s.layersForProof(); l == nil || !ok || *l != want {
		t.Fatalf("layersForProof = %+v %v", l, ok)
	}
}

// Under the layered runtime, a response while the layers are unknown goes
// out without a proof: never a v1 one.
func TestServeWithProof_NoV1UnderTheLayeredRuntime(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	s := New(state.New(), "")
	s.SetProofLayers(func() (ProofLayers, bool) { return ProofLayers{}, false })
	rec := httptest.NewRecorder()
	if err := s.serveWithProof(rec, httptest.NewRequest(http.MethodGet, "/hello", nil), crypto.FromECDSA(priv), nil, []byte("x"), nil, 200,
		"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator); err != nil {
		t.Fatal(err)
	}
	if h := rec.Header().Get("X-Agent-Proof"); h != "" || rec.Body.String() != "x" {
		t.Fatalf("proof %q, body %q: want the body without a proof", h, rec.Body.String())
	}
}

// The v2 vector with a model name outside ASCII (sealed/LAYERS.md §7): the
// strings are hashed as their UTF-8 bytes. The other ServeProof
// implementations assert the same values (computed with cast, the procedure
// above).
const (
	katModelUTF8       = "模型-é"
	katModelUTF8Bytes  = "e6a8a1e59e8b2dc3a9"
	katProofHashV2UTF8 = "00dc0a9ba85191968c4bdcb00d11b4003216306420d80a6e68432fe01f24a977"
	katV0DigestV2UTF8  = "cab300c137d0d07deb4e73c3e027db4ff63df5045e0a95767519cce28ffbd963"
)

func TestServeProofDigestV2_NonASCIIModelVector(t *testing.T) {
	if got := hex.EncodeToString([]byte(katModelUTF8)); got != katModelUTF8Bytes {
		t.Fatalf("model bytes %s, want %s", got, katModelUTF8Bytes)
	}
	taskHash, _ := hexToBytes32("0x" + strings.Repeat("11", 32))
	dh0, _ := hexToBytes32("0x" + strings.Repeat("22", 32))
	dh1, _ := hexToBytes32("0x" + strings.Repeat("33", 32))
	fwBytes, _ := hexToBytes32("0x" + strings.Repeat("44", 32))
	sealedBytes, _ := hexToBytes32("0x" + strings.Repeat("55", 32))
	harnessBytes, _ := hexToBytes32("0x" + strings.Repeat("66", 32))
	proofHash := serveProofHashV2(big.NewInt(16602), addrWord("0x00000000000000000000000000000000000000A9"),
		addrWord("0x00000000000000000000000000000000000000C1"), big.NewInt(42), 1700000000, 1700003600,
		taskHash, append(append([]byte{}, dh0...), dh1...), fwBytes, sealedBytes, harnessBytes, katInferenceURL, katModelUTF8)
	if got := hex.EncodeToString(proofHash); got != katProofHashV2UTF8 {
		t.Fatalf("v2 serve-proof hash (non-ASCII model):\n got  0x%s\n want 0x%s", got, katProofHashV2UTF8)
	}
	validator, _ := parseValidator(testValidator)
	if got := hex.EncodeToString(serveProofDigest(validator, proofHash)); got != katV0DigestV2UTF8 {
		t.Fatalf("v2 serve-proof digest (non-ASCII model):\n got  0x%s\n want 0x%s", got, katV0DigestV2UTF8)
	}
}

// The envelope carries such a model as raw UTF-8 (not \u escapes, not
// Latin-1), so a verifier that decodes the base64 to bytes and the bytes as
// UTF-8 gets the string that was hashed.
func TestWriteServeProofV2_ModelGoesOutAsUTF8(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	rec := httptest.NewRecorder()
	layers := &ProofLayers{SealedHash: "0x" + strings.Repeat("55", 32), HarnessHash: "0x" + strings.Repeat("66", 32),
		InferenceURL: katInferenceURL, Model: katModelUTF8}
	if err := writeServeProofLayered(rec, httptest.NewRequest(http.MethodGet, "/hello", nil), crypto.FromECDSA(priv), nil, []byte("x"), nil, 200,
		"30", "0x"+strings.Repeat("11", 32), "16602", "0x00000000000000000000000000000000000000A9", testValidator, layers); err != nil {
		t.Fatal(err)
	}
	_, envB64, _ := strings.Cut(rec.Header().Get("X-Agent-Proof"), ".")
	raw, err := base64.RawURLEncoding.DecodeString(envB64)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hex.EncodeToString(raw), katModelUTF8Bytes) {
		t.Fatalf("envelope %q does not carry the model's UTF-8 bytes", raw)
	}
	_, env := decodeProofHeaderV2(t, rec.Header().Get("X-Agent-Proof"))
	if env.Model != katModelUTF8 {
		t.Fatalf("model %q, want %q", env.Model, katModelUTF8)
	}
}

// decodeProofHeaderV2 is decodeProofHeader for a v2 envelope.
func decodeProofHeaderV2(t *testing.T, header string) ([]byte, serveProofV2) {
	t.Helper()
	sigHex, envB64, ok := strings.Cut(header, ".")
	if !ok {
		t.Fatalf("malformed header %q", header)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("bad sig: %v len=%d", err, len(sig))
	}
	raw, err := base64.RawURLEncoding.DecodeString(envB64)
	if err != nil {
		t.Fatalf("bad envelope b64: %v", err)
	}
	var env serveProofV2
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal v2 envelope: %v", err)
	}
	return sig, env
}
