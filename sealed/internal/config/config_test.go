package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"seal-verify/internal/provision"
)

// VERIFIED_FEEDBACK_ADDR is normalized at boot: anything that can't name the
// registry proxy becomes "" (serve-proofs off), never a partial value the
// proxy might sign against.
func TestVerifiedFeedbackAddr_Normalizes(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"unset", "", ""},
		{"blank", "   ", ""},
		{"malformed", "0x1234", ""},
		{"not hex", "0xZZ000000000000000000000000000000000000B7", ""},
		{"zero address", "0x0000000000000000000000000000000000000000", ""},
		// EIP-55's own test vector.
		{"lowercase → checksummed", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"surrounding space", " 0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED\n", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
	}
	for _, c := range cases {
		if got := verifiedFeedbackAddr(c.raw); got != c.want {
			t.Errorf("%s: verifiedFeedbackAddr(%q) = %q, want %q", c.name, c.raw, got, c.want)
		}
	}
}

func TestVerifyAttestationV2AppSignerAndTamper(t *testing.T) {
	data, err := os.ReadFile("../provision/testdata/attestation-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelope     provision.Attestation `json:"envelope"`
		AppSigner    string                `json:"app_signer"`
		ContainerKey string                `json:"test_container_private_key"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimPrefix(vector.ContainerKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	appSigner := common.HexToAddress(vector.AppSigner)
	if err := verifyAttestation(key, vector.Envelope, &appSigner); err != nil {
		t.Fatal(err)
	}
	// The signature is from the app key, not this independent boot/node key.
	nodeKey, err := crypto.HexToECDSA(strings.Repeat("03", 32))
	if err != nil {
		t.Fatal(err)
	}
	nodeSigner := crypto.PubkeyToAddress(nodeKey.PublicKey)
	if err := verifyAttestation(key, vector.Envelope, &nodeSigner); err == nil {
		t.Fatal("app signature accepted as node signature")
	}
	changes := map[string]func(*provision.Attestation){
		"missing version": func(a *provision.Attestation) { a.Version = 0 },
		"legacy version":  func(a *provision.Attestation) { a.Version = 1 },
		"unknown version": func(a *provision.Attestation) { a.Version = 3 },
		"chain":           func(a *provision.Attestation) { a.ChainID++ },
		"registry":        func(a *provision.Attestation) { a.RegistryAddress = "0x" + strings.Repeat("44", 20) },
		"app exact bytes": func(a *provision.Attestation) { a.AppID += " " },
		"epoch":           func(a *provision.Attestation) { a.RegisteredAt++ },
		"seal":            func(a *provision.Attestation) { a.SealID = strings.Repeat("44", 32) },
		"container key": func(a *provision.Attestation) {
			a.Pubkey = "0x" + hex.EncodeToString(crypto.CompressPubkey(&nodeKey.PublicKey))
		},
		"image":     func(a *provision.Attestation) { a.ImageHash = "sha256:" + strings.Repeat("44", 32) },
		"issued at": func(a *provision.Attestation) { a.Ts++ },
		"signature": func(a *provision.Attestation) { a.Signature = a.Signature[:2] + "00" + a.Signature[4:] },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			a := vector.Envelope
			change(&a)
			if err := verifyAttestation(key, a, &appSigner); err == nil {
				t.Fatal("tampered envelope passed Phase 0")
			}
		})
	}
}

func TestLoadRejectsValidLegacyPayloadWithoutFallback(t *testing.T) {
	appKey, err := crypto.HexToECDSA(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	containerKey, err := crypto.HexToECDSA(strings.Repeat("02", 32))
	if err != nil {
		t.Fatal(err)
	}
	a := provision.Attestation{Version: 1, SealID: strings.Repeat("22", 32), Pubkey: "0x" + hex.EncodeToString(crypto.CompressPubkey(&containerKey.PublicKey)), ImageHash: "sha256:" + strings.Repeat("33", 32), Ts: 1793000000}
	legacyDigest := crypto.Keccak256Hash([]byte(fmt.Sprintf("ImageAttestation:%s:%s:%s:%d", a.SealID, a.Pubkey, a.ImageHash, a.Ts)))
	sig, err := crypto.Sign(legacyDigest[:], appKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	a.Signature = "0x" + hex.EncodeToString(sig)
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDBOX_SEAL_KEY", "0x"+strings.Repeat("02", 32))
	t.Setenv("SANDBOX_SEAL_ATTESTATION", string(raw))
	t.Setenv("TEE_SIGNER_ADDRESS", crypto.PubkeyToAddress(appKey.PublicKey).Hex())
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "v2 required") {
		t.Fatalf("legacy payload not rejected explicitly: %v", err)
	}
}

func TestProvisioningSecretsDoNotReachFrameworkEnvironment(t *testing.T) {
	for _, name := range []string{"SEAL_BOOT_TICKET", "SANDBOX_SEAL_KEY", "SANDBOX_SEAL_ATTESTATION", "API_KEY", "SEAL_SECRET_ENV"} {
		t.Setenv(name, "test-secret")
	}
	key := []byte{1, 2, 3}
	ScrubProvisioningSecrets(key)
	for _, name := range []string{"SEAL_BOOT_TICKET", "SANDBOX_SEAL_KEY", "SANDBOX_SEAL_ATTESTATION", "API_KEY", "SEAL_SECRET_ENV"} {
		if os.Getenv(name) != "" {
			t.Errorf("%s retained", name)
		}
	}
	for _, b := range key {
		if b != 0 {
			t.Fatal("key retained")
		}
	}
}
