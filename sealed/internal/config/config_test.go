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

// certificateVector is the shared v3 known-answer vector.
type certificateVector struct {
	ProviderKey struct {
		Address string `json:"address"`
	} `json:"test_only_provider_key"`
	ContainerKey struct {
		PrivateKey string `json:"private_key"`
	} `json:"test_only_container_key"`
	Wire string `json:"sandbox_seal_attestation"`
}

func loadCertificateVector(t *testing.T) certificateVector {
	t.Helper()
	data, err := os.ReadFile("../provision/testdata/image-attestation-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector certificateVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestLoadVerifiesV3CertificateAndRecoversProvider(t *testing.T) {
	vector := loadCertificateVector(t)
	t.Setenv("SANDBOX_SEAL_KEY", vector.ContainerKey.PrivateKey)
	t.Setenv("SANDBOX_SEAL_ATTESTATION", vector.Wire)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProviderSigner.Hex() != vector.ProviderKey.Address {
		t.Fatalf("provider %s, want %s", cfg.ProviderSigner.Hex(), vector.ProviderKey.Address)
	}
	if string(cfg.Certificate) != vector.Wire {
		t.Fatal("certificate not kept verbatim for /provision")
	}
	anchor := cfg.AttestorAnchor()
	if anchor.ChainID != 16602 || !strings.EqualFold(anchor.Registry.Hex(), cfg.Attestation.RegistryAddress) || anchor.Provider != cfg.ProviderSigner {
		t.Fatalf("anchor %+v", anchor)
	}
}

// The env value is forwarded at first /provision; anything but exactly one
// JSON object is refused in Phase 0, and surrounding whitespace is dropped.
func TestLoadKeepsOnlyOneCompactCertificate(t *testing.T) {
	vector := loadCertificateVector(t)
	t.Setenv("SANDBOX_SEAL_KEY", vector.ContainerKey.PrivateKey)
	for _, trailing := range []string{"}", "]", "{}"} {
		t.Setenv("SANDBOX_SEAL_ATTESTATION", vector.Wire+trailing)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "trailing data") {
			t.Fatalf("certificate with trailing %q accepted: %v", trailing, err)
		}
	}
	t.Setenv("SANDBOX_SEAL_ATTESTATION", " \n"+vector.Wire+"\n ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Certificate) != vector.Wire {
		t.Fatalf("certificate kept as %q", cfg.Certificate)
	}
	if _, err := json.Marshal(cfg.Certificate); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsCertificateNotForThisKey(t *testing.T) {
	vector := loadCertificateVector(t)
	t.Setenv("SANDBOX_SEAL_ATTESTATION", vector.Wire)
	t.Setenv("SANDBOX_SEAL_KEY", "0x"+strings.Repeat("02", 32))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "keypair mismatch") {
		t.Fatalf("certificate for another key accepted: %v", err)
	}
}

// Phase 0 has no signer pin: a certificate re-signed by any key verifies
// locally, and recovers that key, which the attestor then refuses unless it
// is the provider it trusts. A field changed after signing recovers some
// other address the same way.
func TestLoadRecoversWhicheverKeySigned(t *testing.T) {
	vector := loadCertificateVector(t)
	a, err := provision.ParseAttestation([]byte(vector.Wire))
	if err != nil {
		t.Fatal(err)
	}
	a.Ts++
	key, err := hex.DecodeString(strings.TrimPrefix(vector.ContainerKey.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := verifyAttestation(key, a)
	if err != nil {
		t.Fatal(err)
	}
	if signer == common.HexToAddress(vector.ProviderKey.Address) {
		t.Fatal("a changed certificate recovered the provider")
	}
}

func TestLoadRejectsOtherCertificateVersions(t *testing.T) {
	vector := loadCertificateVector(t)
	t.Setenv("SANDBOX_SEAL_KEY", vector.ContainerKey.PrivateKey)
	appKey, err := crypto.HexToECDSA(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	containerKey, err := crypto.HexToECDSA(strings.TrimPrefix(vector.ContainerKey.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	// A v1-style certificate, validly signed over its own legacy digest.
	a := provision.Attestation{Version: 1, SealID: strings.Repeat("22", 32), Pubkey: "0x" + hex.EncodeToString(crypto.CompressPubkey(&containerKey.PublicKey)), ImageHash: "sha256:" + strings.Repeat("33", 32), Ts: 1793000000}
	legacyDigest := crypto.Keccak256Hash([]byte(fmt.Sprintf("ImageAttestation:%s:%s:%s:%d", a.SealID, a.Pubkey, a.ImageHash, a.Ts)))
	sig, err := crypto.Sign(legacyDigest[:], appKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	a.Signature = "0x" + hex.EncodeToString(sig)
	legacy, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"v1": string(legacy),
		"v2": strings.Replace(vector.Wire, `"version":3`, `"version":2`, 1),
		"v4": strings.Replace(vector.Wire, `"version":3`, `"version":4`, 1),
	} {
		t.Setenv("SANDBOX_SEAL_ATTESTATION", raw)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "v3 required") {
			t.Fatalf("%s certificate not rejected explicitly: %v", name, err)
		}
	}
}

// /log is public: a malformed SANDBOX_SEAL_KEY never appears in the error.
func TestLoadNeverEchoesTheSealKey(t *testing.T) {
	vector := loadCertificateVector(t)
	t.Setenv("SANDBOX_SEAL_ATTESTATION", vector.Wire)
	for _, key := range []string{"0x" + strings.Repeat("7z", 32), strings.Repeat("ab", 31), "secret-value"} {
		t.Setenv("SANDBOX_SEAL_KEY", key)
		_, err := Load()
		if err == nil {
			t.Fatalf("malformed key %q accepted", key)
		}
		if strings.Contains(err.Error(), strings.TrimPrefix(key, "0x")[:6]) || strings.Contains(err.Error(), "U+") {
			t.Fatalf("error echoes the key: %v", err)
		}
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
