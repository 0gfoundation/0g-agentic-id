package provision

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type attestationVector struct {
	Envelope         Attestation    `json:"envelope"`
	EncodedWords     string         `json:"encoded_words"`
	Digest           string         `json:"digest"`
	AppSigner        string         `json:"app_signer"`
	ContainerKey     string         `json:"test_container_private_key"`
	ProvisionRequest map[string]any `json:"provision_request"`
}

func loadAttestationVector(t *testing.T) attestationVector {
	t.Helper()
	data, err := os.ReadFile("testdata/attestation-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector attestationVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestImageAttestationV2KnownAnswer(t *testing.T) {
	vector := loadAttestationVector(t)
	words, err := vector.Envelope.signingWords()
	if err != nil {
		t.Fatal(err)
	}
	if got := "0x" + hex.EncodeToString(words); got != vector.EncodedWords {
		t.Fatalf("nine-word encoding differs: %s", got)
	}
	digest, err := vector.Envelope.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const independentlyEncodedDigest = "0x89f5a12fefe1868ddbc9a3f31091db032edb737c0782c876b3a455a493744b38"
	if digest.Hex() != independentlyEncodedDigest || digest.Hex() != vector.Digest {
		t.Fatalf("digest differs: %s", digest.Hex())
	}
	signer, err := vector.Envelope.RecoverSigner()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Hex() != vector.AppSigner {
		t.Fatalf("app signer differs: %s", signer.Hex())
	}
	// Recovery byte normalization never changes the v2 signed payload.
	raw := vector.Envelope
	signature, err := hex.DecodeString(strings.TrimPrefix(raw.Signature, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	signature[64] -= 27
	raw.Signature = "0x" + hex.EncodeToString(signature)
	if recovered, err := raw.RecoverSigner(); err != nil || recovered != signer {
		t.Fatalf("raw recovery byte rejected: %v", err)
	}
}

func TestImageAttestationV2RejectsInvalidShapeAndLegacy(t *testing.T) {
	original := loadAttestationVector(t).Envelope
	cases := map[string]func(*Attestation){
		"missing version":     func(a *Attestation) { a.Version = 0 },
		"v1":                  func(a *Attestation) { a.Version = 1 },
		"unknown":             func(a *Attestation) { a.Version = 3 },
		"zero chain":          func(a *Attestation) { a.ChainID = 0 },
		"zero epoch":          func(a *Attestation) { a.RegisteredAt = 0 },
		"zero timestamp":      func(a *Attestation) { a.Ts = 0 },
		"zero registry":       func(a *Attestation) { a.RegistryAddress = "0x" + strings.Repeat("0", 40) },
		"short registry":      func(a *Attestation) { a.RegistryAddress = "0x1234" },
		"empty app":           func(a *Attestation) { a.AppID = "" },
		"long UTF8 app":       func(a *Attestation) { a.AppID = strings.Repeat("界", 86) },
		"invalid UTF8 app":    func(a *Attestation) { a.AppID = string([]byte{0xff}) },
		"prefixed seal":       func(a *Attestation) { a.SealID = "0x" + a.SealID },
		"short seal":          func(a *Attestation) { a.SealID = "aa" },
		"bad image prefix":    func(a *Attestation) { a.ImageHash = "0x" + strings.Repeat("3", 64) },
		"invalid pubkey":      func(a *Attestation) { a.Pubkey = "0x04" + strings.Repeat("0", 64) },
		"short signature":     func(a *Attestation) { a.Signature = "0x12" },
		"unknown recovery id": func(a *Attestation) { a.Signature = a.Signature[:130] + "1d" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := original
			change(&a)
			if _, err := a.RecoverSigner(); err == nil {
				t.Fatal("accepted invalid v2 envelope")
			}
		})
	}
	for _, raw := range []string{`{"version":2,"chain_id":-1}`, `{"version":2,"registered_at":18446744073709551616}`, `{"version":2,"ts":-1}`, `{"version":2.5}`} {
		var a Attestation
		if err := json.Unmarshal([]byte(raw), &a); err == nil {
			t.Fatalf("accepted non-uint64 JSON: %s", raw)
		}
	}
}

func TestImageAttestationV2ExactAppIDBytes(t *testing.T) {
	original := loadAttestationVector(t).Envelope
	original.AppID = "é"
	digest, err := original.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, appID := range []string{"e\u0301", "é ", "É"} {
		a := original
		a.AppID = appID
		changed, err := a.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if changed == digest {
			t.Fatalf("app_id was normalized: %q", appID)
		}
	}
}
