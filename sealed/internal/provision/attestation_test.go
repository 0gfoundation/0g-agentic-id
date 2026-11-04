package provision

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/eip712"
)

// certificateVector is testdata/image-attestation-v3.json, the known-answer
// vector shared byte-identical with the provider and the attestor.
type certificateVector struct {
	ProviderKey struct {
		PrivateKey string `json:"private_key"`
		Address    string `json:"address"`
	} `json:"test_only_provider_key"`
	ContainerKey struct {
		PrivateKey string `json:"private_key"`
		Address    string `json:"address"`
	} `json:"test_only_container_key"`
	TypedData        apitypes.TypedData `json:"typed_data"`
	TypeHash         string             `json:"type_hash"`
	DomainSeparator  string             `json:"domain_separator"`
	StructHash       string             `json:"struct_hash"`
	Digest           string             `json:"digest"`
	Signature        string             `json:"signature"`
	RecoveredAddress string             `json:"recovered_address"`
	Wire             string             `json:"sandbox_seal_attestation"`
}

func loadCertificateVector(t *testing.T) certificateVector {
	t.Helper()
	data, err := os.ReadFile("testdata/image-attestation-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector certificateVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func (v certificateVector) certificate(t *testing.T) Attestation {
	t.Helper()
	a, err := ParseAttestation([]byte(v.Wire))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (v certificateVector) containerKey(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString(strings.TrimPrefix(v.ContainerKey.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// resign signs a with the vector's provider key, as the provider would.
func (v certificateVector) resign(t *testing.T, a Attestation) Attestation {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.TrimPrefix(v.ProviderKey.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	signature[64] += 27
	a.Signature = "0x" + hex.EncodeToString(signature)
	return a
}

func TestContainerCertificateV3KnownAnswer(t *testing.T) {
	vector := loadCertificateVector(t)
	a := vector.certificate(t)
	if got := certificateTypeHash.Hex(); got != vector.TypeHash {
		t.Fatalf("type hash %s, want %s", got, vector.TypeHash)
	}
	domain, structHash, _, err := a.hashes()
	if err != nil {
		t.Fatal(err)
	}
	if domain.Hex() != vector.DomainSeparator || structHash.Hex() != vector.StructHash {
		t.Fatalf("domain %s struct %s differ from the vector", domain.Hex(), structHash.Hex())
	}
	digest, err := a.Digest()
	if err != nil || digest.Hex() != vector.Digest {
		t.Fatalf("digest %s (%v), want %s", digest.Hex(), err, vector.Digest)
	}
	// An independent EIP-712 implementation over the vector's typed data.
	typedDomain, err := vector.TypedData.HashStruct("EIP712Domain", vector.TypedData.Domain.Map())
	if err != nil {
		t.Fatal(err)
	}
	typedStruct, err := vector.TypedData.HashStruct(vector.TypedData.PrimaryType, vector.TypedData.Message)
	if err != nil {
		t.Fatal(err)
	}
	if hexutilString(typedDomain) != vector.DomainSeparator || hexutilString(typedStruct) != vector.StructHash {
		t.Fatal("go-ethereum apitypes disagrees with the vector")
	}
	if got := eip712.Digest(domain, structHash).Hex(); got != vector.Digest {
		t.Fatalf("0x1901 digest %s", got)
	}

	signer, err := a.RecoverSigner()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Hex() != vector.RecoveredAddress || signer.Hex() != vector.ProviderKey.Address {
		t.Fatalf("recovered %s, want %s", signer.Hex(), vector.RecoveredAddress)
	}
	if a.Signature != vector.Signature || vector.resign(t, a).Signature != vector.Signature {
		t.Fatal("deterministic re-signing does not reproduce the vector signature")
	}
	// The raw 0/1 recovery byte recovers the same signer.
	raw := a
	raw.Signature = a.Signature[:130] + "01"
	if a.Signature[130:] != "1c" {
		t.Fatalf("vector recovery byte %s", a.Signature[130:])
	}
	if got, err := raw.RecoverSigner(); err != nil || got != signer {
		t.Fatalf("v=1 recovered %s (%v)", got.Hex(), err)
	}
	// The certificate names the vector's container key.
	key, err := crypto.ToECDSA(vector.containerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if "0x"+hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey)) != a.Pubkey || crypto.PubkeyToAddress(key.PublicKey).Hex() != vector.ContainerKey.Address {
		t.Fatal("container key does not match the certificate pubkey")
	}
	if a.FrameworkHash() != vector.TypedData.Message["imageHash"] {
		t.Fatalf("framework hash %s", a.FrameworkHash())
	}
	if !strings.EqualFold(a.Registry().Hex(), vector.TypedData.Domain.VerifyingContract) {
		t.Fatalf("registry %s", a.Registry().Hex())
	}
}

func hexutilString(b []byte) string { return "0x" + hex.EncodeToString(b) }

func TestContainerCertificateV3RejectsInvalidShape(t *testing.T) {
	original := loadCertificateVector(t).certificate(t)
	cases := map[string]func(*Attestation){
		"missing version":    func(a *Attestation) { a.Version = 0 },
		"v1":                 func(a *Attestation) { a.Version = 1 },
		"v2":                 func(a *Attestation) { a.Version = 2 },
		"v4":                 func(a *Attestation) { a.Version = 4 },
		"zero chain":         func(a *Attestation) { a.ChainID = 0 },
		"zero registered_at": func(a *Attestation) { a.RegisteredAt = 0 },
		"zero ts":            func(a *Attestation) { a.Ts = 0 },
		"zero registry":      func(a *Attestation) { a.RegistryAddress = "0x" + strings.Repeat("0", 40) },
		"short registry":     func(a *Attestation) { a.RegistryAddress = "0x1234" },
		"empty app":          func(a *Attestation) { a.AppID = "" },
		"long app":           func(a *Attestation) { a.AppID = strings.Repeat("界", 86) },
		"invalid UTF-8 app":  func(a *Attestation) { a.AppID = string([]byte{0xff}) },
		"prefixed seal":      func(a *Attestation) { a.SealID = "0x" + a.SealID[2:] },
		"uppercase seal":     func(a *Attestation) { a.SealID = strings.ToUpper(a.SealID) },
		"short seal":         func(a *Attestation) { a.SealID = "aa" },
		"0x image hash":      func(a *Attestation) { a.ImageHash = "0x" + strings.Repeat("3", 64) },
		"uppercase image hash": func(a *Attestation) {
			a.ImageHash = "sha256:" + strings.ToUpper(strings.TrimPrefix(a.ImageHash, "sha256:"))
		},
		"uncompressed pubkey":  func(a *Attestation) { a.Pubkey = "0x04" + strings.Repeat("0", 128) },
		"not a curve point":    func(a *Attestation) { a.Pubkey = "0x02" + strings.Repeat("ff", 32) },
		"short signature":      func(a *Attestation) { a.Signature = "0x12" },
		"unknown recovery id":  func(a *Attestation) { a.Signature = a.Signature[:130] + "1d" },
		"unprefixed signature": func(a *Attestation) { a.Signature = a.Signature[2:] + "00" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := original
			change(&a)
			if _, err := a.RecoverSigner(); err == nil {
				t.Fatal("accepted an invalid certificate")
			}
			raw, _ := json.Marshal(a)
			var decoded Attestation
			// Skip shapes JSON cannot carry (invalid UTF-8 is replaced).
			if json.Unmarshal(raw, &decoded) == nil && decoded == a {
				if _, err := ParseAttestation(raw); err == nil {
					t.Fatal("ParseAttestation accepted an invalid certificate")
				}
			}
		})
	}
	vector := loadCertificateVector(t)
	for name, raw := range map[string]string{
		"unknown field":   strings.Replace(vector.Wire, `"ts":`, `"issued_at":1,"ts":`, 1),
		"trailing object": vector.Wire + `{}`,
		"trailing brace":  vector.Wire + `}`,
		"trailing ]":      vector.Wire + `]`,
		"negative chain":  strings.Replace(vector.Wire, `"chain_id":16602`, `"chain_id":-1`, 1),
		"uint64 overflow": strings.Replace(vector.Wire, `"registered_at":1792108800`, `"registered_at":18446744073709551616`, 1),
		"fractional ts":   strings.Replace(vector.Wire, `"ts":1793318445`, `"ts":1793318445.5`, 1),
		"string version":  strings.Replace(vector.Wire, `"version":3`, `"version":"3"`, 1),
		"not an object":   `"` + vector.Wire + `"`,
	} {
		if raw == vector.Wire {
			t.Fatalf("%s: fixture edit did not apply", name)
		}
		if _, err := ParseAttestation([]byte(raw)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Every signed field changes the digest, so a tampered certificate recovers
// some other signer, which the attestor does not trust.
func TestContainerCertificateV3BindsEveryField(t *testing.T) {
	vector := loadCertificateVector(t)
	original := vector.certificate(t)
	provider, err := original.RecoverSigner()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _ := crypto.HexToECDSA(strings.Repeat("03", 32))
	changes := map[string]func(*Attestation){
		"chain":          func(a *Attestation) { a.ChainID++ },
		"registry":       func(a *Attestation) { a.RegistryAddress = "0x" + strings.Repeat("44", 20) },
		"app exact byte": func(a *Attestation) { a.AppID += " " },
		"app NFC":        func(a *Attestation) { a.AppID = "0g-sandbox-providé" },
		"registered_at":  func(a *Attestation) { a.RegisteredAt++ },
		"seal":           func(a *Attestation) { a.SealID = strings.Repeat("44", 32) },
		"pubkey":         func(a *Attestation) { a.Pubkey = "0x" + hex.EncodeToString(crypto.CompressPubkey(&otherKey.PublicKey)) },
		"image":          func(a *Attestation) { a.ImageHash = "sha256:" + strings.Repeat("44", 32) },
		"ts":             func(a *Attestation) { a.Ts++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			a := original
			change(&a)
			if signer, err := a.RecoverSigner(); err == nil && signer == provider {
				t.Fatal("changed field still recovers the provider")
			}
		})
	}
	// The v2 domain and encoding are gone: a v2-style digest signed by the
	// provider key does not verify as v3.
	v2 := original
	v2Digest := crypto.Keccak256Hash([]byte("0g.sandbox.ImageAttestation.v2"))
	key, _ := crypto.HexToECDSA(strings.TrimPrefix(vector.ProviderKey.PrivateKey, "0x"))
	signature, _ := crypto.Sign(v2Digest[:], key)
	signature[64] += 27
	v2.Signature = "0x" + hex.EncodeToString(signature)
	if signer, err := v2.RecoverSigner(); err == nil && signer == provider {
		t.Fatal("a signature over another digest recovered the provider")
	}
}

func TestContainerCertificateV3ExactAppIDBytes(t *testing.T) {
	original := loadCertificateVector(t).certificate(t)
	original.AppID = "é"
	digest, err := original.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, appID := range []string{"é", "é ", "É"} {
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
