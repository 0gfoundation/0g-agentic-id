package attestorhttp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/eip712"
)

// statementVector is testdata/attestor-tls-v3.json, the known-answer vector
// shared byte-identical with the provider and the attestor.
type statementVector struct {
	ProviderKey struct {
		PrivateKey string `json:"private_key"`
		Address    string `json:"address"`
	} `json:"test_only_provider_key"`
	TypedData        apitypes.TypedData `json:"typed_data"`
	TypeHash         string             `json:"type_hash"`
	PinsHash         string             `json:"tls_spki_sha256_array_hash"`
	DomainSeparator  string             `json:"domain_separator"`
	StructHash       string             `json:"struct_hash"`
	Digest           string             `json:"digest"`
	Signature        string             `json:"signature"`
	RecoveredAddress string             `json:"recovered_address"`
	ResponseBody     string             `json:"response_body"`
}

func loadStatementVector(t *testing.T) statementVector {
	t.Helper()
	data, err := os.ReadFile("testdata/attestor-tls-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector statementVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// vectorAnchor is the anchor a container certified by the shared vectors'
// provider would hold.
func vectorAnchor(t *testing.T) Anchor {
	t.Helper()
	vector := loadStatementVector(t)
	registry, err := eip712.Address(vector.TypedData.Domain.VerifyingContract)
	if err != nil {
		t.Fatal(err)
	}
	return Anchor{ChainID: 16602, Registry: registry, Provider: common.HexToAddress(vector.ProviderKey.Address)}
}

func providerKey(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString(strings.TrimPrefix(loadStatementVector(t).ProviderKey.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sign signs s with key, as the provider does: raw over the EIP-712 digest.
func sign(t *testing.T, key []byte, s Statement) Statement {
	t.Helper()
	priv, err := crypto.ToECDSA(key)
	if err != nil {
		t.Fatal(err)
	}
	domain, structHash, err := s.hashes()
	if err != nil {
		t.Fatal(err)
	}
	digest := eip712.Digest(domain, structHash)
	signature, err := crypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatal(err)
	}
	signature[64] += 27
	s.Signature = "0x" + hex.EncodeToString(signature)
	return s
}

func TestAttestorTLSStatementV3KnownAnswer(t *testing.T) {
	vector := loadStatementVector(t)
	s, err := parseStatement([]byte(vector.ResponseBody))
	if err != nil {
		t.Fatal(err)
	}
	if got := statementTypeHash.Hex(); got != vector.TypeHash {
		t.Fatalf("type hash %s, want %s", got, vector.TypeHash)
	}
	var pins []byte
	for _, pin := range s.TLSPins {
		raw, _ := hex.DecodeString(pin)
		pins = append(pins, raw...)
	}
	if got := crypto.Keccak256Hash(pins).Hex(); got != vector.PinsHash {
		t.Fatalf("pin array hash %s", got)
	}
	domain, structHash, err := s.hashes()
	if err != nil {
		t.Fatal(err)
	}
	if domain.Hex() != vector.DomainSeparator || structHash.Hex() != vector.StructHash {
		t.Fatalf("domain %s struct %s differ from the vector", domain.Hex(), structHash.Hex())
	}
	if got := eip712.Digest(domain, structHash).Hex(); got != vector.Digest {
		t.Fatalf("digest %s", got)
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
	if "0x"+hex.EncodeToString(typedDomain) != vector.DomainSeparator || "0x"+hex.EncodeToString(typedStruct) != vector.StructHash {
		t.Fatal("go-ethereum apitypes disagrees with the vector")
	}
	if sign(t, providerKey(t), s).Signature != vector.Signature || s.Signature != vector.Signature {
		t.Fatal("deterministic re-signing does not reproduce the vector signature")
	}
	signature, err := eip712.DecodeSignature(s.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := eip712.Recover(eip712.Digest(domain, structHash), signature)
	if err != nil || signer.Hex() != vector.RecoveredAddress || signer.Hex() != vector.ProviderKey.Address {
		t.Fatalf("recovered %s (%v)", signer.Hex(), err)
	}
	// Accepted inside its window, with the 0/1 recovery byte too.
	l, err := s.accept(vectorAnchor(t), int64(s.IssuedAt)+10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(l.pins, ",") != strings.Join(s.TLSPins, ",") || l.issuedAt != int64(s.IssuedAt) || l.expiresAt != int64(s.ExpiresAt) {
		t.Fatalf("lease %+v", l)
	}
	raw := s
	raw.Signature = s.Signature[:130] + "01"
	if _, err := raw.accept(vectorAnchor(t), int64(s.IssuedAt)+10, 0); err != nil {
		t.Fatalf("v=1: %v", err)
	}
}

func TestAttestorTLSStatementAcceptance(t *testing.T) {
	vector := loadStatementVector(t)
	anchor := vectorAnchor(t)
	key := providerKey(t)
	otherKey := crypto.Keccak256([]byte("another key"))
	const now = int64(1793318460)
	pinA, pinB := strings.Repeat("2b", 32), strings.Repeat("3c", 32)
	base := Statement{Version: 3, ChainID: anchor.ChainID, RegistryAddress: vector.TypedData.Domain.VerifyingContract,
		TLSPins: []string{pinA, pinB}, IssuedAt: uint64(now), ExpiresAt: uint64(now + 120)}
	accepted := map[string]func(*Statement){
		"base":                 func(*Statement) {},
		"issued 30 s ahead":    func(s *Statement) { s.IssuedAt, s.ExpiresAt = uint64(now+30), uint64(now+60) },
		"6 s left":             func(s *Statement) { s.IssuedAt, s.ExpiresAt = uint64(now-200), uint64(now+6) },
		"300 s lease":          func(s *Statement) { s.ExpiresAt = uint64(now + 300) },
		"one pin":              func(s *Statement) { s.TLSPins = []string{pinB} },
		"checksummed registry": func(s *Statement) { s.RegistryAddress = anchor.Registry.Hex() },
		"sixteen pins":         func(s *Statement) { s.TLSPins = ascendingPins(16) },
	}
	for name, change := range accepted {
		s := base
		change(&s)
		if _, err := sign(t, key, s).accept(anchor, now, 0); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	// A refresh may return the statement already held.
	if _, err := sign(t, key, base).accept(anchor, now, now); err != nil {
		t.Errorf("same issued_at as held rejected: %v", err)
	}
	rejected := map[string]func(*Statement) Statement{
		"another signer":         func(s *Statement) Statement { return sign(t, otherKey, *s) },
		"tampered after signing": func(s *Statement) Statement { signed := sign(t, key, *s); signed.ExpiresAt++; return signed },
		"bad recovery id": func(s *Statement) Statement {
			signed := sign(t, key, *s)
			signed.Signature = signed.Signature[:130] + "1d"
			return signed
		},
		"v2":          func(s *Statement) Statement { s.Version = 2; return sign(t, key, *s) },
		"other chain": func(s *Statement) Statement { s.ChainID++; return sign(t, key, *s) },
		"other registry": func(s *Statement) Statement {
			s.RegistryAddress = "0x" + strings.Repeat("44", 20)
			return sign(t, key, *s)
		},
		"expired": func(s *Statement) Statement {
			s.IssuedAt, s.ExpiresAt = uint64(now-200), uint64(now-1)
			return sign(t, key, *s)
		},
		"5 s left": func(s *Statement) Statement {
			s.IssuedAt, s.ExpiresAt = uint64(now-200), uint64(now+5)
			return sign(t, key, *s)
		},
		"issued 31 s ahead": func(s *Statement) Statement {
			s.IssuedAt, s.ExpiresAt = uint64(now+31), uint64(now+60)
			return sign(t, key, *s)
		},
		"301 s lease": func(s *Statement) Statement { s.ExpiresAt = uint64(now + 301); return sign(t, key, *s) },
		"expires at issue": func(s *Statement) Statement {
			s.IssuedAt, s.ExpiresAt = uint64(now+10), uint64(now+10)
			return sign(t, key, *s)
		},
		"older than held": func(s *Statement) Statement { s.IssuedAt = uint64(now - 1); return sign(t, key, *s) },
		"no pins":         func(s *Statement) Statement { s.TLSPins = nil; return sign(t, key, *s) },
		"seventeen pins":  func(s *Statement) Statement { s.TLSPins = ascendingPins(17); return sign(t, key, *s) },
		"descending pins": func(s *Statement) Statement { s.TLSPins = []string{pinB, pinA}; return sign(t, key, *s) },
		"duplicate pins":  func(s *Statement) Statement { s.TLSPins = []string{pinA, pinA}; return sign(t, key, *s) },
		"uppercase pin":   func(s *Statement) Statement { s.TLSPins = []string{strings.ToUpper(pinA)}; return sign(t, key, *s) },
		"0x pin": func(s *Statement) Statement {
			signed := sign(t, key, *s)
			signed.TLSPins = []string{"0x" + pinA}
			return signed
		},
		"short pin": func(s *Statement) Statement {
			signed := sign(t, key, *s)
			signed.TLSPins = []string{pinA[:62]}
			return signed
		},
		"time overflow": func(s *Statement) Statement { s.IssuedAt, s.ExpiresAt = 1<<63, 1<<63+10; return sign(t, key, *s) },
	}
	for name, change := range rejected {
		s := base
		// Each case fails on its own: only "older than held" holds a lease.
		held := int64(0)
		if name == "older than held" {
			held = now
		}
		if _, err := change(&s).accept(anchor, now, held); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A statement from another provider, however well formed, is not this
	// container's.
	stranger := anchor
	stranger.Provider = common.HexToAddress("0x" + strings.Repeat("55", 20))
	if _, err := sign(t, key, base).accept(stranger, now, 0); err == nil {
		t.Error("accepted for an anchor with another provider")
	}
	for name, body := range map[string]string{
		"unknown field":  strings.Replace(vector.ResponseBody, `"issued_at"`, `"app_id":"x","issued_at"`, 1),
		"trailing data":  vector.ResponseBody + "{}",
		"trailing brace": vector.ResponseBody + "}",
		"trailing ]":     vector.ResponseBody + "]",
		"negative time":  strings.Replace(vector.ResponseBody, `"issued_at":1793318460`, `"issued_at":-1`, 1),
		"not an object":  `[]`,
		"string version": strings.Replace(vector.ResponseBody, `"version":3`, `"version":"3"`, 1),
	} {
		if body == vector.ResponseBody {
			t.Fatalf("%s: fixture edit did not apply", name)
		}
		if _, err := parseStatement([]byte(body)); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

func ascendingPins(n int) []string {
	pins := make([]string, n)
	for i := range pins {
		pins[i] = strings.Repeat(hex.EncodeToString([]byte{byte(16 + i)}), 32)
	}
	return pins
}
