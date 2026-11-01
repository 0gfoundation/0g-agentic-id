package eip712

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRecoverAcceptsBothRecoveryByteForms(t *testing.T) {
	key, err := crypto.HexToECDSA(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	digest := Digest(DomainSeparator("name", "3", 16602, crypto.PubkeyToAddress(key.PublicKey)), crypto.Keccak256Hash([]byte("struct")))
	raw, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []byte{raw[64], raw[64] + 27} {
		signature := append(append([]byte(nil), raw[:64]...), v)
		decoded, err := DecodeSignature("0x" + hex.EncodeToString(signature))
		if err != nil {
			t.Fatalf("v=%d: %v", v, err)
		}
		signer, err := Recover(digest, decoded)
		if err != nil || signer != crypto.PubkeyToAddress(key.PublicKey) {
			t.Fatalf("v=%d recovered %s (%v)", v, signer.Hex(), err)
		}
	}
	for _, bad := range []string{"", "0x", "0x" + strings.Repeat("00", 64) + "1d", strings.Repeat("00", 65), "0x" + strings.Repeat("zz", 65)} {
		if _, err := DecodeSignature(bad); err == nil {
			t.Fatalf("accepted signature %q", bad)
		}
	}
}

func TestAddressRejectsZeroAndMalformed(t *testing.T) {
	for _, bad := range []string{"0x" + strings.Repeat("0", 40), "0x1234", strings.Repeat("11", 20), "0x" + strings.Repeat("g", 40)} {
		if _, err := Address(bad); err == nil {
			t.Fatalf("accepted address %q", bad)
		}
	}
	lower, err := Address("0x" + strings.Repeat("ab", 20))
	if err != nil {
		t.Fatal(err)
	}
	if upper, err := Address("0x" + strings.Repeat("AB", 20)); err != nil || upper != lower {
		t.Fatal("address case changed its value")
	}
}
