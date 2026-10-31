// Package eip712 holds what the two provider-signed v3 statements share:
// the container certificate (SANDBOX_SEAL_ATTESTATION, internal/provision)
// and the attestor TLS statement (internal/attestorhttp). Both use the
// four-field EIP712Domain with the provider's TappRegistry as
// verifyingContract, and both are signed raw over the 0x1901 digest, with
// no EIP-191 prefix.
package eip712

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// DomainTypeHash is keccak256 of the EIP712Domain type both statements use.
var DomainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))

// DomainSeparator hashes EIP712Domain(name, version, chainId, verifyingContract).
func DomainSeparator(name, version string, chainID uint64, verifyingContract common.Address) common.Hash {
	return crypto.Keccak256Hash(DomainTypeHash[:], crypto.Keccak256([]byte(name)), crypto.Keccak256([]byte(version)),
		Uint64(chainID), common.LeftPadBytes(verifyingContract[:], 32))
}

// Uint64 encodes v as one 32-byte big-endian ABI word.
func Uint64(v uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], v)
	return word
}

// Digest is keccak256(0x1901 ‖ domainSeparator ‖ structHash).
func Digest(domainSeparator, structHash common.Hash) common.Hash {
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domainSeparator[:], structHash[:])
}

// DecodeSignature parses a "0x"-prefixed 65-byte r‖s‖v signature. The
// recovery byte may be 27/28 (what the provider emits) or 0/1.
func DecodeSignature(value string) ([]byte, error) {
	signature, err := ExactHex(value, "0x", crypto.SignatureLength)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	switch signature[64] {
	case 27, 28:
		signature[64] -= 27
	case 0, 1:
	default:
		return nil, fmt.Errorf("signature recovery id %d not in {27,28,0,1}", signature[64])
	}
	return signature, nil
}

// Recover returns the address whose key signed digest. signature comes from
// DecodeSignature.
func Recover(digest common.Hash, signature []byte) (common.Address, error) {
	pubkey, err := crypto.SigToPub(digest[:], signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover signer: %w", err)
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}

// ExactHex decodes prefix followed by exactly size bytes of hex.
func ExactHex(value, prefix string, size int) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+size*2 {
		return nil, fmt.Errorf("expected %q followed by %d bytes of hex", prefix, size)
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}
	return decoded, nil
}

// Address parses a nonzero "0x"-prefixed 20-byte address. Case is not
// significant: the provider writes it lowercase, and only the parsed value
// is compared.
func Address(value string) (common.Address, error) {
	raw, err := ExactHex(value, "0x", common.AddressLength)
	if err != nil {
		return common.Address{}, err
	}
	address := common.BytesToAddress(raw)
	if address == (common.Address{}) {
		return common.Address{}, fmt.Errorf("zero address")
	}
	return address, nil
}
