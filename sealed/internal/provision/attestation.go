package provision

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const attestationDomain = "0g.sandbox.ImageAttestation.v2"

// Attestation is the sandbox-injected v2 SANDBOX_SEAL_ATTESTATION envelope.
// The issuer scope belongs to the signed message; never replace it with local
// defaults when forwarding it to the attestor. AppID is exact UTF-8 bytes.
type Attestation struct {
	Version         uint64 `json:"version"`
	ChainID         uint64 `json:"chain_id"`
	RegistryAddress string `json:"registry_address"`
	AppID           string `json:"app_id"`
	RegisteredAt    uint64 `json:"registered_at"`
	SealID          string `json:"seal_id"`
	Pubkey          string `json:"pubkey"`
	ImageHash       string `json:"image_hash"`
	Signature       string `json:"signature"`
	Ts              uint64 `json:"ts"`
}

// signingWords is the fixed nine-word ABI encoding shared by the sandbox and
// attestor. Dynamic fields are hashed individually; there are no ABI offsets,
// string formatting, EIP-191 prefix or node-key fallback in this protocol.
func (a Attestation) signingWords() ([]byte, error) {
	if a.Version != 2 {
		return nil, fmt.Errorf("unsupported image attestation version %d (v2 required)", a.Version)
	}
	if a.ChainID == 0 || a.RegisteredAt == 0 || a.Ts == 0 {
		return nil, fmt.Errorf("image attestation requires nonzero chain_id, registered_at and ts")
	}
	if !utf8.ValidString(a.AppID) || len(a.AppID) == 0 || len(a.AppID) > 256 {
		return nil, fmt.Errorf("image attestation app_id must be 1..256 UTF-8 bytes")
	}
	registry, err := exactHex(a.RegistryAddress, "0x", common.AddressLength)
	if err != nil || common.BytesToAddress(registry) == (common.Address{}) {
		return nil, fmt.Errorf("image attestation registry_address must be a nonzero 20-byte hex address")
	}
	seal, err := exactHex(a.SealID, "", common.HashLength)
	if err != nil {
		return nil, fmt.Errorf("image attestation seal_id: %w", err)
	}
	pubkey, err := exactHex(a.Pubkey, "0x", 33)
	if err != nil {
		return nil, fmt.Errorf("image attestation pubkey: %w", err)
	}
	if _, err := crypto.DecompressPubkey(pubkey); err != nil {
		return nil, fmt.Errorf("image attestation pubkey must be compressed secp256k1")
	}
	image, err := exactHex(a.ImageHash, "sha256:", common.HashLength)
	if err != nil {
		return nil, fmt.Errorf("image attestation image_hash: %w", err)
	}

	words := make([]byte, 9*common.HashLength)
	copy(words[0:32], crypto.Keccak256([]byte(attestationDomain)))
	binary.BigEndian.PutUint64(words[56:64], a.ChainID)
	copy(words[76:96], registry)
	copy(words[96:128], crypto.Keccak256([]byte(a.AppID)))
	binary.BigEndian.PutUint64(words[152:160], a.RegisteredAt)
	copy(words[160:192], seal)
	copy(words[192:224], crypto.Keccak256(pubkey))
	copy(words[224:256], image)
	binary.BigEndian.PutUint64(words[280:288], a.Ts)
	return words, nil
}

// Digest validates the v2 signed fields and returns their raw keccak256 digest.
// Signature authentication against the current app instance remains the
// attestor's responsibility; Phase 0 can additionally pin its expected signer.
func (a Attestation) Digest() (common.Hash, error) {
	words, err := a.signingWords()
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(words), nil
}

// RecoverSigner verifies the v2 envelope's encoding and recovers its app signer.
// The sandbox emits Ethereum's 27/28 recovery id; common raw 0/1 library
// output is also accepted and normalized for SigToPub, with the same v2 digest.
func (a Attestation) RecoverSigner() (common.Address, error) {
	digest, err := a.Digest()
	if err != nil {
		return common.Address{}, err
	}
	signature, err := exactHex(a.Signature, "0x", crypto.SignatureLength)
	if err != nil {
		return common.Address{}, fmt.Errorf("image attestation signature: %w", err)
	}
	switch signature[64] {
	case 27, 28:
		signature[64] -= 27
	case 0, 1:
		// Already normalized; this does not enable the old signed payload.
	default:
		return common.Address{}, fmt.Errorf("invalid image attestation recovery id %d", signature[64])
	}
	pubkey, err := crypto.SigToPub(digest[:], signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover image attestation app signer: %w", err)
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}

func exactHex(value, prefix string, size int) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+size*2 {
		return nil, fmt.Errorf("expected %s-prefixed %d-byte hex", prefix, size)
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}
	return decoded, nil
}
