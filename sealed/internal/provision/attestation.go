package provision

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/eip712"
)

// The v3 container certificate's EIP-712 domain name and version. The
// verifyingContract is the provider's TappRegistry (registry_address).
const (
	certificateDomainName    = "0G Sandbox ImageAttestation"
	certificateDomainVersion = "3"
)

var certificateTypeHash = crypto.Keccak256Hash([]byte("ImageAttestation(string appId,uint64 registeredAt,bytes32 sealId,bytes containerPubkey,bytes32 imageHash,uint64 issuedAt)"))

// Attestation is the v3 container certificate the sandbox provider writes
// into SANDBOX_SEAL_ATTESTATION at sealed create. Field order follows the
// wire form. The certificate is public; what it certifies is that the
// provider created this container from image_hash with the key pubkey.
//
// The provider instance (chain_id, registry_address, app_id, registered_at)
// is part of the signed message. sealed only recovers the signer: whether
// that signer and scope are a provider the attestor trusts is decided by the
// attestor at first /provision, which receives the certificate verbatim.
type Attestation struct {
	Version         uint64 `json:"version"`
	ChainID         uint64 `json:"chain_id"`
	RegistryAddress string `json:"registry_address"`
	AppID           string `json:"app_id"`
	RegisteredAt    uint64 `json:"registered_at"`
	SealID          string `json:"seal_id"`
	Pubkey          string `json:"pubkey"`
	ImageHash       string `json:"image_hash"`
	Ts              uint64 `json:"ts"`
	Signature       string `json:"signature"`
}

// certificateFields are an Attestation's values decoded and checked.
type certificateFields struct {
	registry  common.Address
	seal      []byte
	pubkey    []byte
	image     []byte
	signature []byte
}

// ParseAttestation decodes a SANDBOX_SEAL_ATTESTATION value: one JSON
// object with exactly the v3 fields, in the formats checked by Digest.
func ParseAttestation(raw []byte) (Attestation, error) {
	var a Attestation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil {
		return Attestation{}, fmt.Errorf("container certificate is not the v3 JSON object: %w", err)
	}
	// More() would miss a trailing '}' or ']'; only a clean EOF ends it.
	if err := decoder.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return Attestation{}, fmt.Errorf("container certificate has trailing data")
	}
	if _, err := a.fields(); err != nil {
		return Attestation{}, err
	}
	return a, nil
}

func (a Attestation) fields() (certificateFields, error) {
	var f certificateFields
	if a.Version != 3 {
		return f, fmt.Errorf("unsupported container certificate version %d (v3 required)", a.Version)
	}
	if a.ChainID == 0 || a.RegisteredAt == 0 || a.Ts == 0 {
		return f, fmt.Errorf("container certificate requires nonzero chain_id, registered_at and ts")
	}
	if !utf8.ValidString(a.AppID) || len(a.AppID) == 0 || len(a.AppID) > 256 {
		return f, fmt.Errorf("container certificate app_id must be 1..256 UTF-8 bytes")
	}
	var err error
	if f.registry, err = eip712.Address(a.RegistryAddress); err != nil {
		return f, fmt.Errorf("container certificate registry_address: %w", err)
	}
	if f.seal, err = eip712.ExactHex(a.SealID, "", common.HashLength); err != nil || hex.EncodeToString(f.seal) != a.SealID {
		return f, fmt.Errorf("container certificate seal_id must be 64 lowercase hex without 0x")
	}
	if f.pubkey, err = eip712.ExactHex(a.Pubkey, "0x", 33); err != nil {
		return f, fmt.Errorf("container certificate pubkey: %w", err)
	}
	if _, err := crypto.DecompressPubkey(f.pubkey); err != nil {
		return f, fmt.Errorf("container certificate pubkey must be a compressed secp256k1 key")
	}
	if f.image, err = eip712.ExactHex(a.ImageHash, "sha256:", common.HashLength); err != nil || hex.EncodeToString(f.image) != strings.TrimPrefix(a.ImageHash, "sha256:") {
		return f, fmt.Errorf("container certificate image_hash must be sha256: followed by 64 lowercase hex")
	}
	if f.signature, err = eip712.DecodeSignature(a.Signature); err != nil {
		return f, fmt.Errorf("container certificate %w", err)
	}
	return f, nil
}

// hashes returns the certificate's EIP-712 domain separator and struct hash.
func (a Attestation) hashes() (domain, structHash common.Hash, f certificateFields, err error) {
	if f, err = a.fields(); err != nil {
		return
	}
	domain = eip712.DomainSeparator(certificateDomainName, certificateDomainVersion, a.ChainID, f.registry)
	structHash = crypto.Keccak256Hash(certificateTypeHash[:], crypto.Keccak256([]byte(a.AppID)), eip712.Uint64(a.RegisteredAt),
		f.seal, crypto.Keccak256(f.pubkey), f.image, eip712.Uint64(a.Ts))
	return
}

// Digest validates the certificate and returns the EIP-712 digest the
// provider signed.
func (a Attestation) Digest() (common.Hash, error) {
	domain, structHash, _, err := a.hashes()
	if err != nil {
		return common.Hash{}, err
	}
	return eip712.Digest(domain, structHash), nil
}

// RecoverSigner validates the certificate and recovers the provider key
// that signed it.
func (a Attestation) RecoverSigner() (common.Address, error) {
	domain, structHash, f, err := a.hashes()
	if err != nil {
		return common.Address{}, err
	}
	signer, err := eip712.Recover(eip712.Digest(domain, structHash), f.signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("container certificate: %w", err)
	}
	return signer, nil
}

// Registry is the certificate's TappRegistry address, the zero address when
// the certificate does not validate.
func (a Attestation) Registry() common.Address {
	f, err := a.fields()
	if err != nil {
		return common.Address{}
	}
	return f.registry
}

// FrameworkHash is image_hash as the bytes32 hex AgenticID records in
// validFrameworkHashes and serve-proofs sign: "0x" and 64 lowercase hex.
// Empty when the certificate does not validate.
func (a Attestation) FrameworkHash() string {
	f, err := a.fields()
	if err != nil {
		return ""
	}
	return "0x" + hex.EncodeToString(f.image)
}
