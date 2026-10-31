package attestorhttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/eip712"
)

// The attestor TLS statement's EIP-712 domain name and version. Its
// verifyingContract is the provider's TappRegistry, as for the certificate;
// the different name and type keep the two signatures apart.
const (
	statementDomainName    = "0G Sandbox AttestorTLS"
	statementDomainVersion = "3"
)

var statementTypeHash = crypto.Keccak256Hash([]byte("AttestorTLS(bytes32[] tlsSpkiSha256,uint64 issuedAt,uint64 expiresAt)"))

// Statement limits.
const (
	maxPins = 16
	// maxLease bounds expires_at - issued_at.
	maxLease = 300
	// maxIssuedAhead is how far issued_at may be ahead of sealed's clock.
	maxIssuedAhead = 30
	// minRemaining is how long a statement must still be valid to be used.
	minRemaining = 5
)

// Statement is the provider-signed list of the attestor's TLS key pins,
// served by the provider at GET /api/attestor-tls and relayed unchanged by
// the attestor at GET /attestor-tls?provider=<address>.
type Statement struct {
	Version         uint64   `json:"version"`
	ChainID         uint64   `json:"chain_id"`
	RegistryAddress string   `json:"registry_address"`
	TLSPins         []string `json:"tls_spki_sha256"`
	IssuedAt        uint64   `json:"issued_at"`
	ExpiresAt       uint64   `json:"expires_at"`
	Signature       string   `json:"signature"`
}

// lease is an accepted statement: the pins and their validity window.
type lease struct {
	pins      []string
	issuedAt  int64
	expiresAt int64
}

// parseStatement decodes one statement body: exactly the v3 fields.
func parseStatement(body []byte) (Statement, error) {
	var s Statement
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return Statement{}, fmt.Errorf("attestor TLS statement is not the v3 JSON object: %w", err)
	}
	// More() would miss a trailing '}' or ']'; only a clean EOF ends it.
	if err := decoder.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return Statement{}, fmt.Errorf("attestor TLS statement has trailing data")
	}
	return s, nil
}

// hashes returns the statement's EIP-712 domain separator and struct hash,
// with the domain built from the statement's own chain and registry.
func (s Statement) hashes() (domain, structHash common.Hash, err error) {
	registry, err := eip712.Address(s.RegistryAddress)
	if err != nil {
		return common.Hash{}, common.Hash{}, fmt.Errorf("attestor TLS statement registry_address: %w", err)
	}
	pins := make([]byte, 0, len(s.TLSPins)*common.HashLength)
	for _, pin := range s.TLSPins {
		raw, err := eip712.ExactHex(pin, "", common.HashLength)
		if err != nil {
			return common.Hash{}, common.Hash{}, fmt.Errorf("attestor TLS statement pin: %w", err)
		}
		pins = append(pins, raw...)
	}
	domain = eip712.DomainSeparator(statementDomainName, statementDomainVersion, s.ChainID, registry)
	structHash = crypto.Keccak256Hash(statementTypeHash[:], crypto.Keccak256(pins), eip712.Uint64(s.IssuedAt), eip712.Uint64(s.ExpiresAt))
	return domain, structHash, nil
}

// accept checks a statement against the anchor taken from this container's
// certificate and returns its lease. now is sealed's clock in unix seconds;
// heldIssuedAt is the issued_at of the lease already held (0 for none), which
// a newer statement may not go back behind. Which TLS connection the
// statement arrived over is checked by the caller.
func (s Statement) accept(anchor Anchor, now, heldIssuedAt int64) (lease, error) {
	if s.Version != 3 {
		return lease{}, fmt.Errorf("unsupported attestor TLS statement version %d (v3 required)", s.Version)
	}
	if s.ChainID != anchor.ChainID {
		return lease{}, fmt.Errorf("attestor TLS statement chain_id differs from the container certificate")
	}
	if registry, err := eip712.Address(s.RegistryAddress); err != nil || registry != anchor.Registry {
		return lease{}, fmt.Errorf("attestor TLS statement registry_address differs from the container certificate")
	}
	if len(s.TLSPins) == 0 || len(s.TLSPins) > maxPins {
		return lease{}, fmt.Errorf("attestor TLS statement must list 1..%d pins", maxPins)
	}
	for i, pin := range s.TLSPins {
		if !validPin(pin) {
			return lease{}, fmt.Errorf("attestor TLS statement pin is not 64 lowercase hex")
		}
		if i > 0 && pin <= s.TLSPins[i-1] {
			return lease{}, fmt.Errorf("attestor TLS statement pins are not strictly ascending")
		}
	}
	signature, err := eip712.DecodeSignature(s.Signature)
	if err != nil {
		return lease{}, fmt.Errorf("attestor TLS statement %w", err)
	}
	domain, structHash, err := s.hashes()
	if err != nil {
		return lease{}, err
	}
	signer, err := eip712.Recover(eip712.Digest(domain, structHash), signature)
	if err != nil {
		return lease{}, fmt.Errorf("attestor TLS statement: %w", err)
	}
	if signer != anchor.Provider {
		return lease{}, fmt.Errorf("attestor TLS statement is not signed by this container's provider")
	}
	if s.IssuedAt > math.MaxInt64 || s.ExpiresAt > math.MaxInt64 {
		return lease{}, fmt.Errorf("attestor TLS statement times out of range")
	}
	issued, expires := int64(s.IssuedAt), int64(s.ExpiresAt)
	switch {
	case issued > now+maxIssuedAhead:
		return lease{}, fmt.Errorf("attestor TLS statement issued in the future")
	case expires <= now+minRemaining:
		return lease{}, fmt.Errorf("attestor TLS statement expired")
	case expires <= issued || expires-issued > maxLease:
		return lease{}, fmt.Errorf("attestor TLS statement lease must be 1..%d seconds", maxLease)
	case issued < heldIssuedAt:
		return lease{}, fmt.Errorf("attestor TLS statement is older than the one already held")
	}
	return lease{pins: append([]string(nil), s.TLSPins...), issuedAt: issued, expiresAt: expires}, nil
}

// validPin reports whether pin is a SHA-256 digest as 64 lowercase hex
// characters without 0x.
func validPin(pin string) bool {
	decoded, err := hex.DecodeString(pin)
	return err == nil && len(decoded) == common.HashLength && hex.EncodeToString(decoded) == pin
}

// hasPin reports whether spki (a lowercase hex SHA-256) is one of pins.
func hasPin(pins []string, spki string) bool {
	for _, pin := range pins {
		if pin == spki {
			return true
		}
	}
	return false
}
