// Package credentials loads the owner's credential set into sealed and
// serves it: entries go to the credential proxy (internal/credproxy), the
// harness reaches them through two unix sockets, and the owner manages them
// through /_seal/credentials* on :8080.
//
// The owner signs one EIP-712 CredentialSet per agent. It lists each
// entry's definition hash; each definition carries the keccak of its value's
// ciphertext; each ciphertext is sealed to this agent's agentSeal key and
// names the owner, the seal and the chain inside. One signature therefore
// covers every entry and value, and a value cannot be swapped, moved to
// another agent, or kept by a later owner.
package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/eip712"
)

// Domain constants of the owner's EIP-712 signatures.
const (
	DomainName    = "AgentDNA Credentials"
	DomainVersion = "1"
)

var (
	setTypeHash = crypto.Keccak256Hash([]byte(
		"CredentialSet(bytes32 sealId,uint64 ownerEpoch,uint64 version,Entry[] entries)Entry(string name,bytes32 defHash)"))
	entryTypeHash    = crypto.Keccak256Hash([]byte("Entry(string name,bytes32 defHash)"))
	approvalTypeHash = crypto.Keccak256Hash([]byte(
		"Approval(bytes32 sealId,bytes32 bootId,bytes32 authReqId,bytes32 requestDigest,uint64 expiresAt)"))
)

// Domain is what every owner signature is bound to.
type Domain struct {
	ChainID  uint64
	Contract common.Address // AgenticID
}

func (d Domain) separator() common.Hash {
	return eip712.DomainSeparator(DomainName, DomainVersion, d.ChainID, d.Contract)
}

// SetEntry is one line of a CredentialSet.
type SetEntry struct {
	Name    string `json:"name"`
	DefHash string `json:"def_hash"`
}

// CredentialSet is the object the owner signs.
type CredentialSet struct {
	SealID     string     `json:"seal_id"`
	OwnerEpoch uint64     `json:"owner_epoch"`
	Version    uint64     `json:"version"`
	Entries    []SetEntry `json:"entries"`
}

// Digest is the EIP-712 digest of s under d.
func (s CredentialSet) Digest(d Domain) (common.Hash, error) {
	seal, err := hash32(s.SealID)
	if err != nil {
		return common.Hash{}, fmt.Errorf("seal_id: %w", err)
	}
	var entryHashes []byte
	for _, e := range s.Entries {
		dh, err := hash32(e.DefHash)
		if err != nil {
			return common.Hash{}, fmt.Errorf("entry %q def_hash: %w", e.Name, err)
		}
		h := crypto.Keccak256(entryTypeHash[:], crypto.Keccak256([]byte(e.Name)), dh[:])
		entryHashes = append(entryHashes, h...)
	}
	structHash := crypto.Keccak256Hash(setTypeHash[:], seal[:], eip712.Uint64(s.OwnerEpoch), eip712.Uint64(s.Version),
		crypto.Keccak256(entryHashes))
	return eip712.Digest(d.separator(), structHash), nil
}

// Approval is the owner's one-time consent to one pending request.
type Approval struct {
	SealID        string `json:"seal_id"`
	BootID        string `json:"boot_id"`
	AuthReqID     string `json:"auth_req_id"`
	RequestDigest string `json:"request_digest"`
	ExpiresAt     uint64 `json:"expires_at"`
}

// Digest is the EIP-712 digest of a under d.
func (a Approval) Digest(d Domain) (common.Hash, error) {
	var words [4]common.Hash
	for i, v := range []string{a.SealID, a.BootID, a.AuthReqID, a.RequestDigest} {
		h, err := hash32(v)
		if err != nil {
			return common.Hash{}, fmt.Errorf("approval field %d: %w", i, err)
		}
		words[i] = h
	}
	structHash := crypto.Keccak256Hash(approvalTypeHash[:], words[0][:], words[1][:], words[2][:], words[3][:], eip712.Uint64(a.ExpiresAt))
	return eip712.Digest(d.separator(), structHash), nil
}

// Recover returns the address that signed digest.
func Recover(digest common.Hash, sigHex string) (common.Address, error) {
	sig, err := eip712.DecodeSignature(sigHex)
	if err != nil {
		return common.Address{}, err
	}
	return eip712.Recover(digest, sig)
}

// TokenTake is one value a token request keeps from the response.
type TokenTake struct {
	Field          string               `json:"field"`
	Name           string               `json:"name"`
	Hosts          []string             `json:"hosts"`
	Positions      []credproxy.Position `json:"positions"`
	ExpiresInField string               `json:"expires_in_field,omitempty"`
}

// TokenRequest is the template sealed follows to call a token endpoint
// (RFC 6749 §3.2) with an entry's value.
type TokenRequest struct {
	URL       string            `json:"url"`
	Encoding  string            `json:"encoding"` // "form" or "json"
	Fields    map[string]string `json:"fields"`
	BasicAuth *struct {
		UsernameEntry string `json:"username_entry"`
		PasswordEntry string `json:"password_entry"`
	} `json:"basic_auth,omitempty"`
	Params      []string    `json:"params,omitempty"`
	Take        []TokenTake `json:"take"`
	RotateField string      `json:"rotate_field,omitempty"`
}

// Definition is one entry as the owner defined it.
type Definition struct {
	V            int                  `json:"v"`
	Name         string               `json:"name"`
	Hosts        []string             `json:"hosts"`
	Positions    []credproxy.Position `json:"positions"`
	Use          credproxy.Use        `json:"use"`
	ValueHash    string               `json:"value_hash"`
	Description  string               `json:"description,omitempty"`
	ExpiresAt    int64                `json:"expires_at,omitempty"`
	AllowReveal  bool                 `json:"allow_reveal,omitempty"`
	Writeback    bool                 `json:"writeback,omitempty"`
	TokenRequest *TokenRequest        `json:"token_request,omitempty"`
	Signer       *credproxy.Signer    `json:"signer,omitempty"`
	MCP          json.RawMessage      `json:"mcp,omitempty"`
}

// valuePlaintext is what a value's ciphertext holds.
type valuePlaintext struct {
	V       int    `json:"v"`
	Type    string `json:"type"`
	Owner   string `json:"owner"`
	SealID  string `json:"seal_id"`
	ChainID uint64 `json:"chain_id"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// Writeback is a value sealed itself obtained (a rotated refresh token, or a
// login) and stored at the attestor, signed by agentSeal.
type Writeback struct {
	Ciphertext string `json:"ciphertext"`
	SetVersion uint64 `json:"set_version"`
	BootID     string `json:"boot_id"`
	Signature  string `json:"signature"`
}

// WritebackMessage is what agentSeal signs (keccak256, no EIP-191 prefix).
// The sign socket offers no raw-hash signing, so the harness cannot forge it.
func WritebackMessage(sealID, name string, setVersion uint64, bootID string, ciphertext []byte) []byte {
	return []byte(fmt.Sprintf("CredentialWriteback.v1:%s:%s:%d:%s:%s",
		strings.ToLower(sealID), name, setVersion, bootID, crypto.Keccak256Hash(ciphertext).Hex()))
}

// Document is a signed set with its definitions, values and writebacks, as
// the owner posts it and the attestor hands it over at boot.
type Document struct {
	Set        CredentialSet        `json:"set"`
	Signature  string               `json:"signature"`
	Defs       map[string]string    `json:"defs"`   // name → base64 definition bytes
	Values     map[string]string    `json:"values"` // name → base64 ciphertext
	Writebacks map[string]Writeback `json:"writebacks,omitempty"`
}

// Opened is a verified document.
type Opened struct {
	Set     CredentialSet
	Defs    map[string]*Definition
	Values  map[string][]byte
	Skipped map[string]string // name → why the entry was left out
}

// Check is what verifying a document needs from its environment.
type Check struct {
	Domain        Domain
	SealID        string
	Owner         common.Address // the live on-chain owner
	AgentSeal     common.Address
	AgentSealPriv []byte
	// MinVersion: documents below it are refused (anti-rollback).
	MinVersion uint64
	// OwnerEpoch, when non-zero, must equal the set's.
	OwnerEpoch uint64
}

// Errors returned by Open.
var (
	ErrWrongSigner = errors.New("the credential set is not signed by the agent's current owner")
	ErrWrongSeal   = errors.New("the credential set is for another agent")
	ErrStale       = errors.New("the credential set is older than one this agent already loaded")
	ErrWrongEpoch  = errors.New("the credential set was signed for an earlier ownership of this agent")
)

// Open verifies doc and decrypts its values. A document whose signature,
// seal, version or epoch is wrong is refused whole; an entry whose
// definition or value does not check out is skipped and named in Skipped.
func Open(doc Document, c Check) (*Opened, error) {
	if !strings.EqualFold(doc.Set.SealID, c.SealID) {
		return nil, ErrWrongSeal
	}
	if doc.Set.Version < c.MinVersion {
		return nil, ErrStale
	}
	if c.OwnerEpoch != 0 && doc.Set.OwnerEpoch != c.OwnerEpoch {
		return nil, ErrWrongEpoch
	}
	digest, err := doc.Set.Digest(c.Domain)
	if err != nil {
		return nil, err
	}
	signer, err := Recover(digest, doc.Signature)
	if err != nil {
		return nil, fmt.Errorf("credential set signature: %w", err)
	}
	if signer != c.Owner {
		return nil, ErrWrongSigner
	}
	out := &Opened{Set: doc.Set, Defs: map[string]*Definition{}, Values: map[string][]byte{}, Skipped: map[string]string{}}
	seen := map[string]bool{}
	for _, e := range doc.Set.Entries {
		if seen[e.Name] {
			return nil, fmt.Errorf("credential %q listed twice", e.Name)
		}
		seen[e.Name] = true
		def, value, why := openEntry(doc, e, c)
		if why != "" {
			out.Skipped[e.Name] = why
			continue
		}
		out.Defs[e.Name] = def
		out.Values[e.Name] = value
	}
	return out, nil
}

func openEntry(doc Document, e SetEntry, c Check) (*Definition, []byte, string) {
	raw, err := base64.StdEncoding.DecodeString(doc.Defs[e.Name])
	if err != nil || len(raw) == 0 {
		return nil, nil, "definition missing"
	}
	if !strings.EqualFold(crypto.Keccak256Hash(raw).Hex(), e.DefHash) {
		return nil, nil, "definition does not match the signed hash"
	}
	var def Definition
	if err := json.Unmarshal(raw, &def); err != nil || def.V != 1 || def.Name != e.Name {
		return nil, nil, "definition is not valid"
	}
	if !credproxy.ValidName(def.Name) || strings.HasPrefix(def.Name, "derived:") {
		return nil, nil, "name is not valid for an owner entry"
	}
	ct, err := chooseCiphertext(doc, &def, c)
	if err != nil {
		return nil, nil, err.Error()
	}
	if ct == nil { // a login entry with no value yet
		return &def, nil, ""
	}
	value, err := openValue(ct, def.Name, c)
	if err != nil {
		return nil, nil, err.Error()
	}
	// An entry the proxy cannot serve is left out here, with its reason,
	// rather than failing the whole set where the proxy loads it.
	if err := def.Entry(value).Validate(); err != nil {
		return nil, nil, err.Error()
	}
	return &def, value, ""
}

// chooseCiphertext prefers a valid writeback (a rotated or logged-in value
// sealed stored for this set version) over the owner's value.
func chooseCiphertext(doc Document, def *Definition, c Check) ([]byte, error) {
	if wb, ok := doc.Writebacks[def.Name]; ok && def.Writeback && wb.SetVersion == doc.Set.Version {
		ct, err := base64.StdEncoding.DecodeString(wb.Ciphertext)
		if err == nil {
			msg := WritebackMessage(c.SealID, def.Name, wb.SetVersion, wb.BootID, ct)
			if sig, derr := hexSig(wb.Signature); derr == nil {
				if pub, perr := crypto.SigToPub(crypto.Keccak256(msg), sig); perr == nil && crypto.PubkeyToAddress(*pub) == c.AgentSeal {
					return ct, nil
				}
			}
		}
	}
	if def.ValueHash == "" {
		if len(def.MCP) > 0 {
			return nil, nil
		}
		return nil, errors.New("definition has no value hash")
	}
	ct, err := base64.StdEncoding.DecodeString(doc.Values[def.Name])
	if err != nil || len(ct) == 0 {
		return nil, errors.New("value missing")
	}
	if !strings.EqualFold(crypto.Keccak256Hash(ct).Hex(), def.ValueHash) {
		return nil, errors.New("value does not match the signed hash")
	}
	return ct, nil
}

func openValue(ct []byte, name string, c Check) ([]byte, error) {
	pt, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(c.AgentSealPriv), ct)
	if err != nil {
		return nil, errors.New("value is not sealed to this agent")
	}
	var p valuePlaintext
	if err := json.Unmarshal(pt, &p); err != nil || p.V != 1 || p.Type != "credential" {
		return nil, errors.New("value is not a credential")
	}
	if !strings.EqualFold(p.SealID, c.SealID) || p.ChainID != c.Domain.ChainID || p.Name != name {
		return nil, errors.New("value is bound to another agent or entry")
	}
	if !common.IsHexAddress(p.Owner) || common.HexToAddress(p.Owner) != c.Owner {
		return nil, errors.New("value was sealed by a different owner")
	}
	return []byte(p.Value), nil
}

// SealValue encrypts value for the agent whose public key is pub, in the
// format openValue reads. sealed uses it for writebacks; the SDK mirrors it.
func SealValue(pub *eciesgo.PublicKey, owner common.Address, sealID string, chainID uint64, name string, value []byte) ([]byte, error) {
	pt, err := json.Marshal(valuePlaintext{V: 1, Type: "credential", Owner: owner.Hex(), SealID: strings.ToLower(sealID), ChainID: chainID, Name: name, Value: string(value)})
	if err != nil {
		return nil, err
	}
	return eciesgo.Encrypt(pub, pt)
}

// Entry converts a definition and its value into a proxy entry.
func (d *Definition) Entry(value []byte) *credproxy.Entry {
	e := &credproxy.Entry{
		Name:      d.Name,
		Hosts:     append([]string(nil), d.Hosts...),
		Positions: append([]credproxy.Position(nil), d.Positions...),
		Use:       d.Use,
		Signer:    d.Signer,
		Value:     value,
	}
	if d.ExpiresAt > 0 {
		e.ExpiresAt = time.Unix(d.ExpiresAt, 0)
	}
	return e
}

func hash32(s string) (common.Hash, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil || len(b) != 32 {
		return common.Hash{}, fmt.Errorf("want 32 bytes of hex, got %q", s)
	}
	return common.BytesToHash(b), nil
}

func hexSig(s string) ([]byte, error) {
	sig, err := eip712.DecodeSignature(s)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
