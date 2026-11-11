package uploader

// Plaintext commitments (sealed/LAYERS.md §7.1). An entry's dataHash is the
// root of its ciphertext, which a fresh random nonce makes different on every
// upload, so it says nothing about the plaintext. For adapters that declare
// it (framework.PlaintextCommitter: 0g-harness) every entry this uploader
// writes also carries a salted commitment to its plaintext, in its
// dataDescription:
//
//	"commitments": {"sha256": "0x…"}
//
// computed as (‖ is concatenation; root is a 32-byte storage root):
//
//	salt(root)  = HMAC-SHA256(dataKey, "AgentDNA.Commitment.v1" ‖ 0x00 ‖ role ‖ 0x00 ‖ root)
//	leaf role   : sha256(salt(dataHash) ‖ sha256(plaintext))
//	directory   : the Merkle root of its entries in manifest (path) order, each
//	              leaf sha256(0x00 ‖ sha256(path) ‖ sha256(salt(entry root) ‖ content_hash)),
//	              each node sha256(0x01 ‖ left ‖ right), split as RFC 6962
//	              does (the left part holds the largest power of two below n)
//
// The salt is never stored: only sealed holds the data key, and it computes
// a salt again when it is needed. Revealing one salt (with the plaintext,
// and for a directory the Merkle path) proves that one version or that one
// file and nothing else, since every version and every file has its own
// root. Without the salt, guessing the plaintext does not reproduce the
// commitment.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"seal-verify/internal/manifest"
)

// commitmentLabel opens every salt's HMAC input.
const commitmentLabel = "AgentDNA.Commitment.v1"

// commitments is the dataDescription field.
type commitments struct {
	SHA256 string `json:"sha256"`
}

// commitmentSalt is salt(root) for one role.
func commitmentSalt(dataKey []byte, role string, root [32]byte) []byte {
	mac := hmac.New(sha256.New, dataKey)
	mac.Write([]byte(commitmentLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(role))
	mac.Write([]byte{0})
	mac.Write(root[:])
	return mac.Sum(nil)
}

// saltedHash is sha256(salt ‖ contentHash).
func saltedHash(salt []byte, contentHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(contentHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// leafCommitment is a leaf role's commitment.
func leafCommitment(dataKey []byte, role string, dataHash [32]byte, plaintext []byte) [32]byte {
	return saltedHash(commitmentSalt(dataKey, role, dataHash), sha256.Sum256(plaintext))
}

// manifestCommitment is a directory role's commitment, over the entries of
// its filled manifest (every storage pointer set).
func manifestCommitment(dataKey []byte, role string, m *manifest.Manifest) ([32]byte, error) {
	leaves := make([][32]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		root, err := hash32(e.StoragePtr.RootHash)
		if err != nil {
			return [32]byte{}, fmt.Errorf("entry %q storage root: %w", e.Path, err)
		}
		content, err := hash32(e.ContentHash)
		if err != nil {
			return [32]byte{}, fmt.Errorf("entry %q content hash: %w", e.Path, err)
		}
		file := saltedHash(commitmentSalt(dataKey, role, root), content)
		path := sha256.Sum256([]byte(e.Path))
		leaf := sha256.New()
		leaf.Write([]byte{0})
		leaf.Write(path[:])
		leaf.Write(file[:])
		var l [32]byte
		copy(l[:], leaf.Sum(nil))
		leaves = append(leaves, l)
	}
	return merkleRoot(leaves), nil
}

// merkleRoot is the RFC 6962 tree hash of leaves (already leaf-hashed):
// the left subtree holds the largest power of two below n. No leaves give
// sha256 of nothing.
func merkleRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	left, right := merkleRoot(leaves[:k]), merkleRoot(leaves[k:])
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func hash32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("not 32 bytes of hex: %q", s)
	}
	copy(out[:], b)
	return out, nil
}

func commitmentsOf(c [32]byte) *commitments {
	return &commitments{SHA256: "0x" + hex.EncodeToString(c[:])}
}
