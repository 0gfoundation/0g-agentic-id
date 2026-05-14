// Package manifest defines the on-chain plaintext shape for
// directory-shaped roles (e.g. workspace/, workspace/skills/) and
// helpers for content hashing + deterministic packaging.
//
// A leaf role's iData points directly to a single encrypted blob
// (handled outside this package). A manifest role's iData points to
// a Manifest plaintext (this package's type) whose entries each point
// to their own content blob.
//
// Determinism is required: identical disk state must produce identical
// plaintext bytes so the watcher's sha256-based drift detection is
// stable across runs. See package functions' doc comments for the
// canonicalisation guarantees each provides.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SchemaVersion is the manifest plaintext schema version. Bumped only
// when reader-incompatible changes to Manifest/Entry fields land.
const SchemaVersion = 1

// KindLabel is the constant value Manifest.Kind takes for a directory
// manifest. Reserved for future variants (e.g. delta manifests) that
// may share the iData role layout but differ in entry semantics.
const KindLabel = "directory_manifest"

// EntryKind enumerates entry payload shapes inside a manifest.
type EntryKind string

const (
	// EntryFile means Entry.Path is a single file; the referenced blob's
	// plaintext is that file's raw bytes.
	EntryFile EntryKind = "file"

	// EntryDir means Entry.Path is a directory; the referenced blob's
	// plaintext is the deterministic tar.gz of that subtree.
	EntryDir EntryKind = "dir"
)

// StoragePtr names a 0g-storage blob. Same field names as the on-chain
// dataDescription.storage_ptr nested object so wire formats line up.
//
// indexer URL is NOT stored here: manifests share the role-level data_key
// and live in the same indexer as their parent iData entry, so a single
// indexer is configured at upload time and applies to all child blobs.
// Storing it per-entry would invite per-entry override which we don't
// support.
type StoragePtr struct {
	RootHash string `json:"root_hash"` // 0x-prefixed hex of 0g-storage root
	Size     int    `json:"size"`      // ciphertext byte count
}

// Entry is one item inside a Manifest. See EntryKind for the two cases.
type Entry struct {
	Path        string     `json:"path"`         // relative to role root; dirs end in "/"
	Kind        EntryKind  `json:"kind"`
	ContentHash string     `json:"content_hash"` // 0x-prefixed hex of plaintext sha256
	Size        int        `json:"size"`         // plaintext byte count
	StoragePtr  StoragePtr `json:"storage_ptr"`
}

// Manifest is the plaintext blob payload for a manifest-shape role.
//
// JSON output is deterministic: entries are sorted by Path, struct fields
// marshal in declaration order. Identical input data structures → identical
// bytes.
type Manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Kind          string  `json:"kind"`
	Entries       []Entry `json:"entries"`
}

// New returns an empty manifest with the current SchemaVersion and the
// default Kind. Use this rather than &Manifest{} so the type fields stay
// in sync.
func New() *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		Kind:          KindLabel,
		Entries:       []Entry{},
	}
}

// Marshal returns the canonical plaintext bytes for this manifest.
// Entries are sorted by Path in place before marshalling so the output
// is byte-identical for any input order.
func (m *Manifest) Marshal() ([]byte, error) {
	if m.SchemaVersion == 0 {
		m.SchemaVersion = SchemaVersion
	}
	if m.Kind == "" {
		m.Kind = KindLabel
	}
	if m.Entries == nil {
		m.Entries = []Entry{}
	}
	sort.Slice(m.Entries, func(i, j int) bool {
		return m.Entries[i].Path < m.Entries[j].Path
	})
	return json.Marshal(m)
}

// Unmarshal parses plaintext bytes into a Manifest. Validates schema
// version and kind so a wildly different blob shape can't be mistakenly
// treated as a manifest.
func Unmarshal(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("manifest: unsupported schema_version: %d (reader supports %d)",
			m.SchemaVersion, SchemaVersion)
	}
	if m.Kind != KindLabel {
		return nil, fmt.Errorf("manifest: unexpected kind: %q (expected %q)", m.Kind, KindLabel)
	}
	if m.Entries == nil {
		m.Entries = []Entry{}
	}
	return &m, nil
}

// StripStoragePtrs unmarshals manifest plaintext, zeroes every entry's
// StoragePtr, and re-marshals. Result is the "empty-ptr" canonical form
// whose sha256 is the watcher-facing ContentHash (the value
// uploader.Apply records via RecordChainUpload — see push_manifest.go:22-26).
//
// Why this exists: manifest-shape roles round-trip two distinct plaintexts
// through the stack. evoXxx() produces the empty-ptr form (adapter doesn't
// know storage roots), and that's what watcher drift hashes. pushManifest
// then fills the StoragePtr fields and uploads THAT form to 0g-storage,
// which is what subsequent bootstraps decrypt and pass to SeedChainSnapshot.
// Without stripping at bootstrap time, sha256(decrypted plaintext) != sha256
// (evo output) — the two snapshots disagree on what "in sync" means and
// every restart triggers a phantom upload.
func StripStoragePtrs(plaintext []byte) ([]byte, error) {
	m, err := Unmarshal(plaintext)
	if err != nil {
		return nil, err
	}
	for i := range m.Entries {
		m.Entries[i].StoragePtr = StoragePtr{}
	}
	return m.Marshal()
}

// EntryByPath returns the entry with the given path, or nil if absent.
// Path lookup is exact (no prefix matching). Used by uploader.Push to
// look up the previous storage_ptr for an unchanged entry.
func (m *Manifest) EntryByPath(path string) *Entry {
	for i := range m.Entries {
		if m.Entries[i].Path == path {
			return &m.Entries[i]
		}
	}
	return nil
}

// HashHex returns the 0x-prefixed hex sha256 of b. Same algorithm used
// for both Entry.ContentHash and iData.dataHash so the formats round-trip.
func HashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(sum[:])
}
