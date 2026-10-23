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
	"strings"
	"unicode/utf8"

	"seal-verify/internal/logger"
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
	Path        string     `json:"path"` // relative to role root; dirs end in "/"
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

// ValidEntryPath reports whether p is a well-formed entry path: exactly one
// path segment, optionally followed by "/" (a dir entry). RestoreEntry joins
// the path under the role's directory, so anything that could name a
// different directory — "", ".", "..", a "/" inside the segment, a NUL — is
// refused. So is a name that is not valid UTF-8: a manifest is JSON, which
// carries only UTF-8 strings, and encoding/json would rewrite the invalid
// bytes as U+FFFD, naming a file that does not exist. Every other byte is an
// ordinary file-name byte on Linux (a backslash included) and is accepted,
// so any UTF-8 name a directory listing returns is a valid entry path.
func ValidEntryPath(p string) error {
	seg := strings.TrimSuffix(p, "/")
	switch {
	case seg == "", seg == ".", seg == "..":
		return fmt.Errorf("manifest: invalid entry path %q", p)
	case strings.ContainsAny(seg, "/\x00"):
		return fmt.Errorf("manifest: entry path %q is not a single path segment", p)
	case !utf8.ValidString(seg):
		return fmt.Errorf("manifest: entry path %q is not valid UTF-8, which a manifest (JSON) cannot carry", p)
	}
	return nil
}

// Carries reports whether the directory entry name, found in dir, can be
// carried as a manifest entry (ValidEntryPath of name, or of name+"/" for a
// directory — the two agree). Every producer checks the names it lists
// through here, so what a producer emits is exactly what Unmarshal keeps and
// what the uploader can load back by its path; a name that cannot be
// carried is skipped and logged once, and the rest of the role keeps
// committing.
func Carries(dir, name string) bool {
	if err := ValidEntryPath(name); err != nil {
		logger.Once("manifest.carries:"+dir+"/"+name, "manifest: not tracking %q in %s: %v", name, dir, err)
		return false
	}
	return true
}

// Unmarshal parses plaintext bytes into a Manifest. Validates schema
// version and kind so a wildly different blob shape can't be mistakenly
// treated as a manifest. Manifests arrive from chain, where an agent's own
// commits (or an older sealed) put them, so an entry whose path is not a
// valid entry path (ValidEntryPath) is dropped with one log line rather
// than failing the whole manifest: every other entry still restores, and
// the next commit no longer carries the dropped one.
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
	kept := make([]Entry, 0, len(m.Entries))
	for _, e := range m.Entries {
		if err := ValidEntryPath(e.Path); err != nil {
			logger.Once("manifest.unmarshal:"+e.Path, "manifest: dropping entry: %v", err)
			continue
		}
		kept = append(kept, e)
	}
	m.Entries = kept
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

// heldHash is the ContentHash of a held entry (Held). It is not a hex
// digest, so no entry built from content carries it.
const heldHash = "held"

// Held is the entry a producer emits for path when the entry's content is
// over its size limit: it stands for "keep the committed version of this
// entry". It appears only in the drift form EvolutionFor returns, never on
// chain: the uploader replaces it with the entry for path in the manifest
// committed on chain, or leaves it out when that manifest has none
// (uploader.pushManifest). Holding one entry rather than failing the role
// keeps every other entry of the role committing.
func Held(path string, kind EntryKind) Entry {
	return Entry{Path: path, Kind: kind, ContentHash: heldHash}
}

// IsHeld reports whether e is a Held entry.
func (e Entry) IsHeld() bool { return e.ContentHash == heldHash }

// HashHex returns the 0x-prefixed hex sha256 of b. Same algorithm used
// for both Entry.ContentHash and iData.dataHash so the formats round-trip.
func HashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(sum[:])
}
