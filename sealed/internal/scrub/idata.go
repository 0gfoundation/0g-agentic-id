// Package scrub keeps secrets out of what sealed commits on chain. The agent
// can have a secret written into its files (a revealed key pasted into a
// memory note, a token in a skill's script); the role content sealed uploads
// carries a stand-in instead, so a later owner, a transferee or a clone that
// decrypts the agent's data never gets the secret. Two passes, in order:
//
//   - the credential values sealed holds become their placeholders,
//     [[credential:<name>]] (credproxy.Registry);
//   - secrets of a known format that sealed does not hold become
//     [redacted:<kind>] (patterns.go).
//
// Every committed role of every framework goes through both, whether or not
// any credential is held. The file on disk keeps what the agent wrote; only
// the committed copy is scrubbed, so a reset restores the stand-in.
//
// Drift is judged on the scrubbed content too: a file that still holds the
// secret scrubs to the same bytes on every pass, so it is committed once,
// not every 30 seconds.
package scrub

import (
	"context"
	"strings"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

// Values is what sealed holds (credproxy.Registry).
type Values interface {
	// Len is the number of values held; no value is scrubbed while it is 0.
	Len() int
	// Generation advances whenever the values change.
	Generation() uint64
	// Scrub replaces every value in b with its placeholder, returning b
	// itself when nothing matched.
	Scrub(b []byte) []byte
}

// maxCache bounds the per-entry results kept between passes.
const maxCache = 4096

// IData wraps the adapter for the watcher and the uploader: EvolutionFor and
// LoadEntry return scrubbed content, and a manifest's entries carry the
// hashes and sizes of their scrubbed content. Everything else passes
// through.
type IData struct {
	framework.Framework
	values Values

	mu    sync.Mutex
	gen   uint64
	cache map[string]entryResult // role, path, adapter's content hash → scrubbed
}

type entryResult struct {
	hash string
	size int
}

// Wrap returns fw with its committed content scrubbed of v's values (none
// when v is nil) and of the secret formats patterns.go knows.
func Wrap(fw framework.Framework, v Values) *IData {
	return &IData{Framework: fw, values: v, cache: map[string]entryResult{}}
}

// scrub runs both passes over one file's bytes, returning b itself when
// nothing matched.
func (a *IData) scrub(b []byte) []byte {
	if a.values != nil && a.values.Len() > 0 {
		b = a.values.Scrub(b)
	}
	return Patterns(b)
}

func (a *IData) generation() uint64 {
	if a.values == nil {
		return 0
	}
	return a.values.Generation()
}

func (a *IData) shapeOf(role string) framework.Shape {
	for _, r := range a.Roles() {
		if r.Name == role {
			return r.Shape
		}
	}
	return framework.Leaf
}

// EvolutionFor returns the role's content as it is committed.
func (a *IData) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	raw, err := a.Framework.EvolutionFor(ctx, role)
	if err != nil {
		return raw, err
	}
	if a.shapeOf(role) == framework.DirectoryManifest {
		return a.scrubManifest(ctx, role, raw)
	}
	return a.scrub(raw), nil
}

// LoadEntry returns one manifest entry's content as it is committed.
func (a *IData) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	raw, err := a.Framework.LoadEntry(ctx, role, path)
	if err != nil {
		return raw, err
	}
	return a.scrubEntry(path, raw)
}

// scrubEntry scrubs a file's bytes, or every file inside a directory
// entry's archive.
func (a *IData) scrubEntry(path string, content []byte) ([]byte, error) {
	if strings.HasSuffix(path, "/") {
		return manifest.ScrubArchive(content, a.scrub)
	}
	return a.scrub(content), nil
}

// scrubManifest gives each entry the hash and size of its scrubbed content.
// An entry's result is kept by its unscrubbed hash until the values change
// (the secret formats are fixed in the binary), so an unchanged entry is not
// read again on the next pass.
func (a *IData) scrubManifest(ctx context.Context, role string, raw []byte) ([]byte, error) {
	m, err := manifest.Unmarshal(raw)
	if err != nil {
		return raw, nil // the uploader reports an unreadable manifest
	}
	a.mu.Lock()
	if gen := a.generation(); gen != a.gen || len(a.cache) > maxCache {
		a.gen, a.cache = gen, map[string]entryResult{}
	}
	a.mu.Unlock()

	changed := false
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.IsHeld() {
			continue
		}
		key := role + "\x00" + e.Path + "\x00" + e.ContentHash
		a.mu.Lock()
		got, ok := a.cache[key]
		a.mu.Unlock()
		if !ok {
			content, err := a.Framework.LoadEntry(ctx, role, e.Path)
			if err != nil {
				return nil, err
			}
			scrubbed, err := a.scrubEntry(e.Path, content)
			if err != nil {
				return nil, err
			}
			got = entryResult{hash: manifest.HashHex(scrubbed), size: len(scrubbed)}
			// Kept only for the content the manifest names: a file that
			// changed between the manifest and this read is read again on
			// the next pass, never remembered under the other hash.
			if manifest.HashHex(content) == e.ContentHash {
				if got.hash == e.ContentHash {
					got = entryResult{hash: e.ContentHash, size: e.Size}
				}
				a.mu.Lock()
				a.cache[key] = got
				a.mu.Unlock()
			}
		}
		if got.hash != e.ContentHash {
			e.ContentHash, e.Size = got.hash, got.size
			changed = true
		}
	}
	if !changed {
		return raw, nil
	}
	return m.Marshal()
}
