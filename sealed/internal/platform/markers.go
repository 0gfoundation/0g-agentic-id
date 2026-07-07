package platform

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Marker-injection delivery mechanism, shared by every framework adapter.
//
// Content generation lives in context.go (Build → PlatformContext); this
// file owns the delivery primitive: wrapping a section in stable HTML
// comment markers inside an agent-owned file, and stripping it back out
// so evolution hashing sees only agent-owned bytes.
//
// History: these helpers started life inside the openclaw adapter
// (toolsmd.go). Porting the second adapter (claudecode) showed the marker
// convention is protocol-level — every adapter that injects platform
// context into chain-tracked files must strip with the exact same rules,
// or its round-trip breaks — so they moved here.

const (
	MarkerStart = "<!-- 0g-platform-injected:start -->"
	MarkerEnd   = "<!-- 0g-platform-injected:end -->"
)

// UpsertMarkedSection writes (or replaces) a marker-delimited body in
// path. Owner / agent content outside the markers is preserved
// BYTE-EXACTLY: StripInjected(result) == the pre-injection content.
//
// Wire format (lossless by construction — the separator is exactly one
// "\n" owned by the section, never a normalization of the owner bytes):
//
//	<owner bytes, verbatim>
//	"\n" + MarkerStart + "\n" + body + MarkerEnd + "\n"
//
// The historical version instead ensured a blank line before the section
// by conditionally appending newlines to the owner content. That
// normalization is not invertible ("abc" and "abc\n" produced the same
// file), so StripInjected had to guess — it trimmed ALL trailing
// newlines, silently eating the owner's final "\n" and causing one
// guaranteed phantom-drift chain.Update per injected file on an agent's
// first boot. The claudecode adapter's conformance tests caught this;
// see FRAMEWORK_ADAPTER.md's port findings.
//
// Empty body → strip the existing section entirely and leave whatever
// remains. Creates parent directories as needed.
func UpsertMarkedSection(path, body string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	cleaned := StripInjected(existing)

	var out []byte
	if body == "" {
		out = cleaned
	} else {
		section := MarkerStart + "\n" + body + MarkerEnd + "\n"
		out = cleaned
		if len(out) > 0 {
			out = append(out, '\n')
		}
		out = append(out, []byte(section)...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// StripInjected removes the marker-delimited section, returning the
// agent-owned content only — the exact inverse of UpsertMarkedSection's
// wire format. Files without markers pass through unchanged.
//
// Adapters MUST run this on every chain-tracked file that may carry an
// injection, both when hashing (EvolutionFor) and when returning entry
// plaintext (LoadEntry) — the two paths must agree byte-for-byte or the
// watcher reports phantom drift.
func StripInjected(content []byte) []byte {
	s := bytes.Index(content, []byte(MarkerStart))
	if s < 0 {
		return content
	}
	// The byte before MarkerStart is the section's own "\n" separator
	// (absent when the section is the whole file); removing exactly one
	// "\n" recovers the owner bytes verbatim. On-disk files never outlive
	// a boot (Restore rewrites them from chain plaintext before the first
	// upsert), so no legacy-format tolerance is needed here.
	before := bytes.TrimSuffix(content[:s], []byte("\n"))
	rest := content[s:]
	e := bytes.Index(rest, []byte(MarkerEnd))
	if e < 0 {
		return before
	}
	// Drop the "\n" upsert writes after MarkerEnd; anything beyond it is
	// owner/agent content and passes through verbatim.
	after := bytes.TrimPrefix(rest[e+len(MarkerEnd):], []byte("\n"))
	if len(after) == 0 {
		return before
	}
	return append(append([]byte{}, before...), after...)
}
