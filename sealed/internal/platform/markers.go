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
//
// The body is normalized to end in "\n" so both markers always sit on
// lines of their own — StripInjected only recognizes line-anchored
// markers (see below), so the writer must uphold that shape.
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
		if body[len(body)-1] != '\n' {
			body += "\n"
		}
		section := MarkerStart + "\n" + body + MarkerEnd + "\n"
		out = cleaned
		if len(out) > 0 {
			out = append(out, '\n')
		}
		out = append(out, []byte(section)...)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Write via a same-directory temp file + rename so a failure mid-write
	// (disk full, killed process) cannot truncate or corrupt the existing
	// file — the rename is the only step that can observably change it, and
	// it either fully succeeds or leaves the original untouched.
	tmp, err := os.CreateTemp(dir, ".markers-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp to %s: %w", path, err)
	}
	return nil
}

// StripInjected removes the marker-delimited section, returning the
// agent-owned content only — the exact inverse of UpsertMarkedSection's
// wire format. Files without markers pass through unchanged.
//
// A marker counts as a section boundary only when it sits on a line of
// its own (start of content or preceded by '\n', and followed by '\n'
// or end of content) — exactly how UpsertMarkedSection writes it. The
// marker strings are visible to the agent in its own context files
// every turn, so agent prose that merely QUOTES a marker mid-line must
// be owner content, not a boundary: a first-index scan here once
// treated such a quote as the section start and silently deleted
// everything from the quote to the real section's end marker — a loss
// that was then written back to disk and hashed on chain, permanently.
// Hence:
//   - the start marker is matched from the END of the content (the
//     real section is the one the writer appended last), and
//   - a start with no matching end strips nothing (owner content),
//     instead of truncating to EOF.
//
// Still ambiguous by construction: an agent-written EXACT reproduction
// of the wire format — both markers, each on a line of its own — is
// indistinguishable from a real section and will be treated as one.
// Mentioning a marker mid-line (the realistic case) is safe.
//
// Adapters MUST run this on every chain-tracked file that may carry an
// injection, both when hashing (EvolutionFor) and when returning entry
// plaintext (LoadEntry) — the two paths must agree byte-for-byte or the
// watcher reports phantom drift.
func StripInjected(content []byte) []byte {
	s := lastAnchored(content, []byte(MarkerStart))
	if s < 0 {
		return content
	}
	rest := content[s:]
	e := firstAnchored(rest, []byte(MarkerEnd))
	if e < 0 {
		return content
	}
	// The byte before MarkerStart is the section's own "\n" separator
	// (absent when the section is the whole file); removing exactly one
	// "\n" recovers the owner bytes verbatim. On-disk files never outlive
	// a boot (Restore rewrites them from chain plaintext before the first
	// upsert), so no legacy-format tolerance is needed here.
	before := bytes.TrimSuffix(content[:s], []byte("\n"))
	// Drop the "\n" upsert writes after MarkerEnd; anything beyond it is
	// owner/agent content and passes through verbatim.
	after := bytes.TrimPrefix(rest[e+len(MarkerEnd):], []byte("\n"))
	if len(after) == 0 {
		return before
	}
	return append(append([]byte{}, before...), after...)
}

// lastAnchored returns the offset of the last line-anchored occurrence
// of marker in content, or -1.
func lastAnchored(content, marker []byte) int {
	for hi := len(content); hi > 0; {
		i := bytes.LastIndex(content[:hi], marker)
		if i < 0 {
			return -1
		}
		if lineAnchored(content, i, len(marker)) {
			return i
		}
		hi = i
	}
	return -1
}

// firstAnchored returns the offset of the first line-anchored occurrence
// of marker in content, or -1.
func firstAnchored(content, marker []byte) int {
	for lo := 0; ; {
		i := bytes.Index(content[lo:], marker)
		if i < 0 {
			return -1
		}
		i += lo
		if lineAnchored(content, i, len(marker)) {
			return i
		}
		lo = i + 1
	}
}

// lineAnchored reports whether content[i:i+n] occupies a line of its
// own: at offset 0 or preceded by '\n', and followed by '\n' or the end
// of the content.
func lineAnchored(content []byte, i, n int) bool {
	if i > 0 && content[i-1] != '\n' {
		return false
	}
	j := i + n
	return j >= len(content) || content[j] == '\n'
}
