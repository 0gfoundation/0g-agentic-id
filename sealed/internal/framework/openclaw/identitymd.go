package openclaw

import (
	"bytes"
	"fmt"
	"os"
)

// IDENTITY.md sealed-managed injection.
//
// This file is the openclaw adapter's delivery layer: it takes a
// pre-built platform.Identity section string and writes it to
// IDENTITY.md using the marker-injection mechanism. Content generation
// lives in internal/platform/context.go.
//
// The adapter's only job here is:
//   - ensure the file has a safe heading for openclaw's identity merger
//   - wrap the platform content in marker comments
//   - handle the file I/O

// identityMDHeader is the canonical top-level heading for IDENTITY.md.
// It matches openclaw's own empty-file fallback string. We seed it
// when the file is fresh so owner identity-CLI mutations (`openclaw
// identity set name=...`) land BETWEEN this heading and our marker
// block — i.e. outside the markers — and survive the chain round-trip.
//
// Background: openclaw's identity-file merger inserts owner-set fields
// (`- Name: ...`) just after the first `#`-prefixed line in the file.
// If our marker block is the first thing in the file, its `##` heading
// becomes the "first heading" and openclaw inserts owner content
// INSIDE our markers — at which point EvolutionFor strips it and the
// owner's bio is lost on the next reboot. Seeding a level-1 heading
// outside the markers anchors openclaw's insert point safely.
const identityMDHeader = "# IDENTITY.md - Agent Identity\n"

// upsertIdentityMD writes (or replaces) the sealed-managed section in
// IDENTITY.md with the platform identity content. On a fresh file, also
// seeds the canonical top-level heading outside the marker block (see
// identityMDHeader).
//
// Empty identitySection strips the section (does not unseed the heading).
func upsertIdentityMD(path, identitySection string) error {
	if err := ensureIdentityHeader(path); err != nil {
		return err
	}
	return upsertMarkedSection(path, identitySection)
}

// ensureIdentityHeader makes sure IDENTITY.md starts with a top-level
// heading (any `#`-prefixed line) so openclaw's identity merger has a
// safe insertion point outside our marker block. Idempotent: if a
// heading already exists, leaves the file alone.
func ensureIdentityHeader(path string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	cleaned := stripPlatformInjection(existing)
	if hasTopLevelHeading(cleaned) {
		return nil
	}
	var buf []byte
	buf = append(buf, []byte(identityMDHeader)...)
	if len(cleaned) > 0 {
		if !bytes.HasPrefix(cleaned, []byte("\n")) {
			buf = append(buf, '\n')
		}
		buf = append(buf, cleaned...)
	}
	// Preserve any existing marker section verbatim — strip removed it,
	// but upsertMarkedSection re-adds it on the next call.
	if start := bytes.Index(existing, []byte(platformMarkerStart)); start >= 0 {
		if end := bytes.Index(existing[start:], []byte(platformMarkerEnd)); end >= 0 {
			section := existing[start : start+end+len(platformMarkerEnd)]
			if !bytes.HasSuffix(buf, []byte("\n")) {
				buf = append(buf, '\n')
			}
			buf = append(buf, '\n')
			buf = append(buf, section...)
			buf = append(buf, '\n')
		}
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return fmt.Errorf("seed IDENTITY.md header: %w", err)
	}
	return nil
}

// hasTopLevelHeading reports whether content has any non-blank line
// whose first non-whitespace character is `#`.
func hasTopLevelHeading(content []byte) bool {
	for _, line := range bytes.Split(content, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("#")) {
			return true
		}
	}
	return false
}
