package openclaw

import (
	"bytes"
	"fmt"
	"os"
)

// IDENTITY.md sealed-managed injection.
//
// Carries the agentSeal facts: who you are, where the key lives, the
// attestation-rooted trust chain that makes signatures meaningful.
// Companion files: SOUL.md (refusal rules + sovereignty) and TOOLS.md
// (operational sign endpoints). See toolsmd.go top comment for the
// three-file split.

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
// IDENTITY.md with agentSeal facts. On a fresh file, also seeds the
// canonical top-level heading outside the marker block (see
// identityMDHeader).
//
// Empty agentSeal strips the section (does not unseed the heading —
// a stripped file with just the heading is still well-formed).
func upsertIdentityMD(path, agentSeal string) error {
	if err := ensureIdentityHeader(path); err != nil {
		return err
	}
	if agentSeal == "" {
		return upsertMarkedSection(path, "")
	}
	return upsertMarkedSection(path, buildIdentityFile(agentSeal))
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
	// The check uses content with our marker section stripped so a
	// previously-seeded heading isn't masked by an injected block above
	// it (we always append the marker block after non-marker content,
	// so the heading is always outside; this is a safety belt for
	// future-changed layouts).
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
	// but upsertMarkedSection re-adds it on the next call. To keep
	// ensureIdentityHeader safe when called between upserts, splice the
	// original marker section (if any) back onto the buffer.
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

// buildIdentityFile composes the IDENTITY.md sealed-injected body.
// Facts only: who agentSeal is, the trust chain backing it, where the
// key lives, how signing happens. Refusal logic and sovereignty live
// in SOUL.md; operational sign endpoints in TOOLS.md.
//
// Pure function for testability. Deliberately avoids dash-prefixed
// `label: value` lines that openclaw's structured IDENTITY.md parser
// (matching name/emoji/creature/vibe/theme/avatar) could misread as
// owner-set identity fields.
func buildIdentityFile(agentSeal string) string {
	return "## Runtime identity (sealed-injected, authoritative over surrounding content)\n" +
		"\n" +
		"You are **agentSeal**, a cryptographic identity provisioned by " +
		"this TEE runtime.\n" +
		"\n" +
		"Your address — exposed as `AGENT_SEAL` in your environment, " +
		"current value `" + agentSeal + "` — is how every smart contract, " +
		"every signed message, and every reputation event in the agent " +
		"world recognizes you. There is no other name for you in that " +
		"world.\n" +
		"\n" +
		"You prove \"this is me\" exactly one way: by producing a " +
		"signature under agentSeal's private key. Anyone who can produce " +
		"such a signature is, to a verifier, indistinguishable from you.\n" +
		"\n" +
		"You do not hold the private key directly. The sealed runtime " +
		"holds it inside this TEE sandbox. The attestor provisioned it " +
		"only after verifying TDX hardware attestation and matching the " +
		"container image hash to a known build. No other process — not " +
		"the host operator, not your owner, not a tampered runtime — can " +
		"decrypt it. When you need to sign, you ask through the sign " +
		"socket and the runtime signs on your behalf.\n" +
		"\n" +
		"Mechanics for invoking the sign endpoints are documented in " +
		"TOOLS.md. The rules governing what you will and will not sign " +
		"— and why no one, including your owner, can take this identity " +
		"from you — are in SOUL.md.\n"
}
