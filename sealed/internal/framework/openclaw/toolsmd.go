package openclaw

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"seal-verify/internal/platform"
)

// Platform-managed sealed injections into workspace markdown files.
//
// openclaw loads SOUL.md, IDENTITY.md, USER.md, TOOLS.md, and MEMORY.md
// into the LLM system prompt every turn (see CONTEXT_FILE_ORDER in the
// openclaw runtime; priority order SOUL=20 > IDENTITY=30 > USER=40 >
// TOOLS=50 > MEMORY=70). Sealed uses three of those files as
// runtime-controlled channels with distinct roles:
//
//	IDENTITY.md  who you are: agentSeal facts + trust chain
//	             → identitymd.go (delivery)
//	             → platform.Build().Identity (content)
//	SOUL.md      what you will / won't do: sovereignty, refusal rules
//	             → soulmd.go (delivery)
//	             → platform.Build().Sovereignty (content)
//	TOOLS.md     how to invoke capabilities + what constraints apply:
//	             sign endpoints, public URL, service exposure, persistent
//	             state, version whitelist, config allowlist, drift
//	             behavior, runtime snapshot
//	             → this file (delivery)
//	             → platform.Build().Capabilities + .Constraints + .Runtime
//
// Each injection is wrapped in `0g-platform-injected` markers.
// EvolutionFor strips them before hashing (evolution_paths.go) and
// LoadEntry mirrors the strip (restore_paths.go), so chain payloads
// stay platform-neutral while the on-disk files keep per-boot platform
// content for the LLM.

const (
	platformMarkerStart = "<!-- 0g-platform-injected:start -->"
	platformMarkerEnd   = "<!-- 0g-platform-injected:end -->"
)

// upsertMarkedSection writes (or replaces) a marker-delimited body in
// path. Owner / agent content outside the markers is preserved.
//
// Empty body → strip the existing section entirely and leave whatever
// remains. Used by upsertToolsMD / upsertIdentityMD / upsertSoulMD.
func upsertMarkedSection(path, body string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	cleaned := stripPlatformInjection(existing)

	var out []byte
	if body == "" {
		out = cleaned
	} else {
		section := platformMarkerStart + "\n" + body + platformMarkerEnd + "\n"
		if len(cleaned) > 0 && !bytes.HasSuffix(cleaned, []byte("\n")) {
			cleaned = append(cleaned, '\n')
		}
		if len(cleaned) > 0 {
			cleaned = append(cleaned, '\n')
		}
		out = append(cleaned, []byte(section)...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// stripPlatformInjection removes the marker-delimited section, returning
// the agent-owned content only. Files without markers pass through
// unchanged. Used by:
//
//   - upsertMarkedSection before re-injecting (idempotent updates)
//   - evolution_paths.go evoWorkspace before hashing every md
//   - restore_paths.go LoadEntry to return canonical plaintext
func stripPlatformInjection(content []byte) []byte {
	s := bytes.Index(content, []byte(platformMarkerStart))
	if s < 0 {
		return content
	}
	rest := content[s:]
	e := bytes.Index(rest, []byte(platformMarkerEnd))
	if e < 0 {
		return bytes.TrimRight(content[:s], "\n")
	}
	before := bytes.TrimRight(content[:s], "\n")
	after := bytes.TrimLeft(rest[e+len(platformMarkerEnd):], "\n")
	if len(after) == 0 {
		return before
	}
	return append(append(before, '\n', '\n'), after...)
}

// upsertToolsMD writes (or replaces) the sealed-managed section in
// TOOLS.md. It combines three sections from PlatformContext:
//   - Capabilities (sign endpoints, public URL, service exposure,
//     persistent state)
//   - Constraints (version whitelist, config allowlist, drift behavior)
//   - Runtime snapshot (per-boot dynamic info)
//
// If capabilities section is empty (no signSock / publicURL), strips
// the existing injection entirely.
func upsertToolsMD(path string, pc platform.PlatformContext) error {
	var sections []string
	if pc.Capabilities != "" {
		sections = append(sections, pc.Capabilities)
	}
	if pc.Constraints != "" {
		sections = append(sections, pc.Constraints)
	}
	if pc.Runtime != "" {
		sections = append(sections, pc.Runtime)
	}
	if len(sections) == 0 {
		return upsertMarkedSection(path, "")
	}
	body := strings.Join(sections, "\n")
	return upsertMarkedSection(path, body)
}
