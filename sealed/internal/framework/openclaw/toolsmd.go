package openclaw

import (
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

// The marker delivery primitive moved to internal/platform/markers.go when
// the second adapter (claudecode) needed byte-identical strip rules. The
// package-local names below are thin aliases so this adapter's call sites
// and tests read the same as before the move.

const (
	platformMarkerStart = platform.MarkerStart
	platformMarkerEnd   = platform.MarkerEnd
)

func upsertMarkedSection(path, body string) error {
	return platform.UpsertMarkedSection(path, body)
}

// stripPlatformInjection removes the marker-delimited section, returning
// the agent-owned content only. Used by:
//
//   - upsertMarkedSection before re-injecting (idempotent updates)
//   - evolution_paths.go evoWorkspace before hashing every md
//   - restore_paths.go LoadEntry to return canonical plaintext
func stripPlatformInjection(content []byte) []byte {
	return platform.StripInjected(content)
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
