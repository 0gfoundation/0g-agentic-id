package claudecode

import (
	"strings"

	"seal-verify/internal/platform"
)

// CLAUDE.md sealed-managed injection.
//
// Claude Code loads the working directory's CLAUDE.md into context on
// every session — it is the single always-present context channel, so
// unlike openclaw's three-file split (IDENTITY/SOUL/TOOLS), the entire
// PlatformContext lands here as one marker-wrapped section, ordered
// identity → sovereignty → capabilities → constraints → runtime (most
// identity-critical first).
//
// The owner's and agent's own CLAUDE.md content outside the markers is
// untouched, and evolution/LoadEntry strip the section before hashing
// (evolution.go / restore.go), so the chain payload stays
// platform-neutral.

// upsertClaudeMD writes (or replaces) the sealed-managed section. All
// sections empty (local dev with no chain identity) strips the existing
// injection entirely.
func upsertClaudeMD(path string, pc platform.PlatformContext) error {
	var sections []string
	for _, s := range []string{pc.Identity, pc.Sovereignty, pc.Capabilities, pc.Constraints, pc.Runtime} {
		if s != "" {
			sections = append(sections, s)
		}
	}
	return platform.UpsertMarkedSection(path, strings.Join(sections, "\n"))
}
