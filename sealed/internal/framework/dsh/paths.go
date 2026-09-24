package dsh

// Filesystem paths the dsh adapter manages.
//
// DSH keeps all user data under one root: $DSH_HOME, default ~/.dsh
// (dsh-home-paths' resolveDshHome()). This adapter tracks two children of
// that root as agent identity:
//
//	skills/          agent-installed skills — the "user-dsh" rank-400 root in
//	                 the skill-discovery table (docs/subsystems/skills.md),
//	                 <name>/SKILL.md or <name>.md per skill (skills.go)
//	APPEND_SYSTEM.md the owner persona (persona.go)
//
// Deliberately NOT managed (never on chain):
//
//   - $DSH_HOME/settings.yaml — DSH's own hot-reloaded settings file. This
//     adapter no longer writes, reads or tracks it: the inference pin comes
//     from the owner's settings document and reaches the bridge as env
//     (settings.go). Nothing regressed by dropping it — the bridge never
//     mounted `dsh-settings-file`, so DSH itself never read the file either.
//     An agent minted while the role existed still has one last use for it:
//     HandleLegacy reads the pin out of the chain entry once at boot, and the
//     platform persists it as that agent's settings document (settings.go).
//
//   - $DSH_HOME/AGENTS.md — the spine's workspace-context file. Nothing
//     mounts the extra that reads it (the knob that would is refused, see
//     settings.go), and no role carries it: an agent may write it, but it is
//     read by nothing and survives nothing.
//
//   - Any session-persistence backend's output. This adapter's composition
//     mounts NO session-persistence plugin: the bridge keeps one Agent
//     object alive in process memory for the container's lifetime, so
//     `followup()` continuity does not depend on a durable session log —
//     and DSH's own session log is append-only, growing on every turn, which
//     would phantom-drift on every 30s tick if it were ever tracked.
//   - $DSH_HOME/.credentials.yaml — the credentials store. The inference key
//     reaches the bridge via env only; nothing writes this file.
//   - $DSH_HOME/skills/.system — the local skill provider's own reserved
//     child (docs/subsystems/skills.md), never agent content.
//   - The sealed platform/doctrine text: injected in code via
//     ctx.systemPrompt.section() after boot settles (see spawn.go), never
//     through a tracked file — the same pattern prime-agent uses and for the
//     same reason (FRAMEWORK_ADAPTER.md §13 point 2: pick the authoritative
//     channel, keep platform-authored bytes out of every tracked role).
//   - The DSH checkout itself (packages/, apps/) — this port does not track
//     agent self-modification of harness source. DSH is unusual among the
//     shipped adapters in explicitly inviting that (a system-prompt section
//     names its own checkout path so its self-referential toolset can read
//     and edit it), but doing so safely needs a promote/rollback primitive
//     this codebase does not have yet (see the package doc). v1 tracks only
//     the framework's DATA surface — the persona and the installed skills.
//     The inference pin is NOT part of it: it is the owner's settings
//     document, rendered into the bridge's environment at every Start
//     (settings.go), and no role carries it.
//
// `dshHome` is a var (not const) so unit tests can redirect into
// t.TempDir(). Production code never reassigns it.

import (
	"fmt"
	"os"
)

var dshHome = "/root/.dsh"

// ensureDir creates a managed directory (and parents) if absent.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

func skillsDir() string { return dshHome + "/skills" }

// appendSystemPath holds the owner persona, injected by the bridge into
// ctx.systemPrompt at boot (see spawn.go) — DSH has no native
// append-system-prompt-from-file convention the way prime-agent does, so
// nothing but this adapter ever reads this file. It lives under dshHome
// anyway for FrameworkFacts' Home reporting and cross-adapter naming
// consistency (informational only — tooling reads role names, not paths).
func appendSystemPath() string { return dshHome + "/APPEND_SYSTEM.md" }

// agentDocPath is where Start writes the assembled agent doc (platform
// mechanics + this adapter's FrameworkFacts) for the bridge to inject via
// ctx.systemPrompt.section(). Deliberately OUTSIDE dshHome: per-boot platform
// text must never be reachable by a tracked role.
func agentDocPath() string { return "/run/seal-agentdoc.md" }
