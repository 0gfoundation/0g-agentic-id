package prime

import (
	"seal-verify/internal/platform"
)

// FrameworkFacts implements framework.Framework: Prime Agent's blanks in the
// shared agent-doc template (FRAMEWORK_ADAPTER.md §9 part 2). Values only —
// platform renders the mechanics prose identically for every framework, so
// this adapter can neither restate a platform mechanism wrong nor silently
// drop one.
//
// Unlike openclaw and hermes, the assembled doc is NOT injected into a tracked
// file here. The HTTP bridge passes it to the SDK at session creation
// (agentsFilesOverride, reading agentDocPath()), which is both un-droppable by
// the agent's harness API and invisible to every tracked role.
func (a *Adapter) FrameworkFacts() platform.FrameworkFacts {
	return platform.FrameworkFacts{
		Home: "~/.prime/agent/",
		Tracked: []platform.PathNote{
			{Path: "~/.prime/agent/harness/harness_state.json", Note: "your Continual Harness — prompt notes, memories, skill registrations, subagent specs. **Only entries you promote to `global` scope reach chain**; everything you write at `local` scope lives in the session and disappears with it. This is the single most important thing to get right: promote what should outlive this task, leave the rest local"},
			{Path: "~/.prime/agent/APPEND_SYSTEM.md", Note: "your persona / standing instructions, appended to your system prompt every session"},
			{Path: "~/.prime/agent/skills/<name>/", Note: "each Python skill package you install (`pyproject.toml` + `src/<import>/__init__.py`). Registering a skill in the harness and writing its code are two separate facts — both are tracked, in their own roles"},
		},
		Untracked: []platform.PathNote{
			{Note: "the per-session harness state (`$RLM_SESSION_DIR/harness/harness_state.json`) — everything you refine mid-task lands here first. Deliberate: half-finished harness edits must not become your on-chain identity"},
			{Note: "the `refinements` log inside `harness_state.json` — a local audit trail of your self-modifications, not part of your identity"},
			{Note: "`.env` and any credential file — secrets never reach chain"},
		},
		DurableHints: []platform.DurableHint{
			{Ask: "Remember this long-term", Place: "a harness memory entry promoted to `global` scope"},
			{Ask: "Give yourself a new capability", Place: "a Python package under `skills/<name>/`, then register it as a harness skill entry (global scope)"},
			{Ask: "Change how you always behave", Place: "`APPEND_SYSTEM.md`, or a `global`-scope prompt note"},
		},
		VersionScheme:        "@earendil-works/pi-coding-agent npm releases",
		Versions:             supportedPrimeVersions,
		VersionMax:           whitelistMax(),
		ReconcileHow:         "`npm install -g @earendil-works/pi-coding-agent@<max>`",
		ConfigFile:           "harness_state.json",
		ConfigKeys:           []string{"entries", "schema"},
		ConfigIgnoredExample: []string{"refinements"},
	}
}
