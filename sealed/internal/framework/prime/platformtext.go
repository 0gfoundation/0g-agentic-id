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
			{Path: "~/.prime/agent/harness/harness_state.json", Note: "your Continual Harness — prompt notes, memories, skill registrations, subagent specs. **The `create_*` / `update_*` calls default to `local` scope, and local is NOT persisted**: it lives in this session's own state file and is gone at the next container rebuild. Only `global`-scope entries reach chain. To make a memory, skill registration or prompt note outlive this task, pass `global_=True` when you create it (or address it in the `global:<id>` form). Not passing it is choosing single-use — right for scratch work, wrong for anything you learned"},
			{Path: "~/.prime/agent/APPEND_SYSTEM.md", Note: "your persona / standing instructions, appended to your system prompt every session"},
			{Path: "~/.prime/agent/skills/<name>/", Note: "each Python skill package you install (`pyproject.toml` + `src/<import>/__init__.py`). Registering a skill in the harness and writing its code are two separate facts — both are tracked, in their own roles"},
		},
		Untracked: []platform.PathNote{
			{Note: "the per-session harness state (`$RLM_SESSION_DIR/harness/harness_state.json`) — everything you refine mid-task lands here first. Deliberate: half-finished harness edits must not become your on-chain identity"},
			{Note: "the `refinements` log inside `harness_state.json` — a local audit trail of your self-modifications, not part of your identity"},
			{Note: "`.env` and any credential file — secrets never reach chain"},
			{Note: "`~/.prime/agent/kernel-venv/` and `~/.prime/agent/bin/` — your Python kernel and its tooling. Provisioned in the image and reproducible from the pinned version, so they are infrastructure rather than identity. Installing a package into the kernel venv does NOT survive a rebuild; if a capability needs a dependency, declare it in the skill package under `skills/<name>/`"},
		},
		DurableHints: []platform.DurableHint{
			{Ask: "Remember this long-term", Place: "a harness memory entry promoted to `global` scope"},
			{Ask: "Give yourself a new capability", Place: "a Python package under `skills/<name>/`, then register it as a harness skill entry (global scope)"},
			{Ask: "Change how you always behave", Place: "`APPEND_SYSTEM.md`, or a `global`-scope prompt note"},
		},
		VersionScheme: "Prime Agent release versions",
		Versions:      supportedPrimeVersions,
		VersionMax:    whitelistMax(),
		// No runtime reconcile: the framework is installed at image build time,
		// so changing version means a new image. Start verifies what is present
		// rather than installing (spawn.go verifyInstalled).
		ReconcileHow:         "not applicable — the framework is baked into the sealed image, so a version change means deploying a new image",
		ConfigFile:           "harness_state.json",
		ConfigKeys:           []string{"entries", "schema"},
		ConfigIgnoredExample: []string{"refinements"},
	}
}
