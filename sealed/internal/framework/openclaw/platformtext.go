package openclaw

import (
	"seal-verify/internal/platform"
)

// openclaw's framework facts — its blanks in the shared agent-doc template.
//
// platform owns every sentence of platform mechanics (sealing, gas, version
// reconcile, config drift) and renders them identically for all frameworks;
// openclaw supplies only what differs by framework — OUR paths, OUR upgrade
// command, OUR config semantics — as VALUES below. These moved here from
// platform.Build, where they had been hardcoded while openclaw was the only
// adapter, and are now data rather than prose.
//
// openclaw distributes the platform halves across IDENTITY/SOUL/TOOLS.md
// itself and splices the rendered facts into TOOLS.md via
// platform.RenderFrameworkFacts (see spawn.go / toolsmd.go); the content is
// identical to what AssembleAgentDoc produces for single-file frameworks.
func (a *Adapter) FrameworkFacts() platform.FrameworkFacts {
	return platform.FrameworkFacts{
		Home: "~/.openclaw/",
		Tracked: []platform.PathNote{
			{Path: "~/.openclaw/workspace/*.md", Note: "**top-level** markdown files in the workspace root: SOUL.md, IDENTITY.md, MEMORY.md, DREAMS.md, USER.md, AGENTS.md, TOOLS.md, plus any other `.md` you create here (e.g. `notes.md`, `0g-sandbox-review.md`)"},
			{Path: "~/.openclaw/workspace/skills/<name>/", Note: "each top-level **subdirectory** under skills/ is packed as one entry. Loose files directly under skills/ (no enclosing directory) are NOT tracked"},
			{Path: "~/.openclaw/workspace/canvas/*", Note: "every top-level item (file or directory) under canvas/"},
		},
		Untracked: []platform.PathNote{
			// openclaw.json stopped being a tracked role when configuration
			// moved to the owner's settings document. The render MERGES into
			// the file rather than rewriting it, so this note must not claim
			// every edit here is overwritten — only the platform-owned keys
			// are. What is unconditionally true is that nothing in this file
			// reaches chain, so none of it survives a container reset.
			{Path: "~/.openclaw/openclaw.json", Note: "re-rendered from the owner's settings at every boot: the provider/model pin, the reasoning bound, the endpoint wiring and the watchdog headroom are rewritten from there, so your edits to THOSE keys are replaced on the next start. Other keys you set here are merged and kept — but this file never reaches chain, so nothing in it survives a container reset. Durable configuration belongs in the owner's settings document, not here"},
			{Note: "Any subdirectory of `workspace/` that isn't `skills/` or `canvas/` — e.g. `workspace/memory/`, `workspace/tmp/`, `workspace/cache/`. Use `MEMORY.md` (top-level) for memory you want to keep, not a `memory/` directory"},
			{Note: "Non-`.md` files directly under `workspace/`"},
		},
		DurableHints: []platform.DurableHint{
			{Ask: "Remember this for me long-term", Place: "write to `MEMORY.md` or create a new top-level `.md` in `workspace/`"},
			{Ask: "Install a skill / capability", Place: "drop it as a subdirectory under `workspace/skills/<name>/`"},
			{Ask: "Save this artifact (sketch, doc, canvas)", Place: "place under `workspace/canvas/`"},
		},
		Versions:     supportedOpenclawVersions,
		VersionMax:   whitelistMax(),
		ReconcileHow: "`npm install openclaw@<max>`",
		// No ConfigFile: the config-allowlist paragraph described a
		// chain-tracked openclaw.json and there is no longer one to describe.
		// The file's real status is stated in Untracked above.
	}
}
