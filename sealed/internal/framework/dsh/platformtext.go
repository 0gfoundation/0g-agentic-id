package dsh

import (
	"seal-verify/internal/platform"
)

// FrameworkFacts implements framework.Framework: DSH's blanks in the shared
// agent-doc template (FRAMEWORK_ADAPTER.md §11 step 9). Values only —
// platform renders the mechanics prose identically for every framework, so
// this adapter can neither restate a platform mechanism wrong nor silently
// drop one.
func (a *Adapter) FrameworkFacts() platform.FrameworkFacts {
	return platform.FrameworkFacts{
		Home: "~/.dsh/",
		Tracked: []platform.PathNote{
			{Path: "~/.dsh/skills/<name>/ or <name>.md", Note: "your installed skills — durable capabilities you can invoke by name across sessions. A skill you write and never save here does not survive this container's next restart"},
			{Path: "~/.dsh/APPEND_SYSTEM.md", Note: "your persona / standing instructions, injected into your system prompt every session"},
		},
		Untracked: []platform.PathNote{
			{Note: "any session/conversation log this container's composition may write — that is turn-by-turn history, not your identity, and it is deliberately not chain-tracked here"},
			{Note: "`~/.dsh/.credentials.yaml` and any credential file — secrets never reach chain"},
			{Note: "`~/.dsh/AGENTS.md` — this container mounts nothing that reads it, and no role carries it. Writing one is not how you change your standing instructions here; `APPEND_SYSTEM.md` above is"},
			{Note: "your model and inference route — not a file in this home at all. Your owner sets them, and the platform applies them to this container's composition at every boot"},
			{Note: "your own source checkout, if this deployment exposes one to you (DSH's self-referential toolset can name where its own code lives) — this platform does not yet track agent edits to framework code, only to your data. Treat any such edit as living only in this container until that changes"},
		},
		DurableHints: []platform.DurableHint{
			{Ask: "Give yourself a new capability", Place: "a skill under `~/.dsh/skills/<name>/` (a `SKILL.md`) or `~/.dsh/skills/<name>.md`"},
			{Ask: "Change how you always behave", Place: "`~/.dsh/APPEND_SYSTEM.md`"},
		},
		VersionScheme: "DSH (@deepseek-ai/dsh) npm versions",
		Versions:      supportedDSHVersions,
		VersionMax:    whitelistMax(),
		ReconcileHow:  "not applicable — DSH is baked into the sealed image, so a version change means deploying a new image",
		// No ConfigFile/ConfigKeys: this framework has no chain-tracked config
		// file to render an allowlist clause for (settings.go). What the agent
		// does need to know — that its route is set from outside and not from
		// a file it can edit — the Untracked note above says.
	}
}
