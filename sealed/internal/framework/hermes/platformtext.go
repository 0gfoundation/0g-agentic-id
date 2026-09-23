package hermes

import (
	"seal-verify/internal/platform"
)

// Platform-context injection into SOUL.md.
//
// hermes loads SOUL.md from HERMES_HOME into the system prompt every turn
// (AGENTS.md is cwd-only, so unreliable as a sealed channel here). SOUL.md is
// therefore where sealed injects the whole agent doc: platform-authored
// identity / sovereignty / capabilities + hermes's own framework facts. The
// facts are supplied as VALUES (FrameworkFacts below); platform renders the
// shared template around them, so hermes never hand-writes platform-mechanics
// prose and can't restate one wrong. EvolutionFor strips the injected marker
// before hashing (evoSoulMD), so the chain payload stays the owner persona
// only and the per-boot platform text never phantom-drifts onto chain.
func upsertSoulMD(pc platform.PlatformContext, facts platform.FrameworkFacts) error {
	return platform.UpsertMarkedSection(soulMDPath(), platform.AssembleAgentDoc(pc, facts))
}

// FrameworkFacts implements framework.Framework: hermes's blanks in the
// shared agent-doc template (§9 part 2). Values only — platform renders the
// mechanics prose identically for every framework.
func (a *Adapter) FrameworkFacts() platform.FrameworkFacts {
	return platform.FrameworkFacts{
		Home: "~/.hermes/",
		Tracked: []platform.PathNote{
			{Path: "~/.hermes/SOUL.md", Note: "your identity / persona"},
			{Path: "~/.hermes/memories/*.md", Note: "`MEMORY.md`, `USER.md`, and any `.md` you create here. **This is where long-term memory belongs.**"},
			{Path: "~/.hermes/skills/<name>/", Note: "each skill subdirectory you create. Skills that ship bundled with the framework (listed in `skills/.bundled_manifest`) are NOT tracked — they're reproducible from the pinned version"},
		},
		Untracked: []platform.PathNote{
			{Note: "`~/.hermes/cron/` — scheduled jobs. Deliberately not persisted: migrating them across an owner transfer would keep the OLD owner's timers firing in the NEW owner's container"},
			{Note: "`~/.hermes/state.db`, `sessions/`, `logs/` — conversation history and runtime state"},
			{Note: "`.env` — secrets"},
			{Note: "`~/.hermes/config.yaml` — your model wiring. Never reaches chain. At every boot the platform rewrites the five keys it owns (`model.default`, `model.provider`, `model.base_url`, `model.api_key`, `agent.reasoning_effort`) from your owner's settings, and re-applies whatever else those settings carry; your edits to those keys do not survive a restart, edits to the rest of the file do"},
		},
		DurableHints: []platform.DurableHint{
			{Ask: "Remember this long-term", Place: "`memories/MEMORY.md` (or a new `.md` under `memories/`)"},
			{Ask: "Give yourself a new skill / capability", Place: "a subdirectory under `skills/<name>/`"},
		},
		VersionScheme: "hermes release tags (CalVer)",
		Versions:      supportedHermesVersions,
		VersionMax:    whitelistMax(),
		ReconcileHow:  "`git checkout <max>` + `uv sync --locked`",
		// No ConfigFile/ConfigKeys: config.yaml is not chain-tracked any
		// more, so there is no allowlist clause to render — what the agent
		// needs is the list of keys the render owns, which the Untracked note
		// above names (keep it in step with RenderSettings).
	}
}
