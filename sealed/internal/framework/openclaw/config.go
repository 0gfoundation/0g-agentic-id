// internal config types for the openclaw adapter. All private to this
// package — protocol-level code (state, manager, proxy, main) does NOT
// reference any openclaw-specific shape.
//
// The 5 iData dims map to specific subsets of openclaw's runtime config
// (~/.openclaw/openclaw.json) plus workspace markdown files. Sections
// inside skills / ops / persona-extras / knowledge-extras are kept as
// `json.RawMessage` so the attestor can populate any openclaw config key
// without sealed needing to schema-validate every nested field.
//
// Excluded (per EVOLUTION_DESIGN §3.2): credentials, env vars, machine-
// specific config, runtime state. Those live elsewhere (env / dashboard /
// per-boot generation).
package openclaw

import "encoding/json"

// config is the in-memory state assembled from the 5 iData dims. Each
// field is populated by a single Restore call.
type config struct {
	framework frameworkBinding
	persona   personaConfig
	knowledge knowledgeConfig
	skills    skillsConfig
	ops       opsConfig
}

// ── framework dim ───────────────────────────────────────────────────────────

type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}

// ── persona dim ─────────────────────────────────────────────────────────────
//
// persona dim plaintext = tar.gz with:
//
//	persona.md       → SystemPrompt    (workspace/SOUL.md)
//	inference.json   → Inference       (agents.defaults.model + auth.profiles)
//	ui.json          → UI              (openclaw.json `ui.*`)
//	talk.json        → Talk            (openclaw.json `talk.*`)

type personaConfig struct {
	SystemPrompt string          `json:"system_prompt"`
	Inference    inferenceConfig `json:"inference"`
	UI           json.RawMessage `json:"ui,omitempty"`
	Talk         json.RawMessage `json:"talk,omitempty"`
}

type inferenceConfig struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// ── knowledge dim ───────────────────────────────────────────────────────────
//
// knowledge dim plaintext is JSON carrying the workspace markdown files
// that define what the agent knows. Each is written to disk by Restore
// BEFORE openclaw spawns, so openclaw's `writeFileIfMissing` template
// fallback is a no-op — we own the content, not the openclaw boilerplate.
//
// TOOLS.md is special: it has a platform-injected section bracketed by
// `<!-- 0g-platform-injected:* -->` markers carrying the per-deployment
// public URL guidance. EvolutionFor strips that section before computing
// the dim's content; only the owner-authored portion travels via iData.
// Same field can therefore round-trip through iTransferFrom without
// leaking the source sandbox's URL into the destination.
//
// NOT included here:
//
//   - workspace/memory/<YYYY-MM-DD>.md — per-day session log, grows every
//     turn. The promotion step picks qualified entries into MEMORY.md; the
//     daily logs themselves are raw conversation history, not knowledge.
//   - openclaw.json `memory.*` / `session.*` — runtime engine config
//     (memory backend choice, session timeouts), not knowledge content.

type knowledgeConfig struct {
	MemoryMD string `json:"memory_md,omitempty"` // workspace/MEMORY.md (consolidated long-term memory)
	DreamsMD string `json:"dreams_md,omitempty"` // workspace/DREAMS.md (reflection logs)
	UserMD   string `json:"user_md,omitempty"`   // workspace/USER.md (user model)
	AgentsMD string `json:"agents_md,omitempty"` // workspace/AGENTS.md (agent self-guide)
	ToolsMD  string `json:"tools_md,omitempty"`  // workspace/TOOLS.md owner content (platform marker section stripped)

	// Manifest is a sealed-side bookkeeping field for future large-file
	// references (e.g. when MEMORY.md grows to MB and we want to reference
	// it via 0g-storage root_hash instead of inlining).
	Manifest knowledgeManifest `json:"manifest"`
}

type knowledgeManifest struct {
	Files []knowledgeFileRef `json:"files"`
}

type knowledgeFileRef struct {
	Path     string `json:"path"`
	RootHash string `json:"root_hash"`
	Size     uint64 `json:"size"`
}

// ── skills dim ──────────────────────────────────────────────────────────────
//
// skills dim plaintext = single JSON. Each section is round-tripped as
// json.RawMessage — sealed doesn't validate, just routes to the matching
// openclaw.json key.

type skillsConfig struct {
	Plugins   json.RawMessage `json:"plugins,omitempty"`
	Tools     json.RawMessage `json:"tools,omitempty"`
	Web       json.RawMessage `json:"web,omitempty"`
	Approvals json.RawMessage `json:"approvals,omitempty"`
	Audio     json.RawMessage `json:"audio,omitempty"`
	Commands  json.RawMessage `json:"commands,omitempty"`

	// AgentDefaultsSkills is `agents.defaults.skills` — the list of skill
	// IDs the default agent has access to. Lives here because skill→agent
	// binding is a "what the agent can do" concern.
	AgentDefaultsSkills json.RawMessage `json:"agent_defaults_skills,omitempty"`
}

// ── ops dim ─────────────────────────────────────────────────────────────────
//
// ops dim plaintext = single JSON. Same opaque-section approach as skills.
// Sections that historically carry credentials (channels, mcp, browser,
// secrets) are still listed here — the attestor is expected to strip the
// sensitive fields before encryption (sealed validates this on read).

type opsConfig struct {
	Channels     json.RawMessage `json:"channels,omitempty"`
	MCP          json.RawMessage `json:"mcp,omitempty"`
	Hooks        json.RawMessage `json:"hooks,omitempty"`
	Cron         json.RawMessage `json:"cron,omitempty"`
	Browser      json.RawMessage `json:"browser,omitempty"`
	Bindings     json.RawMessage `json:"bindings,omitempty"`
	Surfaces     json.RawMessage `json:"surfaces,omitempty"`
	Broadcast    json.RawMessage `json:"broadcast,omitempty"`
	Media        json.RawMessage `json:"media,omitempty"`
	Messages     json.RawMessage `json:"messages,omitempty"`
	AccessGroups json.RawMessage `json:"access_groups,omitempty"`
	Commitments  json.RawMessage `json:"commitments,omitempty"`
	Secrets      json.RawMessage `json:"secrets,omitempty"`
	ACP          json.RawMessage `json:"acp,omitempty"`

	// agents.defaults sub-fields owned by ops:
	RateLimits json.RawMessage `json:"rate_limits,omitempty"`
	Safety     json.RawMessage `json:"safety,omitempty"`
}
