package openclaw

import (
	"context"
	"encoding/json"
	"fmt"

	"seal-verify/internal/logger"
)

// Restore applies a dimension's plaintext to the in-memory composed state
// AND writes the corresponding sections of openclaw.json + workspace
// files to disk. Per EVOLUTION_DESIGN §7.2 calls must commute and be
// idempotent — each dim populates its own slice without touching others.
//
// Writing to disk during Restore (rather than deferring to Start) makes
// EvolutionFor's "read disk → produce iData bytes" path work both pre-
// and post-Start: at boot we seed snapshots before openclaw runs but
// after disk is written, ensuring the seed hash matches what the watcher
// will compute on the first tick.
//
// "framework" is also handled here even though it's not in Dimensions() —
// bootstrap calls it explicitly so the adapter validates schema_version.
// framework dim has no openclaw.json artifact (the npm version drives
// `npm install` separately).
func (a *Adapter) Restore(ctx context.Context, dim string, plaintext []byte) error {
	a.mu.Lock()
	if a.cfg == nil {
		a.cfg = &config{}
	}
	a.mu.Unlock()

	switch dim {
	case "framework":
		return a.restoreFramework(plaintext)
	case "persona":
		return a.restorePersona(plaintext)
	case "knowledge":
		return a.restoreKnowledge(plaintext)
	case "skills":
		return a.restoreSkills(plaintext)
	case "ops":
		return a.restoreOps(plaintext)
	default:
		logger.Logf("openclaw.Restore[%s]: unknown dim, ignoring (%d bytes)", dim, len(plaintext))
		return nil
	}
}

// ── framework ───────────────────────────────────────────────────────────────

func (a *Adapter) restoreFramework(plaintext []byte) error {
	var fb frameworkBinding
	if err := json.Unmarshal(plaintext, &fb); err != nil {
		return fmt.Errorf("parse framework: %w", err)
	}
	if fb.Name != "openclaw" {
		return fmt.Errorf("framework.name = %q; openclaw adapter expected", fb.Name)
	}
	if fb.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version: %d (this reader supports 1)", fb.SchemaVersion)
	}
	a.mu.Lock()
	a.cfg.framework = fb
	a.mu.Unlock()
	logger.Logf("openclaw.Restore[framework]: name=%s package_version=%s schema=%d",
		fb.Name, fb.PackageVersion, fb.SchemaVersion)
	return nil
}

// ── persona ─────────────────────────────────────────────────────────────────

func (a *Adapter) restorePersona(plaintext []byte) error {
	var p personaConfig
	if len(plaintext) > 0 {
		if err := json.Unmarshal(plaintext, &p); err != nil {
			return fmt.Errorf("parse persona: %w", err)
		}
	}

	a.mu.Lock()
	a.cfg.persona = p
	a.mu.Unlock()

	// Workspace: SOUL.md gets the system prompt. openclaw injects this
	// into the agent's context every turn.
	if err := writeWorkspaceFile(soulMDPath(), p.SystemPrompt); err != nil {
		return err
	}

	// openclaw.json: agents.defaults.model + auth.profiles + ui + talk.
	// (System prompt lives only in SOUL.md — openclaw 2026.5.6+ removed
	// agents.defaults.systemPrompt from the schema.)
	if err := updateOpenclawJSON(func(cfg map[string]any) {
		applyInferenceToConfig(cfg, p.Inference)
		_ = setSection(cfg, "ui", p.UI)
		_ = setSection(cfg, "talk", p.Talk)
	}); err != nil {
		return err
	}

	logger.Logf("openclaw.Restore[persona]: prompt=%dB inference=%s/%s ui=%s talk=%s",
		len(p.SystemPrompt), p.Inference.Provider, p.Inference.Model,
		nonEmpty(p.UI), nonEmpty(p.Talk))
	return nil
}

// applyInferenceToConfig writes provider/model into agents.defaults.model
// and ensures auth.profiles has an api_key profile for that provider.
//
// 0g-compute is presented to openclaw as plain "openai" (network is
// OpenAI-protocol-compatible). The endpoint override is written under
// `models.providers.openai.baseUrl` -- the path openclaw actually reads
// (see shared.ts resolveConfiguredOpenAIBaseUrl). Top-level "providers"
// is rejected by openclaw's schema validator; OPENAI_BASE_URL env is
// NOT consulted either.
func applyInferenceToConfig(cfg map[string]any, inf inferenceConfig) {
	if inf.Provider == "" || inf.Model == "" {
		return
	}
	clawProvider := inf.Provider
	customBaseURL := ""
	if clawProvider == "0g-compute" {
		clawProvider = "openai"
		customBaseURL = "https://router-api.0g.ai/v1"
	}

	primary := clawProvider + "/" + inf.Model
	model := map[string]any{"primary": primary}
	_ = setAgentsDefaults(cfg, "model", json.RawMessage(mustMarshal(model)))

	if customBaseURL != "" {
		// Shape per openclaw's authoritative type defs
		// (plugin-sdk/src/config/types.models.d.ts):
		//   ModelProviderConfig requires { baseUrl, models }; everything
		//   else optional. ModelDefinitionConfig requires { id, name,
		//   reasoning, input, cost{4 fields}, contextWindow, maxTokens }.
		// apiKey uses SecretRef shape { source:"env", provider, id }.
		modelDef := map[string]any{
			"id":            inf.Model,
			"name":          inf.Model,
			"reasoning":     false,
			"input":         []string{"text"},
			"cost":          map[string]any{"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
			"contextWindow": 128000,
			"maxTokens":     8192,
			// Conservative compat tuned to 0G's chat-completions parser.
			// requiresStringContent is the critical one: 0G rejects the
			// OpenAI multimodal array form (content: [{type:"text",...}])
			// with "400 Invalid request body"; openclaw must serialize the
			// message content as a plain string instead. The supports*
			// flags are off out of an abundance of caution -- newer
			// OpenAI-only fields aren't in 0G's supported_parameters list.
			"compat": map[string]any{
				"requiresStringContent":    true,
				"supportsStore":            false,
				"supportsDeveloperRole":    false,
				"supportsReasoningEffort":  false,
				"supportsUsageInStreaming": false,
				"supportsStrictMode":       false,
				"maxTokensField":           "max_tokens",
			},
		}
		providerEntry := map[string]any{
			"baseUrl": customBaseURL,
			"api":     "openai-completions",
			"apiKey": map[string]any{
				"source":   "env",
				"provider": "default",
				"id":       "OPENAI_API_KEY",
			},
			"models": []any{modelDef},
		}
		models, _ := cfg["models"].(map[string]any)
		if models == nil {
			models = map[string]any{}
		}
		providers, _ := models["providers"].(map[string]any)
		if providers == nil {
			providers = map[string]any{}
		}
		providers[clawProvider] = providerEntry
		models["providers"] = providers
		cfg["models"] = models
	}

	// auth.profiles[<provider>:api] = {provider, mode: api_key}
	authBlock, _ := cfg["auth"].(map[string]any)
	if authBlock == nil {
		authBlock = map[string]any{}
	}
	profiles, _ := authBlock["profiles"].(map[string]any)
	if profiles == nil {
		profiles = map[string]any{}
	}
	profiles[clawProvider+":api"] = map[string]any{
		"provider": clawProvider,
		"mode":     "api_key",
	}
	authBlock["profiles"] = profiles
	order, _ := authBlock["order"].(map[string]any)
	if order == nil {
		order = map[string]any{}
	}
	order[clawProvider] = []any{clawProvider + ":api"}
	authBlock["order"] = order
	cfg["auth"] = authBlock
}

// ── knowledge ───────────────────────────────────────────────────────────────

func (a *Adapter) restoreKnowledge(plaintext []byte) error {
	var k knowledgeConfig
	if len(plaintext) > 0 {
		if err := json.Unmarshal(plaintext, &k); err != nil {
			return fmt.Errorf("parse knowledge: %w", err)
		}
	}

	a.mu.Lock()
	a.cfg.knowledge = k
	a.mu.Unlock()

	// Write every workspace markdown file even when content is empty —
	// openclaw's `writeFileIfMissing` template fallback only fires when
	// the file doesn't exist, so creating the file (empty or not)
	// suppresses the multi-KB stock template install for AGENTS.md /
	// USER.md / TOOLS.md.
	//
	// TOOLS.md gets owner content here; spawn.go's upsertPlatformSection
	// will append the per-deployment public URL section between markers
	// before openclaw spawns. EvolutionFor strips that section back out
	// when reading TOOLS.md, so the round-trip preserves owner content.
	for _, f := range []struct {
		path    string
		content string
	}{
		{memoryMDPath(), k.MemoryMD},
		{dreamsMDPath(), k.DreamsMD},
		{userMDPath(), k.UserMD},
		{agentsMDPath(), k.AgentsMD},
		{toolsMDPath(), k.ToolsMD},
	} {
		if err := writeWorkspaceFile(f.path, f.content); err != nil {
			return err
		}
	}

	logger.Logf("openclaw.Restore[knowledge]: memory=%dB dreams=%dB user=%dB agents=%dB tools=%dB manifest_files=%d",
		len(k.MemoryMD), len(k.DreamsMD), len(k.UserMD), len(k.AgentsMD), len(k.ToolsMD), len(k.Manifest.Files))
	return nil
}

// ── skills ──────────────────────────────────────────────────────────────────

func (a *Adapter) restoreSkills(plaintext []byte) error {
	var s skillsConfig
	if len(plaintext) > 0 {
		if err := json.Unmarshal(plaintext, &s); err != nil {
			return fmt.Errorf("parse skills: %w", err)
		}
	}

	a.mu.Lock()
	a.cfg.skills = s
	a.mu.Unlock()

	// openclaw.json: top-level sections plugins/tools/web/approvals/audio/
	// commands; plus agents.defaults.skills.
	if err := updateOpenclawJSON(func(cfg map[string]any) {
		_ = setSection(cfg, "plugins", s.Plugins)
		_ = setSection(cfg, "tools", s.Tools)
		_ = setSection(cfg, "web", s.Web)
		_ = setSection(cfg, "approvals", s.Approvals)
		_ = setSection(cfg, "audio", s.Audio)
		_ = setSection(cfg, "commands", s.Commands)
		_ = setAgentsDefaults(cfg, "skills", s.AgentDefaultsSkills)
	}); err != nil {
		return err
	}

	logger.Logf("openclaw.Restore[skills]: plugins=%s tools=%s web=%s approvals=%s audio=%s commands=%s",
		nonEmpty(s.Plugins), nonEmpty(s.Tools), nonEmpty(s.Web),
		nonEmpty(s.Approvals), nonEmpty(s.Audio), nonEmpty(s.Commands))
	return nil
}

// ── ops ─────────────────────────────────────────────────────────────────────

func (a *Adapter) restoreOps(plaintext []byte) error {
	var o opsConfig
	if len(plaintext) > 0 {
		if err := json.Unmarshal(plaintext, &o); err != nil {
			return fmt.Errorf("parse ops: %w", err)
		}
	}

	a.mu.Lock()
	a.cfg.ops = o
	a.mu.Unlock()

	if err := updateOpenclawJSON(func(cfg map[string]any) {
		_ = setSection(cfg, "channels", o.Channels)
		_ = setSection(cfg, "mcp", o.MCP)
		_ = setSection(cfg, "hooks", o.Hooks)
		_ = setSection(cfg, "cron", o.Cron)
		_ = setSection(cfg, "browser", o.Browser)
		_ = setSection(cfg, "bindings", o.Bindings)
		_ = setSection(cfg, "surfaces", o.Surfaces)
		_ = setSection(cfg, "broadcast", o.Broadcast)
		_ = setSection(cfg, "media", o.Media)
		_ = setSection(cfg, "messages", o.Messages)
		_ = setSection(cfg, "accessGroups", o.AccessGroups)
		_ = setSection(cfg, "commitments", o.Commitments)
		_ = setSection(cfg, "secrets", o.Secrets)
		_ = setSection(cfg, "acp", o.ACP)
		_ = setAgentsDefaults(cfg, "rateLimits", o.RateLimits)
		_ = setAgentsDefaults(cfg, "safety", o.Safety)
	}); err != nil {
		return err
	}

	logger.Logf("openclaw.Restore[ops]: channels=%s mcp=%s cron=%s hooks=%s",
		nonEmpty(o.Channels), nonEmpty(o.MCP), nonEmpty(o.Cron), nonEmpty(o.Hooks))
	return nil
}

// ── small utilities ─────────────────────────────────────────────────────────

func nonEmpty(r json.RawMessage) string {
	if len(r) == 0 || string(r) == "null" {
		return "none"
	}
	return fmt.Sprintf("%dB", len(r))
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Map[string]any with primitive values is infallible; if this
		// triggers we have a programming bug, not a runtime issue.
		panic(err)
	}
	return b
}

// jsonString serialises a string as a JSON value (escaped, double-quoted).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
