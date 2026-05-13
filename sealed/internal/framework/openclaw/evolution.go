package openclaw

import (
	"context"
	"encoding/json"

	"seal-verify/internal/framework"
)

// EvolutionFor produces canonical iData plaintext bytes for `dim` by
// reading the live state from disk: ~/.openclaw/openclaw.json + the
// workspace markdown files. Reading from disk (rather than a stale
// in-memory cfg) is what makes evolution detection correct — when the
// agent self-modifies its config (dashboard upgrade, plugin install,
// MEMORY.md write), the watcher's next tick observes those changes.
//
// Output MUST be deterministic: same on-disk state → byte-identical
// output. We pin field order via tagged struct serialization, sort
// tar entries, and zero out non-content fields in tar headers.
//
// All five dims — including "framework" — are exported here so the
// bootstrap can seed every snapshot through a single code path.
func (a *Adapter) EvolutionFor(ctx context.Context, dim string) ([]byte, error) {
	switch dim {
	case "framework":
		return a.evoFramework(ctx)
	case "persona":
		return a.evoPersona()
	case "knowledge":
		return a.evoKnowledge()
	case "skills":
		return a.evoSkills()
	case "ops":
		return a.evoOps()
	}
	return nil, framework.ErrUnsupportedDim
}

// ── framework ───────────────────────────────────────────────────────────────

func (a *Adapter) evoFramework(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	fb := frameworkBinding{}
	if a.cfg != nil {
		fb = a.cfg.framework
	}
	a.mu.RUnlock()
	// Live-probe the installed openclaw npm version so a dashboard upgrade
	// is observable as drift on this dim. Empty result means probe failed
	// (binary not installed yet — happens during pre-Start seed) so we
	// keep the cfg value.
	if v := probeOpenclawVersion(ctx); v != "" {
		fb.PackageVersion = v
	}
	return json.Marshal(&fb)
}

// ── persona ─────────────────────────────────────────────────────────────────

func (a *Adapter) evoPersona() ([]byte, error) {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return nil, err
	}
	out := personaConfig{
		SystemPrompt: readWorkspaceFile(soulMDPath()),
		Inference:    readInferenceFromConfig(cfg),
		UI:           section(cfg, "ui"),
		Talk:         section(cfg, "talk"),
	}
	return json.Marshal(&out)
}

func readInferenceFromConfig(cfg map[string]any) inferenceConfig {
	agents, _ := cfg["agents"].(map[string]any)
	if agents == nil {
		return inferenceConfig{}
	}
	defaults, _ := agents["defaults"].(map[string]any)
	if defaults == nil {
		return inferenceConfig{}
	}
	model, _ := defaults["model"].(map[string]any)
	if model == nil {
		return inferenceConfig{}
	}
	primary, _ := model["primary"].(string)
	provider, modelName := splitProviderModel(primary)
	return inferenceConfig{Provider: provider, Model: modelName}
}

// splitProviderModel parses "<provider>/<model>" into its parts. Anything
// before the FIRST slash is provider; the rest is model (model strings
// can contain further slashes — e.g. "anthropic/claude-3-5-sonnet-latest").
func splitProviderModel(combined string) (provider, model string) {
	for i := 0; i < len(combined); i++ {
		if combined[i] == '/' {
			return combined[:i], combined[i+1:]
		}
	}
	return combined, ""
}

// ── knowledge ───────────────────────────────────────────────────────────────

func (a *Adapter) evoKnowledge() ([]byte, error) {
	// Manifest is sealed-side state (we own the on-chain "files" pointer
	// list), not something openclaw modifies — pull from in-memory cfg.
	a.mu.RLock()
	manifest := knowledgeManifest{}
	if a.cfg != nil {
		manifest = a.cfg.knowledge.Manifest
	}
	a.mu.RUnlock()
	if manifest.Files == nil {
		manifest.Files = []knowledgeFileRef{}
	}

	// TOOLS.md gets the platform-injected section stripped out — only
	// owner-authored content travels via iData; the per-deployment
	// public URL guidance is regenerated each boot from rt.PublicURL
	// in spawn.go's upsertPlatformSection.
	rawTools := readWorkspaceFile(toolsMDPath())
	ownerTools := string(stripPlatformInjection([]byte(rawTools)))

	out := knowledgeConfig{
		MemoryMD: readWorkspaceFile(memoryMDPath()),
		DreamsMD: readWorkspaceFile(dreamsMDPath()),
		UserMD:   readWorkspaceFile(userMDPath()),
		AgentsMD: readWorkspaceFile(agentsMDPath()),
		ToolsMD:  ownerTools,
		Manifest: manifest,
	}
	return json.Marshal(&out)
}

// ── skills ──────────────────────────────────────────────────────────────────

func (a *Adapter) evoSkills() ([]byte, error) {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return nil, err
	}
	out := skillsConfig{
		Plugins:             section(cfg, "plugins"),
		Tools:               section(cfg, "tools"),
		Web:                 section(cfg, "web"),
		Approvals:           section(cfg, "approvals"),
		Audio:               section(cfg, "audio"),
		Commands:            section(cfg, "commands"),
		AgentDefaultsSkills: agentsDefaultsSection(cfg, "skills"),
	}
	return json.Marshal(&out)
}

// ── ops ─────────────────────────────────────────────────────────────────────

func (a *Adapter) evoOps() ([]byte, error) {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return nil, err
	}
	out := opsConfig{
		Channels:     section(cfg, "channels"),
		MCP:          section(cfg, "mcp"),
		Hooks:        section(cfg, "hooks"),
		Cron:         section(cfg, "cron"),
		Browser:      section(cfg, "browser"),
		Bindings:     section(cfg, "bindings"),
		Surfaces:     section(cfg, "surfaces"),
		Broadcast:    section(cfg, "broadcast"),
		Media:        section(cfg, "media"),
		Messages:     section(cfg, "messages"),
		AccessGroups: section(cfg, "accessGroups"),
		Commitments:  section(cfg, "commitments"),
		Secrets:      section(cfg, "secrets"),
		ACP:          section(cfg, "acp"),
		RateLimits:   agentsDefaultsSection(cfg, "rateLimits"),
		Safety:       agentsDefaultsSection(cfg, "safety"),
	}
	return json.Marshal(&out)
}
