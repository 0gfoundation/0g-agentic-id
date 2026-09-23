package openclaw

import (
	"context"
	"encoding/json"
	"strings"

	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// Mint-only ingestion: attestor's default_i_data emits a semantic `persona`
// role at mint (`{system_prompt, inference}`) because attestor stays
// framework-agnostic and doesn't speak openclaw's config schema. Sealed
// translates this on first boot into the path-driven disk artifacts that
// every subsequent boot uses verbatim — SOUL.md for the prompt and a
// minimal openclaw.json subset for model + auth.
//
// persona is NOT in Roles() and NOT in Restore()'s dispatch: it's a
// one-shot bootstrap-time conversion, not a steady-state role. After the
// first successful uploader.Apply, the wholesale chain.Update produces a
// newDatas array that doesn't contain persona; chain forgets about it
// and the path-driven invariant takes over.

// personaPlaintext is the on-chain `persona` role schema. Mirrors the
// shape attestor's `AgentProfile::default_i_data` emits.
type personaPlaintext struct {
	SystemPrompt string             `json:"system_prompt"`
	Inference    personaInferenceIn `json:"inference"`
}

type personaInferenceIn struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// HandleLegacy implements framework.Framework. Bootstrap calls this once
// per chain iData entry whose role isn't in Roles():
//
//	persona       the mint-time seed this file translates (below). It is
//	              also the ONLY place the model pin exists for an agent
//	              minted before the settings channel that never drifted:
//	              attestor mints two roles, `framework` and `persona`, so
//	              such an agent has no retired config role for the branch
//	              below to read
//	openclaw.json the retired config role. Once such an agent HAS drifted,
//	              this is where its pin lives — later than the seed above
//	              and the one of the two that wins — so it is read out into
//	              the owner's settings document before the watcher drops the
//	              entry (inference.go)
//
// Unknown role names are logged and ignored (per the contract
// in framework.go: a chain with an experimental role this adapter version
// can't translate should still boot).
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.ingestPersona(ctx, plaintext)
	case legacyConfigRole:
		return a.handleLegacyConfig(plaintext)
	default:
		logger.Logf("openclaw.HandleLegacy: unknown legacy role %q (%d bytes) — ignoring",
			role, len(plaintext))
		return nil
	}
}

// ingestPersona is HandleLegacy's "persona" branch. Translates the
// mint-time persona plaintext into path-driven disk artifacts:
//
//   - persona.SystemPrompt → ~/.openclaw/workspace/SOUL.md
//   - persona.Inference    → ~/.openclaw/openclaw.json (agents.defaults.model.primary
//                            + auth.{order,profiles})
//
// Idempotent: re-invoking with the same plaintext yields the same disk
// state. Provider/model are written as the user's literal choice; per-
// boot runtime augmentation (0g-compute → openai endpoint mapping) is
// the concern of spawn.go's applyZGComputeAugmentation, not this
// translator.
//
// It also REPORTS the pin to the platform (seedFromPersona), which is what
// actually reaches the runtime now that RenderSettings owns openclaw.json.
//
// Nothing in here fails a boot, matching the config branch: Phase C
// propagates an error (main.go returns on it), so an unreadable mint seed
// would take the container offline instead of merely leaving it degraded.
// Every failure below is logged and stepped over.
func (a *Adapter) ingestPersona(ctx context.Context, plaintext []byte) error {
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		logger.Logf("openclaw.HandleLegacy[persona]: empty plaintext; nothing to ingest")
		return nil
	}
	var p personaPlaintext
	if err := json.Unmarshal(plaintext, &p); err != nil {
		logger.Logf("openclaw.HandleLegacy[persona]: WARN parse failed (%v); nothing ingested", err)
		return nil
	}

	// The pin BEFORE either disk write. It is the half only this boot can
	// recover — the watcher's first wholesale commit rebuilds the chain array
	// from Roles() and this entry is not in it — it cannot fail, and a disk
	// that refuses SOUL.md must not also cost the owner their model.
	a.seedFromPersona(p.Inference)

	if err := writeWorkspaceFile(soulMDPath(), p.SystemPrompt); err != nil {
		logger.Logf("openclaw.HandleLegacy[persona]: WARN write SOUL.md: %v", err)
	}

	if err := updateOpenclawJSON(func(cfg map[string]any) {
		applyInferenceToConfig(cfg, p.Inference)
	}); err != nil {
		logger.Logf("openclaw.HandleLegacy[persona]: WARN update openclaw.json: %v", err)
	}

	logger.Logf("openclaw.HandleLegacy[persona]: prompt=%dB inference=%s/%s",
		len(p.SystemPrompt), p.Inference.Provider, p.Inference.Model)
	return nil
}

// seedFromPersona reports the mint-time pin to the platform, which persists
// it as the owner's settings document (framework.LegacySettingsSeeder →
// report.SeedSettings) when attestor holds none.
//
// This is the whole fix for the population three reviews found: attestor
// mints `framework` and `persona` only, so an agent minted before the
// settings channel that has never committed drift carries its pin HERE and
// nowhere else. Writing it to openclaw.json (above) no longer reaches the
// runtime — RenderSettings owns that file and rebuilds its inference half
// from the owner's document every Start — so without this report the agent
// comes up modelless: a failed first message on openclaw, a refused Start
// (hence an OFFLINE container) on prime.
//
// Both halves of the pin are required before anything is reported. A model
// with no provider passes settings.Doc.Validate but openclaw cannot render
// it — its config indexes models BY provider label, so there is no pin to
// write, no auth profile and no key env — and a half document, once
// persisted, is consulted ahead of this recovery on every later boot. Better
// to report nothing and leave the owner a document they can push.
//
// No level is recovered because persona has no field that could carry one;
// Effort() derives a sound bound from the model alone.
func (a *Adapter) seedFromPersona(inf personaInferenceIn) {
	provider := strings.TrimSpace(inf.Provider)
	model := strings.TrimSpace(inf.Model)
	if provider == "" || model == "" {
		logger.Logf("openclaw.HandleLegacy[persona]: seed names provider=%q model=%q; no usable pin to recover",
			inf.Provider, inf.Model)
		return
	}

	// Provider verbatim: persona records what the OWNER picked, so
	// "0g-compute" stays "0g-compute" and settings.Resolve supplies the
	// router endpoint for it. This is the seed's one advantage over the
	// retired config role — and also why it does not outrank it; see
	// legacySource (inference.go) for the rule.
	doc := settings.Doc{Provider: provider, Model: model}
	if !a.stashSeededPin(sourcePersona, doc) {
		logger.Logf("openclaw.HandleLegacy[persona]: mint seed pins %s/%s, but the retired %s role already recovered the agent's later pin; keeping that one",
			provider, model, legacyConfigRole)
		return
	}
	logger.Logf("openclaw.HandleLegacy[persona]: recovered pin provider=%s model=%s from the mint seed; the platform will persist it as the owner's settings document",
		provider, model)
}

// applyInferenceToConfig writes the minimal model + auth subset the
// runtime needs into openclaw.json. Empty provider/model is a no-op
// (caller pre-Restore'd an empty openclaw.json; we don't force invalid
// config to land on disk).
func applyInferenceToConfig(cfg map[string]any, inf personaInferenceIn) {
	if inf.Provider == "" || inf.Model == "" {
		return
	}

	primary := inf.Provider + "/" + inf.Model
	_ = setAgentsDefaults(cfg, "model", json.RawMessage(mustMarshal(map[string]any{
		"primary": primary,
	})))

	profileKey := inf.Provider + ":api"
	authBlock, _ := cfg["auth"].(map[string]any)
	if authBlock == nil {
		authBlock = map[string]any{}
	}
	profiles, _ := authBlock["profiles"].(map[string]any)
	if profiles == nil {
		profiles = map[string]any{}
	}
	profiles[profileKey] = map[string]any{
		"provider": inf.Provider,
		"mode":     "api_key",
	}
	authBlock["profiles"] = profiles

	order, _ := authBlock["order"].(map[string]any)
	if order == nil {
		order = map[string]any{}
	}
	order[inf.Provider] = []any{profileKey}
	authBlock["order"] = order
	cfg["auth"] = authBlock
}
