package openclaw

import (
	"context"
	"encoding/json"
	"fmt"

	"seal-verify/internal/logger"
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
// per chain iData entry whose role isn't in Roles() — currently only
// "persona". Unknown role names are logged and ignored (per the contract
// in framework.go: a chain with an experimental role this adapter version
// can't translate should still boot).
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.ingestPersona(ctx, plaintext)
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
func (a *Adapter) ingestPersona(ctx context.Context, plaintext []byte) error {
	if len(plaintext) == 0 {
		return fmt.Errorf("openclaw.HandleLegacy[persona]: empty plaintext")
	}
	var p personaPlaintext
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("openclaw.HandleLegacy[persona]: parse: %w", err)
	}

	if err := writeWorkspaceFile(soulMDPath(), p.SystemPrompt); err != nil {
		return fmt.Errorf("openclaw.HandleLegacy[persona]: write SOUL.md: %w", err)
	}

	if err := updateOpenclawJSON(func(cfg map[string]any) {
		applyInferenceToConfig(cfg, p.Inference)
	}); err != nil {
		return fmt.Errorf("openclaw.HandleLegacy[persona]: update openclaw.json: %w", err)
	}

	logger.Logf("openclaw.HandleLegacy[persona]: prompt=%dB inference=%s/%s",
		len(p.SystemPrompt), p.Inference.Provider, p.Inference.Model)
	return nil
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
