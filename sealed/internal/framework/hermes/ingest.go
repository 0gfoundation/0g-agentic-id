package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"seal-verify/internal/logger"
)

// Mint-only ingestion: attestor's default_i_data emits a semantic `persona`
// role at mint (`{system_prompt, inference}`) because attestor stays
// framework-agnostic. Sealed translates this on first boot into the
// path-driven disk artifacts — SOUL.md for the prompt and config.yaml's
// model section for inference.
//
// persona is NOT in Roles() and NOT in Restore()'s dispatch: it's a
// one-shot bootstrap-time conversion. After the first uploader.Apply the
// wholesale chain.Update drops it and the path-driven invariant takes over.

// personaPlaintext mirrors the shape attestor's default_i_data emits.
type personaPlaintext struct {
	SystemPrompt string             `json:"system_prompt"`
	Inference    personaInferenceIn `json:"inference"`
}

type personaInferenceIn struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// HandleLegacy implements framework.Framework. Unknown legacy roles are
// logged and ignored per the contract in framework.go.
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.ingestPersona(ctx, plaintext)
	default:
		logger.Logf("hermes.HandleLegacy: unknown legacy role %q (%d bytes) — ignoring",
			role, len(plaintext))
		return nil
	}
}

// ingestPersona translates the mint-time persona plaintext:
//
//   - persona.SystemPrompt → ~/.hermes/SOUL.md
//   - persona.Inference    → config.yaml model.{provider,default}
//
// Provider/model are written as the user's literal choice; the 0g-compute
// → custom-endpoint rewrite is spawn.go's per-boot concern, not this
// translator's. Idempotent: same plaintext → same disk state.
func (a *Adapter) ingestPersona(ctx context.Context, plaintext []byte) error {
	if len(plaintext) == 0 {
		return fmt.Errorf("hermes.HandleLegacy[persona]: empty plaintext")
	}
	var p personaPlaintext
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("hermes.HandleLegacy[persona]: parse: %w", err)
	}

	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		return fmt.Errorf("hermes.HandleLegacy[persona]: mkdir: %w", err)
	}
	if err := os.WriteFile(soulMDPath(), []byte(p.SystemPrompt), 0o644); err != nil {
		return fmt.Errorf("hermes.HandleLegacy[persona]: write SOUL.md: %w", err)
	}

	if p.Inference.Provider != "" && p.Inference.Model != "" {
		if err := updateConfigYAML(func(cfg map[string]any) {
			model, _ := cfg["model"].(map[string]any)
			if model == nil {
				model = map[string]any{}
			}
			model["provider"] = p.Inference.Provider
			model["default"] = p.Inference.Model
			cfg["model"] = model
		}); err != nil {
			return fmt.Errorf("hermes.HandleLegacy[persona]: update config.yaml: %w", err)
		}
	}

	logger.Logf("hermes.HandleLegacy[persona]: prompt=%dB inference=%s/%s",
		len(p.SystemPrompt), p.Inference.Provider, p.Inference.Model)
	return nil
}
