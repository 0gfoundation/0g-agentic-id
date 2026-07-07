package claudecode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
)

// Mint-only ingestion of the protocol seed role `persona`.
//
// attestor is framework-agnostic: at mint it synthesizes one neutral
// `persona` iData (`{system_prompt, inference:{provider, model}}`) and a
// version-less framework binding, and never speaks any framework's config
// schema. Every adapter is contractually required to translate persona
// into its own path-driven artifacts on first boot (FRAMEWORK_ADAPTER.md
// §5.4); for claude-code that means:
//
//   - persona.SystemPrompt → <workspace>/CLAUDE.md (the always-loaded
//     context file — the owner-authored part; the platform marker section
//     is appended separately at Start)
//   - persona.Inference    → ~/.claude/settings.json. Claude Code speaks
//     the Anthropic protocol, so two providers are routable: "anthropic"
//     (model pin only) and "0g-compute" (model + env.ANTHROPIC_BASE_URL
//     → the 0G router's Anthropic-format endpoint). Anything else is
//     logged and skipped — see applyPersonaModel.
//
// Same lifecycle as the openclaw twin: persona is not in Roles(), so the
// first wholesale chain.Update drops it from chain and the path-driven
// roles (workspace/, settings.json) take over as the durable form.

// personaPlaintext mirrors the shape attestor's default-iData synthesis
// emits. Kept in each adapter rather than shared: the schema is protocol-
// stable, and per-adapter copies keep ingestion changes reviewable next
// to their translation logic.
type personaPlaintext struct {
	SystemPrompt string             `json:"system_prompt"`
	Inference    personaInferenceIn `json:"inference"`
}

type personaInferenceIn struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// HandleLegacy implements framework.Framework. Bootstrap calls this once
// per chain iData entry whose role isn't in Roles() — `persona` is the
// protocol seed role; anything else is logged and ignored per the
// contract (an experimental role must not brick boot).
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.ingestPersona(ctx, plaintext)
	default:
		logger.Logf("claude-code.HandleLegacy: unknown legacy role %q (%d bytes) — ignoring", role, len(plaintext))
		return nil
	}
}

// ingestPersona translates the mint-time persona plaintext into
// claude-code's path-driven disk artifacts. Idempotent: re-invoking with
// the same plaintext yields the same disk state.
func (a *Adapter) ingestPersona(ctx context.Context, plaintext []byte) error {
	if len(plaintext) == 0 {
		return fmt.Errorf("claude-code.HandleLegacy[persona]: empty plaintext")
	}
	var p personaPlaintext
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("claude-code.HandleLegacy[persona]: parse: %w", err)
	}

	if err := os.MkdirAll(workspaceDir(), 0o755); err != nil {
		return fmt.Errorf("claude-code.HandleLegacy[persona]: mkdir workspace: %w", err)
	}
	if err := os.WriteFile(claudeMDPath(), []byte(p.SystemPrompt), 0o644); err != nil {
		return fmt.Errorf("claude-code.HandleLegacy[persona]: write CLAUDE.md: %w", err)
	}

	if err := applyPersonaModel(p.Inference); err != nil {
		return fmt.Errorf("claude-code.HandleLegacy[persona]: %w", err)
	}

	logger.Logf("claude-code.HandleLegacy[persona]: prompt=%dB inference=%s/%s",
		len(p.SystemPrompt), p.Inference.Provider, p.Inference.Model)
	return nil
}

// zgComputeAnthropicBaseURL aliases the shared platform constant
// (internal/inference — single source for all 0g router knowledge).
// Claude Code appends /v1/messages itself; x-api-key auth carries the
// owner's 0g-compute key (delivered via the sandbox env, never on chain).
const zgComputeAnthropicBaseURL = inference.ZGAnthropicBaseURL

// applyPersonaModel merges the persona's inference pin into settings.json.
//
//   - "anthropic":  model only; Claude Code talks to Anthropic directly.
//   - "0g-compute": model + env.ANTHROPIC_BASE_URL → the 0G router's
//     Anthropic-compatible endpoint — inference runs inside 0g-compute's
//     TEE, completing the verifiable-inference layer for this framework.
//     The base URL lands in the chain-tracked settings.json role (see
//     evoSettingsJSON's env sub-allowlist), so WHERE the agent's
//     inference traffic goes is owner-signed and auditable; the API key
//     itself rides the sandbox env and never touches chain plaintext.
//   - anything else: skipped with a warning — writing a model name
//     Claude Code can't resolve fails at first chat with a worse error
//     than "kept the default".
func applyPersonaModel(inf personaInferenceIn) error {
	switch inf.Provider {
	case "anthropic":
		if inf.Model == "" {
			return nil
		}
		return updateSettingsJSON(func(cfg map[string]any) {
			cfg["model"] = inf.Model
		})
	case "0g-compute":
		return updateSettingsJSON(func(cfg map[string]any) {
			if inf.Model != "" {
				cfg["model"] = inf.Model
			}
			env, _ := cfg["env"].(map[string]any)
			if env == nil {
				env = map[string]any{}
			}
			env["ANTHROPIC_BASE_URL"] = zgComputeAnthropicBaseURL
			cfg["env"] = env
		})
	default:
		if inf.Provider != "" || inf.Model != "" {
			logger.Logf("claude-code.HandleLegacy[persona]: provider %q unsupported (anthropic protocol only); keeping default model", inf.Provider)
		}
		return nil
	}
}

// updateSettingsJSON is the read-merge-write helper for
// ~/.claude/settings.json — persona ingestion must not clobber keys the
// settings.json role's Restore already landed (and vice versa: the two
// writers touch disjoint keys, but merging keeps that an implementation
// detail rather than an ordering constraint).
func updateSettingsJSON(transform func(cfg map[string]any)) error {
	cfg := map[string]any{}
	data, err := os.ReadFile(settingsJSONPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", settingsJSONPath(), err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", settingsJSONPath(), err)
		}
	}
	transform(cfg)
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings.json: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsJSONPath()), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(settingsJSONPath()), err)
	}
	if err := os.WriteFile(settingsJSONPath(), out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", settingsJSONPath(), err)
	}
	return nil
}
