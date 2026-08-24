package dsh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"seal-verify/internal/logger"
)

// role="APPEND_SYSTEM.md" — the owner persona, and the mint-time `persona`
// seed's destination.
//
// DSH has no native "append this file to my system prompt" convention the
// way prime-agent's DefaultResourceLoader does — its own `persona` concept is
// a config VALUE inside the plugin composition (dsh-system-prompt's `persona`
// field), which is per-boot platform structure this adapter authors, not
// agent-owned state. So this role's bytes reach the model through the
// bridge's own code: a ctx.systemPrompt.section() call at boot (spawn.go),
// the same authoritative channel the sealed platform doc uses — never a file
// DSH itself reads. Consequence: like prime-agent's APPEND_SYSTEM.md, this
// role needs no marker stripping, because nothing platform-authored ever
// shares its bytes.

// evoAppendSystem returns the persona file's bytes verbatim. Missing or empty
// file → nil, matching Defaults so an absent persona produces no chain entry.
func (a *Adapter) evoAppendSystem() ([]byte, error) {
	content, err := os.ReadFile(appendSystemPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dsh evoAppendSystem: read %s: %w", appendSystemPath(), err)
	}
	if len(content) == 0 {
		return nil, nil
	}
	return content, nil
}

// restoreAppendSystem writes the persona file verbatim. nil plaintext leaves
// an existing file alone (so a supervisor restart never clobbers an agent's
// own edits) and touches an empty one otherwise, so a fresh container never
// synthesizes a stock template that would land on chain as first-boot drift.
func (a *Adapter) restoreAppendSystem(plaintext []byte) error {
	if err := ensureDir(dshHome); err != nil {
		return fmt.Errorf("dsh.Restore[APPEND_SYSTEM.md]: %w", err)
	}
	if len(plaintext) == 0 {
		if _, err := os.Stat(appendSystemPath()); err == nil {
			return nil
		}
		if err := os.WriteFile(appendSystemPath(), nil, 0o644); err != nil {
			return fmt.Errorf("dsh.Restore[APPEND_SYSTEM.md]: touch: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(appendSystemPath(), plaintext, 0o644); err != nil {
		return fmt.Errorf("dsh.Restore[APPEND_SYSTEM.md]: write: %w", err)
	}
	logger.Logf("dsh.Restore[APPEND_SYSTEM.md]: %d bytes", len(plaintext))
	return nil
}

// personaSeed is the protocol seed role every adapter must ingest
// (FRAMEWORK_ADAPTER.md §5.4). The deploy client builds it; the attestor
// synthesizes nothing.
type personaSeed struct {
	SystemPrompt string `json:"system_prompt"`
	Inference    struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	} `json:"inference"`
}

// HandleLegacy translates mint-only ingestion roles into this adapter's
// path-driven artifacts. Unknown roles are logged and ignored — never an
// error — because chains may carry experimental roles a given adapter
// version does not understand.
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	if role != "persona" {
		logger.Logf("dsh.HandleLegacy: ignoring unknown role %q (%d bytes)", role, len(plaintext))
		return nil
	}
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		logger.Logf("dsh.HandleLegacy[persona]: empty seed, nothing to ingest")
		return nil
	}

	var seed personaSeed
	if err := json.Unmarshal(plaintext, &seed); err != nil {
		// A malformed seed must not stop the boot: log and keep defaults.
		logger.Logf("dsh.HandleLegacy[persona]: WARN parse failed (%v); keeping defaults", err)
		return nil
	}

	if seed.SystemPrompt != "" {
		if err := a.restoreAppendSystem([]byte(seed.SystemPrompt)); err != nil {
			return fmt.Errorf("dsh.HandleLegacy[persona]: %w", err)
		}
	}

	// Translate the inference pin into the tracked settings.yaml role. This
	// MUST be persisted, not merely remembered: `persona` is a mint-time seed
	// that leaves the chain at the first drift commit (§5.4), so an
	// in-memory-only pin would survive exactly until then — the bug found live
	// on prime-agent's agent 271 (FRAMEWORK_ADAPTER.md §13), fixed there by
	// tracking models.json. Same fix here, DSH's own file.
	if seed.Inference.Provider != "" && seed.Inference.Model != "" {
		if err := writeSettingsYAML(buildSettingsRoute(seed.Inference.Provider, seed.Inference.Model)); err != nil {
			return fmt.Errorf("dsh.HandleLegacy[persona]: %w", err)
		}
	}
	logger.Logf("dsh.HandleLegacy[persona]: system_prompt=%d bytes, inference=%s/%s",
		len(seed.SystemPrompt), seed.Inference.Provider, seed.Inference.Model)
	return nil
}
