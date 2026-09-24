package dsh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
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

// HandleLegacy translates mint-only ingestion roles, and roles this adapter
// has retired, into what the running container needs. Unknown roles are
// logged and ignored — never an error — because chains may carry experimental
// roles a given adapter version does not understand.
//
//	persona       the mint seed (below)
//	settings.yaml the retired inference-pin role; its provider+model are
//	              recovered into the owner's settings document (settings.go)
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.handleLegacyPersona(plaintext)
	case legacySettingsRole:
		return a.handleLegacySettings(plaintext)
	}
	logger.Logf("dsh.HandleLegacy: ignoring unknown role %q (%d bytes)", role, len(plaintext))
	return nil
}

// handleLegacyPersona ingests the protocol seed role every adapter must
// handle (FRAMEWORK_ADAPTER.md §5.4).
func (a *Adapter) handleLegacyPersona(plaintext []byte) error {
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

	// The pin BEFORE the prompt's disk write: it is the half only this boot
	// can recover (the watcher's first wholesale commit drops this entry), it
	// cannot fail, and a disk that refuses APPEND_SYSTEM.md must not also
	// cost the owner their model.
	a.seedFromPersona(seed.Inference.Provider, seed.Inference.Model)

	if seed.SystemPrompt != "" {
		if err := a.restoreAppendSystem([]byte(seed.SystemPrompt)); err != nil {
			// Logged, never returned: Phase C propagates an error (main.go
			// returns on it), so an unwritable persona file would take the
			// container OFFLINE — strictly worse than running on the stock
			// system prompt, and worse than what the pre-migration code did
			// with the same disk.
			logger.Logf("dsh.HandleLegacy[persona]: WARN write APPEND_SYSTEM.md: %v", err)
		}
	}

	logger.Logf("dsh.HandleLegacy[persona]: system_prompt=%d bytes", len(seed.SystemPrompt))
	return nil
}

// seedFromPersona REPORTS the mint-time pin to the platform
// (framework.LegacySettingsSeeder → report.SeedSettings), closing the gap the
// settings migration left: attestor mints exactly two iData roles, `framework`
// and `persona`, so an agent minted before the channel that never committed
// drift carries its pin HERE and nowhere else — the retired settings.yaml role
// settings.go recovers from only exists on chain after a drift commit. For dsh
// an unrecovered pin is an outage, not a degradation: Start hard-fails without
// one (spawn.go), and the pre-migration code booted these agents fine.
//
// The pin is deliberately NOT written into a settings.yaml on disk. It used to
// be, and that translation was itself the fix for a live bug (prime-agent's
// agent 271: the seed leaves the chain at the first drift commit and an
// in-memory pin died with it) — but the durable home is the owner's document
// now, and a second on-disk source of truth is the ambiguity that bug was
// made of.
//
// The provider is carried VERBATIM: the seed records what the owner picked
// ("0g-compute" for a routed model), which is already the spelling
// settings.Resolve turns back into the router endpoint. Both halves or
// nothing, exactly as the settings.yaml branch: what comes back is PERSISTED
// as the owner's document, and a half-pin would fail every future boot while
// outranking this recovery each time.
func (a *Adapter) seedFromPersona(provider, model string) {
	provider = strings.TrimSpace(provider)
	model = strings.TrimSpace(model)
	if provider == "" || model == "" {
		if provider != "" || model != "" {
			logger.Logf("dsh.HandleLegacy[persona]: seed pins provider=%q model=%q; half a pin is not a recovery", provider, model)
		}
		return
	}
	doc := settings.Doc{Provider: provider, Model: model}
	if !a.stashSeededPin(sourcePersona, doc) {
		logger.Logf("dsh.HandleLegacy[persona]: the mint seed pins %s/%s, but the retired %s role already recovered this agent's later pin; keeping that one",
			provider, model, legacySettingsRole)
		return
	}
	logger.Logf("dsh.HandleLegacy[persona]: recovered pin provider=%s model=%s from the mint seed; the platform will persist it as the owner's settings document",
		provider, model)
}
