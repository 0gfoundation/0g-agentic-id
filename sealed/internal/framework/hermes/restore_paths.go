package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
)

// Path-driven Restore + LoadEntry + RestoreEntry for the role set declared
// by Adapter.Roles(). Counterpart to evolution_paths.go (read path).

// ── Restore: role="config.yaml" ─────────────────────────────────────────────

// ownedHermesKeys lists the top-level config.yaml keys sealed writes onto
// chain — the only keys that belong in iData. Everything else (gateway
// runtime state, messaging platform blocks, hermes's own bookkeeping,
// future keys we haven't validated) stays local.
//
// Allow-list rather than deny-list, same rationale as the openclaw twin:
// a deny-list silently re-introduces phantom drift every time the
// framework adds a new top-level field.
//
//	model      inference routing (provider/base_url/default; api_key stripped)
//	approvals  exec approval policy — agent self-tuning worth tracking
//	terminal   terminal backend selection — ditto
var ownedHermesKeys = []string{"approvals", "model", "terminal"}

// restoreConfigYAML applies the canonical JSON plaintext (owned keys only)
// onto the on-disk YAML: owned keys present in the plaintext are replaced,
// owned keys absent from it are deleted, unowned keys are left untouched.
// nil/empty plaintext means "chain has no entry" → owned keys cleared.
func (a *Adapter) restoreConfigYAML(plaintext []byte) error {
	parsed := map[string]any{}
	if len(plaintext) > 0 {
		if err := json.Unmarshal(plaintext, &parsed); err != nil {
			return fmt.Errorf("hermes.Restore[config.yaml]: parse: %w", err)
		}
	}
	if err := updateConfigYAML(func(cfg map[string]any) {
		for _, k := range ownedHermesKeys {
			if v, ok := parsed[k]; ok {
				cfg[k] = v
			} else {
				delete(cfg, k)
			}
		}
	}); err != nil {
		return fmt.Errorf("hermes.Restore[config.yaml]: %w", err)
	}
	logger.Logf("hermes.Restore[config.yaml]: %d bytes", len(plaintext))
	return nil
}

// ── Restore: role="SOUL.md" ─────────────────────────────────────────────────

// restoreSoulMD writes the identity file verbatim. nil plaintext touches
// an empty file if none exists — defense against hermes template-installing
// a stock SOUL.md on first boot (which would land verbatim on chain as
// drift for every agent). An existing file is left alone on nil so restarts
// don't clobber agent self-edits.
func (a *Adapter) restoreSoulMD(plaintext []byte) error {
	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		return fmt.Errorf("hermes.Restore[SOUL.md]: mkdir %s: %w", hermesHome, err)
	}
	if len(plaintext) == 0 {
		if _, err := os.Stat(soulMDPath()); err == nil {
			return nil
		}
		if err := os.WriteFile(soulMDPath(), nil, 0o644); err != nil {
			return fmt.Errorf("hermes.Restore[SOUL.md]: touch: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(soulMDPath(), plaintext, 0o644); err != nil {
		return fmt.Errorf("hermes.Restore[SOUL.md]: write: %w", err)
	}
	logger.Logf("hermes.Restore[SOUL.md]: %d bytes", len(plaintext))
	return nil
}

// ── Restore: manifest roles ─────────────────────────────────────────────────

// restoreManifestDir validates the manifest parses and ensures the role's
// directory exists. Actual entry content arrives via RestoreEntry.
func (a *Adapter) restoreManifestDir(plaintext []byte, rootDir, label string) error {
	entryCount := 0
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("hermes.Restore[%s]: %w", label, err)
		}
		entryCount = len(m.Entries)
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return fmt.Errorf("hermes.Restore[%s]: mkdir %s: %w", label, rootDir, err)
	}
	logger.Logf("hermes.Restore[%s]: parsed manifest (%d entries)", label, entryCount)
	return nil
}

// ── LoadEntry ───────────────────────────────────────────────────────────────

// LoadEntry returns the plaintext bytes for one entry inside a manifest
// role. Must match EXACTLY what EvolutionFor hashes for that entry.
func (a *Adapter) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	switch role {
	case "memories/":
		return a.loadEntryMemories(path)
	case "skills/":
		return a.loadEntrySkills(path)
	}
	return nil, framework.ErrUnsupportedDim
}

func (a *Adapter) loadEntryMemories(path string) ([]byte, error) {
	if strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("hermes.LoadEntry[memories/]: dir entries not supported (got %q)", path)
	}
	full := filepath.Join(memoriesDir(), path)
	content, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("hermes.LoadEntry[memories/]: read %s: %w", full, err)
	}
	return content, nil
}

func (a *Adapter) loadEntrySkills(path string) ([]byte, error) {
	if !strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("hermes.LoadEntry[skills/]: only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') {
		return nil, fmt.Errorf("hermes.LoadEntry[skills/]: invalid slug %q", path)
	}
	dir := filepath.Join(skillsDir(), slug)
	return manifest.PackDir(dir)
}

// ── RestoreEntry ────────────────────────────────────────────────────────────

// RestoreEntry writes one entry's content under the role's disk location.
// Inverse of LoadEntry. Creates parent dirs as needed (order-independent
// with Restore).
func (a *Adapter) RestoreEntry(ctx context.Context, role, path string, plaintext []byte) error {
	switch role {
	case "memories/":
		return a.restoreEntryMemories(path, plaintext)
	case "skills/":
		return a.restoreEntrySkills(path, plaintext)
	}
	return framework.ErrUnsupportedDim
}

func (a *Adapter) restoreEntryMemories(path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: dir entries not supported (got %q)", path)
	}
	if err := os.MkdirAll(memoriesDir(), 0o755); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: mkdir: %w", err)
	}
	full := filepath.Join(memoriesDir(), path)
	if err := os.WriteFile(full, plaintext, 0o644); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: write %s: %w", full, err)
	}
	return nil
}

func (a *Adapter) restoreEntrySkills(path string, plaintext []byte) error {
	if !strings.HasSuffix(path, "/") {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: invalid slug %q", path)
	}
	// A chain entry colliding with a locally-bundled slug is written like
	// any other: the restored content wins on disk, and because the slug is
	// then still listed in .bundled_manifest it drops out of the next
	// manifest build — a one-time disappearance the uploader reconciles.
	// (Can't happen through normal operation: bundled slugs never enter
	// the manifest in the first place.)
	dst := filepath.Join(skillsDir(), slug)
	// Clean any prior content at this slug so deletions inside the tarball
	// are honoured (UnpackDir overwrites files but doesn't remove stale ones).
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: clean %s: %w", dst, err)
	}
	return manifest.UnpackDir(plaintext, dst)
}
