package openclaw

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

// This file implements the path-driven Restore + LoadEntry + RestoreEntry
// for the role set declared by Adapter.Roles(). Counterpart to
// evolution_paths.go (read path).

// ── Restore: role="openclaw.json" ───────────────────────────────────────────

// restoreOpenclawJSON writes the plaintext (already filtered by the encoder
// to exclude per-boot keys) verbatim to ~/.openclaw/openclaw.json.
//
// Per the path-driven model, this role owns the entire file; no merge with
// other roles is needed. Per-boot sections (gateway.*) get re-added by
// spawn.go writeRuntimeSections after Restore completes. The model-provider
// dynamic augmentation (models.providers entries for 0g-compute routing)
// is handled separately at Start time.
func (a *Adapter) restoreOpenclawJSON(plaintext []byte) error {
	if len(plaintext) == 0 {
		// Required role; an empty plaintext at this layer indicates the
		// caller wanted to clear the config. Write an empty object so
		// the file exists.
		plaintext = []byte("{}")
	}
	// Verify it parses — fail loud on garbage rather than silently
	// corrupting the agent's config file.
	var cfg map[string]any
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return fmt.Errorf("openclaw.Restore[openclaw.json]: parse: %w", err)
	}
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		return fmt.Errorf("openclaw.Restore[openclaw.json]: mkdir %s: %w", openclawHome, err)
	}
	if err := os.WriteFile(openclawJSONPath(), plaintext, 0o600); err != nil {
		return fmt.Errorf("openclaw.Restore[openclaw.json]: write %s: %w", openclawJSONPath(), err)
	}
	logger.Logf("openclaw.Restore[openclaw.json]: %d bytes", len(plaintext))
	return nil
}

// ── Restore: role="workspace/" ──────────────────────────────────────────────

// workspaceRequiredMDs are root-level md files openclaw will auto-install
// a multi-KB template for via writeFileIfMissing on first chat. Restore
// touches an empty file for every required name NOT present in the
// manifest so openclaw's template install is a no-op. Subsequent
// RestoreEntry calls overwrite these with actual content.
var workspaceRequiredMDs = []string{
	"SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md", "TOOLS.md",
	"MEMORY.md", "DREAMS.md",
}

// restoreWorkspace parses the manifest plaintext, ensures the workspace
// directory exists, and touches empty defense files for any required md
// not in the manifest. Does NOT fetch entry contents — caller (bootstrap)
// iterates the manifest's Entries and calls RestoreEntry separately.
//
// Treats nil/empty plaintext as "no manifest" (chain has no entry for
// this role) — touches all empty defense files.
func (a *Adapter) restoreWorkspace(plaintext []byte) error {
	var present map[string]bool
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("openclaw.Restore[workspace/]: %w", err)
		}
		present = make(map[string]bool, len(m.Entries))
		for _, e := range m.Entries {
			present[e.Path] = true
		}
	}

	if err := os.MkdirAll(workspaceDir(), 0o755); err != nil {
		return fmt.Errorf("openclaw.Restore[workspace/]: mkdir %s: %w", workspaceDir(), err)
	}

	touched := 0
	for _, md := range workspaceRequiredMDs {
		if present[md] {
			continue // RestoreEntry will write the real content
		}
		path := filepath.Join(workspaceDir(), md)
		if _, err := os.Stat(path); err == nil {
			continue // already exists from previous boot — leave alone
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			return fmt.Errorf("openclaw.Restore[workspace/]: touch %s: %w", path, err)
		}
		touched++
	}
	logger.Logf("openclaw.Restore[workspace/]: parsed manifest (%d entries), touched %d empty md defenses",
		len(present), touched)
	return nil
}

// ── Restore: role="workspace/skills/" ───────────────────────────────────────

// restoreWorkspaceSkills parses the manifest (for validation) and ensures
// the skills directory exists. Actual skill content arrives via
// RestoreEntry per slug.
//
// Treats nil/empty plaintext as "no skills" — just creates the empty dir.
func (a *Adapter) restoreWorkspaceSkills(plaintext []byte) error {
	return a.restoreManifestDir(plaintext, workspaceDir()+"/skills", "workspace/skills/")
}

// ── Restore: role="workspace/canvas/" ───────────────────────────────────────

func (a *Adapter) restoreWorkspaceCanvas(plaintext []byte) error {
	return a.restoreManifestDir(plaintext, workspaceDir()+"/canvas", "workspace/canvas/")
}

// restoreManifestDir is shared bookkeeping for manifest roles whose only
// disk responsibility at Restore time is "ensure dir exists + validate
// manifest parses". Used by skills + canvas; future per-subdir roles can
// reuse it.
func (a *Adapter) restoreManifestDir(plaintext []byte, rootDir, label string) error {
	entryCount := 0
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("openclaw.Restore[%s]: %w", label, err)
		}
		entryCount = len(m.Entries)
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return fmt.Errorf("openclaw.Restore[%s]: mkdir %s: %w", label, rootDir, err)
	}
	logger.Logf("openclaw.Restore[%s]: parsed manifest (%d entries)", label, entryCount)
	return nil
}

// ── LoadEntry ───────────────────────────────────────────────────────────────

// LoadEntry returns the plaintext bytes for one entry inside a manifest
// role. Must match EXACTLY what EvolutionFor would hash for that entry —
// otherwise round-trip (LoadEntry → RestoreEntry → next EvolutionFor)
// produces a different content_hash and the watcher reports phantom drift.
func (a *Adapter) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	switch role {
	case "workspace/":
		return a.loadEntryWorkspace(path)
	case "workspace/skills/":
		return a.loadEntryWorkspaceSkills(path)
	case "workspace/canvas/":
		return a.loadEntryWorkspaceCanvas(path)
	}
	return nil, framework.ErrUnsupportedDim
}

func (a *Adapter) loadEntryWorkspace(path string) ([]byte, error) {
	if strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("openclaw.LoadEntry[workspace/]: dir entries not supported (got %q)", path)
	}
	full := filepath.Join(workspaceDir(), path)
	content, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("openclaw.LoadEntry[workspace/]: read %s: %w", full, err)
	}
	// Strip any sealed-injected section so the returned plaintext matches
	// what EvolutionFor would hash. Files without markers are unaffected.
	// See evoWorkspace for the mirrored strip on the hash path.
	if strings.HasSuffix(path, ".md") {
		content = stripPlatformInjection(content)
	}
	return content, nil
}

func (a *Adapter) loadEntryWorkspaceSkills(path string) ([]byte, error) {
	if !strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("openclaw.LoadEntry[workspace/skills/]: only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') {
		return nil, fmt.Errorf("openclaw.LoadEntry[workspace/skills/]: invalid slug %q", path)
	}
	dir := filepath.Join(workspaceDir(), "skills", slug)
	return manifest.PackDir(dir)
}

func (a *Adapter) loadEntryWorkspaceCanvas(path string) ([]byte, error) {
	full := filepath.Join(workspaceDir(), "canvas", strings.TrimSuffix(path, "/"))
	if strings.HasSuffix(path, "/") {
		return manifest.PackDir(full)
	}
	return os.ReadFile(full)
}

// ── RestoreEntry ────────────────────────────────────────────────────────────

// RestoreEntry writes one entry's content under the role's disk location.
// Inverse of LoadEntry. Creates parent dirs as needed (order-independent
// with Restore — caller can call RestoreEntry before or after Restore).
func (a *Adapter) RestoreEntry(ctx context.Context, role, path string, plaintext []byte) error {
	switch role {
	case "workspace/":
		return a.restoreEntryWorkspace(path, plaintext)
	case "workspace/skills/":
		return a.restoreEntryWorkspaceSkills(path, plaintext)
	case "workspace/canvas/":
		return a.restoreEntryWorkspaceCanvas(path, plaintext)
	}
	return framework.ErrUnsupportedDim
}

func (a *Adapter) restoreEntryWorkspace(path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/]: dir entries not supported (got %q)", path)
	}
	if err := os.MkdirAll(workspaceDir(), 0o755); err != nil {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/]: mkdir: %w", err)
	}
	full := filepath.Join(workspaceDir(), path)
	if err := os.WriteFile(full, plaintext, 0o644); err != nil {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/]: write %s: %w", full, err)
	}
	return nil
}

func (a *Adapter) restoreEntryWorkspaceSkills(path string, plaintext []byte) error {
	if !strings.HasSuffix(path, "/") {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/skills/]: only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/skills/]: invalid slug %q", path)
	}
	dst := filepath.Join(workspaceDir(), "skills", slug)
	// Clean any prior content at this slug so deletions inside the tarball
	// are honoured (UnpackDir overwrites files but doesn't remove stale ones).
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/skills/]: clean %s: %w", dst, err)
	}
	return manifest.UnpackDir(plaintext, dst)
}

func (a *Adapter) restoreEntryWorkspaceCanvas(path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		dst := filepath.Join(workspaceDir(), "canvas", strings.TrimSuffix(path, "/"))
		if err := os.RemoveAll(dst); err != nil {
			return fmt.Errorf("openclaw.RestoreEntry[workspace/canvas/]: clean %s: %w", dst, err)
		}
		return manifest.UnpackDir(plaintext, dst)
	}
	full := filepath.Join(workspaceDir(), "canvas", path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/canvas/]: mkdir parent of %s: %w", full, err)
	}
	if err := os.WriteFile(full, plaintext, 0o644); err != nil {
		return fmt.Errorf("openclaw.RestoreEntry[workspace/canvas/]: write %s: %w", full, err)
	}
	return nil
}
