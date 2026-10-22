package hermes

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
)

// Path-driven Restore + LoadEntry + RestoreEntry for the role set declared
// by Adapter.Roles(). Counterpart to evolution_paths.go (read path).
//
// Every disk access goes through internal/privsep (the hermes home is
// agent-writable), and every entry path is checked to be a single segment
// (manifest.ValidEntryPath) before it is joined under the role directory.
// Restore is authoritative over the shape of the role directories:
// ensureRoleDir (privsep.EnsureDir) replaces a link or file the agent left
// where one belongs, never following it, so it cannot keep the agent from
// booting.

// ensureRoleDir makes dir, inside hermesHome, a real directory.
func ensureRoleDir(dir string) error {
	return privsep.EnsureDir(hermesHome, dir, 0o755)
}

// ── Restore: role="SOUL.md" ─────────────────────────────────────────────────

// restoreSoulMD writes the identity file verbatim. nil plaintext touches
// an empty file if none exists — defense against hermes template-installing
// a stock SOUL.md on first boot (which would land verbatim on chain as
// drift for every agent). An existing file is left alone on nil so restarts
// don't clobber agent self-edits.
func (a *Adapter) restoreSoulMD(plaintext []byte) error {
	if err := privsep.MkdirAll(hermesHome, 0o755); err != nil {
		return fmt.Errorf("hermes.Restore[SOUL.md]: mkdir %s: %w", hermesHome, err)
	}
	if len(plaintext) == 0 {
		if _, err := privsep.Lstat(soulMDPath()); err == nil {
			return nil
		}
		if err := privsep.WriteFile(soulMDPath(), nil, 0o644); err != nil {
			return fmt.Errorf("hermes.Restore[SOUL.md]: touch: %w", err)
		}
		return nil
	}
	if err := privsep.WriteFile(soulMDPath(), plaintext, 0o644); err != nil {
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
	if err := ensureRoleDir(rootDir); err != nil {
		return fmt.Errorf("hermes.Restore[%s]: mkdir %s: %w", label, rootDir, err)
	}
	logger.Logf("hermes.Restore[%s]: parsed manifest (%d entries)", label, entryCount)
	return nil
}

// ── LoadEntry ───────────────────────────────────────────────────────────────

// LoadEntry returns the plaintext bytes for one entry inside a manifest
// role. Must match EXACTLY what EvolutionFor hashes for that entry.
func (a *Adapter) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	if err := manifest.ValidEntryPath(path); err != nil {
		return nil, fmt.Errorf("hermes.LoadEntry[%s]: %w", role, err)
	}
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
	if err := manifest.ValidEntryPath(path); err != nil {
		return nil, fmt.Errorf("hermes.LoadEntry[memories/]: %w", err)
	}
	full := filepath.Join(memoriesDir(), path)
	content, err := privsep.ReadFile(full, privsep.LimitTracked)
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
	if err := manifest.ValidEntryPath(path); err != nil {
		return nil, fmt.Errorf("hermes.LoadEntry[skills/]: invalid slug %q: %w", path, err)
	}
	dir := filepath.Join(skillsDir(), slug)
	return manifest.PackDir(dir)
}

// ── RestoreEntry ────────────────────────────────────────────────────────────

// RestoreEntry writes one entry's content under the role's disk location.
// Inverse of LoadEntry. Creates parent dirs as needed (order-independent
// with Restore).
func (a *Adapter) RestoreEntry(ctx context.Context, role, path string, plaintext []byte) error {
	if err := manifest.ValidEntryPath(path); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[%s]: %w", role, err)
	}
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
	// A memories entry is one file directly under memories/; anything that
	// could name another directory is refused before the join.
	if err := manifest.ValidEntryPath(path); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: %w", err)
	}
	if err := ensureRoleDir(memoriesDir()); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: mkdir: %w", err)
	}
	full := filepath.Join(memoriesDir(), path)
	if err := privsep.WriteFile(full, plaintext, 0o644); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[memories/]: write %s: %w", full, err)
	}
	return nil
}

func (a *Adapter) restoreEntrySkills(path string, plaintext []byte) error {
	if !strings.HasSuffix(path, "/") {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if err := manifest.ValidEntryPath(path); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: invalid slug %q: %w", path, err)
	}
	// A chain entry colliding with a locally-bundled slug is written like
	// any other: the restored content wins on disk, and because the slug is
	// then still listed in .bundled_manifest it drops out of the next
	// manifest build — a one-time disappearance the uploader reconciles.
	// (Can't happen through normal operation: bundled slugs never enter
	// the manifest in the first place.)
	if err := ensureRoleDir(skillsDir()); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: %w", err)
	}
	dst := filepath.Join(skillsDir(), slug)
	// Clean any prior content at this slug so deletions inside the tarball
	// are honoured (UnpackDir overwrites files but doesn't remove stale ones).
	if err := privsep.RemoveAll(dst); err != nil {
		return fmt.Errorf("hermes.RestoreEntry[skills/]: clean %s: %w", dst, err)
	}
	return manifest.UnpackDir(plaintext, dst)
}
