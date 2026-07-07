package claudecode

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
	"seal-verify/internal/platform"
)

// Restore applies a role's plaintext to disk + the small in-memory state
// the adapter retains (framework binding). Commutative across roles +
// idempotent per role: each role owns a disjoint disk slice.
func (a *Adapter) Restore(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "framework":
		return a.restoreFramework(plaintext)
	case "settings.json":
		return a.restoreSettingsJSON(plaintext)
	case "workspace/":
		return a.restoreManifestDir(plaintext, workspaceDir(), "workspace/")
	case "agents/":
		return a.restoreManifestDir(plaintext, agentsDir(), "agents/")
	case "skills/":
		return a.restoreManifestDir(plaintext, skillsDir(), "skills/")
	default:
		logger.Logf("claude-code.Restore[%s]: unknown role, ignoring (%d bytes)", role, len(plaintext))
		return nil
	}
}

// restoreFramework parses + validates the binding. nil plaintext means
// "chain has no entry" → adapter-derived defaults. A binding naming a
// different framework fails loud: the chain record and the running image
// disagree about what this agent is, and starting anyway forges identity.
//
// An empty/absent package_version in a present binding resolves to
// whitelistMax — attestor mints version-less bindings; version knowledge
// lives here with the allowlist (see the openclaw twin for the full
// rationale).
func (a *Adapter) restoreFramework(plaintext []byte) error {
	var fb frameworkBinding
	if len(plaintext) == 0 {
		fb = frameworkBinding{
			Name:           "claude-code",
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		}
	} else {
		if err := json.Unmarshal(plaintext, &fb); err != nil {
			return fmt.Errorf("claude-code.Restore[framework]: parse: %w", err)
		}
		if fb.Name != "claude-code" {
			return fmt.Errorf("claude-code.Restore[framework]: framework.name = %q; claude-code adapter expected", fb.Name)
		}
		if fb.SchemaVersion != 1 {
			return fmt.Errorf("claude-code.Restore[framework]: unsupported schema_version: %d (this reader supports 1)", fb.SchemaVersion)
		}
		if fb.PackageVersion == "" {
			fb.PackageVersion = whitelistMax()
		}
	}
	a.mu.Lock()
	a.binding = &fb
	a.mu.Unlock()
	logger.Logf("claude-code.Restore[framework]: name=%s package_version=%s schema=%d",
		fb.Name, fb.PackageVersion, fb.SchemaVersion)
	return nil
}

// restoreSettingsJSON writes the plaintext verbatim to
// ~/.claude/settings.json. The plaintext is already allowlist-filtered
// (it round-trips through evoSettingsJSON); per-boot keys Claude Code
// writes for itself land in the same file later and are filtered back
// out at evolution time.
func (a *Adapter) restoreSettingsJSON(plaintext []byte) error {
	if len(plaintext) == 0 {
		plaintext = []byte("{}")
	}
	var cfg map[string]any
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return fmt.Errorf("claude-code.Restore[settings.json]: parse: %w", err)
	}
	if err := os.MkdirAll(claudeHome, 0o755); err != nil {
		return fmt.Errorf("claude-code.Restore[settings.json]: mkdir %s: %w", claudeHome, err)
	}
	if err := os.WriteFile(settingsJSONPath(), plaintext, 0o600); err != nil {
		return fmt.Errorf("claude-code.Restore[settings.json]: write %s: %w", settingsJSONPath(), err)
	}
	logger.Logf("claude-code.Restore[settings.json]: %d bytes", len(plaintext))
	return nil
}

// restoreManifestDir validates the manifest parses and ensures the role's
// root directory exists. Entry contents arrive via RestoreEntry — this
// adapter has no template-defense step (Claude Code doesn't auto-install
// stock templates the way openclaw's writeFileIfMissing does).
func (a *Adapter) restoreManifestDir(plaintext []byte, rootDir, label string) error {
	entryCount := 0
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("claude-code.Restore[%s]: %w", label, err)
		}
		entryCount = len(m.Entries)
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return fmt.Errorf("claude-code.Restore[%s]: mkdir %s: %w", label, rootDir, err)
	}
	logger.Logf("claude-code.Restore[%s]: parsed manifest (%d entries)", label, entryCount)
	return nil
}

// ── LoadEntry / RestoreEntry ────────────────────────────────────────────────
//
// Entry shape per role:
//   workspace/  file entries only; .md content is strip-filtered so the
//               CLAUDE.md platform injection never reaches chain
//   agents/     file entries only (subagent .md definitions), raw bytes
//   skills/     dir entries only (one slug per skill), deterministic tar.gz

// LoadEntry returns one entry's canonical plaintext. Must byte-match what
// EvolutionFor hashed for that path or uploads loop (see
// FRAMEWORK_ADAPTER.md §5.3).
func (a *Adapter) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	switch role {
	case "workspace/":
		return loadFileEntry(workspaceDir(), "workspace/", path, true)
	case "agents/":
		return loadFileEntry(agentsDir(), "agents/", path, false)
	case "skills/":
		return loadDirEntry(skillsDir(), "skills/", path)
	}
	return nil, framework.ErrUnsupportedDim
}

// RestoreEntry writes one entry's plaintext under the role's disk
// location. Inverse of LoadEntry.
func (a *Adapter) RestoreEntry(ctx context.Context, role, path string, plaintext []byte) error {
	switch role {
	case "workspace/":
		return restoreFileEntry(workspaceDir(), "workspace/", path, plaintext)
	case "agents/":
		return restoreFileEntry(agentsDir(), "agents/", path, plaintext)
	case "skills/":
		return restoreDirEntry(skillsDir(), "skills/", path, plaintext)
	}
	return framework.ErrUnsupportedDim
}

func loadFileEntry(rootDir, label, path string, stripMD bool) ([]byte, error) {
	if strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("claude-code.LoadEntry[%s]: dir entries not supported (got %q)", label, path)
	}
	full := filepath.Join(rootDir, path)
	content, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("claude-code.LoadEntry[%s]: read %s: %w", label, full, err)
	}
	if stripMD && strings.HasSuffix(path, ".md") {
		content = platform.StripInjected(content)
	}
	return content, nil
}

func restoreFileEntry(rootDir, label, path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("claude-code.RestoreEntry[%s]: dir entries not supported (got %q)", label, path)
	}
	full := filepath.Join(rootDir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("claude-code.RestoreEntry[%s]: mkdir: %w", label, err)
	}
	if err := os.WriteFile(full, plaintext, 0o644); err != nil {
		return fmt.Errorf("claude-code.RestoreEntry[%s]: write %s: %w", label, full, err)
	}
	return nil
}

func loadDirEntry(rootDir, label, path string) ([]byte, error) {
	slug, err := dirSlug(label, path)
	if err != nil {
		return nil, err
	}
	return manifest.PackDir(filepath.Join(rootDir, slug))
}

func restoreDirEntry(rootDir, label, path string, plaintext []byte) error {
	slug, err := dirSlug(label, path)
	if err != nil {
		return err
	}
	dst := filepath.Join(rootDir, slug)
	// Clean prior content so deletions inside the tarball are honoured
	// (UnpackDir overwrites files but doesn't remove stale ones).
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("claude-code.RestoreEntry[%s]: clean %s: %w", label, dst, err)
	}
	return manifest.UnpackDir(plaintext, dst)
}

func dirSlug(label, path string) (string, error) {
	if !strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("claude-code entry[%s]: only dir entries supported (got %q)", label, path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') {
		return "", fmt.Errorf("claude-code entry[%s]: invalid slug %q", label, path)
	}
	return slug, nil
}

// ── small shared helpers ────────────────────────────────────────────────────

func marshalBinding(fb frameworkBinding) []byte {
	b, err := json.Marshal(&fb)
	if err != nil {
		return nil
	}
	return b
}

func emptyManifestBytes() []byte {
	b, err := manifest.New().Marshal()
	if err != nil {
		return nil
	}
	return b
}
