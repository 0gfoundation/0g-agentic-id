package openclaw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/manifest"
)

// This file implements EvolutionFor for the path-driven role set (§16).
// The dispatch case-table lives in evolution.go's EvolutionFor; the per-
// role builders live here so the old 5-dim file stays focused on the
// legacy implementation until Phase 4 cleanup.

// ── role="openclaw.json" ────────────────────────────────────────────────────

// ownedOpenclawKeys lists the top-level keys sealed writes into
// openclaw.json — the only keys that belong on chain. Everything else
// (gateway auth tokens, openclaw's own logging / discovery / wizard /
// push runtime state, future keys we haven't seen yet) is openclaw
// process bookkeeping and stays local.
//
// Allow-list rather than deny-list: a deny-list silently re-introduces
// drift every time openclaw adds a new top-level field, and we already
// saw that play out (logging/wizard-shape per-boot writes triggered an
// extra chain.Update on every restart).
var ownedOpenclawKeys = []string{"agents", "auth", "models"}

// evoOpenclawJSON reads ~/.openclaw/openclaw.json, keeps only the keys
// sealed owns, and returns the canonical plaintext bytes used for chain
// upload.
//
// Determinism: encoding/json marshals map[string]any with sorted keys,
// so the same on-disk state always produces the same bytes.
func (a *Adapter) evoOpenclawJSON() ([]byte, error) {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(ownedOpenclawKeys))
	for _, k := range ownedOpenclawKeys {
		if v, ok := cfg[k]; ok {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// ── role="workspace/" ───────────────────────────────────────────────────────

// evoWorkspace builds a Manifest whose entries are the top-level *.md
// files in ~/.openclaw/workspace/ (each one a Kind=file entry). Sub-
// directories of workspace (memory/, skills/, canvas/, ...) are NOT
// scanned here — they have their own roles or are explicitly excluded.
//
// Returned manifest entries have StoragePtr left zero — uploader fills
// these at push time once each blob is encrypted and stored.
func (a *Adapter) evoWorkspace() ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(workspaceDir())
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("openclaw evoWorkspace: read %s: %w", workspaceDir(), err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		full := filepath.Join(workspaceDir(), e.Name())
		content, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("openclaw evoWorkspace: read %s: %w", full, err)
		}
		// TOOLS.md special case: strip the per-boot platform-injected
		// section (CORS / public URL guidance) before hashing. The
		// spawn-time helper upsertPlatformSection adds it back to disk
		// after Restore, so the chain payload stays platform-neutral.
		if e.Name() == "TOOLS.md" {
			content = stripPlatformInjection(content)
		}
		// Empty md is not tracked — Restore's template-defense touch
		// creates zero-byte files for required md names, and openclaw
		// 5.x writes empty placeholders for some on first boot. Treating
		// them as "no content = no entry" keeps the manifest stable
		// across the defense-touch step (round-trip property).
		if len(content) == 0 {
			continue
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        e.Name(),
			Kind:        manifest.EntryFile,
			ContentHash: manifest.HashHex(content),
			Size:        len(content),
		})
	}
	// Marshal sorts entries by Path, so iteration order here doesn't matter.
	return m.Marshal()
}

// ── role="workspace/skills/" ────────────────────────────────────────────────

// evoWorkspaceSkills builds a Manifest whose entries are the top-level
// subdirectories of ~/.openclaw/workspace/skills/ (each a Kind=dir entry).
//
// Each entry's ContentHash is sha256 of the deterministic tar.gz of that
// skill's subtree. The tarball bytes themselves are NOT stored in the
// manifest — the uploader produces them on demand at push time via
// LoadEntry (Phase 2) and encrypts → 0g-storage → fills StoragePtr.
//
// Loose files directly under workspace/skills/ (no enclosing dir) are
// ignored: openclaw skills are always folder-based per docs.
func (a *Adapter) evoWorkspaceSkills() ([]byte, error) {
	return a.evoSubdirManifest(workspaceDir() + "/skills")
}

// ── role="workspace/canvas/" ────────────────────────────────────────────────

// evoWorkspaceCanvas builds a Manifest whose entries are the top-level
// items in ~/.openclaw/workspace/canvas/. Unlike skills (always folder),
// canvas allows mixed top-level: index.html as a file, scripts/ as a dir.
//
// File entries hash the file bytes; dir entries hash the tar.gz of the
// subtree.
func (a *Adapter) evoWorkspaceCanvas() ([]byte, error) {
	dir := workspaceDir() + "/canvas"
	m := manifest.New()

	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("openclaw evoWorkspaceCanvas: read %s: %w", dir, err)
	}

	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			tarBytes, err := manifest.PackDir(full)
			if err != nil {
				return nil, fmt.Errorf("openclaw evoWorkspaceCanvas: pack %s: %w", full, err)
			}
			m.Entries = append(m.Entries, manifest.Entry{
				Path:        e.Name() + "/",
				Kind:        manifest.EntryDir,
				ContentHash: manifest.HashHex(tarBytes),
				Size:        len(tarBytes),
			})
		} else {
			content, err := os.ReadFile(full)
			if err != nil {
				return nil, fmt.Errorf("openclaw evoWorkspaceCanvas: read %s: %w", full, err)
			}
			m.Entries = append(m.Entries, manifest.Entry{
				Path:        e.Name(),
				Kind:        manifest.EntryFile,
				ContentHash: manifest.HashHex(content),
				Size:        len(content),
			})
		}
	}
	return m.Marshal()
}

// ── shared: directory-of-subdirs manifest ───────────────────────────────────

// evoSubdirManifest builds a Manifest where each top-level subdirectory
// of root becomes a Kind=dir entry. Used by workspace/skills/; potentially
// reusable for future "directory of independent subprojects" roles.
//
// Iteration is sorted by directory name (Marshal also sorts, but sorting
// here keeps in-memory order predictable for tests inspecting m.Entries
// before Marshal).
func (a *Adapter) evoSubdirManifest(root string) ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("openclaw evoSubdirManifest: read %s: %w", root, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		sub := filepath.Join(root, name)
		tarBytes, err := manifest.PackDir(sub)
		if err != nil {
			return nil, fmt.Errorf("openclaw evoSubdirManifest: pack %s: %w", sub, err)
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        name + "/",
			Kind:        manifest.EntryDir,
			ContentHash: manifest.HashHex(tarBytes),
			Size:        len(tarBytes),
		})
	}
	return m.Marshal()
}
