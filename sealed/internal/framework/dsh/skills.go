package dsh

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/manifest"
)

// role="skills/" — the agent's installed skills under $DSH_HOME/skills/, rank
// 400 ("user-dsh") in DSH's own skill-discovery priority table
// (docs/subsystems/skills.md). A skill is either a directory bundle
// (`<name>/SKILL.md`) or a flat file (`<name>.md`); this role tracks both
// shapes, one manifest entry per top-level filesystem entry.
//
// The local skill provider reserves one child of this directory for itself
// (`.system`) — never agent content — which evoSkills excludes, the same
// pattern hermes uses for `skills/.bundled_manifest`.

// evoSkills builds a Manifest whose entries are the top-level contents of
// $DSH_HOME/skills/: directories packed as one deterministic tar.gz each,
// flat `.md` files tracked as file entries.
func (a *Adapter) evoSkills() ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(skillsDir())
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("dsh evoSkills: read %s: %w", skillsDir(), err)
	}

	type item struct {
		name  string
		isDir bool
	}
	var items []item
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue // .system and any dotfile are provider-reserved, never agent content
		}
		if e.IsDir() {
			items = append(items, item{name, true})
			continue
		}
		if strings.HasSuffix(name, ".md") {
			items = append(items, item{name, false})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })

	for _, it := range items {
		full := filepath.Join(skillsDir(), it.name)
		if it.isDir {
			tarBytes, err := manifest.PackDir(full)
			if err != nil {
				return nil, fmt.Errorf("dsh evoSkills: pack %s: %w", full, err)
			}
			m.Entries = append(m.Entries, manifest.Entry{
				Path:        it.name + "/",
				Kind:        manifest.EntryDir,
				ContentHash: manifest.HashHex(tarBytes),
				Size:        len(tarBytes),
			})
			continue
		}
		content, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("dsh evoSkills: read %s: %w", full, err)
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        it.name,
			Kind:        manifest.EntryFile,
			ContentHash: manifest.HashHex(content),
			Size:        len(content),
		})
	}
	return m.Marshal()
}

func (a *Adapter) loadEntrySkills(path string) ([]byte, error) {
	full := filepath.Join(skillsDir(), path)
	if strings.HasSuffix(path, "/") {
		return manifest.PackDir(strings.TrimSuffix(full, "/"))
	}
	slug, err := skillFileSlug(path)
	if err != nil {
		return nil, fmt.Errorf("dsh.LoadEntry[skills/]: %w", err)
	}
	return os.ReadFile(filepath.Join(skillsDir(), slug))
}

func (a *Adapter) restoreEntrySkills(path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		slug, err := skillDirSlug(path)
		if err != nil {
			return fmt.Errorf("dsh.RestoreEntry[skills/]: %w", err)
		}
		dst := filepath.Join(skillsDir(), slug)
		// Clean any prior content so deletions inside the tarball are honoured
		// (UnpackDir overwrites files but does not remove stale ones).
		if err := os.RemoveAll(dst); err != nil {
			return fmt.Errorf("dsh.RestoreEntry[skills/]: clean %s: %w", dst, err)
		}
		return manifest.UnpackDir(plaintext, dst)
	}
	slug, err := skillFileSlug(path)
	if err != nil {
		return fmt.Errorf("dsh.RestoreEntry[skills/]: %w", err)
	}
	if err := ensureDir(skillsDir()); err != nil {
		return fmt.Errorf("dsh.RestoreEntry[skills/]: %w", err)
	}
	if err := os.WriteFile(filepath.Join(skillsDir(), slug), plaintext, 0o644); err != nil {
		return fmt.Errorf("dsh.RestoreEntry[skills/]: write %s: %w", slug, err)
	}
	return nil
}

// skillDirSlug validates a manifest dir-entry path: trailing slash, single
// path segment.
func skillDirSlug(path string) (string, error) {
	if !strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("only dir entries supported here (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') || slug == "." || slug == ".." {
		return "", fmt.Errorf("invalid slug %q", path)
	}
	return slug, nil
}

// skillFileSlug validates a manifest file-entry path: single `<name>.md`
// segment, no traversal.
func skillFileSlug(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '/') || !strings.HasSuffix(path, ".md") {
		return "", fmt.Errorf("invalid flat skill path %q (want a single <name>.md segment)", path)
	}
	return path, nil
}
