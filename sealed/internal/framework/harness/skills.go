package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
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
// flat `.md` files tracked as file entries. The tree is agent-writable, so
// it is read through internal/privsep: links and special files are never
// tracked, and an entry the read rules refuse is skipped with a log line.
// An entry over its size limit is held instead (manifest.Held, through
// manifest.FileEntryOf / DirEntryOf): its committed version stays while the
// other skills keep committing. Entry names go through manifest.Carries,
// so what is emitted is what Unmarshal keeps.
func (a *Adapter) evoSkills() ([]byte, error) {
	m := manifest.New()

	entries, err := privsep.ReadDir(skillsDir())
	if errors.Is(err, fs.ErrNotExist) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("harness evoSkills: read %s: %w", skillsDir(), err)
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
		if !manifest.Carries(skillsDir(), name) {
			continue
		}
		if e.IsDir() {
			items = append(items, item{name, true})
			continue
		}
		if e.IsRegular() && strings.HasSuffix(name, ".md") {
			items = append(items, item{name, false})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })

	for _, it := range items {
		full := filepath.Join(skillsDir(), it.name)
		var (
			entry manifest.Entry
			ok    bool
		)
		if it.isDir {
			entry, ok, err = manifest.DirEntryOf(full, it.name)
		} else {
			entry, ok, err = manifest.FileEntryOf(full, it.name, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("harness evoSkills: %w", err)
		}
		if ok {
			m.Entries = append(m.Entries, entry)
		}
	}
	return m.Marshal()
}

func (a *Adapter) loadEntrySkills(path string) ([]byte, error) {
	if strings.HasSuffix(path, "/") {
		slug, err := skillDirSlug(path)
		if err != nil {
			return nil, fmt.Errorf("harness.LoadEntry[skills/]: %w", err)
		}
		return manifest.PackDir(filepath.Join(skillsDir(), slug))
	}
	slug, err := skillFileSlug(path)
	if err != nil {
		return nil, fmt.Errorf("harness.LoadEntry[skills/]: %w", err)
	}
	return privsep.ReadFile(filepath.Join(skillsDir(), slug), privsep.LimitTracked)
}

func (a *Adapter) restoreEntrySkills(path string, plaintext []byte) error {
	if strings.HasSuffix(path, "/") {
		slug, err := skillDirSlug(path)
		if err != nil {
			return fmt.Errorf("harness.RestoreEntry[skills/]: %w", err)
		}
		if err := ensureRoleDir(skillsDir()); err != nil {
			return fmt.Errorf("harness.RestoreEntry[skills/]: %w", err)
		}
		dst := filepath.Join(skillsDir(), slug)
		// Clean any prior content so deletions inside the tarball are honoured
		// (UnpackDir overwrites files but does not remove stale ones).
		if err := privsep.RemoveAll(dst); err != nil {
			return fmt.Errorf("harness.RestoreEntry[skills/]: clean %s: %w", dst, err)
		}
		return manifest.UnpackDir(plaintext, dst)
	}
	slug, err := skillFileSlug(path)
	if err != nil {
		return fmt.Errorf("harness.RestoreEntry[skills/]: %w", err)
	}
	if err := ensureRoleDir(skillsDir()); err != nil {
		return fmt.Errorf("harness.RestoreEntry[skills/]: %w", err)
	}
	if err := privsep.WriteFile(filepath.Join(skillsDir(), slug), plaintext, 0o644); err != nil {
		return fmt.Errorf("harness.RestoreEntry[skills/]: write %s: %w", slug, err)
	}
	return nil
}

// skillDirSlug validates a manifest dir-entry path: trailing slash, single
// path segment.
func skillDirSlug(path string) (string, error) {
	if !strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("only dir entries supported here (got %q)", path)
	}
	if err := manifest.ValidEntryPath(path); err != nil {
		return "", fmt.Errorf("invalid slug %q: %w", path, err)
	}
	return strings.TrimSuffix(path, "/"), nil
}

// skillFileSlug validates a manifest file-entry path: single `<name>.md`
// segment, no traversal.
func skillFileSlug(path string) (string, error) {
	if manifest.ValidEntryPath(path) != nil || strings.HasSuffix(path, "/") || !strings.HasSuffix(path, ".md") {
		return "", fmt.Errorf("invalid flat skill path %q (want a single <name>.md segment)", path)
	}
	return path, nil
}
