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

// role="memory/" and role="memory-public/" — the agent's long-term memory,
// two visibility levels (0g-harness src/memory.mjs):
//   - memory/ under $DSH_HOME/memory/: private, used only in the owner's own
//     sessions and tasks;
//   - memory-public/ under $DSH_HOME/memory-public/: public, which may also be
//     used outside the owner's sessions (a hosted program's agent_data mounts
//     this role alone, so its chain hash names exactly what was shared).
// Each is one Markdown file per memory plus its MEMORY.md index. A role
// tracks the flat *.md files directly in its directory, one manifest entry
// each, the same shape as hermes's memories/. A subdirectory, a dotfile, a
// link or an empty file is not a memory and is not tracked. Trust (whether an
// item may guide actions) is per item, inside the file (`trusted_by`), and is
// the harness's business, not the role's.

// memoryRoleDir is the directory of a memory role.
func memoryRoleDir(role string) string {
	if role == "memory-public/" {
		return publicMemoryDir()
	}
	return memoryDir()
}

// evoMemory builds a Manifest whose entries are the non-empty top-level *.md
// files of the role's directory. The tree is agent-writable, so it is read
// through internal/privsep; an entry over its size limit is held (its
// committed version stays while the other memories keep committing).
func (a *Adapter) evoMemory(role string) ([]byte, error) {
	dir := memoryRoleDir(role)
	m := manifest.New()

	entries, err := privsep.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("harness evoMemory: read %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !e.IsRegular() || !strings.HasSuffix(name, ".md") || !manifest.Carries(dir, name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry, ok, err := manifest.FileEntryOf(filepath.Join(dir, name), name, nil)
		if err != nil {
			return nil, fmt.Errorf("harness evoMemory: %w", err)
		}
		if !ok || (!entry.IsHeld() && entry.Size == 0) {
			continue
		}
		m.Entries = append(m.Entries, entry)
	}
	return m.Marshal()
}

func (a *Adapter) loadEntryMemory(role, path string) ([]byte, error) {
	name, err := memoryFileName(path)
	if err != nil {
		return nil, fmt.Errorf("harness.LoadEntry[%s]: %w", role, err)
	}
	return privsep.ReadFile(filepath.Join(memoryRoleDir(role), name), privsep.LimitTracked)
}

func (a *Adapter) restoreEntryMemory(role, path string, plaintext []byte) error {
	name, err := memoryFileName(path)
	if err != nil {
		return fmt.Errorf("harness.RestoreEntry[%s]: %w", role, err)
	}
	dir := memoryRoleDir(role)
	if err := ensureRoleDir(dir); err != nil {
		return fmt.Errorf("harness.RestoreEntry[%s]: %w", role, err)
	}
	if err := privsep.WriteFile(filepath.Join(dir, name), plaintext, 0o644); err != nil {
		return fmt.Errorf("harness.RestoreEntry[%s]: write %s: %w", role, name, err)
	}
	return nil
}

// memoryFileName validates a manifest entry path of the memory/ role: one
// `<name>.md` segment directly in the directory, no traversal, no dotfile.
func memoryFileName(path string) (string, error) {
	if manifest.ValidEntryPath(path) != nil || strings.HasSuffix(path, "/") || !strings.HasSuffix(path, ".md") || strings.HasPrefix(path, ".") {
		return "", fmt.Errorf("invalid memory path %q (want a single <name>.md segment)", path)
	}
	return path, nil
}
