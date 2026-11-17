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

// role="memory/" — the agent's long-term memory under $DSH_HOME/memory/: one
// Markdown file per memory and the MEMORY.md index, which the harness keeps
// in the model's context every turn (0g-harness src/memory.mjs). The role
// tracks the flat *.md files directly in the directory, one manifest entry
// each, the same shape as hermes's memories/. A subdirectory, a dotfile, a
// link or an empty file is not a memory and is not tracked.

// evoMemory builds a Manifest whose entries are the non-empty top-level *.md
// files of $DSH_HOME/memory/. The tree is agent-writable, so it is read
// through internal/privsep; an entry over its size limit is held (its
// committed version stays while the other memories keep committing).
func (a *Adapter) evoMemory() ([]byte, error) {
	m := manifest.New()

	entries, err := privsep.ReadDir(memoryDir())
	if errors.Is(err, fs.ErrNotExist) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("harness evoMemory: read %s: %w", memoryDir(), err)
	}

	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !e.IsRegular() || !strings.HasSuffix(name, ".md") || !manifest.Carries(memoryDir(), name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry, ok, err := manifest.FileEntryOf(filepath.Join(memoryDir(), name), name, nil)
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

func (a *Adapter) loadEntryMemory(path string) ([]byte, error) {
	name, err := memoryFileName(path)
	if err != nil {
		return nil, fmt.Errorf("harness.LoadEntry[memory/]: %w", err)
	}
	return privsep.ReadFile(filepath.Join(memoryDir(), name), privsep.LimitTracked)
}

func (a *Adapter) restoreEntryMemory(path string, plaintext []byte) error {
	name, err := memoryFileName(path)
	if err != nil {
		return fmt.Errorf("harness.RestoreEntry[memory/]: %w", err)
	}
	if err := ensureRoleDir(memoryDir()); err != nil {
		return fmt.Errorf("harness.RestoreEntry[memory/]: %w", err)
	}
	if err := privsep.WriteFile(filepath.Join(memoryDir(), name), plaintext, 0o644); err != nil {
		return fmt.Errorf("harness.RestoreEntry[memory/]: write %s: %w", name, err)
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
