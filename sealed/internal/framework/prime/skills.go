package prime

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/manifest"
)

// role="skills/" — the agent's installed Python skill packages.
//
// Prime Agent has two distinct notions of "skill" and only one of them lives
// here:
//
//   - FILESYSTEM skills: a directory under ~/.prime/agent/skills/<name>/ laid
//     out as a Python package (pyproject.toml + src/<import>/__init__.py).
//     packages/coding-agent/src/core/skills.ts scans exactly this directory
//     (source "user") plus <cwd>/.prime/agent/skills (source "project").
//     These are what this role tracks: one tar.gz manifest entry per
//     top-level subdirectory.
//   - HARNESS skill entries: records inside harness_state.json holding a
//     Python import reference plus a call contract. Those ride the
//     harness_state.json role, not this one — an agent that writes a new
//     skill package AND registers it produces drift in both roles, which is
//     correct: the code and its registration are separate facts.
//
// Unlike the hermes adapter there is no bundled-skill exclusion list: Prime
// Agent's stock skills (refine, edit, compact, websearch, …) ship inside the
// installed package and are loaded from the install tree, not copied into the
// agent dir, so ~/.prime/agent/skills/ should contain agent-installed content
// only. VERIFY THIS ON THE FIRST LIVE BOOT: if the framework does seed stock
// skills here, they must be excluded the way hermes excludes
// skills/.bundled_manifest, or every agent puts a copy of the stock library on
// chain.

// evoSkills builds a Manifest whose entries are the top-level subdirectories
// of ~/.prime/agent/skills/, each packed as one deterministic tar.gz.
func (a *Adapter) evoSkills() ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(skillsDir())
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("prime evoSkills: read %s: %w", skillsDir(), err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		sub := filepath.Join(skillsDir(), name)
		tarBytes, err := manifest.PackDir(sub)
		if err != nil {
			return nil, fmt.Errorf("prime evoSkills: pack %s: %w", sub, err)
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

func (a *Adapter) loadEntrySkills(path string) ([]byte, error) {
	slug, err := skillSlug(path)
	if err != nil {
		return nil, fmt.Errorf("prime.LoadEntry[skills/]: %w", err)
	}
	return manifest.PackDir(filepath.Join(skillsDir(), slug))
}

func (a *Adapter) restoreEntrySkills(path string, plaintext []byte) error {
	slug, err := skillSlug(path)
	if err != nil {
		return fmt.Errorf("prime.RestoreEntry[skills/]: %w", err)
	}
	dst := filepath.Join(skillsDir(), slug)
	// Clean any prior content so deletions inside the tarball are honoured
	// (UnpackDir overwrites files but does not remove stale ones).
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("prime.RestoreEntry[skills/]: clean %s: %w", dst, err)
	}
	return manifest.UnpackDir(plaintext, dst)
}

// skillSlug validates a manifest entry path for the skills/ role: dir entries
// only (trailing slash), single path segment.
func skillSlug(path string) (string, error) {
	if !strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("only dir entries supported (got %q)", path)
	}
	slug := strings.TrimSuffix(path, "/")
	if slug == "" || strings.ContainsRune(slug, '/') || slug == "." || slug == ".." {
		return "", fmt.Errorf("invalid slug %q", path)
	}
	return slug, nil
}
