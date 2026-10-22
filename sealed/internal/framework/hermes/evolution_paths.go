package hermes

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
)

// EvolutionFor per-role canonical plaintext builders (read path).
// Counterpart to restore_paths.go.
//
// The hermes home is agent-writable, so every read goes through
// internal/privsep: links are never followed, only regular files are read,
// and an entry the read rules refuse (a link, a special file, a foreign
// hard link) is skipped, or for a leaf role counts as absent, with one log
// line per path. Content over its size limit is the agent's data, not
// something to skip: a manifest entry is held (manifest.Held, through
// manifest.FileEntryOf / DirEntryOf) and keeps its committed version while
// the role's other entries keep committing; a leaf role, which is one
// entry, fails with privsep.ErrTooLarge and keeps its committed version.
// Every entry name goes through manifest.Carries, so what is emitted is
// what manifest.Unmarshal keeps.

// ── role="SOUL.md" ──────────────────────────────────────────────────────────

// evoSoulMD returns the identity file's bytes verbatim. Missing file (or
// one the read rules refuse, which is the agent removing it) → nil,
// matching Defaults("SOUL.md") so an absent identity produces no chain
// entry. A file over its size limit is an error: the committed persona
// stays rather than being deleted.
func (a *Adapter) evoSoulMD() ([]byte, error) {
	content, err := privsep.ReadFile(soulMDPath(), privsep.LimitTracked)
	if errors.Is(err, fs.ErrNotExist) || privsep.Refused(soulMDPath(), err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoSoulMD: read %s: %w", soulMDPath(), err)
	}
	// Strip the sealed platform-injection marker section (Start injects it
	// into SOUL.md every boot via upsertSoulMD). Only the owner persona
	// belongs on chain; the platform text carries per-boot content
	// (BootTime) that would phantom-drift otherwise. No-op on files without
	// the marker.
	content = platform.StripInjected(content)
	if len(content) == 0 {
		return nil, nil
	}
	return content, nil
}

// ── role="memories/" ────────────────────────────────────────────────────────

// evoMemories builds a Manifest whose entries are the top-level *.md files
// in ~/.hermes/memories/ (each a Kind=file entry). Empty files are not
// tracked ("no content = no entry" keeps the manifest stable if hermes
// ever touches placeholders).
func (a *Adapter) evoMemories() ([]byte, error) {
	m := manifest.New()

	entries, err := privsep.ReadDir(memoriesDir())
	if errors.Is(err, fs.ErrNotExist) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoMemories: read %s: %w", memoriesDir(), err)
	}

	for _, e := range entries {
		if !e.IsRegular() || !strings.HasSuffix(e.Name(), ".md") || !manifest.Carries(memoriesDir(), e.Name()) {
			continue
		}
		entry, ok, err := manifest.FileEntryOf(filepath.Join(memoriesDir(), e.Name()), e.Name(), nil)
		if err != nil {
			return nil, fmt.Errorf("hermes evoMemories: %w", err)
		}
		if !ok || (!entry.IsHeld() && entry.Size == 0) {
			continue
		}
		m.Entries = append(m.Entries, entry)
	}
	return m.Marshal()
}

// ── role="skills/" ──────────────────────────────────────────────────────────

// evoSkills builds a Manifest whose entries are the top-level
// subdirectories of ~/.hermes/skills/ EXCLUDING install-bundled skills.
//
// Bundled skills ship with the framework (re-seeded by hermes's first-run
// init on every fresh container) and are fully determined by the pinned
// package_version — putting ~8.6MB of stock content on chain per agent
// would be pure bloat. hermes records what it seeded in
// skills/.bundled_manifest ("slug:hash" per line); anything listed there
// is excluded, anything else (agent-created or third-party-installed) is
// tracked.
//
// v1 limitation (deliberate): an agent-MODIFIED bundled skill stays
// untracked — exclusion is by slug, not by content comparison. Revisit if
// the manifest's per-slug hash proves reproducible on our side.
func (a *Adapter) evoSkills() ([]byte, error) {
	bundled, err := bundledSkillSlugs()
	if err != nil {
		return nil, fmt.Errorf("hermes evoSkills: %w", err)
	}

	m := manifest.New()
	entries, err := privsep.ReadDir(skillsDir())
	if errors.Is(err, fs.ErrNotExist) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoSkills: read %s: %w", skillsDir(), err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || bundled[e.Name()] || !manifest.Carries(skillsDir(), e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		entry, ok, err := manifest.DirEntryOf(filepath.Join(skillsDir(), name), name)
		if err != nil {
			return nil, fmt.Errorf("hermes evoSkills: %w", err)
		}
		if ok {
			m.Entries = append(m.Entries, entry)
		}
	}
	return m.Marshal()
}

// bundledSkillSlugs parses skills/.bundled_manifest ("slug:hash" per
// line, hash optional for forward-compat) into a slug set. A missing
// manifest means nothing is excluded — on a container where hermes
// hasn't initialised yet, there are no bundled skills on disk either,
// so the fallback is exact, not lossy. The file is agent-writable and
// only ever used as an exclusion list (data, never a path); one the privsep
// read rules refuse, or one over its size limit, counts as missing.
func bundledSkillSlugs() (map[string]bool, error) {
	raw, err := privsep.ReadFile(bundledManifestPath(), privsep.LimitConfig)
	if errors.Is(err, fs.ErrNotExist) || privsep.Refused(bundledManifestPath(), err) {
		return map[string]bool{}, nil
	}
	if errors.Is(err, privsep.ErrTooLarge) {
		logger.Once("hermes.bundled-too-large", "hermes: %v; excluding no bundled skills", err)
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", bundledManifestPath(), err)
	}

	slugs := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		slug, _, _ := strings.Cut(line, ":")
		if slug = strings.TrimSpace(slug); slug != "" {
			slugs[slug] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", bundledManifestPath(), err)
	}
	return slugs, nil
}
