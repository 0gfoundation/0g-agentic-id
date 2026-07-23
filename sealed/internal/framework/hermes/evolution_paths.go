package hermes

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/manifest"
)

// EvolutionFor per-role canonical plaintext builders (read path).
// Counterpart to restore_paths.go.

// ── role="config.yaml" ──────────────────────────────────────────────────────

// evoConfigYAML reads ~/.hermes/config.yaml, keeps only ownedHermesKeys,
// strips secrets, and returns canonical JSON (encoding/json marshals maps
// with sorted keys — deterministic).
func (a *Adapter) evoConfigYAML() ([]byte, error) {
	cfg, err := loadConfigYAML()
	if err != nil {
		return nil, fmt.Errorf("hermes evoConfigYAML: %w", err)
	}
	out := make(map[string]any, len(ownedHermesKeys))
	for _, k := range ownedHermesKeys {
		if v, ok := cfg[k]; ok {
			out[k] = v
		}
	}
	stripSecrets(out)
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("hermes evoConfigYAML: marshal: %w", err)
	}
	return b, nil
}

// ── role="SOUL.md" ──────────────────────────────────────────────────────────

// evoSoulMD returns the identity file's bytes verbatim. Missing file →
// nil, matching Defaults("SOUL.md") so an absent identity produces no
// chain entry.
func (a *Adapter) evoSoulMD() ([]byte, error) {
	content, err := os.ReadFile(soulMDPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoSoulMD: read %s: %w", soulMDPath(), err)
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

	entries, err := os.ReadDir(memoriesDir())
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoMemories: read %s: %w", memoriesDir(), err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		full := filepath.Join(memoriesDir(), e.Name())
		content, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("hermes evoMemories: read %s: %w", full, err)
		}
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
	entries, err := os.ReadDir(skillsDir())
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("hermes evoSkills: read %s: %w", skillsDir(), err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || bundled[e.Name()] {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		sub := filepath.Join(skillsDir(), name)
		tarBytes, err := manifest.PackDir(sub)
		if err != nil {
			return nil, fmt.Errorf("hermes evoSkills: pack %s: %w", sub, err)
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

// bundledSkillSlugs parses skills/.bundled_manifest ("slug:hash" per
// line, hash optional for forward-compat) into a slug set. A missing
// manifest means nothing is excluded — on a container where hermes
// hasn't initialised yet, there are no bundled skills on disk either,
// so the fallback is exact, not lossy.
func bundledSkillSlugs() (map[string]bool, error) {
	f, err := os.Open(bundledManifestPath())
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", bundledManifestPath(), err)
	}
	defer f.Close()

	slugs := map[string]bool{}
	sc := bufio.NewScanner(f)
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
