package claudecode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
	"seal-verify/internal/platform"
)

// EvolutionFor produces canonical iData plaintext for `role` by reading
// live disk state, so the watcher observes agent self-modification
// (a settings edit, a new skill, a CLAUDE.md memory write). Output is
// deterministic: stable JSON marshalling, path-sorted manifests,
// determinism-tar for dir entries, empty StoragePtrs throughout.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		return a.evoFramework(ctx)
	case "settings.json":
		return a.evoSettingsJSON()
	case "workspace/":
		return evoFilesManifest(workspaceDir(), "workspace/", true)
	case "agents/":
		return evoFilesManifest(agentsDir(), "agents/", false)
	case "skills/":
		return evoSubdirManifest(skillsDir(), "skills/")
	}
	return nil, framework.ErrUnsupportedDim
}

// evoFramework returns the binding with the live-probed installed version
// layered on top, so an in-container `npm install -g` of a different
// claude-code shows up as drift on this role. Probe failure (binary not
// installed yet, e.g. pre-Start seeding) keeps the restored value.
func (a *Adapter) evoFramework(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	fb := frameworkBinding{
		Name:           "claude-code",
		PackageVersion: whitelistMax(),
		SchemaVersion:  1,
	}
	if a.binding != nil {
		fb = *a.binding
	}
	a.mu.RUnlock()
	if v := probeVersion(ctx); v != "" {
		fb.PackageVersion = v
	}
	return json.Marshal(&fb)
}

// ownedSettingsKeys lists the top-level settings.json keys sealed treats
// as agent identity — the only keys that belong on chain.
//
//   - model:       which Claude model the agent runs; core identity
//   - permissions: the allow/deny/ask rule set; defines what the agent
//     may do, i.e. behavioural identity
//   - outputStyle: response persona configuration
//   - env:         SUB-ALLOWLISTED (see ownedEnvKeys) — inference routing
//     is identity, credentials are not
//
// Deliberately excluded:
//
//   - apiKeyHelper / awsAuthRefresh: carry credentials or machine-local
//     paths; secrets must never reach chain plaintext
//   - hooks: behaviour-defining in principle, but hook commands embed
//     local paths and often credentials; excluded from v1, revisit with a
//     sanitising encoder
//   - feedbackSurveyState and other runtime bookkeeping Claude Code
//     writes for itself: per-boot noise, the phantom-drift generator an
//     allowlist exists to keep out
var ownedSettingsKeys = []string{"env", "model", "outputStyle", "permissions"}

// ownedEnvKeys is the sub-allowlist inside settings.json's env block.
// ANTHROPIC_BASE_URL is WHERE the agent's inference traffic goes —
// identity-relevant and auditable (a 0g-compute-routed agent proves it on
// chain; a hijacked base URL would be visible). Everything else in env is
// presumed credential-bearing (ANTHROPIC_API_KEY, AUTH_TOKEN, …) and
// stays local.
var ownedEnvKeys = []string{"ANTHROPIC_BASE_URL"}

// evoSettingsJSON reads ~/.claude/settings.json, keeps only the owned
// keys (env filtered to its sub-allowlist), and returns canonical bytes
// (json.Marshal sorts map keys).
func (a *Adapter) evoSettingsJSON() ([]byte, error) {
	data, err := os.ReadFile(settingsJSONPath())
	if os.IsNotExist(err) {
		return []byte("{}"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("claude-code evoSettingsJSON: read %s: %w", settingsJSONPath(), err)
	}
	cfg := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("claude-code evoSettingsJSON: parse %s: %w", settingsJSONPath(), err)
		}
	}
	out := make(map[string]any, len(ownedSettingsKeys))
	for _, k := range ownedSettingsKeys {
		v, ok := cfg[k]
		if !ok {
			continue
		}
		if k == "env" {
			env, _ := v.(map[string]any)
			kept := make(map[string]any, len(ownedEnvKeys))
			for _, ek := range ownedEnvKeys {
				if ev, ok := env[ek]; ok {
					kept[ek] = ev
				}
			}
			if len(kept) == 0 {
				continue // no owned env keys → omit the block entirely
			}
			out[k] = kept
			continue
		}
		out[k] = v
	}
	return json.Marshal(out)
}

// evoFilesManifest builds a Manifest of the root-level *.md files under
// rootDir (Kind=file each). stripMD runs platform.StripInjected on every
// .md before hashing so the CLAUDE.md injection stays off chain. Empty
// (post-strip) files are not tracked — keeps the manifest stable across
// touch-only writes.
func evoFilesManifest(rootDir, label string, stripMD bool) ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(rootDir)
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("claude-code evo[%s]: read %s: %w", label, rootDir, err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		full := filepath.Join(rootDir, e.Name())
		content, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("claude-code evo[%s]: read %s: %w", label, full, err)
		}
		if stripMD {
			content = platform.StripInjected(content)
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

// evoSubdirManifest builds a Manifest where each top-level subdirectory
// of rootDir becomes a Kind=dir entry hashed via deterministic tar.gz.
func evoSubdirManifest(rootDir, label string) ([]byte, error) {
	m := manifest.New()

	entries, err := os.ReadDir(rootDir)
	if os.IsNotExist(err) {
		return m.Marshal()
	}
	if err != nil {
		return nil, fmt.Errorf("claude-code evo[%s]: read %s: %w", label, rootDir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		tarBytes, err := manifest.PackDir(filepath.Join(rootDir, name))
		if err != nil {
			return nil, fmt.Errorf("claude-code evo[%s]: pack %s: %w", label, name, err)
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
