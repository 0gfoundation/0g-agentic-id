package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
)

// watchdogAccepted records, for every whitelisted openclaw version, whether
// its config schema has diagnostics.stuckSessionAbortMs (checked against
// `openclaw config validate` of that version: 2026.5.6 and 2026.5.7 answer
// `diagnostics: Unrecognized key: "stuckSessionAbortMs"`). A newly
// whitelisted version needs a row, checked the same way.
var watchdogAccepted = map[string]bool{
	"2026.5.6": false,
	"2026.5.7": false,
	"2026.7.1": true,
}

func watchdogOf(t *testing.T) (any, bool) {
	t.Helper()
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	d, _ := cfg["diagnostics"].(map[string]any)
	v, ok := d["stuckSessionAbortMs"]
	return v, ok
}

// The render writes the stuck-session watchdog only for a version whose
// schema has it, and takes it out again for one whose schema does not: an
// openclaw that rejects the key rejects the platform half of the config,
// and no Start succeeds.
func TestRenderWatchdogOnlyForVersionsThatAcceptIt(t *testing.T) {
	for _, v := range supportedOpenclawVersions {
		accepted, known := watchdogAccepted[v]
		if !known {
			t.Errorf("whitelisted openclaw %s has no watchdogAccepted row: check whether its schema has diagnostics.stuckSessionAbortMs", v)
			continue
		}
		t.Run(v, func(t *testing.T) {
			useTempHome(t)
			// What an earlier render (or an owner overlay) left, beside a
			// diagnostics key that is not the platform's.
			writeJSONConfig(t, map[string]any{"diagnostics": map[string]any{"stuckSessionAbortMs": 900000, "otel": map[string]any{"enabled": false}}})
			a := New()
			if err := a.Restore(context.Background(), "framework", []byte(`{"name":"openclaw","package_version":"`+v+`","schema_version":1}`)); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
					t.Fatal(err)
				}
				got, ok := watchdogOf(t)
				switch {
				case accepted && (!ok || got != float64(stuckSessionAbortMs)):
					t.Fatalf("openclaw %s accepts the watchdog, rendered %v", v, got)
				case !accepted && ok:
					t.Fatalf("openclaw %s rejects diagnostics.stuckSessionAbortMs, rendered %v", v, got)
				}
				cfg, _ := loadOpenclawJSON()
				if d, _ := cfg["diagnostics"].(map[string]any); d["otel"] == nil {
					t.Fatalf("the render dropped a diagnostics key it does not own: %v", cfg["diagnostics"])
				}
			}
		})
	}
	// With nothing else in diagnostics, removing the key removes the
	// section rather than leaving it empty.
	useTempHome(t)
	writeJSONConfig(t, map[string]any{"diagnostics": map[string]any{"stuckSessionAbortMs": 900000}})
	a := New()
	if err := a.Restore(context.Background(), "framework", []byte(`{"name":"openclaw","package_version":"2026.5.6","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := loadOpenclawJSON(); cfg["diagnostics"] != nil {
		t.Fatalf("diagnostics = %v, want the section gone", cfg["diagnostics"])
	}
}

// After the first Start nothing is installed again, so a restart renders
// for the version on disk, not the pin it was started from.
func TestRenderWatchdogFollowsTheInstalledVersionAfterStart(t *testing.T) {
	useTempHome(t)
	installed := "2026.5.7"
	prev := probeOpenclawVersion
	probeOpenclawVersion = func(context.Context) string { return installed }
	t.Cleanup(func() { probeOpenclawVersion = prev })
	a := New()
	if err := a.Restore(context.Background(), "framework", []byte(`{"name":"openclaw","package_version":"2026.7.1","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, ok := watchdogOf(t); !ok {
		t.Fatal("before the first Start the render is for the pinned 2026.7.1, which takes the watchdog")
	}
	a.mu.Lock()
	a.initialized = true
	a.mu.Unlock()
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if v, ok := watchdogOf(t); ok {
		t.Fatalf("restart on an installed %s rendered the watchdog %v", installed, v)
	}
	installed = "2026.7.1"
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, ok := watchdogOf(t); !ok {
		t.Fatal("restart after a reconcile to 2026.7.1 did not render the watchdog")
	}
}

func memoryWikiEntry(t *testing.T) (map[string]any, bool) {
	t.Helper()
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	entries, _ := plugins["entries"].(map[string]any)
	e, ok := entries["memory-wiki"].(map[string]any)
	return e, ok
}

func vaultPathOf(e map[string]any) any {
	c, _ := e["config"].(map[string]any)
	v, _ := c["vault"].(map[string]any)
	return v["path"]
}

// memory-wiki takes its default vault from os.homedir() (HOME, the agent's
// home), which on 2026.7.1 leads through the ~/.openclaw link into a
// symlink-refusing append. The render gives an enabled plugin with no vault
// path the absolute default inside the tree, keeps a path that is set, and
// neither enables the plugin nor creates its entry.
func TestRenderFillsTheMemoryWikiVault(t *testing.T) {
	useTempHome(t)
	a := New()
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	render := func(overlay string) {
		t.Helper()
		s.Others = json.RawMessage(overlay)
		if err := a.RenderSettings(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	want := filepath.Join(openclawHome, "wiki", "main")

	render(``)
	if e, ok := memoryWikiEntry(t); ok {
		t.Fatalf("the render created a memory-wiki entry: %v", e)
	}

	render(`{"plugins":{"entries":{"memory-wiki":{"enabled":true,"config":{"vaultMode":"isolated"}}}}}`)
	e, _ := memoryWikiEntry(t)
	if got := vaultPathOf(e); got != want {
		t.Fatalf("enabled memory-wiki without a vault path: path = %v, want %s", got, want)
	}
	if c, _ := e["config"].(map[string]any); c["vaultMode"] != "isolated" {
		t.Fatalf("the render dropped the plugin's own config: %v", e)
	}

	render(`{"plugins":{"entries":{"memory-wiki":{"enabled":true,"config":{"vault":{"path":"~/.openclaw/notes"}}}}}}`)
	e, _ = memoryWikiEntry(t)
	if got := vaultPathOf(e); got != "~/.openclaw/notes" {
		t.Fatalf("a set vault path was replaced: %v", got)
	}

	// The owner withdraws the plugin: the default goes with it, and the
	// entry is not left behind holding only the platform's value.
	render(`{"plugins":{"entries":{"memory-wiki":{"enabled":true}}}}`)
	if e, _ := memoryWikiEntry(t); vaultPathOf(e) != want {
		t.Fatalf("path = %v, want the default", vaultPathOf(e))
	}
	render(``)
	if e, ok := memoryWikiEntry(t); ok {
		t.Fatalf("withdrawn memory-wiki left %v behind", e)
	}

	// A disabled entry is left as it is.
	render(`{"plugins":{"entries":{"memory-wiki":{"enabled":false}}}}`)
	if e, _ := memoryWikiEntry(t); vaultPathOf(e) != nil {
		t.Fatalf("disabled memory-wiki was given a vault: %v", e)
	}
}

// logLinesSince returns the log lines added after n.
func logLinesSince(n int) []string { return logger.Lines()[n:] }

// A "~/x" or "/root/x" path the agent put in openclaw.json itself is kept,
// and logged once, naming where ReclaimHome put what such a path held.
func TestRenderLogsRootHomePathsTheAgentKeeps(t *testing.T) {
	useTempHome(t)
	rootHome := filepath.Dir(openclawHome)
	writeJSONConfig(t, map[string]any{"agents": map[string]any{"list": []any{
		map[string]any{"id": "main", "default": true},
		map[string]any{"id": "helper", "workspace": rootHome + "/helper"},
		map[string]any{"id": "notes", "workspace": "~/notes"},
		map[string]any{"id": "tree", "workspace": openclawHome + "/workspace-tree"},
	}}})
	a := New()
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	n := len(logger.Lines())
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadOpenclawJSON()
	list, _ := cfg["agents"].(map[string]any)["list"].([]any)
	if ws := list[1].(map[string]any)["workspace"]; ws != rootHome+"/helper" {
		t.Fatalf("the agent's own workspace was rewritten to %v", ws)
	}
	var line string
	for _, l := range logLinesSince(n) {
		if strings.Contains(l, "openclaw.json values openclaw resolves in root's home") {
			line = l
		}
	}
	home := privsep.AgentHome()
	for _, want := range []string{
		fmt.Sprintf("%q", rootHome+"/helper"), fmt.Sprintf("%q", filepath.Join(home, "helper")),
		`"~/notes"`, fmt.Sprintf("%q", filepath.Join(home, "notes")),
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q does not name %s", line, want)
		}
	}
	if strings.Contains(line, "workspace-tree") {
		t.Errorf("a path inside the tree was reported: %q", line)
	}
	n = len(logger.Lines())
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, l := range logLinesSince(n) {
		if strings.Contains(l, "openclaw.json values openclaw resolves in root's home") {
			t.Fatalf("the same values were reported again: %q", l)
		}
	}
}

// The values logRootHomePaths reports are the agent's and as large as
// openclaw.json may be; what a render keeps in the log for them is bounded
// however large they are.
func TestRootHomePathLogIsBounded(t *testing.T) {
	useTempHome(t)
	big := "~/" + strings.Repeat("a", 6<<20)
	long := strings.Repeat("k", 1<<20) // a JSON path is the agent's too
	writeJSONConfig(t, map[string]any{"logging": map[string]any{"file": big}, long: "~/x"})
	if fi, err := os.Stat(openclawJSONPath()); err != nil || fi.Size() <= privsep.LimitConfig/2 {
		t.Fatalf("test config is %v bytes (%v); want one close to the limit", fi.Size(), err)
	}
	a := New()
	n := len(logger.Lines())
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatal(err)
	}
	total := 0
	reported := false
	for _, l := range logLinesSince(n) {
		total += len(l)
		reported = reported || strings.Contains(l, "logging.file")
	}
	if !reported {
		t.Fatal("the value was not reported at all")
	}
	if total > 8<<10 {
		t.Fatalf("a render over a %d-byte value logged %d bytes", len(big), total)
	}
}

// The agent doc's notes on how openclaw resolves paths are rendered as
// notes, not as untracked paths, and say what the agent needs: `~` for the
// media tools, where the gateway reads environment files from, and what to
// do about the plugins that reach the tree through the ~/.openclaw link.
func TestFrameworkNotesSayHowPathsResolve(t *testing.T) {
	facts := New().FrameworkFacts()
	for _, u := range facts.Untracked {
		if u.Path == "" && (strings.Contains(u.Note, "media tools") || strings.Contains(u.Note, "gateway.env")) {
			t.Errorf("a path rule is listed as an untracked path: %q", u.Note)
		}
	}
	notes := strings.Join(facts.Notes, "\n")
	for _, want := range []string{"media tools", "~/.openclaw/.env", "gateway.env", "memory-wiki", "plugins.entries.memory-wiki.config.vault.path", "/root/.openclaw/wiki/main"} {
		if !strings.Contains(notes, want) {
			t.Errorf("FrameworkFacts().Notes say nothing of %q: %q", want, notes)
		}
	}
	if !strings.Contains(platform.RenderFrameworkFacts(facts), "**Framework notes:**") {
		t.Error("the notes are not rendered under their own heading")
	}
}

// homedirPluginDefaults records, per whitelisted openclaw version, the
// bundled plugins whose default locations come from os.homedir() — HOME,
// the agent's home — rather than OPENCLAW_HOME or OPENCLAW_STATE_DIR, and
// so reach the tree through the ~/.openclaw link (found by searching the
// version's dist for os.homedir() joined with ".openclaw"; QUIRKS.md). A
// newly whitelisted version needs a row, checked the same way, and a
// plugin there whose write refuses the link needs handling like
// memory-wiki's (applyMemoryWikiVault) or a QUIRKS.md entry.
var homedirPluginDefaults = map[string][]string{
	"2026.5.6": {"memory-wiki", "file-transfer"},
	"2026.5.7": {"memory-wiki", "file-transfer"},
	"2026.7.1": {"memory-wiki", "file-transfer", "memory-lancedb", "voice-call"},
}

func TestEveryWhitelistedVersionHasItsHomedirPluginsRecorded(t *testing.T) {
	for _, v := range supportedOpenclawVersions {
		plugins, ok := homedirPluginDefaults[v]
		if !ok {
			t.Errorf("whitelisted openclaw %s has no homedirPluginDefaults row: check its bundled plugins for default locations taken from os.homedir()", v)
			continue
		}
		for _, p := range plugins {
			if p == "memory-wiki" {
				useTempHome(t)
				cfg := map[string]any{"plugins": map[string]any{"entries": map[string]any{"memory-wiki": map[string]any{"enabled": true}}}}
				applyMemoryWikiVault(cfg)
				if e, _ := cfg["plugins"].(map[string]any)["entries"].(map[string]any)["memory-wiki"].(map[string]any); vaultPathOf(e) != memoryWikiVaultDefault() {
					t.Errorf("openclaw %s: an enabled memory-wiki is not given a vault in the tree: %v", v, e)
				}
			}
		}
	}
}
