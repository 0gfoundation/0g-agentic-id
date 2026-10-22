package hermes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
)

const initPy = `"""Hermes CLI."""

__version__ = "0.19.0"
__release_date__ = "2026.7.20"
`

func TestStaticVersionProbeParsesReleaseDate(t *testing.T) {
	if got := parseReleaseDate([]byte(initPy)); got != "v2026.7.20" {
		t.Fatalf("parseReleaseDate = %q, want v2026.7.20", got)
	}
	for _, bad := range []string{`__version__ = "0.19.0"`, `__release_date__ = "unknown"`, `x__release_date__ = "2026.7.20"`, ``} {
		if got := parseReleaseDate([]byte(bad)); got != "" {
			t.Errorf("parseReleaseDate(%q) = %q, want empty", bad, got)
		}
	}
	prev := hermesInstallDir
	hermesInstallDir = t.TempDir()
	t.Cleanup(func() { hermesInstallDir = prev })
	if got := probeHermesVersion(context.Background()); got != "" {
		t.Fatalf("probe without a checkout = %q, want empty", got)
	}
	if err := os.MkdirAll(filepath.Join(hermesInstallDir, "hermes_cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hermesInstallDir, "hermes_cli", "__init__.py"), []byte(initPy), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := probeHermesVersion(context.Background()); got != "v2026.7.20" {
		t.Fatalf("probe = %q, want v2026.7.20", got)
	}
}

func TestConversationIDLivesInStateDir(t *testing.T) {
	redirectHome(t)
	id := (&Adapter{}).ConversationHeaders()[sessionIDHeader]
	b, err := os.ReadFile(filepath.Join(framework.StateDir, conversationIDState))
	if err != nil || strings.TrimSpace(string(b)) != id {
		t.Fatalf("id not persisted in StateDir: %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(hermesHome, ".seal-conversation-id")); !os.IsNotExist(err) {
		t.Fatalf("id still written into the agent tree: %v", err)
	}
}

// A link planted at config.yaml is treated as absent: the render rebuilds
// the file as a regular file and never reads or writes the link's target.
func TestRenderDoesNotFollowLinkedConfig(t *testing.T) {
	a := newTestAdapter(t)
	target := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(target, []byte("keep: me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configYAMLPath()); err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(context.Background(), routed("0gm-1.0-35b-a3b", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep: me\n" {
		t.Fatalf("link target changed: %q", b)
	}
	fi, err := os.Lstat(configYAMLPath())
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("config.yaml = %v, %v; want a regular file", fi, err)
	}
	if b, _ := os.ReadFile(configYAMLPath()); strings.Contains(string(b), "keep") {
		t.Fatalf("target content leaked into config.yaml: %s", b)
	}
}

func TestRestoreEntryMemoriesRefusesTraversal(t *testing.T) {
	a := newTestAdapter(t)
	for _, p := range []string{"../../x.md", "../x.md", "sub/x.md", "..", ""} {
		if err := a.RestoreEntry(context.Background(), "memories/", p, []byte("x")); err == nil {
			t.Errorf("RestoreEntry(memories/, %q) succeeded", p)
		}
		if err := a.restoreEntryMemories(p, []byte("x")); err == nil {
			t.Errorf("restoreEntryMemories(%q) succeeded", p)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(hermesHome), "x.md")); err == nil {
		t.Fatal("a traversal entry was written outside the home")
	}
	if err := a.RestoreEntry(context.Background(), "memories/", "MEMORY.md", []byte("ok")); err != nil {
		t.Fatalf("a plain entry was refused: %v", err)
	}
}

// packTree builds a real skill tarball (manifest.PackDir of a temp dir), so
// a restore-side test fails on the path check, not on bad input.
func packTree(t *testing.T) []byte {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The skills/ entry paths are checked by the dispatchers AND by the
// skills helpers themselves, so a call that reaches the helper directly
// cannot name the home itself ("../") or another directory.
func TestSkillEntryPathsStayInTheRole(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	sentinel := filepath.Join(hermesHome, "SOUL.md")
	if err := os.WriteFile(sentinel, []byte("persona\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball := packTree(t)
	for _, p := range []string{"../", "./", "a/b/", "/"} {
		if err := a.RestoreEntry(ctx, "skills/", p, tarball); err == nil {
			t.Errorf("RestoreEntry(skills/, %q) succeeded", p)
		}
		if err := a.restoreEntrySkills(p, tarball); err == nil {
			t.Errorf("restoreEntrySkills(%q) succeeded", p)
		}
		if _, err := a.LoadEntry(ctx, "skills/", p); err == nil {
			t.Errorf("LoadEntry(skills/, %q) succeeded", p)
		}
		if _, err := a.loadEntrySkills(p); err == nil {
			t.Errorf("loadEntrySkills(%q) succeeded", p)
		}
	}
	for _, p := range []string{"../SOUL.md", "../config.yaml", ".."} {
		if _, err := a.LoadEntry(ctx, "memories/", p); err == nil {
			t.Errorf("LoadEntry(memories/, %q) succeeded", p)
		}
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "persona\n" {
		t.Fatalf("the home's SOUL.md did not survive: %q, %v", b, err)
	}
	if err := a.RestoreEntry(ctx, "skills/", "ok/", tarball); err != nil {
		t.Fatalf("a plain skill entry was refused: %v", err)
	}
}

// Links planted at tracked paths are not followed: EvolutionFor still
// succeeds, a linked SOUL.md counts as absent, and linked memories and
// skills are left out. The link targets are untouched.
func TestEvolutionSkipsLinkedEntries(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.md")
	if err := os.WriteFile(secret, []byte("not agent content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{memoriesDir(), skillsDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(memoriesDir(), "MEMORY.md"), []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		soulMDPath():                          secret,
		filepath.Join(memoriesDir(), "x.md"):  secret,
		filepath.Join(skillsDir(), "leakdir"): outside,
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	soul, err := a.EvolutionFor(ctx, "SOUL.md")
	if err != nil || soul != nil {
		t.Fatalf("EvolutionFor(SOUL.md) over a link = %q, %v; want absent", soul, err)
	}
	for role, want := range map[string]string{"memories/": "MEMORY.md", "skills/": ""} {
		b, err := a.EvolutionFor(ctx, role)
		if err != nil {
			t.Fatalf("EvolutionFor(%s): %v", role, err)
		}
		m, err := manifest.Unmarshal(b)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range m.Entries {
			got = append(got, e.Path)
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s entries = %v, want [%s]", role, got, want)
		}
	}
	if b, _ := os.ReadFile(secret); string(b) != "not agent content\n" {
		t.Fatalf("link target changed: %q", b)
	}
}

// A file name with a backslash is an ordinary name: the role still
// produces a manifest Unmarshal keeps whole (it used to block every push).
func TestBackslashNamesAreTracked(t *testing.T) {
	a := newTestAdapter(t)
	if err := os.MkdirAll(memoriesDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	name := `notes\todo.md`
	if err := os.WriteFile(filepath.Join(memoriesDir(), name), []byte("todo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := a.EvolutionFor(context.Background(), "memories/")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Unmarshal(b)
	if err != nil || len(m.Entries) != 1 || m.Entries[0].Path != name {
		t.Fatalf("manifest = %+v, %v; want the one entry %q", m, err, name)
	}
}

// A top-level name that is not valid UTF-8 (a legal Linux name) cannot ride
// a manifest, which is JSON: it is skipped, and the role still marshals to
// a manifest whose every entry the uploader can load back by its path —
// one such name used to block every commit of the role.
func TestNonUTF8NamesDoNotBlockTheRole(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	for _, p := range []string{
		filepath.Join(memoriesDir(), "caf\xe9.md"),
		filepath.Join(memoriesDir(), "MEMORY.md"),
		filepath.Join(skillsDir(), "s\xff", "SKILL.md"),
		filepath.Join(skillsDir(), "ok", "SKILL.md"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for role, want := range map[string]string{"memories/": "MEMORY.md", "skills/": "ok/"} {
		pt, err := a.EvolutionFor(ctx, role)
		if err != nil {
			t.Fatalf("EvolutionFor(%s) = %v", role, err)
		}
		m, err := manifest.Unmarshal(pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Entries) != 1 || m.Entries[0].Path != want {
			t.Fatalf("%s entries = %+v, want only %q", role, m.Entries, want)
		}
		for _, e := range m.Entries {
			if _, err := a.LoadEntry(ctx, role, e.Path); err != nil {
				t.Fatalf("LoadEntry(%s, %q) = %v; every entry a producer emits must load back", role, e.Path, err)
			}
		}
	}
}

// Content over its size limit is not silently dropped: the leaf SOUL.md
// role fails (its committed persona stands, rather than being deleted), and
// in a manifest role only that entry is held — its committed version is
// kept — while its siblings keep committing. A skill holding a large file
// still packs (only an archive's total is bounded).
func TestOversizedTrackedFileKeepsTheCommittedVersion(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	big := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, privsep.LimitTracked+1); err != nil {
			t.Fatal(err)
		}
	}
	big(soulMDPath())
	big(filepath.Join(memoriesDir(), "MEMORY.md"))
	big(filepath.Join(skillsDir(), "s", "data.bin"))
	if err := os.WriteFile(filepath.Join(memoriesDir(), "USER.md"), []byte("user"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EvolutionFor(ctx, "SOUL.md"); !errors.Is(err, privsep.ErrTooLarge) {
		t.Errorf("EvolutionFor(SOUL.md) = %v, want ErrTooLarge", err)
	}
	entries := func(role string) map[string]manifest.Entry {
		t.Helper()
		pt, err := a.EvolutionFor(ctx, role)
		if err != nil {
			t.Fatalf("EvolutionFor(%s) = %v; one oversized entry must not fail the role", role, err)
		}
		m, err := manifest.Unmarshal(pt)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]manifest.Entry{}
		for _, e := range m.Entries {
			out[e.Path] = e
		}
		return out
	}
	mem := entries("memories/")
	if !mem["MEMORY.md"].IsHeld() {
		t.Errorf("oversized MEMORY.md = %+v, want it held", mem["MEMORY.md"])
	}
	if e := mem["USER.md"]; e.IsHeld() || e.ContentHash != manifest.HashHex([]byte("user")) {
		t.Errorf("sibling USER.md = %+v, want it tracked", e)
	}
	if e, ok := entries("skills/")["s/"]; !ok || e.IsHeld() {
		t.Errorf("skill holding a large file = %+v, %v; want it packed", e, ok)
	}
}

// Restore makes the role directories real again when the agent replaced
// them with a link or a file, without following the link.
func TestRestoreReplacesNonDirectoryRoleDirs(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	outside := t.TempDir()
	if err := os.Symlink(outside, skillsDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memoriesDir(), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"skills/", "memories/"} {
		if err := a.Restore(ctx, role, nil); err != nil {
			t.Fatalf("Restore(%s): %v", role, err)
		}
	}
	if err := a.RestoreEntry(ctx, "skills/", "s1/", tarball); err != nil {
		t.Fatal(err)
	}
	if err := a.RestoreEntry(ctx, "memories/", "MEMORY.md", []byte("m")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{skillsDir(), memoriesDir()} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s = %v, %v; want a real directory", d, fi, err)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("restore wrote through the link: %v", ents)
	}
}

// config.yaml is untracked and the render owns its keys, so any unusable
// file — a socket, one over its limit, one that does not parse — is
// rebuilt instead of failing every start.
func TestRenderRebuildsAnUnusableConfig(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"unparsable": func(t *testing.T) {
			if err := os.WriteFile(configYAMLPath(), []byte("model: [unclosed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"too large": func(t *testing.T) {
			if err := os.WriteFile(configYAMLPath(), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(configYAMLPath(), privsep.LimitConfig+1); err != nil {
				t.Fatal(err)
			}
		},
		"socket": func(t *testing.T) {
			l, err := net.Listen("unix", configYAMLPath())
			if err != nil {
				t.Skipf("cannot bind a unix socket: %v", err)
			}
			t.Cleanup(func() { l.Close() })
		},
		"empty directory": func(t *testing.T) {
			if err := os.Mkdir(configYAMLPath(), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"directory with content": func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(configYAMLPath(), "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc", filepath.Join(configYAMLPath(), "sub", "link")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			a := newTestAdapter(t)
			plant(t)
			if err := a.RenderSettings(context.Background(), routed("0gm-1.0-35b-a3b", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
				t.Fatalf("RenderSettings over an unusable config.yaml: %v", err)
			}
			fi, err := os.Lstat(configYAMLPath())
			if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4096 {
				t.Fatalf("config.yaml = %v, %v; want a rebuilt regular file", fi, err)
			}
			// What was there is set aside, not lost.
			if _, err := os.Lstat(configYAMLPath() + ".corrupt"); err != nil {
				t.Fatalf("the unusable config.yaml was not set aside: %v", err)
			}
		})
	}
}

// An unparsable config.yaml keeps the agent's own settings: its bytes are
// set aside before the rebuild, and a later unusable copy goes to the next
// free name rather than over the first.
func TestRenderSetsAnUnparsableConfigAside(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("0gm-1.0-35b-a3b", "", inference.ModelFacts{CatalogSourced: true})
	first := "mcp_servers:\n  mine: {command: tool}\nmodel: [unclosed\n"
	if err := os.WriteFile(configYAMLPath(), []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	second := "toolsets: [also unclosed\n"
	if err := os.WriteFile(configYAMLPath(), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{".corrupt": first, ".corrupt-2": second} {
		if b, err := os.ReadFile(configYAMLPath() + name); err != nil || string(b) != want {
			t.Fatalf("config.yaml%s = %q, %v; want the unusable copy %q", name, b, err, want)
		}
	}
	cfg, unusable := loadConfigYAML()
	if unusable != nil || cfg["model"] == nil {
		t.Fatalf("rebuilt config.yaml = %v, %v; want the platform's keys", cfg, unusable)
	}

	// Once every name is taken, the newest copy still goes aside: it
	// replaces the last name (a directory there included), never lost.
	for i := 3; i <= maxSetAside; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.corrupt-%d", configYAMLPath(), i), []byte("older"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	last := fmt.Sprintf("%s.corrupt-%d", configYAMLPath(), maxSetAside)
	for _, newest := range []string{"third: [unclosed\n", "fourth: [unclosed\n"} {
		if err := os.WriteFile(configYAMLPath(), []byte(newest), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := a.RenderSettings(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(last); err != nil || string(b) != newest {
			t.Fatalf("%s = %q, %v; want the newest unusable copy %q", last, b, err, newest)
		}
		if err := os.Remove(last); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(last, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := os.ReadFile(configYAMLPath() + ".corrupt"); err != nil || string(b) != first {
		t.Fatalf("the first copy was replaced: %q, %v", b, err)
	}
}

// A restart needs the checkout, not a version the parser recognizes.
func TestRestartChecksCheckoutPresence(t *testing.T) {
	prev := hermesInstallDir
	hermesInstallDir = t.TempDir()
	t.Cleanup(func() { hermesInstallDir = prev })
	if err := checkoutPresent(); err == nil {
		t.Fatal("restart check passed without a checkout")
	}
	if err := os.MkdirAll(filepath.Join(hermesInstallDir, "hermes_cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hermesVersionFile(), []byte("__release_date__: str = \"2026.7.20\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := probeHermesVersion(context.Background()); v != "" {
		t.Fatalf("parser recognized %q; the test needs an unrecognized format", v)
	}
	if err := checkoutPresent(); err != nil {
		t.Fatalf("restart refused over an unrecognized version format: %v", err)
	}
}

// The gateway runs with the agent's own HOME (its default working
// directory) and an explicit HERMES_HOME, and leaves the working directory
// to the owner's terminal.cwd: no TERMINAL_CWD or MESSAGING_CWD in env.
func TestGatewayEnvHomes(t *testing.T) {
	env := gatewayEnv("", "", "server-key", framework.RuntimeContext{})
	want := map[string]bool{"HOME=" + privsep.AgentHome(): false, "HERMES_HOME=" + hermesHome: false}
	for _, kv := range env {
		if _, ok := want[kv]; ok {
			want[kv] = true
		}
		if strings.HasPrefix(kv, "TERMINAL_CWD=") || strings.HasPrefix(kv, "MESSAGING_CWD=") {
			t.Errorf("gateway env sets %s; the owner's terminal.cwd must decide", kv)
		}
	}
	for kv, ok := range want {
		if !ok {
			t.Errorf("gateway env lacks %s: %v", kv, env)
		}
	}
}

// skipOrFail skips, or with SEALED_PRIVSEP_TESTS=1 (the documented way to
// run the security tests, as root in a Linux container) fails.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SEALED_PRIVSEP_TESTS") == "1" {
		t.Fatalf("SEALED_PRIVSEP_TESTS=1, but: "+format, args...)
	}
	t.Skipf(format, args...)
}
