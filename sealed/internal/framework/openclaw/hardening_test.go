package openclaw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
)

// sealed's own bookkeeping (the pinned session key, the applied-overlay
// record) lives in framework.StateDir, not in the tree handed to the agent.
func TestStateLivesOutsideTheAgentTree(t *testing.T) {
	useTempHome(t)
	a := New()
	key := a.ConversationHeaders()[sessionKeyHeader]
	if key == "" {
		t.Fatal("no session key minted")
	}
	b, err := os.ReadFile(filepath.Join(framework.StateDir, conversationKeyState))
	if err != nil || strings.TrimSpace(string(b)) != key {
		t.Fatalf("key not persisted in StateDir: %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(openclawHome, ".seal-conversation-key")); !os.IsNotExist(err) {
		t.Fatalf("key still written into the agent tree: %v", err)
	}

	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"maxConcurrent":2}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(framework.StateDir, appliedOverlayState)); err != nil {
		t.Fatalf("overlay record not in StateDir: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(openclawHome, ".sealed-overlay.json")); !os.IsNotExist(err) {
		t.Fatalf("overlay record still written into the agent tree: %v", err)
	}
}

// A link planted at openclaw.json is set aside (the link itself) and the
// config rebuilt as a regular file; the link's target is never read or
// written.
func TestRenderSettingsSetsAsideALinkedConfig(t *testing.T) {
	useTempHome(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"linkTargetMarker":"me"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, openclawJSONPath()); err != nil {
		t.Fatal(err)
	}
	a := New()
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatalf("RenderSettings over a linked config: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != `{"linkTargetMarker":"me"}` {
		t.Fatalf("link target changed: %s", b)
	}
	fi, err := os.Lstat(openclawJSONPath())
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("openclaw.json = %v, %v; want a regular file", fi, err)
	}
	if b, _ := os.ReadFile(openclawJSONPath()); strings.Contains(string(b), "linkTargetMarker") {
		t.Fatalf("target content leaked into the rebuilt config: %s", b)
	}
	if fi, err := os.Lstat(openclawJSONPath() + ".corrupt"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("set-aside entry = %v, %v; want the link itself", fi, err)
	}
	a.mu.RLock()
	rebuilt := a.configRebuilt
	a.mu.RUnlock()
	if !rebuilt {
		t.Error("a set-aside config must flag the gateway section for Start to re-write")
	}
}

// evoWorkspace tracks regular files only: a link (even to an .md) and a FIFO
// are skipped, and the FIFO never blocks the watcher.
func TestEvoWorkspaceSkipsLinksAndFIFOs(t *testing.T) {
	useTempHome(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("not agent content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkspaceFile(userMDPath(), "user notes"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, memoryMDPath()); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(workspaceDir(), "pipe.md"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspaceDir(), "canvas"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(secret), filepath.Join(workspaceDir(), "canvas", "dir")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(workspaceDir(), "canvas", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := New()
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 2)
	go func() { b, err := a.evoWorkspace(); done <- res{b, err} }()
	go func() { b, err := a.evoWorkspaceCanvas(); done <- res{b, err} }()
	for i := 0; i < 2; i++ {
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatal(r.err)
			}
			m, err := manifest.Unmarshal(r.b)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range m.Entries {
				if e.Path != "USER.md" {
					t.Errorf("tracked %q; links and FIFOs must be skipped", e.Path)
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatal("evolution read blocked on a FIFO")
		}
	}
	if _, err := a.LoadEntry(context.Background(), "workspace/", "MEMORY.md"); err == nil {
		t.Fatal("LoadEntry followed a link")
	}
	if err := a.RestoreEntry(context.Background(), "workspace/canvas/", "../../x", []byte("x")); err == nil {
		t.Fatal("RestoreEntry accepted a path that leaves the role directory")
	}
	// LoadEntry checks entry paths too, at the dispatcher and in the skills
	// helper, so a path cannot name the workspace or the home itself.
	for _, p := range []string{"../x/", "a/b/", "./", "../"} {
		if _, err := a.LoadEntry(context.Background(), "workspace/skills/", p); err == nil {
			t.Errorf("LoadEntry(workspace/skills/, %q) succeeded", p)
		}
		if _, err := a.loadEntryWorkspaceSkills(p); err == nil {
			t.Errorf("loadEntryWorkspaceSkills(%q) succeeded", p)
		}
		if _, err := a.LoadEntry(context.Background(), "workspace/canvas/", p); err == nil {
			t.Errorf("LoadEntry(workspace/canvas/, %q) succeeded", p)
		}
	}
	if _, err := a.LoadEntry(context.Background(), "workspace/", "../openclaw.json"); err == nil {
		t.Fatal("LoadEntry(workspace/) read outside the role directory")
	}
}

func TestStaticVersionProbeReadsPackageJSON(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "lib", "node_modules", "openclaw")
	if err := os.MkdirAll(filepath.Join(pkg, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"openclaw","version":"2026.7.1","bin":{"openclaw":"openclaw.mjs"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A nested package.json with another name (ESM type marker) must not stop
	// the walk.
	if err := os.WriteFile(filepath.Join(pkg, "dist", "package.json"), []byte(`{"type":"module"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := packageVersionAbove(filepath.Join(pkg, "openclaw.mjs"), "openclaw"); got != "2026.7.1" {
		t.Fatalf("version = %q, want 2026.7.1", got)
	}
	if got := packageVersionAbove(filepath.Join(pkg, "dist", "cli.js"), "openclaw"); got != "2026.7.1" {
		t.Fatalf("version from a nested file = %q, want 2026.7.1", got)
	}
	if got := packageVersionAbove(filepath.Join(root, "other", "x"), "openclaw"); got != "" {
		t.Fatalf("version for an unrelated binary = %q, want empty", got)
	}
}

// gateway.mode used to be set by running the openclaw CLI as root; it is now
// part of the subtree writeRuntimeSections writes.
func TestRuntimeSectionsSetGatewayModeLocal(t *testing.T) {
	useTempHome(t)
	if err := writeRuntimeSections("tok"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	gw, _ := cfg["gateway"].(map[string]any)
	if gw["mode"] != "local" {
		t.Fatalf("gateway.mode = %v, want local", gw["mode"])
	}
}

// A link replacing a directory ABOVE the sessions dir (agents/main, pointing
// at a legit-looking store and transcript elsewhere) is refused too: privsep
// follows no link at any path component, not just the leaf, so /clear deletes
// nothing outside the tree. The leaf-link case is
// TestClearSession_DoesNotFollowSymlinks.
func TestClearSessionRefusesLinkedSessionsDir(t *testing.T) {
	redirectHome(t)
	key := currentConversationKey()
	outside := t.TempDir()
	sessions := filepath.Join(outside, "sessions")
	if err := os.MkdirAll(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]sessionEntry{"agent:main:" + key: {SessionID: "sess-1"}})
	if err := os.WriteFile(filepath.Join(sessions, "sessions.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(sessions, "sess-1.jsonl")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(openclawHome, "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(openclawHome, "agents", openclawAgentID)); err != nil {
		t.Fatal(err)
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("/clear deleted through a linked directory: %v", err)
	}
}

// A validator that could not run says nothing about the owner's overlay:
// Start fails, and the overlay stays rendered.
func TestEnsureConfigAcceptable_UnrunnableValidatorKeepsOverlay(t *testing.T) {
	useTempHome(t)
	a := New()
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"maxConcurrent":2}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	prev := validateOpenclawConfig
	defer func() { validateOpenclawConfig = prev }()
	calls := 0
	validateOpenclawConfig = func(context.Context) error {
		calls++
		return fmt.Errorf("%w: openclaw not found", errValidatorUnavailable)
	}
	err := a.ensureConfigAcceptable(context.Background())
	if err == nil || !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("ensureConfigAcceptable = %v, want a validator-unavailable failure", err)
	}
	if calls != 1 {
		t.Fatalf("validator ran %d times, want once (no withdraw-and-retry)", calls)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	if defaults["maxConcurrent"] == nil {
		t.Fatal("the owner's overlay was withdrawn although the validator never ran")
	}
	a.mu.RLock()
	others := string(a.rendered.Others)
	a.mu.RUnlock()
	if !strings.Contains(others, "maxConcurrent") {
		t.Fatalf("rendered overlay replaced: %q", others)
	}
}

// The production validator reports a CLI it cannot resolve as unavailable,
// not as a rejection.
func TestValidatorUnresolvableIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := validateOpenclawConfig(context.Background()); !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("validateOpenclawConfig with no openclaw on PATH = %v, want errValidatorUnavailable", err)
	}
}

// A validator that never finishes is cut off at its deadline and reported
// as unavailable (the owner's overlay stays), and its output is bounded.
func TestValidatorDeadlineAndBoundedOutput(t *testing.T) {
	bin := trustedBin(t)
	writeScript(t, filepath.Join(bin, "openclaw"), `i=0; while [ $i -lt 5000 ]; do echo "noise line $i"; i=$((i+1)); done; sleep 60`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t0 := time.Now()
	err := validateOpenclawConfig(ctx)
	if !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("validator past its deadline = %v, want errValidatorUnavailable", err)
	}
	if d := time.Since(t0); d > 15*time.Second {
		t.Fatalf("validator returned after %v", d)
	}
	// Its own deadline applies when the caller's context has none.
	prev := validateTimeout
	validateTimeout = time.Second
	t.Cleanup(func() { validateTimeout = prev })
	t0 = time.Now()
	if err := validateOpenclawConfig(context.Background()); !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("validator past validateTimeout = %v, want errValidatorUnavailable", err)
	}
	if d := time.Since(t0); d > 15*time.Second {
		t.Fatalf("validator returned after %v without a caller deadline", d)
	}
	validateTimeout = prev
	writeScript(t, filepath.Join(bin, "openclaw"), `i=0; while [ $i -lt 20000 ]; do echo "noise line $i"; i=$((i+1)); done; echo "<root>: Invalid input"; exit 1`)
	err = validateOpenclawConfig(context.Background())
	if err == nil || errors.Is(err, errValidatorUnavailable) || !strings.Contains(err.Error(), "<root>: Invalid input") {
		t.Fatalf("rejecting validator = %v, want a rejection carrying the verdict", err)
	}
	if len(err.Error()) > validateOutputMax+512 {
		t.Fatalf("validator output kept in full (%d bytes)", len(err.Error()))
	}
}

// The root-run install is pointed away from the agent's tree: openclaw's
// install script resolves its state directory from OPENCLAW_HOME, and the
// registry migration that would create state there is off. Checked on the
// command the install really runs (installCommand), not only on installEnv.
func TestInstallEnvKeepsTheInstallOutOfTheAgentTree(t *testing.T) {
	useTempHome(t)
	bin := trustedBin(t)
	writeScript(t, filepath.Join(bin, "npm"), "true")
	cmd, err := installCommand("openclaw@2026.7.1")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(framework.StateDir, installHomeName)
	if strings.HasPrefix(home, openclawHome) {
		t.Fatalf("install home %q is inside %s", home, openclawHome)
	}
	env := "\n" + strings.Join(cmd.Env, "\n") + "\n"
	for _, want := range append(installEnv(home), "HOME=/root", "TMPDIR=/var/lib/sealed/tmp") {
		if !strings.Contains(env, "\n"+want+"\n") {
			t.Errorf("install command env lacks %s:%s", want, env)
		}
	}
	if !strings.Contains(env, "\nOPENCLAW_HOME="+home+"\n") || !strings.Contains(env, "\nOPENCLAW_DISABLE_PLUGIN_REGISTRY_MIGRATION=1\n") {
		t.Errorf("install env does not point openclaw's install script away from the agent tree:%s", env)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Error("the install must run as root (it writes the root-owned global prefix)")
	}
}

// The gateway's HOME is the agent's own home, not root's.
func TestGatewayEnvHomeIsTheAgentHome(t *testing.T) {
	env := gatewayEnv("", "", framework.RuntimeContext{})
	if !contains(env, "HOME="+privsep.AgentHome()) {
		t.Fatalf("gateway env %v lacks HOME=%s", env, privsep.AgentHome())
	}
}

// The gateway is told where its tree is (OPENCLAW_STATE_DIR, and
// OPENCLAW_HOME as the directory holding it), so it never resolves it
// through the ~/.openclaw link in the agent's home: openclaw refuses its
// exec tool under a symlinked path, and a missing or replaced link would
// point it at another tree. HOME stays the agent's own.
func TestGatewayEnvNamesTheTree(t *testing.T) {
	prev := openclawHome
	openclawHome = "/root/.openclaw"
	t.Cleanup(func() { openclawHome = prev })
	env := gatewayEnv("", "", framework.RuntimeContext{})
	for _, want := range []string{"OPENCLAW_STATE_DIR=/root/.openclaw", "OPENCLAW_HOME=/root", "HOME=" + privsep.AgentHome()} {
		if !contains(env, want) {
			t.Fatalf("gateway env %v lacks %s", env, want)
		}
	}
}

// openclaw takes <OPENCLAW_HOME>/.openclaw as its tree; the production
// tree is named so, or OPENCLAW_HOME would not lead to it.
func TestTreeIsNamedAsOpenclawExpects(t *testing.T) {
	if filepath.Base(defaultOpenclawHome) != ".openclaw" {
		t.Fatalf("openclawHome = %s; openclaw finds its tree as <OPENCLAW_HOME>/.openclaw", defaultOpenclawHome)
	}
}

// defaultOpenclawHome is openclawHome before any test redirects it.
var defaultOpenclawHome = openclawHome

// Where each whitelisted openclaw keeps what its exec tool writes before
// every gateway-host command (the approvals file), and the directory it
// refuses to reach through a symbolic link: 2026.5.x expands
// ~/.openclaw/exec-approvals.json from OPENCLAW_HOME (else HOME) and checks
// every component from that home down (dist exec-approvals-*.js
// resolveExecApprovalsPath / ensureDir); 2026.7.1 takes the directory from
// OPENCLAW_STATE_DIR when it is set. A version added to the whitelist must
// be added here, with its rule.
var execApprovalsDir = map[string]func(env map[string]string) (dir, checkedFrom string){
	"2026.5.6": execApprovalsFromHome,
	"2026.5.7": execApprovalsFromHome,
	"2026.7.1": func(env map[string]string) (string, string) {
		if d := env["OPENCLAW_STATE_DIR"]; d != "" {
			return d, openclawHomeOf(env)
		}
		return execApprovalsFromHome(env)
	},
}

func openclawHomeOf(env map[string]string) string {
	if h := env["OPENCLAW_HOME"]; h != "" {
		return h
	}
	return env["HOME"]
}

func execApprovalsFromHome(env map[string]string) (string, string) {
	home := openclawHomeOf(env)
	return filepath.Join(home, ".openclaw"), home
}

// With the gateway's environment and the agent's home linking ~/.openclaw
// to the tree, every whitelisted version keeps its exec approvals in the
// tree itself and reaches it without passing through the agent's home,
// where the link is: through it, 2026.5.x refused every exec ("Refusing to
// traverse symlink in exec approvals path").
func TestEveryWhitelistedVersionReachesItsExecApprovalsWithoutTheLink(t *testing.T) {
	prev := openclawHome
	openclawHome = "/root/.openclaw"
	t.Cleanup(func() { openclawHome = prev })
	env := map[string]string{}
	for _, kv := range gatewayEnv("", "", framework.RuntimeContext{}) {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	env["HOME"] = "/home/agent" // the split's agent home, wherever the test runs
	for _, v := range supportedOpenclawVersions {
		rule, ok := execApprovalsDir[v]
		if !ok {
			t.Errorf("openclaw %s is whitelisted but execApprovalsDir has no rule for it", v)
			continue
		}
		dir, from := rule(env)
		if dir != openclawHome {
			t.Errorf("openclaw %s keeps its exec approvals in %s, want the tree %s", v, dir, openclawHome)
		}
		if from == env["HOME"] || strings.HasPrefix(dir, env["HOME"]+"/") {
			t.Errorf("openclaw %s reaches its exec approvals from the agent's home %s, through the ~/.openclaw link", v, env["HOME"])
		}
	}
}

// The rendered config leaves agents.defaults.workspace alone: openclaw
// finds the default agent's workspace from OPENCLAW_HOME, and pinning the
// key would move every listed agent without a workspace of its own under
// the default agent's tracked workspace. What the owner's overlay sets
// there is kept, as for any key the platform does not own.
func TestRenderLeavesTheWorkspaceToOpenclaw(t *testing.T) {
	useTempHome(t)
	a := New()
	agentsOf := func() map[string]any {
		t.Helper()
		cfg, err := loadOpenclawJSON()
		if err != nil {
			t.Fatal(err)
		}
		agents, _ := cfg["agents"].(map[string]any)
		return agents
	}
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"list":[{"id":"main","default":true},{"id":"helper"}]}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	agents := agentsOf()
	defaults, _ := agents["defaults"].(map[string]any)
	if ws, ok := defaults["workspace"]; ok {
		t.Fatalf("agents.defaults.workspace = %v; the render must not pin it", ws)
	}
	list, _ := agents["list"].([]any)
	if len(list) != 2 {
		t.Fatalf("agents.list = %v, want the overlay's two agents", agents["list"])
	}
	for _, e := range list {
		if ws, ok := e.(map[string]any)["workspace"]; ok {
			t.Fatalf("agents.list entry %v given workspace %v; openclaw places it (workspace-<id>)", e, ws)
		}
	}
	s.Others = json.RawMessage(`{"agents":{"defaults":{"workspace":"/home/agent/elsewhere"}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	defaults, _ = agentsOf()["defaults"].(map[string]any)
	if got := defaults["workspace"]; got != "/home/agent/elsewhere" {
		t.Fatalf("agents.defaults.workspace = %v, want the overlay's value kept", got)
	}
}

// openclaw expands "~" in its config from OPENCLAW_HOME, root's home, where
// the agent can create nothing outside the tree: an overlay's "~/x" or
// "/root/x" workspace or agentDir outside the tree is rendered as x in the
// agent's home (what such a path meant when the agent owned /root, and
// where ReclaimHome moved what it kept there). One under the tree, another
// absolute one and a "~user" one are kept, and a second render of the same
// overlay changes nothing.
func TestRenderMovesHomeRelativeAgentPathsToTheAgentsHome(t *testing.T) {
	useTempHome(t)
	a := New()
	rootHome := filepath.Dir(openclawHome)
	inTree := "~/" + filepath.Base(openclawHome) + "/workspace-x"
	absInTree := filepath.Join(openclawHome, "workspace-y")
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(fmt.Sprintf(`{"agents":{"defaults":{"workspace":"~/main-ws"},"list":[
		{"id":"main","default":true},
		{"id":"helper","workspace":"~/helper-ws","agentDir":"~"},
		{"id":"tree","workspace":%q},
		{"id":"abs","workspace":"/srv/ws"},
		{"id":"user","workspace":"~bob/ws"},
		{"id":"up","workspace":"~/../etc"},
		{"id":"absroot","workspace":%q,"agentDir":%q},
		{"id":"abstree","workspace":%q},
		{"id":"sibling","workspace":%q}]}}`, inTree, rootHome+"/helper-ws2", rootHome+"/agents/x/../y", absInTree, rootHome+"x/ws"))
	home := privsep.AgentHome()
	for range 2 {
		if err := a.RenderSettings(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadOpenclawJSON()
		if err != nil {
			t.Fatal(err)
		}
		agents, _ := cfg["agents"].(map[string]any)
		defaults, _ := agents["defaults"].(map[string]any)
		if got, want := defaults["workspace"], filepath.Join(home, "main-ws"); got != want {
			t.Errorf("agents.defaults.workspace = %v, want %s", got, want)
		}
		list, _ := agents["list"].([]any)
		if len(list) != 9 {
			t.Fatalf("agents.list = %v", agents["list"])
		}
		for i, want := range []map[string]any{
			{"id": "main"},
			{"workspace": filepath.Join(home, "helper-ws"), "agentDir": home},
			{"workspace": inTree},
			{"workspace": "/srv/ws"},
			{"workspace": "~bob/ws"},
			{"workspace": "~/../etc"},
			{"workspace": filepath.Join(home, "helper-ws2"), "agentDir": filepath.Join(home, "agents/y")},
			{"workspace": absInTree},
			{"workspace": rootHome + "x/ws"},
		} {
			e, _ := list[i].(map[string]any)
			for k, v := range want {
				if e[k] != v {
					t.Errorf("agents.list[%d].%s = %v, want %v", i, k, e[k], v)
				}
			}
		}
	}
}

// The validator checks the file the gateway will use: it gets the same
// tree locations.
func TestValidatorEnvNamesTheTree(t *testing.T) {
	useTempHome(t)
	bin := trustedBin(t)
	writeScript(t, filepath.Join(bin, "openclaw"), `echo "state=$OPENCLAW_STATE_DIR home=$OPENCLAW_HOME"; exit 1`)
	err := validateOpenclawConfig(context.Background())
	if err == nil || errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("validator = %v, want a rejection carrying its output", err)
	}
	if want := "state=" + openclawHome + " home=" + filepath.Dir(openclawHome); !strings.Contains(err.Error(), want) {
		t.Fatalf("validator ran without %q: %v", want, err)
	}
}

// A validator ended by a signal gave no verdict: it is unavailable, and the
// owner's overlay stays rendered.
func TestValidatorKilledBySignalIsUnavailable(t *testing.T) {
	useTempHome(t)
	bin := trustedBin(t)
	writeScript(t, filepath.Join(bin, "openclaw"), `kill -9 $$`)
	if err := validateOpenclawConfig(context.Background()); !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("validator killed by a signal = %v, want errValidatorUnavailable", err)
	}
	a := New()
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"maxConcurrent":2}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureConfigAcceptable(context.Background()); !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("ensureConfigAcceptable with a killed validator = %v, want errValidatorUnavailable", err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	if defaults["maxConcurrent"] == nil {
		t.Fatal("the owner's overlay was withdrawn over a validator that was killed")
	}
}

// Whatever sits at openclaw.json or its set-aside name — a directory, a
// file — does not keep the render (the manager's PreStart) from writing a
// regular config file.
func TestRenderRebuildsOverADirectory(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"empty directory": func(t *testing.T) {
			if err := os.Mkdir(openclawJSONPath(), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"directory, file at the set-aside name": func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(openclawJSONPath(), "x"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(openclawJSONPath()+".corrupt", []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directories at both names": func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(openclawJSONPath(), "x"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(openclawJSONPath()+".corrupt", "y"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"unparsable file, directory at the set-aside name": func(t *testing.T) {
			if err := os.WriteFile(openclawJSONPath(), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(openclawJSONPath()+".corrupt", "y"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			useTempHome(t)
			plant(t)
			a := New()
			if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
				t.Fatalf("RenderSettings: %v", err)
			}
			fi, err := os.Lstat(openclawJSONPath())
			if err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("openclaw.json = %v, %v; want a rebuilt regular file", fi, err)
			}
			if _, err := loadOpenclawJSON(); err != nil {
				t.Fatalf("rebuilt config does not load: %v", err)
			}
			// The unusable copy is set aside even when something already
			// sat at the set-aside name.
			if name == "unparsable file, directory at the set-aside name" {
				if b, err := os.ReadFile(openclawJSONPath() + ".corrupt"); err != nil || string(b) != "{" {
					t.Fatalf("set-aside copy = %q, %v; want the unparsable file", b, err)
				}
			}
		})
	}
}

// A role directory the agent replaced with a link (here workspace/skills,
// pointing into its own home) does not keep the agent from booting:
// restore makes it a real directory again, leaves the link's target alone,
// and the role is tracked again.
func TestRestoreReplacesALinkedRoleDirectory(t *testing.T) {
	useTempHome(t)
	ctx := context.Background()
	a := &Adapter{}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.md"), []byte("agent's own"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("skill one"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{workspaceDir() + "/skills", workspaceDir() + "/canvas"} {
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{"workspace/skills/", "workspace/canvas/"} {
		if err := a.Restore(ctx, role, nil); err != nil {
			t.Fatalf("Restore(%s) over a linked role directory: %v", role, err)
		}
	}
	if err := a.RestoreEntry(ctx, "workspace/skills/", "s1/", tarball); err != nil {
		t.Fatalf("RestoreEntry: %v", err)
	}
	if err := a.RestoreEntry(ctx, "workspace/canvas/", "index.html", []byte("<p>")); err != nil {
		t.Fatalf("RestoreEntry(canvas file): %v", err)
	}
	for _, d := range []string{workspaceDir() + "/skills", workspaceDir() + "/canvas"} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s = %v, %v; want a real directory", d, fi, err)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("restore wrote through the link: %v", ents)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "keep.md")); string(b) != "agent's own" {
		t.Fatalf("link target changed: %q", b)
	}
	pt, err := a.EvolutionFor(ctx, "workspace/skills/")
	if err != nil {
		t.Fatalf("EvolutionFor after restore: %v", err)
	}
	m, err := manifest.Unmarshal(pt)
	if err != nil || len(m.Entries) != 1 || m.Entries[0].Path != "s1/" || m.Entries[0].IsHeld() {
		t.Fatalf("skills role after restore = %s, %v; want s1/ tracked", pt, err)
	}
}

// The workspace itself, the central role directory, replaced by a link
// (the agent owns the tree, so it can do that) is replaced by a real
// directory by Restore and by RestoreEntry alike: neither writes through
// the link, and the role is tracked again afterwards.
func TestRestoreReplacesALinkedWorkspace(t *testing.T) {
	useTempHome(t)
	ctx := context.Background()
	a := &Adapter{}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep.md")
	if err := os.WriteFile(sentinel, []byte("agent's own"), 0o644); err != nil {
		t.Fatal(err)
	}
	plantLink := func() {
		t.Helper()
		if err := os.RemoveAll(workspaceDir()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, workspaceDir()); err != nil {
			t.Fatal(err)
		}
	}
	check := func(when string) {
		t.Helper()
		if fi, err := os.Lstat(workspaceDir()); err != nil || !fi.IsDir() {
			t.Fatalf("%s: workspace = %v, %v; want a real directory", when, fi, err)
		}
		if ents, _ := os.ReadDir(outside); len(ents) != 1 {
			t.Fatalf("%s: restore wrote through the link: %v", when, ents)
		}
		if b, _ := os.ReadFile(sentinel); string(b) != "agent's own" {
			t.Fatalf("%s: link target changed: %q", when, b)
		}
		if target, err := os.Readlink(workspaceDir()); err == nil {
			t.Fatalf("%s: workspace is still a link to %s", when, target)
		}
	}
	plantLink()
	if err := a.Restore(ctx, "workspace/", nil); err != nil {
		t.Fatalf("Restore(workspace/) over a linked workspace: %v", err)
	}
	check("Restore")
	plantLink()
	if err := a.RestoreEntry(ctx, "workspace/", "MEMORY.md", []byte("remember this")); err != nil {
		t.Fatalf("RestoreEntry(workspace/, MEMORY.md) over a linked workspace: %v", err)
	}
	check("RestoreEntry")
	if b, err := os.ReadFile(memoryMDPath()); err != nil || string(b) != "remember this" {
		t.Fatalf("MEMORY.md = %q, %v", b, err)
	}
	pt, err := a.EvolutionFor(ctx, "workspace/")
	if err != nil {
		t.Fatalf("EvolutionFor after restore: %v", err)
	}
	m, err := manifest.Unmarshal(pt)
	if err != nil || m.EntryByPath("MEMORY.md") == nil {
		t.Fatalf("workspace role after restore = %s, %v; want MEMORY.md tracked", pt, err)
	}
}

// A tracked entry over its size limit is held (its committed version is
// kept) without holding the rest of its role: a sibling skill, and the
// other workspace files, keep committing. Earlier sealed versions had no
// such limit, so an agent can come back from chain with such a file.
func TestOversizedEntryHoldsOnlyItself(t *testing.T) {
	useTempHome(t)
	ctx := context.Background()
	a := &Adapter{}
	big := func(p string, size int64) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, size); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, c string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A skill holding a file over the per-file limit still packs (only the
	// archive total is bounded), so it is tracked, not held — including one
	// restored from an archive an earlier packer committed.
	big(filepath.Join(workspaceDir(), "skills", "model", "weights.bin"), privsep.LimitTracked+1)
	legacySrc := t.TempDir()
	big(filepath.Join(legacySrc, "data.bin"), privsep.LimitTracked+1)
	legacy, err := manifest.PackDir(legacySrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RestoreEntry(ctx, "workspace/skills/", "legacy/", legacy); err != nil {
		t.Fatalf("RestoreEntry of a legacy skill with a large file: %v", err)
	}
	write(filepath.Join(workspaceDir(), "skills", "newskill", "SKILL.md"), "new")
	big(filepath.Join(workspaceDir(), "log.md"), privsep.LimitTracked+1)
	write(filepath.Join(workspaceDir(), "MEMORY.md"), "remember")
	big(filepath.Join(workspaceDir(), "canvas", "big.html"), privsep.LimitTracked+1)
	write(filepath.Join(workspaceDir(), "canvas", "index.html"), "<p>")

	entries := func(role string) map[string]manifest.Entry {
		t.Helper()
		pt, err := a.EvolutionFor(ctx, role)
		if err != nil {
			t.Fatalf("EvolutionFor(%s) = %v; the role must not fail for one oversized entry", role, err)
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
	skills := entries("workspace/skills/")
	if e, ok := skills["model/"]; !ok || e.IsHeld() {
		t.Errorf("skill with a large file = %+v, %v; want it packed", e, ok)
	}
	if e, ok := skills["newskill/"]; !ok || e.IsHeld() {
		t.Errorf("sibling skill = %+v, %v; want it tracked", e, ok)
	}
	if e, ok := skills["legacy/"]; !ok || e.IsHeld() || e.ContentHash != manifest.HashHex(legacy) {
		t.Errorf("restored legacy skill = %+v, %v; want it tracked unchanged", e, ok)
	}
	ws := entries("workspace/")
	if e := ws["log.md"]; !e.IsHeld() {
		t.Errorf("oversized log.md = %+v; want it held", e)
	}
	if e := ws["MEMORY.md"]; e.IsHeld() || e.ContentHash != manifest.HashHex([]byte("remember")) {
		t.Errorf("MEMORY.md = %+v; want it tracked", e)
	}
	canvas := entries("workspace/canvas/")
	if e := canvas["big.html"]; !e.IsHeld() {
		t.Errorf("oversized canvas file = %+v; want it held", e)
	}
	if e := canvas["index.html"]; e.IsHeld() || e.ContentHash != manifest.HashHex([]byte("<p>")) {
		t.Errorf("canvas sibling = %+v; want it tracked", e)
	}
}

// Stop's sweep pattern matches the gateway's command line in every shape it
// actually has — as exec'd, under the bare title openclaw gives every
// process while it starts (as pkill reads it: padded with spaces, or not),
// and under its gateway title — and not the agent's other processes.
func TestSweepPatternMatchesTheGateway(t *testing.T) {
	re := regexp.MustCompile(gatewaySweepPattern)
	for _, cmdline := range []string{
		"openclaw-gateway                                                ",
		"openclaw",
		"openclaw                                                        ",
		"node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway run --allow-unconfigured --bind loopback --port 3284",
		"/usr/bin/env node /root/.nvm/versions/node/v24.22.0/lib/node_modules/openclaw/openclaw.mjs gateway run",
		"openclaw gateway run --allow-unconfigured",
	} {
		if !re.MatchString(cmdline) {
			t.Errorf("pattern misses %q", cmdline)
		}
	}
	for _, cmdline := range []string{
		"node /usr/local/lib/node_modules/openclaw/openclaw.mjs config validate",
		"node /home/agent/srv/openclaw-backend.js",
		"node /home/agent/srv/openclaw-gateway-proxy.js",
		"tail -f /home/agent/logs/openclaw-gateway.log",
		"python3 /root/.openclaw/workspace/canvas/serve.py --name openclaw-gateway-ui",
		"python3 -m http.server --directory /root/.openclaw/workspace/canvas",
		"sh -c echo myopenclaw gateway run",
		"openclawish",
		"openclaw-gatewayish",
	} {
		if re.MatchString(cmdline) {
			t.Errorf("pattern matches %q", cmdline)
		}
	}
}

// A gateway started the way spawnGateway starts it (AgentCommand on the
// resolved interpreter script) is found by Stop's sweep, and Stop sweeps
// on a cancelled ctx too.
func TestStopSweepsAnUntrackedGatewayEvenWhenCancelled(t *testing.T) {
	bin := trustedBin(t)
	pkg := filepath.Join(filepath.Dir(bin), "lib", "node_modules", "openclaw")
	writeScript(t, filepath.Join(pkg, "openclaw.mjs"), "sleep 300; true")
	if err := os.Symlink(filepath.Join(pkg, "openclaw.mjs"), filepath.Join(bin, "openclaw")); err != nil {
		t.Fatal(err)
	}
	if _, err := privsep.LookPath("pkill"); err != nil {
		skipOrFail(t, "no root-only pkill: %v", err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	gw, err := privsep.AgentCommand(context.Background(), "openclaw", "gateway", "run", "--allow-unconfigured")
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.Start(); err != nil {
		t.Fatal(err)
	}
	gwDone := make(chan struct{})
	go func() { _ = gw.Wait(); close(gwDone) }()
	t.Cleanup(func() { _ = gw.Process.Kill() })

	// The tracked process ignores SIGINT, so Stop reaches its ctx branch.
	tracked := exec.Command("sh", "-c", `trap "" INT; sleep 300; true`)
	if err := tracked.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tracked.Process.Kill() })
	a := &Adapter{cmd: tracked}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	time.Sleep(100 * time.Millisecond)
	if err := a.Stop(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop = %v, want context.Canceled", err)
	}
	select {
	case <-gwDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not sweep the untracked gateway on the cancelled path")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// trustedBin makes a bin directory privsep.LookPath trusts (root-owned all
// the way up, under /var/lib) and puts it first on PATH. Needs root.
func trustedBin(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root: privsep resolves commands only in root-owned directories")
	}
	base, err := os.MkdirTemp("/var/lib", "openclaw-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return bin
}

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
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

// The validator runs as the agent, so Start hands the tree over before it
// validates: on a first boot RenderSettings wrote openclaw.json as root,
// mode 0600, and a validator that could not read it would count as a
// rejection of the owner's overlay. The stand-in validator checks what the
// agent would see when it runs.
func TestStartHandsTheTreeOverBeforeValidating(t *testing.T) {
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root: the handover is a chown to the agent user")
	}
	if !privsep.Active() {
		// The documented runs include one without the account; the one
		// with it runs this.
		t.Skip("no agent account in this run: the handover is a no-op")
	}
	u, err := user.Lookup("agent")
	if err != nil {
		t.Fatal(err)
	}
	agentUID, _ := strconv.Atoi(u.Uid)
	useTempHome(t)
	a := New()
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"maxConcurrent":2}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	prev := validateOpenclawConfig
	t.Cleanup(func() { validateOpenclawConfig = prev })
	ran := 0
	validateOpenclawConfig = func(context.Context) error {
		ran++
		var st unix.Stat_t
		if err := unix.Lstat(openclawJSONPath(), &st); err != nil {
			return err
		}
		if int(st.Uid) != agentUID {
			// What the real validator, as the agent, would do with a
			// root-owned 0600 file: exit 1.
			return fmt.Errorf("openclaw.json is uid %d mode %#o when the validator runs; the agent (uid %d) cannot read it", st.Uid, st.Mode&0o7777, agentUID)
		}
		return nil
	}
	token, err := a.prepareTree(context.Background(), false, false, "")
	if err != nil {
		t.Fatalf("prepareTree: %v", err)
	}
	if ran != 1 || token == "" {
		t.Fatalf("validator ran %d times, token %q; want once, and a minted token", ran, token)
	}
	a.mu.RLock()
	others := string(a.rendered.Others)
	a.mu.RUnlock()
	if !strings.Contains(others, "maxConcurrent") {
		t.Fatalf("the owner's overlay was withdrawn: %q", others)
	}
}
