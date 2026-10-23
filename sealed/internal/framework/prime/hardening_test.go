package prime

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
	"seal-verify/internal/settings"
)

func plantLink(t *testing.T, at string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, at); err != nil {
		t.Fatal(err)
	}
	return target
}

func assertTargetKeptAndRegular(t *testing.T, target, at string) {
	t.Helper()
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("link target changed: %q", b)
	}
	fi, err := os.Lstat(at)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("%s = %v, %v; want a regular file", at, fi, err)
	}
	if b, _ := os.ReadFile(at); strings.Contains(string(b), "keep") {
		t.Fatalf("target content leaked into %s: %q", at, b)
	}
}

func TestLinkedModelsJSONIsNotFollowed(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	target := plantLink(t, modelsJSONPath())
	if _, ok := previousReasoning(inference.ZGComputeProvider, "glm-5.3"); ok {
		t.Fatal("previousReasoning read through a link")
	}
	s := settings.Resolve(context.Background(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk")
	if err := New().RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	assertTargetKeptAndRegular(t, target, modelsJSONPath())
}

func TestLinkedAppendSystemIsNotFollowed(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	target := plantLink(t, appendSystemPath())
	got, err := a.evoAppendSystem()
	if err != nil || got != nil {
		t.Fatalf("evoAppendSystem through a link = %q, %v; want nothing", got, err)
	}
	if err := a.restoreAppendSystem([]byte("persona\n")); err != nil {
		t.Fatal(err)
	}
	assertTargetKeptAndRegular(t, target, appendSystemPath())
}

// skills/ entry paths are checked for LoadEntry and RestoreEntry alike, at
// the dispatcher and in the skills helpers, with a real tarball so a
// missing check would show as a write, not as a gzip error.
func TestSkillEntryPathsStayInTheRole(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	ctx := context.Background()
	sentinel := appendSystemPath()
	if err := os.WriteFile(sentinel, []byte("persona\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "pyproject.toml"), []byte("[project]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../x/", "a/b/", "./", "../"} {
		if err := a.RestoreEntry(ctx, "skills/", p, tarball); err == nil {
			t.Errorf("RestoreEntry(skills/, %q) succeeded", p)
		}
		if err := a.restoreEntrySkills(p, tarball); err == nil {
			t.Errorf("restoreEntrySkills(%q) succeeded", p)
		}
		if _, err := a.LoadEntry(ctx, "skills/", p); err == nil {
			t.Errorf("LoadEntry(skills/, %q) succeeded", p)
		}
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "persona\n" {
		t.Fatalf("APPEND_SYSTEM.md did not survive: %q, %v", b, err)
	}
	if err := a.RestoreEntry(ctx, "skills/", "ok/", tarball); err != nil {
		t.Fatalf("a plain skill entry was refused: %v", err)
	}
}

// A tracked file over its size limit fails its leaf role (the committed
// harness state and persona stay) instead of reading as absent; a skill
// holding a large file still packs (only an archive's total is bounded).
func TestOversizedTrackedFileKeepsTheCommittedVersion(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	for _, p := range []string{harnessStatePath(), appendSystemPath()} {
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
	if _, err := a.evoHarnessState(); !errors.Is(err, privsep.ErrTooLarge) {
		t.Errorf("evoHarnessState = %v, want ErrTooLarge", err)
	}
	if _, err := a.evoAppendSystem(); !errors.Is(err, privsep.ErrTooLarge) {
		t.Errorf("evoAppendSystem = %v, want ErrTooLarge", err)
	}
	big := filepath.Join(skillsDir(), "s", "data.bin")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, privsep.LimitTracked+1); err != nil {
		t.Fatal(err)
	}
	pt, err := a.evoSkills()
	if err != nil {
		t.Fatalf("evoSkills with a large file = %v", err)
	}
	if m, err := manifest.Unmarshal(pt); err != nil || len(m.Entries) != 1 || m.Entries[0].IsHeld() {
		t.Fatalf("skills = %s, %v; want the skill packed", pt, err)
	}
}

func useTempConversationDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := conversationDir
	conversationDir = func() string { return dir }
	t.Cleanup(func() { conversationDir = prev })
	return dir
}

// The conversation file sits one level below the handed-over directory,
// so the SDK's session-artifacts directory (next to the session's
// directory) lands inside that tree rather than in root's home.
func TestConversationLayoutKeepsArtifactsInTheTree(t *testing.T) {
	stubCatalog(t, reasoningModel)
	if got, want := filepath.Dir(filepath.Dir(conversationPath())), conversationDir(); got != want {
		t.Fatalf("artifacts would land in %s/session-artifacts, want them under %s", got, want)
	}
	env := strings.Join(bridgeEnvFor(settings.Resolve(context.Background(), settings.Doc{Provider: "anthropic", Model: "m"}, "sk"), "tok", framework.RuntimeContext{}).environ("/nm"), "\n")
	for _, want := range []string{
		"SEAL_CONVERSATION_FILE=" + conversationPath(),
		"HOME=" + privsep.AgentHome(),
		"PRIME_AGENT_CODING_AGENT_DIR=" + primeHome,
		"PRIME_AGENT_KERNEL_VENV=" + kernelVenvDir(),
	} {
		if !strings.Contains(env, want+"\n") && !strings.HasSuffix(env, want) {
			t.Errorf("bridge env lacks %s:\n%s", want, env)
		}
	}
}

// What the bridge, the kernel and the SDK write is handed to the agent: the
// framework home, the harness state directory, and the directory the SDK
// creates session artifacts in (next to the session directory, so
// conversationDir itself, not only the session directory in it). New and
// spawnBridge both take the trees from handedOverTrees, so narrowing the
// handover — to the session directory, say — fails here instead of every
// chat turn with EACCES.
func TestHandedOverTreesCoverWhereTheAgentWrites(t *testing.T) {
	trees := handedOverTrees()
	inside := func(p string) bool {
		for _, tree := range trees {
			if p == tree || strings.HasPrefix(p, tree+"/") {
				return true
			}
		}
		return false
	}
	for what, p := range map[string]string{
		"the framework home":                                 primeHome,
		"the harness state directory":                        sessionStateDir(),
		"the directory the SDK creates session artifacts in": filepath.Dir(conversationSessionDir()),
		"the session directory":                              conversationSessionDir(),
	} {
		if !inside(p) {
			t.Errorf("%s (%s) is not in a handed-over tree %v", what, p, trees)
		}
	}
	// Both lists come from handedOverTrees: New declares, spawnBridge hands
	// over, each in a loop over it.
	for file, want := range map[string][2]string{"prime.go": {"New", "DeclareTree"}, "spawn.go": {"spawnBridge", "OwnTree"}} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != want[0] || fd.Recv != nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				rs, ok := n.(*ast.RangeStmt)
				if !ok || types.ExprString(rs.X) != "handedOverTrees()" {
					return true
				}
				v, ok := rs.Value.(*ast.Ident)
				if !ok {
					return true
				}
				ast.Inspect(rs.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || len(call.Args) != 1 {
						return true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == want[1] && types.ExprString(sel.X) == "privsep" {
						if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == v.Name {
							found = true
						}
					}
					return true
				})
				return true
			})
		}
		if !found {
			t.Errorf("%s: %s does not call privsep.%s for each of handedOverTrees()", file, want[0], want[1])
		}
	}
}

// A conversation an earlier sealed kept directly in conversationDir moves
// into the nested layout with its rotated siblings; nothing at the
// destination is replaced, and only regular files move.
func TestMigrateConversation(t *testing.T) {
	dir := useTempConversationDir(t)
	if err := os.MkdirAll(conversationSessionDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, conversationFile), "history\n")
	write(filepath.Join(dir, conversationFile+".corrupt-1"), "torn\n")
	write(filepath.Join(dir, "unrelated.txt"), "stay\n")
	target := filepath.Join(t.TempDir(), "target")
	write(target, "keep\n")
	if err := os.Symlink(target, filepath.Join(dir, conversationFile+".stale-2")); err != nil {
		t.Fatal(err)
	}
	migrateConversation()
	for name, want := range map[string]string{conversationFile: "history\n", conversationFile + ".corrupt-1": "torn\n"} {
		if b, err := os.ReadFile(filepath.Join(conversationSessionDir(), name)); err != nil || string(b) != want {
			t.Errorf("%s after migration = %q, %v", name, b, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still in the old location", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(conversationSessionDir(), conversationFile+".stale-2")); !os.IsNotExist(err) {
		t.Error("a link was moved")
	}
	if _, err := os.Stat(filepath.Join(dir, "unrelated.txt")); err != nil {
		t.Error("an unrelated file was moved")
	}
	// A second run with a newer file already in place keeps it.
	write(filepath.Join(dir, conversationFile), "older\n")
	write(conversationPath(), "newer\n")
	migrateConversation()
	if b, _ := os.ReadFile(conversationPath()); string(b) != "newer\n" {
		t.Fatalf("migration replaced the newer conversation: %q", b)
	}
}

// ClearSession removes the conversation, its leftovers and the SDK's
// session artifacts.
func TestClearSessionRemovesArtifacts(t *testing.T) {
	useTempConversationDir(t)
	art := filepath.Join(sessionArtifactsDir(), "0001", "out.txt")
	for _, p := range []string{conversationPath(), conversationPath() + ".rotating", art} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{conversationPath(), conversationPath() + ".rotating", sessionArtifactsDir()} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived ClearSession", p)
		}
	}
}

// Whatever the agent put where the session directory belongs — a link, a
// file — cannot make a clear fail or keep the artifacts (or a copy an
// earlier sealed kept in conversationDir) on disk; the link's target is
// untouched, and the next Start makes the directory anew.
func TestClearSessionWithALinkOrFileAtTheSessionDir(t *testing.T) {
	for _, plant := range []string{"link", "file"} {
		t.Run(plant, func(t *testing.T) {
			dir := useTempConversationDir(t)
			useTempSessionStateDir(t)
			outside := t.TempDir()
			keep := filepath.Join(outside, conversationFile)
			if err := os.WriteFile(keep, []byte("keep\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			art := filepath.Join(sessionArtifactsDir(), "0001", "out.txt")
			old := filepath.Join(dir, conversationFile+".rotating")
			for _, p := range []string{art, old} {
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if plant == "link" {
				if err := os.Symlink(outside, conversationSessionDir()); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(conversationSessionDir(), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := New().ClearSession(context.Background()); err != nil {
				t.Fatalf("ClearSession with a %s at session/: %v", plant, err)
			}
			for _, p := range []string{conversationSessionDir(), sessionArtifactsDir(), old} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("%s survived ClearSession", p)
				}
			}
			if b, _ := os.ReadFile(keep); string(b) != "keep\n" {
				t.Fatalf("the link's target changed: %q", b)
			}
			if err := prepareSessionDirs(); err != nil {
				t.Fatalf("the next Start cannot prepare the session directory: %v", err)
			}
		})
	}
}

func useTempSessionStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "prime-session")
	prev := sessionStateDir
	sessionStateDir = func() string { return dir }
	t.Cleanup(func() { sessionStateDir = prev })
	return dir
}

// Whatever the agent leaves at the names of the directories Start hands it
// outside primeHome — a link, a file — is replaced with a directory, the
// link's target untouched, so the bridge still starts.
func TestPrepareSessionDirsReplacesLinksAndFiles(t *testing.T) {
	for _, plant := range []string{"link", "file"} {
		t.Run(plant, func(t *testing.T) {
			useTempConversationDir(t)
			useTempSessionStateDir(t)
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("keep\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, at := range []string{conversationSessionDir(), sessionStateDir()} {
				if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
					t.Fatal(err)
				}
				var err error
				if plant == "link" {
					err = os.Symlink(outside, at)
				} else {
					err = os.WriteFile(at, []byte("x"), 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareSessionDirs(); err != nil {
				t.Fatalf("prepareSessionDirs over a %s: %v", plant, err)
			}
			for _, d := range []string{conversationSessionDir(), sessionStateDir()} {
				if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
					t.Fatalf("%s = %v, %v; want a real directory", d, fi, err)
				}
			}
			if ents, _ := os.ReadDir(outside); len(ents) != 1 {
				t.Fatalf("the link's target changed: %v", ents)
			}
		})
	}
}

// The per-session harness state is not in the shared /tmp, where the agent
// could replace its name.
func TestSessionStateDirIsNotInSharedTmp(t *testing.T) {
	if d := sessionStateDir(); strings.HasPrefix(d, "/tmp/") || filepath.Dir(d) != "/root" {
		t.Fatalf("sessionStateDir = %s; want it directly in root's home", d)
	}
}

// A /clear with the session directory gone still removes the SDK's session
// artifacts.
func TestClearSessionWithoutTheSessionDir(t *testing.T) {
	useTempConversationDir(t)
	art := filepath.Join(sessionArtifactsDir(), "0001", "out.txt")
	if err := os.MkdirAll(filepath.Dir(art), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sessionArtifactsDir()); !os.IsNotExist(err) {
		t.Fatalf("session artifacts survived a clear without the session directory: %v", err)
	}
}

// migrateConversation runs on every Start over names the agent controls:
// each collision is reported once, not once per Start.
func TestMigrateConversationLogsEachNameOnce(t *testing.T) {
	dir := useTempConversationDir(t)
	if err := os.MkdirAll(conversationSessionDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s.%06d", conversationFile, i)
		for _, d := range []string{dir, conversationSessionDir()} {
			if err := os.WriteFile(filepath.Join(d, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	migrateConversation()
	before := len(logger.Lines())
	for i := 0; i < 3; i++ {
		migrateConversation()
	}
	if added := len(logger.Lines()) - before; added != 0 {
		t.Fatalf("3 more Starts with %d colliding names logged %d lines", n, added)
	}
}

// RenderSettings does not fail over a directory at models.json, whether it
// writes the registration or removes it.
func TestRenderSettingsOverADirectoryAtModelsJSON(t *testing.T) {
	stubCatalog(t, reasoningModel)
	for name, doc := range map[string]settings.Doc{
		"registered": {Provider: inference.ZGComputeProvider, Model: "glm-5.3"},
		"built-in":   {Provider: "anthropic", Model: "m"},
	} {
		t.Run(name, func(t *testing.T) {
			primeHome = t.TempDir()
			if err := os.MkdirAll(filepath.Join(modelsJSONPath(), "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := New().RenderSettings(context.Background(), settings.Resolve(context.Background(), doc, "sk")); err != nil {
				t.Fatalf("RenderSettings over a directory at models.json: %v", err)
			}
			if fi, err := os.Lstat(modelsJSONPath()); err == nil && fi.IsDir() {
				t.Fatal("the directory at models.json is still there")
			}
		})
	}
}

// Restore makes the role directories real again when the agent replaced
// them with a link, without following it.
func TestRestoreReplacesLinkedRoleDirs(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	ctx := context.Background()
	outside := t.TempDir()
	for _, d := range []string{skillsDir(), harnessStateDir()} {
		if err := os.Symlink(outside, d); err != nil {
			t.Fatal(err)
		}
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "pyproject.toml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := manifest.PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Restore(ctx, "skills/", nil); err != nil {
		t.Fatalf("Restore(skills/): %v", err)
	}
	if err := a.RestoreEntry(ctx, "skills/", "s1/", tarball); err != nil {
		t.Fatalf("RestoreEntry(skills/): %v", err)
	}
	if err := a.Restore(ctx, "harness_state.json", nil); err != nil {
		t.Fatalf("Restore(harness_state.json): %v", err)
	}
	for _, d := range []string{skillsDir(), harnessStateDir()} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s = %v, %v; want a real directory", d, fi, err)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("restore wrote through the link: %v", ents)
	}
}

// The kernel venv probe is cut off at its deadline whatever the venv does,
// and keeps only the tail of its output.
func TestKernelProbeDeadlineAndBoundedOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root: the probe runs as the agent user, from a root-owned directory")
	}
	base, err := os.MkdirTemp("/var/lib", "prime-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(base, "python")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(python, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(python, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := probeTimeout
	probeTimeout = time.Second
	t.Cleanup(func() { probeTimeout = prev })

	write(`i=0; while [ $i -lt 5000 ]; do echo "noise line $i"; i=$((i+1)); done; sleep 60`)
	t0 := time.Now()
	err = probeKernelVenv(context.Background(), python)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("probe past its deadline = %v, want a deadline failure", err)
	}
	if d := time.Since(t0); d > 15*time.Second {
		t.Fatalf("probe returned after %v", d)
	}
	write(`i=0; while [ $i -lt 20000 ]; do echo "noise line $i"; i=$((i+1)); done; echo "No module named rlm"; exit 1`)
	err = probeKernelVenv(context.Background(), python)
	if err == nil || !strings.Contains(err.Error(), "No module named rlm") {
		t.Fatalf("failing probe = %v, want the tail of its output", err)
	}
	if len(err.Error()) > probeOutputMax+512 {
		t.Fatalf("probe output kept in full (%d bytes)", len(err.Error()))
	}
	write(`exit 0`)
	if err := probeKernelVenv(context.Background(), python); err != nil {
		t.Fatalf("working probe = %v", err)
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

// Start prepares the conversation through prepareConversation, which makes
// the session directory and then moves a conversation an earlier sealed
// kept one level up into it: dropping either call would start every
// upgraded container on a fresh conversation, and nothing else would fail.
func TestStartPreparesTheConversation(t *testing.T) {
	calls := func(file, fn string) []string {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
			}
			if name != fn {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok {
						out = append(out, id.Name)
					}
				}
				return true
			})
		}
		return out
	}
	if !slices.Contains(calls("spawn.go", "Adapter.Start"), "prepareConversation") {
		t.Fatal("Adapter.Start does not call prepareConversation")
	}
	got := calls("spawn.go", "prepareConversation")
	if i, j := slices.Index(got, "prepareSessionDirs"), slices.Index(got, "migrateConversation"); i < 0 || j < 0 || i > j {
		t.Fatalf("prepareConversation calls %v; want prepareSessionDirs, then migrateConversation", got)
	}
	// And what it does: a flat legacy conversation ends up in the session
	// directory it creates.
	useTempSessionStateDir(t)
	dir := useTempConversationDir(t)
	if err := os.WriteFile(filepath.Join(dir, conversationFile), []byte("history\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareConversation(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(conversationPath()); err != nil || string(b) != "history\n" {
		t.Fatalf("conversation after prepareConversation = %q, %v", b, err)
	}
}

// A conversation an earlier sealed kept directly in conversationDir had its
// session artifacts (RLM session state, local harness state) next to that
// directory, in root's home: New declares their relocation to where the SDK
// now looks (ReclaimHome performs it at boot, TestReclaimHomeRelocatesDeclaredEntries),
// so after the boot-time steps the resumed conversation finds both its
// transcript and its artifacts, and ClearSession removes both.
func TestLegacySessionArtifactsTravelWithTheConversation(t *testing.T) {
	if got := legacySessionArtifactsDir(); got != "/root/session-artifacts" {
		t.Fatalf("legacySessionArtifactsDir() = %s, want /root/session-artifacts (the SDK's dirname(sessionDir)/session-artifacts for the earlier layout)", got)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "prime.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := false
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "New" {
			return true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "DeclareRelocation" &&
				types.ExprString(call.Args[0]) == "legacySessionArtifactsDir()" && types.ExprString(call.Args[1]) == "sessionArtifactsDir()" {
				declared = true
			}
			return true
		})
		return false
	})
	if !declared {
		t.Fatal("New does not declare privsep.DeclareRelocation(legacySessionArtifactsDir(), sessionArtifactsDir())")
	}

	// The earlier layout, under a stand-in root's home.
	useTempSessionStateDir(t)
	home := filepath.Join(t.TempDir(), "root")
	conv := filepath.Join(home, ".prime-conversation")
	prev := conversationDir
	conversationDir = func() string { return conv }
	t.Cleanup(func() { conversationDir = prev })
	state := filepath.Join(legacySessionArtifactsDir(), "sess-1", "harness", "harness_state.json")
	for p, body := range map[string]string{
		filepath.Join(conv, conversationFile): "history\n",
		state:                                 `{"memories":["mid-task"]}`,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// What ReclaimHome does with the declared relocation, then Start.
	if err := privsep.RenameNoReplace(legacySessionArtifactsDir(), sessionArtifactsDir()); err != nil {
		t.Fatal(err)
	}
	if err := prepareConversation(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(conversationPath()); err != nil || string(b) != "history\n" {
		t.Fatalf("conversation = %q, %v", b, err)
	}
	// The SDK resolves the artifacts next to the session directory.
	sdkArtifacts := filepath.Join(filepath.Dir(conversationSessionDir()), "session-artifacts", "sess-1", "harness", "harness_state.json")
	if b, err := os.ReadFile(sdkArtifacts); err != nil || string(b) != `{"memories":["mid-task"]}` {
		t.Fatalf("harness state where the SDK looks (%s) = %q, %v", sdkArtifacts, b, err)
	}
	if err := New().ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{conversationPath(), sessionArtifactsDir()} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived ClearSession: %v", p, err)
		}
	}
}
