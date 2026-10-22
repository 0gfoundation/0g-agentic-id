//go:build linux

package privsep

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
)

// rootOnlyBase makes a directory whose whole chain passes rootOnly. It
// needs root, and a root-only parent: t.TempDir() under /tmp does not
// qualify because /tmp is world-writable.
func rootOnlyBase(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	parent := "/var/lib"
	if err := rootOnly(parent, unix.S_IFDIR); err != nil {
		skipOrFail(t, "%s is not root-only here (%v); cannot build a trusted fixture", parent, err)
	}
	base, err := os.MkdirTemp(parent, "privsep-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func writeExe(t *testing.T, path, body string) {
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

func TestTrustedPATHDropsWritableDirs(t *testing.T) {
	requireRoot(t)
	base := t.TempDir() // under /tmp: world-writable parent, never trusted
	foreign := filepath.Join(base, "foreign")
	open := filepath.Join(base, "open")
	for _, d := range []string{foreign, open} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(foreign, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	trusted, rejected := trustedPATH(foreign + ":" + open + ":relative:/usr/bin")
	if len(trusted) != 1 || trusted[0] != "/usr/bin" {
		t.Fatalf("trusted = %v, want [/usr/bin]", trusted)
	}
	joined := strings.Join(rejected, "\n")
	for _, want := range []string{foreign, open, "relative"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rejected %q does not name %s", joined, want)
		}
	}

	// The same dirs under a root-only base: the 4242-owned and the 0777 one
	// are still refused, a plain root 0755 one is kept.
	rb := rootOnlyBase(t)
	ok := filepath.Join(rb, "ok")
	f2 := filepath.Join(rb, "foreign")
	o2 := filepath.Join(rb, "open")
	for _, d := range []string{ok, f2, o2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chown(f2, 4242, 4242)
	os.Chmod(o2, 0o777)
	trusted, _ = trustedPATH(f2 + ":" + o2 + ":" + ok)
	if len(trusted) != 1 || trusted[0] != ok {
		t.Fatalf("trusted = %v, want [%s]", trusted, ok)
	}
}

func TestLookPathReturnsRealPathFromTrustedDirsOnly(t *testing.T) {
	rb := rootOnlyBase(t)
	trustedBin := filepath.Join(rb, "bin")
	real := filepath.Join(rb, "lib", "tool-real")
	writeExe(t, real, "echo trusted")
	if err := os.MkdirAll(trustedBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../lib/tool-real", filepath.Join(trustedBin, "tool")); err != nil {
		t.Fatal(err)
	}
	// An agent-owned directory ahead of it on PATH, holding a stub.
	agentBin := filepath.Join(rb, "agentbin")
	writeExe(t, filepath.Join(agentBin, "tool"), "echo agent")
	if err := os.Chown(agentBin, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", agentBin+":"+trustedBin)

	got, err := LookPath("tool")
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("LookPath = %q, want the resolved %q", got, real)
	}
	cmd, err := RootCommand(context.Background(), "tool")
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "trusted" {
		t.Fatalf("RootCommand ran %q (%v), want the trusted binary", out, err)
	}

	// A binary in a trusted dir that is itself writable by others is skipped.
	writeExe(t, filepath.Join(trustedBin, "loose"), "echo loose")
	os.Chmod(filepath.Join(trustedBin, "loose"), 0o777)
	if _, err := LookPath("loose"); !errors.Is(err, fs.ErrNotExist) && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("LookPath(loose) = %v, want not found", err)
	}
	if _, err := LookPath("../x"); err == nil {
		t.Fatal("LookPath accepted a path")
	}
	if _, err := RootCommand(context.Background(), filepath.Join(agentBin, "tool")); err == nil {
		t.Fatal("RootCommand accepted an absolute path under an agent-owned dir")
	}
}

func TestRootCommandEnvAndDir(t *testing.T) {
	t.Setenv("SEALED_TEST_CANARY", "must-not-pass")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	t.Setenv("no_proxy", "localhost")
	// The container environment does not choose what root installs or
	// which certificates it trusts.
	for _, k := range []string{
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
		"NPM_CONFIG_REGISTRY", "npm_config_registry", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "PIP_INDEX_URL",
	} {
		t.Setenv(k, "/root/.openclaw/workspace/x")
	}
	t.Setenv("SANDBOX_SEAL_KEY", "secret")
	t.Setenv("TMPDIR", "/tmp")
	cmd, err := RootCommand(context.Background(), "sh", "-c", "true")
	if err != nil {
		skipOrFail(t, "no root-only sh or temporary directory on this machine: %v", err)
	}
	if cmd.Dir != "/" {
		t.Fatalf("Dir = %q, want /", cmd.Dir)
	}
	want := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "HTTPS_PROXY": true, "no_proxy": true}
	for _, kv := range cmd.Env {
		k, v, _ := strings.Cut(kv, "=")
		if !want[k] {
			t.Errorf("unexpected env %s", kv)
		}
		delete(want, k)
		if k == "HOME" && v != rootHome {
			t.Errorf("HOME = %q, want %q", v, rootHome)
		}
		if k == "TMPDIR" && v != rootTmpDir {
			t.Errorf("TMPDIR = %q, want the root-only %q", v, rootTmpDir)
		}
		if k == "PATH" && v != strings.Join(TrustedPATH(), ":") {
			t.Errorf("PATH = %q, want the trusted PATH", v)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing env: %v", want)
	}
	if cmd.Args[0] != "sh" || !filepath.IsAbs(cmd.Path) {
		t.Errorf("Args[0]=%q Path=%q; want the bare name and the resolved path", cmd.Args[0], cmd.Path)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Error("RootCommand must not drop privileges")
	}
}

func TestAgentCommandDropsExactlyWhenSplitActive(t *testing.T) {
	check := func(t *testing.T, wantDrop bool, wantHome, wantDir string) {
		t.Helper()
		cmd, err := AgentCommand(context.Background(), "sh", "-c", "true")
		if err != nil {
			skipOrFail(t, "no root-only sh on this machine: %v", err)
		}
		dropped := cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil
		if dropped != wantDrop {
			t.Fatalf("credential set = %v, want %v", dropped, wantDrop)
		}
		if len(cmd.Env) != 2 || !strings.HasPrefix(cmd.Env[0], "PATH=") || cmd.Env[1] != "HOME="+wantHome {
			t.Fatalf("Env = %v, want exactly PATH and HOME=%s", cmd.Env, wantHome)
		}
		if cmd.Dir != wantDir {
			t.Fatalf("Dir = %q, want %q", cmd.Dir, wantDir)
		}
	}
	// On this machine as it is (Harden has not run: no prepared home).
	withHomeState(t, false, nil, false, nil)
	if splitAvailable() {
		check(t, true, agentHomeDir, "/")
	} else {
		check(t, false, rootHome, "/")
	}
	// With an agent account standing in: the drop and the agent's HOME, and
	// its home as the working directory once it has been prepared, whatever
	// the machine.
	c := withAgentCred(t)
	check(t, true, agentHomeDir, "/")
	withHomeState(t, true, nil, true, nil)
	check(t, true, agentHomeDir, agentHomeDir)
	if got := AgentHome(); got != agentHomeDir {
		t.Fatalf("AgentHome() = %q with the split active, want %q", got, agentHomeDir)
	}
	cmd, _ := AgentCommand(context.Background(), "sh")
	if cred := cmd.SysProcAttr.Credential; cred.Uid != c.Uid || cred.Gid != c.Gid || cred.Groups == nil {
		t.Fatalf("credential = %+v, want the agent's with supplementary groups dropped", cred)
	}
	// Absolute paths are taken as-is (the agent may only hurt itself).
	abs, err := AgentCommand(context.Background(), "/nonexistent/python", "-V")
	if err != nil || abs.Path != "/nonexistent/python" {
		t.Fatalf("absolute AgentCommand: %v, %v", abs, err)
	}
}

// Sweep ends the processes matching its pattern that the agent user could
// signal itself: an agent-uid match is killed and a root process with the
// same command line is left alone.
func TestSweepReachesOnlyAgentProcesses(t *testing.T) {
	withAgentHome(t)
	withAgentCred(t)
	marker := fmt.Sprintf("300.%06d", os.Getpid()%1000000)
	start := func(cmd *exec.Cmd) chan error {
		t.Helper()
		if err := cmd.Start(); err != nil {
			t.Fatalf("cannot start sleep: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		return done
	}
	target, err := AgentCommand(context.Background(), "sleep", marker)
	if err != nil {
		skipOrFail(t, "no root-only sleep: %v", err)
	}
	if _, err := LookPath("pkill"); err != nil {
		skipOrFail(t, "no root-only pkill: %v", err)
	}
	targetDone := start(target)
	rootDone := start(exec.Command(target.Path, marker))
	time.Sleep(100 * time.Millisecond)

	Sweep("sleep " + marker)

	select {
	case <-targetDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Sweep left the matching agent process running")
	}
	select {
	case <-rootDone:
		t.Fatal("Sweep ended a root process")
	case <-time.After(300 * time.Millisecond):
	}
}

// Harden secures root's home, prepares the agent's home and reclaims root's
// home exactly when the split is active, in that order (reclaiming moves
// entries into the prepared home), and runs every step even when an
// earlier one failed (Required refuses either way).
func TestHardenSecuresHomeOnlyWithSplit(t *testing.T) {
	for _, active := range []bool{false, true} {
		var listed bool
		var order []string
		harden(func() []string { order = append(order, "scrub"); return nil },
			func() bool { return active },
			func() { order = append(order, "self") },
			func() error { order = append(order, "secure"); return nil },
			func() error { order = append(order, "prepare"); return nil },
			func() error { order = append(order, "reclaim"); return nil },
			func() []string { listed = true; return nil })
		// sealed's own CA locations are checked first, before anything
		// else runs, with or without the split.
		want := "scrub,self"
		if active {
			want += ",secure,prepare,reclaim"
		}
		if got := strings.Join(order, ","); got != want || listed != active {
			t.Errorf("active=%v: steps %q listed=%v, want %q listed=%v", active, got, listed, want, active)
		}
	}
	var prepared, reclaimed bool
	harden(func() []string { return nil }, func() bool { return true }, func() {}, func() error { return errors.New("simulated") },
		func() error { prepared = true; return nil },
		func() error { reclaimed = true; return nil },
		func() []string { return nil })
	if !prepared || !reclaimed {
		t.Error("a later step was skipped after root's home failed; Required must report the first failure, not stop the rest")
	}
}

// Harden, main's only boot hook, hands harden the real steps in their
// order: TestHardenSecuresHomeOnlyWithSplit checks what harden does with
// them, this checks that Harden passes them (dropping ScrubTrustEnv, say,
// would leave sealed's TLS trusting a CA file the agent can write, and
// dropping ScrubTimeEnv would let its first log line read a zone file the
// agent can write).
func TestHardenWiresEveryStep(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "home.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// callsIn lists, as source text, the arguments of the calls to callee
	// in fn's body, or the callees called there when callee is "".
	callsIn := func(fn, callee string) []string {
		var got []string
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, isID := call.Fun.(*ast.Ident)
				switch {
				case callee == "" && isID && id.Name != "append":
					got = append(got, id.Name)
				case isID && id.Name == callee:
					for _, a := range call.Args {
						got = append(got, types.ExprString(a))
					}
					return false
				}
				return true
			})
		}
		return got
	}
	got := callsIn("Harden", "harden")
	want := "scrubOwnEnv,Active,HardenSelf,SecureHome,PrepareAgentHome,ReclaimHome,UntrustedPATH"
	if strings.Join(got, ",") != want {
		t.Fatalf("Harden calls harden(%s), want harden(%s)", strings.Join(got, ", "), strings.ReplaceAll(want, ",", ", "))
	}
	if got := strings.Join(callsIn("scrubOwnEnv", ""), ","); got != "ScrubTimeEnv,ScrubTrustEnv" {
		t.Fatalf("scrubOwnEnv calls %s, want ScrubTimeEnv,ScrubTrustEnv", got)
	}
}

// Required refuses until both homes are in place: a boot path that never
// ran Harden is refused, not treated as hardened, and each failure is
// reported with its cause. The split is stood in for, so the gate's key
// branch runs on every machine.
func TestRequiredRefusesUntilSecureHomeSucceeded(t *testing.T) {
	withAgentCred(t)
	cases := []struct {
		name            string
		secured, ready  bool
		secErr, prepErr error
		want            string // substring; "" = nil
	}{
		{"nothing ran", false, false, nil, nil, "has not been made root-only"},
		{"root's home failed", false, false, errors.New("simulated-root"), nil, "simulated-root"},
		{"agent home never prepared", true, false, nil, nil, "has not been prepared"},
		{"agent home failed", true, false, nil, errors.New("simulated-agent"), "simulated-agent"},
		{"both in place", true, true, nil, nil, ""},
	}
	t.Run("root's home not reclaimed", func(t *testing.T) {
		withHomeState(t, true, nil, true, nil)
		withReclaimState(t, false, nil)
		if err := Required(); err == nil || !strings.Contains(err.Error(), "ReclaimHome did not run") {
			t.Fatalf("Required() = %v, want the missing reclaim reported", err)
		}
		withReclaimState(t, false, errors.New("simulated-reclaim"))
		if err := Required(); err == nil || !strings.Contains(err.Error(), "simulated-reclaim") {
			t.Fatalf("Required() = %v, want the reclaim failure reported", err)
		}
	})
	t.Run("no_new_privs not set", func(t *testing.T) {
		withHomeState(t, true, nil, true, nil)
		withSelfState(t, false, nil)
		if err := Required(); err == nil || !strings.Contains(err.Error(), "HardenSelf did not run") {
			t.Fatalf("Required() = %v, want the missing no_new_privs reported", err)
		}
		withSelfState(t, false, errors.New("simulated-nnp"))
		if err := Required(); err == nil || !strings.Contains(err.Error(), "simulated-nnp") {
			t.Fatalf("Required() = %v, want the no_new_privs failure reported", err)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHomeState(t, tc.secured, tc.secErr, tc.ready, tc.prepErr)
			err := Required()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Required() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Required() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// RootDir accepts only a root-only working directory.
func TestRootDirRequiresARootOnlyDirectory(t *testing.T) {
	cmd := exec.Command("true")
	if err := RootDir(cmd, t.TempDir()); err == nil {
		t.Fatalf("RootDir accepted a directory under the shared temporary directory (Dir=%q)", cmd.Dir)
	}
	if cmd.Dir != "" {
		t.Fatalf("a refused RootDir still set Dir = %q", cmd.Dir)
	}
	if err := rootOnly("/", unix.S_IFDIR); err != nil {
		skipOrFail(t, "/ is not root-only here: %v", err)
	}
	if err := RootDir(cmd, "/"); err != nil || cmd.Dir != "/" {
		t.Fatalf("RootDir(/) = %v, Dir=%q", err, cmd.Dir)
	}
	// A relative directory is refused, even from a root-only working
	// directory, and the check returns: rootOnly's walk up from a relative
	// path would end at ".", never at "/".
	t.Chdir("/")
	done := make(chan error, 2)
	go func() {
		done <- rootOnly("usr", unix.S_IFDIR)
		done <- RootDir(exec.Command("true"), "usr")
	}()
	for _, what := range []string{`rootOnly("usr")`, `RootDir("usr")`} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s from / accepted a relative path", what)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s from / did not return", what)
		}
	}
}

// RootCommand and TempDir refuse a temporary directory, or a directory
// above it, that another uid could write: MkdirAll does not change an
// existing directory's mode or owner, so the check is what keeps root's
// toolchains out of a shared one.
func TestRootTempRefusesADirectoryOthersCanWrite(t *testing.T) {
	cases := map[string]func(t *testing.T, base, tmp string){
		"fresh": func(t *testing.T, base, tmp string) {},
		"tmp 0777": func(t *testing.T, base, tmp string) {
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tmp, 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"tmp foreign-owned": func(t *testing.T, base, tmp string) {
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(tmp, testUID, testUID); err != nil {
				t.Fatal(err)
			}
		},
		"parent group-writable": func(t *testing.T, base, tmp string) {
			if err := os.Chmod(base, 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"tmp a link": func(t *testing.T, base, tmp string) {
			if err := os.Mkdir(tmp+"-real", 0o700); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, tmp+"-real", tmp)
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			base := rootOnlyBase(t)
			tmp := filepath.Join(base, "tmp")
			prev := rootTmpDir
			rootTmpDir = tmp
			t.Cleanup(func() { rootTmpDir = prev })
			plant(t, base, tmp)

			_, cmdErr := RootCommand(context.Background(), "sh", "-c", "true")
			d, tdErr := TempDir("t-")
			if name == "fresh" {
				if cmdErr != nil || tdErr != nil {
					t.Fatalf("RootCommand = %v, TempDir = %v; want both to work in a fresh root-only directory", cmdErr, tdErr)
				}
				if filepath.Dir(d) != tmp {
					t.Fatalf("TempDir = %q, want a directory under %s", d, tmp)
				}
				return
			}
			if cmdErr == nil {
				t.Error("RootCommand accepted a temporary directory another uid can write")
			}
			if tdErr == nil {
				t.Errorf("TempDir accepted a temporary directory another uid can write (made %s)", d)
			}
		})
	}
}

func TestTempDirIsRootOnly(t *testing.T) {
	requireRoot(t)
	if err := rootOnly("/var/lib", unix.S_IFDIR); err != nil {
		skipOrFail(t, "/var/lib is not root-only here: %v", err)
	}
	d, err := TempDir("t-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	if filepath.Dir(d) != rootTmpDir {
		t.Fatalf("TempDir = %q, want a directory under %s", d, rootTmpDir)
	}
	if err := rootOnly(d, unix.S_IFDIR); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(d)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("TempDir mode = %v (%v), want 0700", fi.Mode(), err)
	}
}

func TestSecureHome(t *testing.T) {
	requireRoot(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if err := secureHome(home); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(home)
	if err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, home); uid != 0 || fi.Mode().Perm() != 0o711 {
		t.Fatalf("home = uid %d mode %o, want 0 and 0711", uid, fi.Mode().Perm())
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chown(target, 4242, 4242)
	link := filepath.Join(filepath.Dir(home), "linkhome")
	mustSymlink(t, target, link)
	wantUnsafe(t, "secureHome(link)", secureHome(link))
	if uid := ownerOf(t, target); uid != 4242 {
		t.Fatal("secureHome followed a link")
	}
}

// sealed's own log lives in its root-only state directory, not the shared
// /tmp.
func TestBootstrapLogIsUnderStateDir(t *testing.T) {
	if !strings.HasPrefix(logger.LogPath, StateDir+"/") {
		t.Fatalf("logger.LogPath = %q, want it under %s", logger.LogPath, StateDir)
	}
}
