//go:build linux

package privsep

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// splitAvailable runs credential()'s probe against the real machine so
// assertions adapt to where the tests run (root dev boxes usually lack an
// "agent" user; the runtime images have one). The probe's own decisions
// are pinned machine-independently by TestAgentCredential and
// TestProbeRemediationMatchesCause.
func splitAvailable() bool {
	c, _ := probe(os.Geteuid(), user.Lookup)
	return c != nil
}

func TestDropMatchesAvailability(t *testing.T) {
	cmd := exec.Command("true")
	dropped := Drop(cmd)
	if want := splitAvailable(); dropped != want {
		t.Fatalf("Drop() = %v, want %v (euid=%d)", dropped, want, os.Geteuid())
	}
	if !dropped {
		if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
			t.Fatal("Drop() returned false but set a credential")
		}
		return
	}
	c := cmd.SysProcAttr.Credential
	if c == nil {
		t.Fatal("Drop() returned true but set no credential")
	}
	if c.Uid == 0 {
		t.Fatal("agent credential must not be root")
	}
	if c.Groups == nil {
		t.Fatal("supplementary groups must be an empty slice (dropped), not nil (inherited)")
	}
}

// Every command gets its own copy of the agent credential: changing one
// command's credential changes neither the shared one nor the next command's.
func TestDropGivesEachCommandItsOwnCredential(t *testing.T) {
	c := withAgentCred(t)
	first, second := exec.Command("true"), exec.Command("true")
	if !Drop(first) || !Drop(second) {
		t.Fatal("Drop() = false with a stand-in agent credential")
	}
	if first.SysProcAttr.Credential == c || first.SysProcAttr.Credential == second.SysProcAttr.Credential {
		t.Fatal("Drop() shares one credential between commands")
	}
	first.SysProcAttr.Credential.Uid = 0
	first.SysProcAttr.Credential.Groups = append(first.SysProcAttr.Credential.Groups, 0)
	third := exec.Command("true")
	Drop(third)
	for name, got := range map[string]uint32{"shared": c.Uid, "second": second.SysProcAttr.Credential.Uid, "third": third.SysProcAttr.Credential.Uid} {
		if got != testUID {
			t.Errorf("%s credential uid = %d after another command's was changed, want %d", name, got, testUID)
		}
	}
	if len(c.Groups) != 0 || len(third.SysProcAttr.Credential.Groups) != 0 {
		t.Errorf("supplementary groups leaked between commands: shared %v, third %v", c.Groups, third.SysProcAttr.Credential.Groups)
	}
}

func TestOwnershipHelpersAreNoopsWithoutSplit(t *testing.T) {
	// Must not panic or error regardless of availability; on a machine
	// without the split they are pure no-ops.
	dir := t.TempDir()
	f := dir + "/x"
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	OwnPath(f)
	OwnTree(dir)
	OwnTree(dir + "/does-not-exist") // best-effort: absent tree is fine
}

func TestRequiredFailsClosedWithoutSplit(t *testing.T) {
	if splitAvailable() {
		// With the split, Required also waits for both homes
		// (TestRequiredRefusesUntilSecureHomeSucceeded); stand in for a
		// successful Harden here.
		withHomeState(t, true, nil, true, nil)
		if err := Required(); err != nil {
			t.Fatalf("Required() = %v with the split available and both homes in place", err)
		}
		return
	}
	err := Required()
	if err == nil {
		t.Fatalf("Required() = nil without the split (euid=%d): sealed would provision the key into a container whose framework shares its uid", os.Geteuid())
	}
	if Active() {
		t.Fatal("Active() must agree with Required()")
	}
	// The refusal is all an operator sees (main logs it, nothing else is
	// reported): it must carry the probe's cause-specific remediation.
	if _, why := probe(os.Geteuid(), user.Lookup); !strings.Contains(err.Error(), why) {
		t.Fatalf("Required() = %q, want it to carry the probe's reason %q", err, why)
	}
}

// An agent account whose home in the account database is not the agent's
// home (an earlier base image's /root) is reported with the fix; the right
// home is not.
func TestPasswdHomeNote(t *testing.T) {
	withHome := func(home string) func(string) (*user.User, error) {
		return func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: "999", Gid: "999", HomeDir: home}, nil
		}
	}
	note := passwdHomeNote(withHome("/root"))
	for _, want := range []string{`"/root"`, "usermod --home /home/agent agent", "ssh"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q lacks %q", note, want)
		}
	}
	for _, home := range []string{"/home/agent", "/home/agent/", ""} {
		if note := passwdHomeNote(withHome(home)); note != "" {
			t.Errorf("home %q reported: %q", home, note)
		}
	}
	if note := passwdHomeNote(func(string) (*user.User, error) { return nil, errors.New("no db") }); note != "" {
		t.Errorf("a failed lookup reported: %q", note)
	}
}

func TestAgentCredential(t *testing.T) {
	cases := []struct {
		name     string
		uid, gid string
		euid     int
		wantErr  string // substring; "" = accepted
	}{
		{"normal system account", "999", "999", 0, ""},
		{"uid 0", "0", "999", 0, "uid 0"},
		{"gid 0", "999", "0", 0, "gid 0"},
		{"uid and gid 0", "0", "0", 0, "uid 0"},
		{"uid equals sealed's euid", "1000", "1000", 1000, "sealed's own uid 1000"},
		{"unparsable uid", "agent", "999", 0, "unparsable uid"},
		{"empty gid", "999", "", 0, "unparsable gid"},
		{"negative uid", "-1", "999", 0, "unparsable uid"},
		{"uid wider than 32 bits", "4294967296", "999", 0, "unparsable uid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := agentCredential(tc.uid, tc.gid, tc.euid)
			if tc.wantErr != "" {
				if err == nil || c != nil {
					t.Fatalf("agentCredential(%q, %q, euid=%d) = %+v, %v; want refusal containing %q", tc.uid, tc.gid, tc.euid, c, err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not name the cause %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("agentCredential(%q, %q, euid=%d) refused a usable account: %v", tc.uid, tc.gid, tc.euid, err)
			}
			if c.Uid != 999 || c.Gid != 999 {
				t.Fatalf("credential = uid %d gid %d, want 999/999", c.Uid, c.Gid)
			}
			if c.Groups == nil || len(c.Groups) != 0 {
				t.Fatalf("supplementary groups = %#v, want an empty non-nil slice (dropped, not inherited)", c.Groups)
			}
		})
	}
}

func TestProbeRemediationMatchesCause(t *testing.T) {
	account := func(uid, gid string) func(string) (*user.User, error) {
		return func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: uid, Gid: gid}, nil
		}
	}
	missing := func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
	unreadable := func(string) (*user.User, error) { return nil, errors.New("open /etc/passwd: permission denied") }
	const (
		runAsRoot  = "run sealed as root"
		fixAccount = `fix the image's "agent" account`
		fixDB      = "fix the image's account database"
	)
	cases := []struct {
		name    string
		euid    int
		lookup  func(string) (*user.User, error)
		want    []string // substrings the reason must contain; nil = split available
		wantNot []string // remediations that belong to other causes
	}{
		{"not root", 1000, func(string) (*user.User, error) {
			t.Error("the account lookup must not run when sealed is not root")
			return nil, errors.New("unreachable")
		}, []string{"euid=1000", runAsRoot}, []string{agentUseradd, fixAccount, fixDB}},
		{"no agent user", 0, missing, []string{`no "agent" user`, agentUseradd}, []string{runAsRoot, fixAccount, fixDB}},
		{"account database unreadable", 0, unreadable, []string{"permission denied", fixDB}, []string{runAsRoot, agentUseradd, fixAccount}},
		{"agent is uid 0", 0, account("0", "999"), []string{"uid 0", fixAccount}, []string{runAsRoot, agentUseradd, fixDB}},
		{"agent is gid 0", 0, account("999", "0"), []string{"gid 0", fixAccount}, []string{runAsRoot, agentUseradd, fixDB}},
		{"agent uid unparsable", 0, account("x", "999"), []string{"unparsable uid", fixAccount}, []string{runAsRoot, agentUseradd, fixDB}},
		{"usable agent account", 0, account("999", "999"), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, why := probe(tc.euid, tc.lookup)
			if tc.want == nil {
				if c == nil || why != "" {
					t.Fatalf("probe = %+v, %q; want a credential and no reason", c, why)
				}
				return
			}
			if c != nil || why == "" {
				t.Fatalf("probe = %+v, %q; want no credential and a reason", c, why)
			}
			for _, w := range tc.want {
				if !strings.Contains(why, w) {
					t.Errorf("reason %q missing %q", why, w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(why, w) {
					t.Errorf("reason %q carries another cause's remediation %q", why, w)
				}
			}
		})
	}
}

// A process sealed starts as the agent user cannot gain privileges through
// an exec once HardenSelf has run (no_new_privs, inherited), whichever of
// sealed's threads forks it: a setuid-root binary runs with the agent's
// uid. The fixture is a setuid-root copy of id(1); as a control, the test
// process (which has not run HardenSelf) first shows that the copy does run
// as root. HardenSelf changes the process for good, and can set
// no_new_privs on every thread only in a binary without cgo (as sealed is
// built), so it runs in a CGO_ENABLED=0 build of this test binary
// (TestNoNewPrivsHelper).
func TestAgentProcessesCannotGainPrivileges(t *testing.T) {
	requireRoot(t)
	id, err := exec.LookPath("id")
	if err != nil {
		skipOrFail(t, "no id(1): %v", err)
	}
	body, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	suid := filepath.Join(rootOnlyBase(t), "id-suid")
	if err := os.WriteFile(suid, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	withAgentCred(t)
	if !hasNoNewPrivs(t) {
		cmd, err := AgentCommand(context.Background(), suid, "-u")
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("setuid id as the agent: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != "0" {
			skipOrFail(t, "the setuid fixture does not run as root here (euid %s; a nosuid mount?)", got)
		}
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		skipOrFail(t, "no go toolchain to build the helper: %v", err)
	}
	helperBin := filepath.Join(t.TempDir(), "privsep-nocgo.test")
	build := exec.Command(gobin, "test", "-c", "-o", helperBin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the helper without cgo: %v\n%s", err, out)
	}
	helper := exec.Command(helperBin, "-test.run=^TestNoNewPrivsHelper$", "-test.v")
	helper.Env = append(os.Environ(), "SEALED_NNP_HELPER="+suid)
	out, err := helper.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "EUID=4242") {
		t.Fatalf("after HardenSelf, a setuid-root binary run as the agent reports\n%s\nwant EUID=4242", out)
	}
	if n := strings.Count(string(out), "CHILD NoNewPrivs:\t1"); n != nnpChildren || strings.Contains(string(out), "CHILD NoNewPrivs:\t0") {
		t.Fatalf("after HardenSelf, %d of %d agent processes started from different threads report NoNewPrivs 1:\n%s", n, nnpChildren, out)
	}
}

// nnpChildren is how many agent processes TestNoNewPrivsHelper starts, each
// from a thread of its own.
const nnpChildren = 8

// TestNoNewPrivsHelper is TestAgentProcessesCannotGainPrivileges' child: it
// runs HardenSelf, then the setuid fixture and, from nnpChildren freshly
// started threads, a shell as the stand-in agent, and prints what they
// report.
func TestNoNewPrivsHelper(t *testing.T) {
	suid := os.Getenv("SEALED_NNP_HELPER")
	if suid == "" {
		t.Skip("run by TestAgentProcessesCannotGainPrivileges")
	}
	HardenSelf()
	if set, err := selfState(); !set {
		t.Fatalf("HardenSelf did not set no_new_privs: %v", err)
	}
	withAgentCred(t)
	cmd, err := AgentCommand(context.Background(), suid, "-u")
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("EUID=%s", strings.TrimSpace(string(out)))
	// os/exec forks on the thread the starting goroutine runs on: start
	// each child from a goroutine locked to a thread of its own (never
	// unlocked, so the thread ends with it and the next one is new).
	results := make([]string, nnpChildren)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runtime.LockOSThread()
			sh, err := AgentCommand(context.Background(), "sh", "-c", "grep NoNewPrivs /proc/self/status")
			if err != nil {
				results[i] = err.Error()
				return
			}
			out, err := sh.Output()
			if err != nil {
				results[i] = err.Error()
				return
			}
			results[i] = strings.TrimSpace(string(out))
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		t.Logf("CHILD %s", r)
	}
}

// hasNoNewPrivs reports whether the test process itself already runs with
// no_new_privs (a container started with no-new-privileges, say).
func hasNoNewPrivs(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), "NoNewPrivs:\t1")
}
