package privsep

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
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
	err := Required()
	if splitAvailable() {
		if err != nil {
			t.Fatalf("Required() = %v with the split available", err)
		}
		return
	}
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
