package privsep

import (
	"os"
	"os/exec"
	"os/user"
	"testing"
)

// splitAvailable mirrors credential()'s probe so assertions adapt to the
// machine the tests run on (root dev boxes usually lack an "agent" user;
// the runtime images have one).
func splitAvailable() bool {
	if os.Geteuid() != 0 {
		return false
	}
	_, err := user.Lookup(agentUsername)
	return err == nil
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
