//go:build linux

package privsep

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func modeOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// PrepareAgentHome creates the parent root:root 0755 and the home
// agent:agent 0700, takes over an existing home, and refuses a link at
// either without touching the link's target.
func TestPrepareAgentHome(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	home := filepath.Join(base, "home", "agent")
	if err := prepareAgentHome(home, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, filepath.Dir(home)); uid != 0 || modeOf(t, filepath.Dir(home)).Perm() != 0o755 {
		t.Fatalf("parent = uid %d mode %v, want root 0755", uid, modeOf(t, filepath.Dir(home)))
	}
	if uid := ownerOf(t, home); uid != testUID || modeOf(t, home).Perm() != 0o700 {
		t.Fatalf("home = uid %d mode %v, want %d 0700", uid, modeOf(t, home), testUID)
	}
	// An existing home with the wrong owner and mode is taken over.
	if err := os.Chown(home, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareAgentHome(home, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, home); uid != testUID || modeOf(t, home).Perm() != 0o700 {
		t.Fatalf("existing home = uid %d mode %v, want %d 0700", uid, modeOf(t, home), testUID)
	}
	// A link where the home (or its parent) should be is refused.
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	linkHome := filepath.Join(base, "home", "linked")
	mustSymlink(t, target, linkHome)
	wantUnsafe(t, "prepareAgentHome(link)", prepareAgentHome(linkHome, testUID, testUID))
	linkParent := filepath.Join(base, "linkparent")
	mustSymlink(t, filepath.Join(base, "home"), linkParent)
	wantUnsafe(t, "prepareAgentHome(under a link)", prepareAgentHome(filepath.Join(linkParent, "agent2"), testUID, testUID))
	if uid := ownerOf(t, target); uid != 0 || modeOf(t, target).Perm() != 0o755 {
		t.Fatal("prepareAgentHome changed a link's target")
	}
}

// LinkAgentHome links a framework tree into the agent's home, creates the
// directories above the link agent-owned, accepts an existing identical
// link and leaves anything else at the name alone.
func TestLinkAgentHome(t *testing.T) {
	requireRoot(t)
	home := filepath.Join(t.TempDir(), "agent")
	if err := prepareAgentHome(home, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := linkAgentHome(home, ".openclaw", "/root/.openclaw"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(filepath.Join(home, ".openclaw")); err != nil || got != "/root/.openclaw" {
		t.Fatalf("link = %q, %v", got, err)
	}
	if err := linkAgentHome(home, ".openclaw", "/root/.openclaw"); err != nil {
		t.Fatalf("relinking the same target: %v", err)
	}
	if err := linkAgentHome(home, ".prime/agent", "/root/.prime/agent"); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, filepath.Join(home, ".prime")); uid != testUID {
		t.Fatalf(".prime owner = %d, want %d", uid, testUID)
	}
	// The agent's own entry at the name stays.
	mine := filepath.Join(home, ".hermes")
	if err := os.Mkdir(mine, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := linkAgentHome(home, ".hermes", "/root/.hermes"); err == nil {
		t.Fatal("linkAgentHome replaced an existing entry")
	}
	if !modeOf(t, mine).IsDir() {
		t.Fatal("the agent's entry was replaced")
	}
	for _, bad := range []string{"", "/abs", "../x", "a/../b", "."} {
		if err := linkAgentHome(home, bad, "/root/x"); err == nil {
			t.Errorf("linkAgentHome(%q) accepted", bad)
		}
	}
	// A linked directory on the way is refused, not followed.
	outside := t.TempDir()
	mustSymlink(t, outside, filepath.Join(home, ".dshdir"))
	wantUnsafe(t, "link under a linked dir", linkAgentHome(home, ".dshdir/x", "/root/.dsh"))
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("a link was created through a linked directory")
	}
}

// BoundedOutput keeps only the tail of a command's output and returns once
// its context ends, even when a descendant keeps the output pipe open.
func TestBoundedOutput(t *testing.T) {
	cmd := exec.Command("sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo line$i; i=$((i+1)); done")
	out, err := BoundedOutput(cmd, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 64+len("…") || !strings.HasPrefix(string(out), "…") || !strings.HasSuffix(string(out), "line1999\n") {
		t.Fatalf("output = %q, want the last 64 bytes marked as truncated", out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	slow := exec.CommandContext(ctx, "sh", "-c", "sleep 30 & echo started; wait")
	slow.WaitDelay = 500 * time.Millisecond
	t0 := time.Now()
	_, err = BoundedOutput(slow, 1<<10)
	if err == nil {
		t.Fatal("a command past its deadline reported success")
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("BoundedOutput returned after %v; a leftover descendant held it", d)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("ctx.Err() = %v", ctx.Err())
	}
}

// Harden's agent home is what AgentCommand runs in: an agent process
// started through it has the agent's HOME and starts there.
func TestAgentCommandRunsInTheAgentHome(t *testing.T) {
	home := withAgentHome(t)
	withAgentCred(t)
	withHomeState(t, true, nil, true, nil)
	cmd, err := AgentCommand(context.Background(), "sh", "-c", `echo "$HOME"; pwd; id -u`)
	if err != nil {
		skipOrFail(t, "no root-only sh: %v", err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := home + "\n" + home + "\n4242\n"
	if string(out) != want {
		t.Fatalf("agent process reports %q, want %q", out, want)
	}
}

// ReclaimHome moves out of root's home what an earlier sealed let the agent
// leave there (an agent-owned ~/.npmrc root's npm would read, a directory,
// a link, a root-owned entry others or a non-root group can write), into
// the agent's home
// without replacing anything there, and leaves root's own entries and the
// declared framework trees where they are.
func TestReclaimHomeMovesWhatTheAgentLeft(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	home := filepath.Join(base, "root")
	agent := filepath.Join(base, "agent")
	for _, d := range []string{home, agent} {
		if err := os.Mkdir(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	plantAs := func(name string, uid, gid int, mode fs.FileMode, dir bool) {
		t.Helper()
		p := filepath.Join(home, name)
		var err error
		if dir {
			err = os.Mkdir(p, mode)
		} else {
			err = os.WriteFile(p, []byte(name), mode)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(p, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	plant := func(name string, uid int, mode fs.FileMode, dir bool) {
		t.Helper()
		plantAs(name, uid, uid, mode, dir)
	}
	plant(".npmrc", testUID, 0o644, false)      // agent-owned config
	plant(".npm-global", testUID, 0o755, true)  // agent-owned directory
	plant(".cache", 0, 0o777, true)             // root's, but anyone can write it
	plant(".profile", 0, 0o644, false)          // root's own: stays
	plant(".nvm", 0, 0o755, true)               // root's own: stays
	plant(".openclaw", testUID, 0o755, true)    // a declared tree: stays
	plantAs(".config", 0, testUID, 0o775, true) // root's, but its group (not root's) can write it
	plantAs(".local", 0, 0, 0o775, true)        // root's, writable only by root's group: stays
	mustSymlink(t, "/etc/passwd", filepath.Join(home, ".gitconfig"))
	if err := os.Lchown(filepath.Join(home, ".gitconfig"), testUID, testUID); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "/nonexistent", filepath.Join(home, ".hermes")) // a declared name, not a directory
	if err := os.Lchown(filepath.Join(home, ".hermes"), testUID, testUID); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(agent, ".npmrc"), "the agent's own") // taken: moved beside it

	keep := []string{".hermes", ".openclaw"}
	if err := reclaimHome(home, agent, keep, nil); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if got := strings.Join(left, ","); got != ".local,.nvm,.openclaw,.profile" {
		t.Fatalf("root's home holds %s, want .local,.nvm,.openclaw,.profile", got)
	}
	for name, want := range map[string]string{
		".npmrc":           "the agent's own",
		".npmrc.from-root": ".npmrc",
	} {
		if got := readBack(t, filepath.Join(agent, name)); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{".npm-global", ".cache", ".config", ".gitconfig", ".hermes.from-root"} {
		if _, err := os.Lstat(filepath.Join(agent, name)); err != nil {
			t.Errorf("%s not moved into the agent's home: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(agent, ".hermes")); !os.IsNotExist(err) {
		t.Errorf("a declared name was moved to its own name in the agent's home, where its link belongs: %v", err)
	}
	if got := readBack(t, "/etc/passwd"); !strings.Contains(got, "root") {
		t.Fatal("a moved link's target changed")
	}
	// A second boot finds nothing left to move.
	if err := reclaimHome(home, agent, keep, nil); err != nil {
		t.Fatal(err)
	}
	// An entry that cannot be moved is reported, so Required refuses.
	plant(".bashrc", testUID, 0o644, false)
	if err := reclaimHome(home, filepath.Join(base, "missing"), keep, nil); err == nil || !strings.Contains(err.Error(), ".bashrc") {
		t.Fatalf("reclaimHome into a missing home = %v, want the entry reported", err)
	}
}

// An entry an adapter declared a relocation for moves to its new place
// inside a declared tree, without following a link or replacing anything;
// when its destination is taken, or its parent is missing, it goes into
// the agent's home like any other entry.
func TestReclaimHomeRelocatesDeclaredEntries(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	home := filepath.Join(base, "root")
	agent := filepath.Join(base, "agent")
	conv := filepath.Join(home, ".prime-conversation")
	for _, d := range []string{home, agent, conv} {
		if err := os.Mkdir(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(home, "session-artifacts", "sess-1", "harness", "harness_state.json")
	mustWrite(t, state, `{"memories":["mid-task"]}`)
	for _, p := range []string{filepath.Join(home, "session-artifacts"), filepath.Join(home, "session-artifacts", "sess-1"), filepath.Join(home, "session-artifacts", "sess-1", "harness"), state, conv} {
		if err := os.Lchown(p, testUID, testUID); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(home, "other"), "x")
	if err := os.Lchown(filepath.Join(home, "other"), testUID, testUID); err != nil {
		t.Fatal(err)
	}
	keep := []string{".prime-conversation"}
	relocate := map[string]string{
		"session-artifacts": filepath.Join(conv, "session-artifacts"),
		"other":             filepath.Join(base, "missing", "other"), // parent missing: falls back
	}
	if err := reclaimHome(home, agent, keep, relocate); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, filepath.Join(conv, "session-artifacts", "sess-1", "harness", "harness_state.json")); got != `{"memories":["mid-task"]}` {
		t.Fatalf("relocated harness state = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(home, "session-artifacts")); !os.IsNotExist(err) {
		t.Fatalf("the legacy entry is still in root's home: %v", err)
	}
	if got := readBack(t, filepath.Join(agent, "other")); got != "x" {
		t.Fatalf("an entry whose relocation failed was not moved into the agent's home: %q", got)
	}
	// A destination already taken is never replaced.
	mustWrite(t, filepath.Join(home, "session-artifacts", "new"), "later")
	if err := os.Lchown(filepath.Join(home, "session-artifacts"), testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := reclaimHome(home, agent, keep, relocate); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(conv, "session-artifacts", "sess-1")); err != nil {
		t.Fatalf("the relocated entry was replaced: %v", err)
	}
	if got := readBack(t, filepath.Join(agent, "session-artifacts", "new")); got != "later" {
		t.Fatalf("an entry whose destination was taken did not go to the agent's home: %q", got)
	}
}

// DeclareRelocation records relocations by their name in root's home.
func TestDeclaredRelocations(t *testing.T) {
	treesMu.Lock()
	prev := relocated
	relocated = nil
	treesMu.Unlock()
	t.Cleanup(func() {
		treesMu.Lock()
		relocated = prev
		treesMu.Unlock()
	})
	DeclareRelocation("/root/session-artifacts", "/root/.prime-conversation/session-artifacts")
	DeclareRelocation("/elsewhere/x", "/root/y")
	got := relocations("/root")
	if len(got) != 1 || got["session-artifacts"] != "/root/.prime-conversation/session-artifacts" {
		t.Fatalf("relocations = %v", got)
	}
}

// declaredTrees gives the declared trees inside root's home relative to
// it, nested ones whole.
func TestDeclaredTrees(t *testing.T) {
	treesMu.Lock()
	prev := declared
	declared = nil
	treesMu.Unlock()
	t.Cleanup(func() {
		treesMu.Lock()
		declared = prev
		treesMu.Unlock()
	})
	for _, p := range []string{"/root/.openclaw", "/root/.prime/agent", "/root/.prime-session", "/tmp/elsewhere", "/root", "/rootish/x"} {
		DeclareTree(p)
	}
	if got := strings.Join(declaredTrees("/root"), ","); got != ".openclaw,.prime-session,.prime/agent" {
		t.Fatalf("declaredTrees = %s, want .openclaw,.prime-session,.prime/agent", got)
	}
}

// A tree declared below a directory of root's home (prime's
// /root/.prime/agent) stays, with what is in it, but the directory above
// it is root's: one another uid owns is made root:root 0755 in place
// (moving it would take the tree along), what else it holds that another
// uid could have changed is moved out, and a link at its name is moved
// out like any other entry.
func TestReclaimHomeSecuresTheDirectoryAboveANestedTree(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	home := filepath.Join(base, "root")
	agent := filepath.Join(base, "agent")
	for _, d := range []string{home, agent} {
		if err := os.Mkdir(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	prime := filepath.Join(home, ".prime")
	venv := filepath.Join(prime, "agent", "kernel-venv", "python")
	mustWrite(t, venv, "baked")
	mustWrite(t, filepath.Join(prime, "stray"), "planted")
	for _, p := range []string{prime, filepath.Join(prime, "agent"), filepath.Join(prime, "stray")} {
		if err := os.Lchown(p, testUID, testUID); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(prime, 0o777); err != nil {
		t.Fatal(err)
	}
	trees := []string{".prime/agent"}
	if err := reclaimHome(home, agent, trees, nil); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, prime); uid != 0 || modeOf(t, prime).Perm() != 0o755 {
		t.Fatalf("%s = uid %d mode %v, want root 0755", prime, uid, modeOf(t, prime))
	}
	if got := readBack(t, venv); got != "baked" {
		t.Fatalf("the declared tree's content = %q, want it kept", got)
	}
	if uid := ownerOf(t, filepath.Join(prime, "agent")); uid != testUID {
		t.Fatalf("the declared tree's owner = %d, want the agent's %d (it is the agent's by design)", uid, testUID)
	}
	if _, err := os.Lstat(filepath.Join(prime, "stray")); !os.IsNotExist(err) {
		t.Fatalf("an agent-owned entry beside the tree stayed: %v", err)
	}
	if got := readBack(t, filepath.Join(agent, "stray")); got != "planted" {
		t.Fatalf("the moved entry = %q", got)
	}
	// A second boot leaves it all as it is.
	if err := reclaimHome(home, agent, trees, nil); err != nil {
		t.Fatal(err)
	}
	// A link at the directory's name is moved out, not to its own name in
	// the agent's home (where the link to the tree goes).
	if err := os.RemoveAll(prime); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, t.TempDir(), prime)
	if err := os.Lchown(prime, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := reclaimHome(home, agent, trees, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(prime); !os.IsNotExist(err) {
		t.Fatalf("a link at the directory's name stayed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(agent, ".prime.from-root")); err != nil {
		t.Fatalf("the link was not moved beside the agent's own name: %v", err)
	}
}

// aclXattr encodes a POSIX ACL as the kernel keeps it in an extended
// attribute; entries are (tag, perm, id) and must be in the kernel's
// order (by tag, then id).
func aclXattr(entries ...[3]uint32) []byte {
	b := []byte{2, 0, 0, 0}
	for _, e := range entries {
		b = append(b, byte(e[0]), byte(e[0]>>8), byte(e[1]), byte(e[1]>>8), byte(e[2]), byte(e[2]>>8), byte(e[2]>>16), byte(e[2]>>24))
	}
	return b
}

const aclUndefined = 0xffffffff

// namedWriterACL gives uid rwx through a named entry, with a mask that
// lets it write.
func namedWriterACL(uid uint32) []byte {
	return aclXattr(
		[3]uint32{0x01, 7, aclUndefined},
		[3]uint32{aclTagUser, 7, uid},
		[3]uint32{aclTagGroupObj, 5, aclUndefined},
		[3]uint32{aclTagMask, 7, aclUndefined},
		[3]uint32{aclTagOther, 5, aclUndefined},
	)
}

// setACL sets an ACL xattr, skipping (or, strict, failing) where the
// filesystem has no ACL support.
func setACL(t *testing.T, p, attr string, acl []byte) {
	t.Helper()
	if err := unix.Setxattr(p, attr, acl, 0); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			skipOrFail(t, "no POSIX ACL support under %s: %v", p, err)
		}
		t.Fatalf("setxattr %s on %s: %v", attr, p, err)
	}
}

// A default ACL the agent set on root's home while an earlier sealed let
// it own it would hand everything root later creates there to the agent
// (inherited, with the umask ignored); SecureHome removes it, and an
// access ACL, along with the owner and mode.
func TestSecureHomeRemovesACLs(t *testing.T) {
	requireRoot(t)
	home := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	setACL(t, home, aclDefaultXattr, namedWriterACL(testUID))
	setACL(t, home, aclAccessXattr, namedWriterACL(testUID))
	if err := os.Chown(home, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := secureHome(home); err != nil {
		t.Fatal(err)
	}
	for _, attr := range []string{aclDefaultXattr, aclAccessXattr} {
		if _, err := unix.Getxattr(home, attr, make([]byte, 256)); err != unix.ENODATA {
			t.Errorf("%s after secureHome: err = %v, want ENODATA (removed)", attr, err)
		}
	}
	if uid := ownerOf(t, home); uid != 0 || modeOf(t, home).Perm() != 0o711 {
		t.Fatalf("home = uid %d mode %v, want root 0711", uid, modeOf(t, home))
	}
	// What root creates there afterwards is root's alone.
	cache := filepath.Join(home, ".npm")
	if err := os.Mkdir(cache, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Getxattr(cache, aclAccessXattr, make([]byte, 256)); err != unix.ENODATA {
		t.Fatalf("a directory root created in the secured home has an ACL: %v", err)
	}
}

// ReclaimHome moves out an entry of root's home that is root's by owner and
// mode but carries an ACL another uid can write through — a root-owned
// file whose access ACL names the agent (its group bits are then the mask,
// not root's group), or a directory whose default ACL would hand the agent
// what root later creates in it — and leaves one whose ACL grants another
// uid no write, or names only root.
func TestReclaimHomeMovesEntriesWithForeignACLs(t *testing.T) {
	requireRoot(t)
	base := t.TempDir()
	home := filepath.Join(base, "root")
	agent := filepath.Join(base, "agent")
	for _, d := range []string{home, agent} {
		if err := os.Mkdir(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	named := filepath.Join(home, ".npmrc")
	mustWrite(t, named, "registry=x")
	setACL(t, named, aclAccessXattr, namedWriterACL(testUID))
	inherits := filepath.Join(home, ".npm")
	if err := os.Mkdir(inherits, 0o755); err != nil {
		t.Fatal(err)
	}
	setACL(t, inherits, aclDefaultXattr, namedWriterACL(testUID))
	if err := os.Chmod(inherits, 0o755); err != nil {
		t.Fatal(err)
	}
	readOnly := filepath.Join(home, ".profile") // names the agent, but the mask allows no write
	mustWrite(t, readOnly, "x")
	setACL(t, readOnly, aclAccessXattr, aclXattr(
		[3]uint32{0x01, 6, aclUndefined},
		[3]uint32{aclTagUser, 7, testUID},
		[3]uint32{aclTagGroupObj, 4, aclUndefined},
		[3]uint32{aclTagMask, 4, aclUndefined},
		[3]uint32{aclTagOther, 4, aclUndefined},
	))
	rootNamed := filepath.Join(home, ".bashrc") // names only root
	mustWrite(t, rootNamed, "x")
	setACL(t, rootNamed, aclAccessXattr, namedWriterACL(0))
	for _, p := range []string{named, readOnly, rootNamed} {
		if err := os.Chown(p, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := reclaimHome(home, agent, nil, nil); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if got := strings.Join(left, ","); got != ".bashrc,.profile" {
		t.Fatalf("root's home holds %s, want .bashrc,.profile", got)
	}
	for _, name := range []string{".npmrc", ".npm"} {
		if _, err := os.Lstat(filepath.Join(agent, name)); err != nil {
			t.Errorf("%s not moved into the agent's home: %v", name, err)
		}
	}
}

// aclGrantsWrite reads the kernel's ACL form: a named writer counts only as
// far as the mask lets it, root's own entries never do, others always, and
// something that does not parse counts.
func TestACLGrantsWrite(t *testing.T) {
	cases := []struct {
		name string
		acl  []byte
		gid  uint32
		want bool
	}{
		{"named user, mask rwx", namedWriterACL(testUID), 0, true},
		{"named root", namedWriterACL(0), 0, false},
		{"named user, mask r-x", aclXattr([3]uint32{0x01, 7, aclUndefined}, [3]uint32{aclTagUser, 7, testUID}, [3]uint32{aclTagGroupObj, 5, aclUndefined}, [3]uint32{aclTagMask, 5, aclUndefined}, [3]uint32{aclTagOther, 5, aclUndefined}), 0, false},
		{"named group", aclXattr([3]uint32{0x01, 7, aclUndefined}, [3]uint32{aclTagGroupObj, 5, aclUndefined}, [3]uint32{aclTagGroup, 6, testUID}, [3]uint32{aclTagMask, 7, aclUndefined}, [3]uint32{aclTagOther, 5, aclUndefined}), 0, true},
		{"others write", aclXattr([3]uint32{0x01, 7, aclUndefined}, [3]uint32{aclTagGroupObj, 5, aclUndefined}, [3]uint32{aclTagOther, 7, aclUndefined}), 0, true},
		{"owning group not root's", aclXattr([3]uint32{0x01, 7, aclUndefined}, [3]uint32{aclTagGroupObj, 7, aclUndefined}, [3]uint32{aclTagOther, 5, aclUndefined}), testUID, true},
		{"owning group root's", aclXattr([3]uint32{0x01, 7, aclUndefined}, [3]uint32{aclTagGroupObj, 7, aclUndefined}, [3]uint32{aclTagOther, 5, aclUndefined}), 0, false},
		{"truncated", namedWriterACL(testUID)[:9], 0, true},
		{"wrong version", append([]byte{1, 0, 0, 0}, namedWriterACL(0)[4:]...), 0, true},
	}
	for _, tc := range cases {
		if got := aclGrantsWrite(tc.acl, tc.gid); got != tc.want {
			t.Errorf("%s: aclGrantsWrite = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// sealed's own CA locations are kept only when they name root-only files
// (as resolved paths), and removed otherwise: an agent-writable CA file, a
// directory holding a link to an agent-writable file, an agent-owned or
// world-writable regular file, or a FIFO.
func TestScrubTrustEnv(t *testing.T) {
	base := rootOnlyBase(t)
	ca := filepath.Join(base, "ca.pem")
	mustWrite(t, ca, "-----BEGIN CERTIFICATE-----\n")
	if err := os.Chmod(ca, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "ca-link.pem")
	mustSymlink(t, ca, link)
	certs := filepath.Join(base, "certs")
	if err := os.Mkdir(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, ca, filepath.Join(certs, "a.pem"))
	agentFile := filepath.Join(t.TempDir(), "agent-ca.pem") // under /tmp: not root-only
	mustWrite(t, agentFile, "x")
	badDir := filepath.Join(base, "bad")
	if err := os.Mkdir(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, agentFile, filepath.Join(badDir, "b.pem"))
	fifoDir := filepath.Join(base, "fifo")
	if err := os.Mkdir(fifoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(fifoDir, "c.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A root-only directory with a root-only PEM beside one another uid
	// owns, or one anyone can write: crypto/x509 would trust what either
	// holds.
	foreignDir := filepath.Join(base, "foreign")
	openDir := filepath.Join(base, "open")
	for _, d := range []string{foreignDir, openDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(d, "good.pem"), "-----BEGIN CERTIFICATE-----\n")
	}
	foreignPEM := filepath.Join(foreignDir, "agent.pem")
	mustWrite(t, foreignPEM, "-----BEGIN CERTIFICATE-----\n")
	if err := os.Chown(foreignPEM, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	openPEM := filepath.Join(openDir, "anyone.pem")
	mustWrite(t, openPEM, "-----BEGIN CERTIFICATE-----\n")
	if err := os.Chmod(openPEM, 0o666); err != nil {
		t.Fatal(err)
	}

	rel := func(p string) string { return strings.TrimPrefix(p, "/") }
	cases := []struct {
		name, file, dir string
		wantFile        string // "" = removed
		wantDir         string
		cwd             string // working directory for a relative location
		wantLine        string // a returned line must name it
	}{
		{"root-only file, through a link", link, "", ca, "", "", ""},
		{"agent-writable file", agentFile, "", "", "", "", ""},
		{"missing file", filepath.Join(base, "none.pem"), "", "", "", "", ""},
		{"root-only directory", "", certs, "", certs, "", ""},
		{"directory with a foreign entry", "", badDir, "", "", "", ""},
		{"directory with a FIFO", "", fifoDir, "", "", "", ""},
		{"directory with an agent-owned file", "", foreignDir, "", "", "", foreignPEM},
		{"directory with a world-writable file", "", openDir, "", "", "", openPEM},
		{"directory with a world-writable file beside a good one", "", openDir + ":" + certs, "", certs, "", openPEM},
		{"mixed directories", "", badDir + ":" + certs, "", certs, "", ""},
		// A relative location names a file against the working directory,
		// as crypto/x509 would open it; it is checked and kept as the
		// absolute path it resolves to, and never sends the check into a
		// walk that cannot reach "/".
		{"relative file from /", rel(link), "", ca, "", "/", ""},
		{"relative file from its directory", "ca-link.pem", "", ca, "", base, ""},
		{"relative missing file from /", "etc/ssl/none.pem", "", "", "", "/", ""},
		{"relative agent-writable file", filepath.Base(agentFile), "", "", "", filepath.Dir(agentFile), ""},
		{"relative directory from /", "", rel(certs), "", certs, "/", ""},
		{"relative directories from base", "", "bad:certs", "", certs, base, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cwd != "" {
				t.Chdir(tc.cwd)
			}
			if tc.file != "" {
				t.Setenv("SSL_CERT_FILE", tc.file)
			} else {
				t.Setenv("SSL_CERT_FILE", "")
				os.Unsetenv("SSL_CERT_FILE")
			}
			if tc.dir != "" {
				t.Setenv("SSL_CERT_DIR", tc.dir)
			} else {
				t.Setenv("SSL_CERT_DIR", "")
				os.Unsetenv("SSL_CERT_DIR")
			}
			done := make(chan []string, 1)
			go func() { done <- ScrubTrustEnv() }()
			var lines []string
			select {
			case lines = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ScrubTrustEnv did not return")
			}
			if tc.wantLine != "" && !strings.Contains(strings.Join(lines, "\n"), tc.wantLine) {
				t.Errorf("ScrubTrustEnv lines %q do not name %s", lines, tc.wantLine)
			}
			got, ok := os.LookupEnv("SSL_CERT_FILE")
			if tc.file != "" && (ok != (tc.wantFile != "") || got != tc.wantFile) {
				t.Errorf("SSL_CERT_FILE = %q (set %v), want %q", got, ok, tc.wantFile)
			}
			got, ok = os.LookupEnv("SSL_CERT_DIR")
			if tc.dir != "" && (ok != (tc.wantDir != "") || got != tc.wantDir) {
				t.Errorf("SSL_CERT_DIR = %q (set %v), want %q", got, ok, tc.wantDir)
			}
		})
	}
}
