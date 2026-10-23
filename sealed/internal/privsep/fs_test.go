//go:build linux

package privsep

import (
	"bytes"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func ownerOf(t *testing.T, path string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Uid
}

func readBack(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func wantUnsafe(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("%s: err = %v, want ErrUnsafePath", what, err)
	}
}

func TestReadRefusesLinkAsLeafOrParent(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "outside", "secret")
	mustWrite(t, secret, "root-only")
	tree := filepath.Join(dir, "tree")
	mustWrite(t, filepath.Join(tree, "ok.md"), "fine")
	mustSymlink(t, secret, filepath.Join(tree, "leaf.md"))
	mustSymlink(t, filepath.Join(dir, "outside"), filepath.Join(tree, "sub"))

	if b, err := ReadFile(filepath.Join(tree, "ok.md"), 1<<10); err != nil || string(b) != "fine" {
		t.Fatalf("regular file: %q, %v", b, err)
	}
	_, err := ReadFile(filepath.Join(tree, "leaf.md"), 1<<10)
	wantUnsafe(t, "link as leaf", err)
	_, err = ReadFile(filepath.Join(tree, "sub", "secret"), 1<<10)
	wantUnsafe(t, "link as parent", err)
	_, err = ReadDir(filepath.Join(tree, "sub"))
	wantUnsafe(t, "ReadDir of a link", err)
	_, err = Lstat(filepath.Join(tree, "sub", "secret"))
	wantUnsafe(t, "Lstat through a link", err)
	// Lstat of the link itself is fine: it reports the link.
	fi, err := Lstat(filepath.Join(tree, "leaf.md"))
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(link) = %v, %v; want a symlink mode", fi, err)
	}
}

func TestReadFIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.md")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(fifo, 1<<10)
		done <- err
	}()
	select {
	case err := <-done:
		wantUnsafe(t, "FIFO", err)
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFile on a FIFO blocked")
	}
}

// A lease on a file (fcntl F_SETLEASE, which the file's owner may take)
// makes every other open of it wait until the lease is broken: up to
// lease-break-time, 45 s by default, and the holder can take it again
// afterwards. Root's reads must not wait: they fail at once with ErrBusy,
// which is not a refusal (the file is there, so a producer must not commit
// its deletion), and succeed once the lease is gone. The lease is taken
// here by the file's owner, the test process itself, through a descriptor
// of its own: any other open breaks it the same way it breaks one an agent
// process holds on its own file.
func TestReadDoesNotWaitForALease(t *testing.T) {
	f := filepath.Join(t.TempDir(), "SOUL.md")
	mustWrite(t, f, "hello")
	holder, err := unix.Open(f, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(holder)
	if _, err := unix.FcntlInt(uintptr(holder), unix.F_SETLEASE, unix.F_WRLCK); err != nil {
		skipOrFail(t, "cannot take a lease on %s here: %v", f, err)
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		b, err := ReadFile(f, 1<<10)
		done <- result{b, err}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, ErrBusy) {
			t.Fatalf("ReadFile of a leased file = %q, %v; want ErrBusy", r.data, r.err)
		}
		if errors.Is(r.err, ErrUnsafePath) || errors.Is(r.err, fs.ErrNotExist) || Refused(f, r.err) {
			t.Fatalf("a leased file reads as refused or absent (%v): a producer would commit its deletion", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile waited for a lease to be broken")
	}
	if _, err := ReadTail(f, 10); !errors.Is(err, ErrBusy) {
		t.Fatalf("ReadTail of a leased file: err = %v, want ErrBusy", err)
	}
	if _, err := unix.FcntlInt(uintptr(holder), unix.F_SETLEASE, unix.F_UNLCK); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(f, 1<<10); err != nil || string(b) != "hello" {
		t.Fatalf("ReadFile once the lease is gone = %q, %v", b, err)
	}
	// The descriptor Open wraps was opened non-blocking and made blocking
	// again before it was returned.
	fd, err := openRegular("open", f)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || fl&unix.O_NONBLOCK != 0 {
		t.Fatalf("the read descriptor's flags = %#x, %v; want a blocking descriptor", fl, err)
	}
}

func TestReadLimitAndNotExist(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big")
	mustWrite(t, f, strings.Repeat("x", 100))
	if _, err := ReadFile(f, 99); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over limit: err = %v, want ErrTooLarge", err)
	}
	if b, err := ReadFile(f, 100); err != nil || len(b) != 100 {
		t.Fatalf("at limit: %d bytes, %v", len(b), err)
	}
	_, err := ReadFile(filepath.Join(dir, "missing"), 10)
	if !errors.Is(err, fs.ErrNotExist) || !os.IsNotExist(err) {
		t.Fatalf("missing: err = %v, want fs.ErrNotExist (and os.IsNotExist)", err)
	}
	_, err = ReadFile(filepath.Join(dir, "nodir", "x"), 10)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing parent: err = %v, want fs.ErrNotExist", err)
	}
	if _, err := ReadDir(filepath.Join(dir, "nodir")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadDir missing: err = %v", err)
	}
}

func TestPathsMustBeAbsoluteAndClean(t *testing.T) {
	for _, p := range []string{"rel/x", "/a/../b", "/a/./b", "/a//b", "/a/", ""} {
		if _, err := ReadFile(p, 10); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("ReadFile(%q) err = %v, want ErrUnsafePath", p, err)
		}
		if err := WriteFile(p, nil, 0o644); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("WriteFile(%q) err = %v, want ErrUnsafePath", p, err)
		}
	}
}

func TestHardlinkOwnerRule(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	// A directory owned by 4242 (standing in for the agent) holding a
	// hard link to a root-owned file: refused.
	agentDir := filepath.Join(dir, "agent")
	if err := os.Mkdir(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agentDir, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	mustWrite(t, secret, "root-only")
	if err := os.Link(secret, filepath.Join(agentDir, "foreign")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFile(filepath.Join(agentDir, "foreign"), 1<<10)
	wantUnsafe(t, "foreign hard link", err)

	// A hard link whose owner matches its directory's owner: accepted.
	own := filepath.Join(agentDir, "own")
	mustWrite(t, own, "agent data")
	if err := os.Chown(own, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(own, filepath.Join(agentDir, "own2")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(filepath.Join(agentDir, "own2"), 1<<10); err != nil || string(b) != "agent data" {
		t.Fatalf("same-owner hard link: %q, %v", b, err)
	}
}

func TestWriteFileReplacesLinkAndTakesParentOwner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	mustWrite(t, target, "untouched")
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tree, "SOUL.md")
	mustSymlink(t, target, link)

	if err := WriteFile(link, []byte("new"), 0o640); err != nil {
		t.Fatalf("WriteFile over a link: %v", err)
	}
	if got := readBack(t, target); got != "untouched" {
		t.Fatalf("link target changed: %q", got)
	}
	fi, err := os.Lstat(link)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
		t.Fatalf("result: %v, %v; want a regular 0640 file", fi, err)
	}
	if got := readBack(t, link); got != "new" {
		t.Fatalf("content = %q", got)
	}
	// Writing through a linked parent is refused.
	mustSymlink(t, filepath.Join(dir), filepath.Join(tree, "up"))
	wantUnsafe(t, "write through linked parent", WriteFile(filepath.Join(tree, "up", "target"), []byte("x"), 0o644))
	if got := readBack(t, target); got != "untouched" {
		t.Fatalf("target changed through linked parent: %q", got)
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(tree)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".sealed-tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}

	if os.Geteuid() != 0 {
		return
	}
	agentDir := filepath.Join(dir, "agent")
	if err := os.Mkdir(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agentDir, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(agentDir, "new.md")
	if err := WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, f); uid != 4242 {
		t.Fatalf("new file in a 4242-owned dir is owned by %d, want 4242", uid)
	}
	g := filepath.Join(dir, "rootfile")
	if err := WriteFile(g, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, g); uid != 0 {
		t.Fatalf("new file in a root-owned dir is owned by %d, want 0", uid)
	}
}

func TestMkdirRemoveRenameNeverFollowLinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(outside, "keep"), "keep")
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(tree, "link"))

	wantUnsafe(t, "MkdirAll through a link", MkdirAll(filepath.Join(tree, "link", "new"), 0o755))
	if _, err := os.Stat(filepath.Join(outside, "new")); err == nil {
		t.Fatal("MkdirAll created a directory through a link")
	}
	if err := MkdirAll(filepath.Join(tree, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(tree, "a", "b", "c")); err != nil || !fi.IsDir() {
		t.Fatalf("MkdirAll result: %v, %v", fi, err)
	}
	if err := MkdirAll(filepath.Join(tree, "a", "b", "c"), 0o755); err != nil {
		t.Fatalf("MkdirAll is not idempotent: %v", err)
	}

	// RemoveAll of the link removes the link, not the target's contents.
	if err := RemoveAll(filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "keep" {
		t.Fatalf("RemoveAll followed the link: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(tree, "link")); !os.IsNotExist(err) {
		t.Fatalf("link still present: %v", err)
	}
	// RemoveAll of a tree containing a link to outside leaves outside alone.
	mustWrite(t, filepath.Join(tree, "d", "f"), "x")
	mustSymlink(t, outside, filepath.Join(tree, "d", "out"))
	if err := RemoveAll(filepath.Join(tree, "d")); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "keep" {
		t.Fatalf("RemoveAll recursed through a link: %q", got)
	}
	if err := RemoveAll(filepath.Join(tree, "absent")); err != nil {
		t.Fatalf("RemoveAll(missing) = %v, want nil", err)
	}
	// Removal through a linked parent is refused.
	mustSymlink(t, outside, filepath.Join(tree, "link2"))
	wantUnsafe(t, "Remove through a link", Remove(filepath.Join(tree, "link2", "keep")))
	wantUnsafe(t, "RemoveAll through a link", RemoveAll(filepath.Join(tree, "link2", "keep")))
	if got := readBack(t, filepath.Join(outside, "keep")); got != "keep" {
		t.Fatalf("removal went through a link: %q", got)
	}
	// Remove of a link removes the link.
	if err := Remove(filepath.Join(tree, "link2")); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "keep" {
		t.Fatal("Remove followed the link")
	}

	// Rename moves a link itself.
	mustSymlink(t, outside, filepath.Join(tree, "link3"))
	if err := Rename(filepath.Join(tree, "link3"), filepath.Join(tree, "link3.corrupt")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(tree, "link3.corrupt")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("renamed entry: %v, %v; want the link itself", fi, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatal("Rename disturbed the link target")
	}
	wantUnsafe(t, "Rename through a link", Rename(filepath.Join(tree, "link3.corrupt", "keep"), filepath.Join(tree, "link3.corrupt", "moved")))
}

func TestReadDirEntriesCarryLstat(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "b.md"), "bb")
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(dir, "a"), filepath.Join(dir, "c"))
	if err := unix.Mkfifo(filepath.Join(dir, "d"), 0o644); err != nil {
		t.Fatal(err)
	}
	ents, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "a,b.md,c,d" {
		t.Fatalf("names = %v", names)
	}
	if !ents[0].IsDir() || !ents[1].IsRegular() || ents[2].IsDir() || ents[2].Type()&fs.ModeSymlink == 0 || ents[3].IsRegular() {
		t.Fatalf("types wrong: %v %v %v %v", ents[0].Type(), ents[1].Type(), ents[2].Type(), ents[3].Type())
	}
	if fi, _ := ents[1].Info(); fi.Size() != 2 {
		t.Fatalf("size = %d", fi.Size())
	}
}

// A tree standing in for a handed-over home, with something outside it
// that must keep root's ownership.
func handoverFixture(t *testing.T) (tree, outside string) {
	t.Helper()
	dir := t.TempDir()
	outside = filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(outside, "f"), "x")
	mustWrite(t, filepath.Join(outside, "sub", "g"), "y")
	tree = filepath.Join(dir, "tree")
	mustWrite(t, filepath.Join(tree, "a.md"), "a")
	mustWrite(t, filepath.Join(tree, "sub", "b.md"), "b")
	return tree, outside
}

func assertRootOwned(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if uid := ownerOf(t, p); uid != 0 {
			t.Errorf("%s changed owner to %d", p, uid)
		}
		return nil
	})
}

func TestOwnTreeStaysInsideTheTree(t *testing.T) {
	requireRoot(t)
	tree, outside := handoverFixture(t)
	mustSymlink(t, outside, filepath.Join(tree, "link"))
	mustSymlink(t, filepath.Join(outside, "f"), filepath.Join(tree, "flink"))
	if err := os.Link(filepath.Join(outside, "f"), filepath.Join(tree, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(tree, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Deeper than the cap: the walk must stop descending.
	deep := tree
	for i := 0; i < maxTreeDepth+3; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ownTree(tree, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{tree, filepath.Join(tree, "a.md"), filepath.Join(tree, "sub"), filepath.Join(tree, "sub", "b.md")} {
		if uid := ownerOf(t, p); uid != 4242 {
			t.Errorf("%s owner = %d, want 4242", p, uid)
		}
	}
	assertRootOwned(t, outside)
	for _, p := range []string{"link", "flink", "hard", "fifo"} {
		if uid := ownerOf(t, filepath.Join(tree, p)); uid != 0 {
			t.Errorf("%s was chowned (uid %d); links, hard links and special files must be skipped", p, uid)
		}
	}
	if uid := ownerOf(t, deep); uid != 0 {
		t.Errorf("entry past the depth cap was chowned")
	}
	// A second run is a no-op on already-owned entries and still succeeds.
	if err := ownTree(tree, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	// The tree root itself must not be a link.
	link := filepath.Join(filepath.Dir(tree), "treelink")
	mustSymlink(t, outside, link)
	wantUnsafe(t, "ownTree on a link", ownTree(link, 4242, 4242))
	assertRootOwned(t, outside)
}

// Regression: an entry swapped between a subdirectory and a link to an
// outside directory while the walk runs never redirects a chown outside
// the tree.
func TestOwnTreeConcurrentSwap(t *testing.T) {
	requireRoot(t)
	tree, outside := handoverFixture(t)
	mustSymlink(t, outside, filepath.Join(tree, "swap"))
	stop := make(chan struct{})
	swapped := make(chan int)
	go func() {
		n := 0
		for i := 0; i < 200; i++ {
			if unix.Renameat2(unix.AT_FDCWD, filepath.Join(tree, "sub"), unix.AT_FDCWD, filepath.Join(tree, "swap"), unix.RENAME_EXCHANGE) == nil {
				n++
			}
			time.Sleep(100 * time.Microsecond)
			select {
			case <-stop:
				swapped <- n
				return
			default:
			}
		}
		swapped <- n
	}()
	rounds := 0
	for {
		_ = ownTree(tree, 4242, 4242)
		rounds++
		select {
		case n := <-swapped:
			close(stop)
			if n == 0 {
				t.Fatal("no swap happened; the test proves nothing")
			}
			assertRootOwned(t, outside)
			t.Logf("%d swaps across %d walks; outside untouched", n, rounds)
			return
		default:
		}
	}
}

func TestHandoverGuard(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tools", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	for _, p := range []string{"/", "/usr", "/root", filepath.Join(dir, "tools"), bin} {
		if err := guardHandover("chown", p); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("guardHandover(%q) = %v, want refusal", p, err)
		}
	}
	if exe, err := os.Executable(); err == nil {
		if err := guardHandover("chown", filepath.Dir(exe)); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("guardHandover(dir of own executable) = %v, want refusal", err)
		}
	}
	home := filepath.Join(dir, "home", ".framework")
	if err := guardHandover("chown", home); err != nil {
		t.Errorf("guardHandover(%q) = %v, want nil", home, err)
	}
	if err := guardHandover("chown", "/root/.openclaw"); err != nil {
		t.Errorf("guardHandover(/root/.openclaw) = %v, want nil", err)
	}
	// The guard is applied by ownTree and ownPath themselves.
	wantUnsafe(t, "ownTree(bin parent)", ownTree(filepath.Join(dir, "tools"), 4242, 4242))
	wantUnsafe(t, "ownPath(/)", ownPath("/", 4242, 4242))
}

func TestRefusedLogsOncePerPath(t *testing.T) {
	err := unsafeErr("open", "/x/y", "test")
	if !Refused("/x/y", err) || !Refused("/x/y", err) {
		t.Fatal("Refused(unsafe) = false")
	}
	if Refused("/x/z", errors.New("other")) {
		t.Fatal("Refused(other error) = true")
	}
	// A tracked file over its limit is still the agent's data: callers must
	// not skip it as if it were absent (they keep the committed version).
	if Refused("/x/w", pathErr("read", "/x/w", ErrTooLarge)) {
		t.Fatal("Refused(too large) = true")
	}
	if Refused("/x/v", pathErr("open", "/x/v", syscall.ENOENT)) {
		t.Fatal("Refused(ENOENT) = true")
	}
}

func TestOpenReturnsReadableFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "f"), "hello\nworld\n")
	f, err := Open(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil || buf.String() != "hello\nworld\n" {
		t.Fatalf("read %q, %v", buf.String(), err)
	}
}

func TestReadTailBoundsTheRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	mustWrite(t, p, "0123456789")
	if got, err := ReadTail(p, 4); err != nil || string(got) != "6789" {
		t.Fatalf("ReadTail(4) = %q, %v; want the last 4 bytes", got, err)
	}
	if got, err := ReadTail(p, 100); err != nil || string(got) != "0123456789" {
		t.Fatalf("ReadTail(100) = %q, %v; want the whole file", got, err)
	}
	link := filepath.Join(dir, "link")
	mustSymlink(t, p, link)
	_, err := ReadTail(link, 4)
	wantUnsafe(t, "ReadTail(link)", err)
}

func TestChmodNeverFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	modeOf := func(p string) os.FileMode {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode()
	}
	target := filepath.Join(dir, "target")
	mustWrite(t, target, "x")
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	mustSymlink(t, target, link)
	wantUnsafe(t, "Chmod(link)", Chmod(link, 0o600))
	linkedDir := filepath.Join(dir, "linkeddir")
	mustSymlink(t, dir, linkedDir)
	wantUnsafe(t, "Chmod(through a linked parent)", Chmod(filepath.Join(linkedDir, "target"), 0o600))
	if m := modeOf(target).Perm(); m != 0o644 {
		t.Fatalf("link target mode changed to %o", m)
	}
	if err := Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(target).Perm(); m != 0o600 {
		t.Fatalf("mode = %o, want 0600", m)
	}

	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		skipOrFail(t, "cannot bind a unix socket here: %v", err)
	}
	defer l.Close()
	if err := Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(sock); m.Type() != os.ModeSocket || m.Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want a socket with 0600", m)
	}
}

// A socket or a device node at a read path is refused like a FIFO: the
// leaf is checked through an O_PATH descriptor, never opened for reading.
func TestReadRefusesSocketAndDevice(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.md")
	l, err := net.Listen("unix", sock)
	if err != nil {
		skipOrFail(t, "cannot bind a unix socket here: %v", err)
	}
	defer l.Close()
	_, err = ReadFile(sock, 1<<10)
	wantUnsafe(t, "ReadFile(socket)", err)
	_, err = Open(sock)
	wantUnsafe(t, "Open(socket)", err)

	if os.Geteuid() != 0 {
		return
	}
	dev := filepath.Join(dir, "null.md")
	if err := unix.Mknod(dev, unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))); err != nil {
		skipOrFail(t, "cannot create a device node here: %v", err)
	}
	_, err = ReadFile(dev, 1<<10)
	wantUnsafe(t, "ReadFile(device)", err)
}

// Directories MkdirAll creates take the owner of the directory they are
// created in: the agent's inside a handed-over tree, root's elsewhere.
func TestMkdirAllTakesParentOwner(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "agent")
	if err := os.Mkdir(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agentDir, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Join(agentDir, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a", "a/b", "a/b/c"} {
		if uid := ownerOf(t, filepath.Join(agentDir, p)); uid != testUID {
			t.Errorf("%s owner = %d, want %d (the parent's)", p, uid, testUID)
		}
	}
	if err := MkdirAll(filepath.Join(dir, "rootdir", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"rootdir", "rootdir/x"} {
		if uid := ownerOf(t, filepath.Join(dir, p)); uid != 0 {
			t.Errorf("%s owner = %d, want 0", p, uid)
		}
	}
}

// RemoveAll handles trees of any depth the filesystem holds, including
// ones whose paths exceed PATH_MAX, with files at many levels.
func TestRemoveAllDeepTree(t *testing.T) {
	for _, depth := range []int{maxHeldDirs - 1, maxHeldDirs * 3, 3000} {
		dir := t.TempDir()
		root := filepath.Join(dir, "deep")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < depth; i++ {
			if i%7 == 0 {
				f, err := unix.Openat(fd, "f", unix.O_CREAT|unix.O_WRONLY, 0o644)
				if err != nil {
					t.Fatal(err)
				}
				unix.Close(f)
			}
			if err := unix.Mkdirat(fd, "d", 0o755); err != nil {
				t.Fatal(err)
			}
			next, err := unix.Openat(fd, "d", unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				t.Fatal(err)
			}
			unix.Close(fd)
			fd = next
		}
		unix.Close(fd)
		if err := RemoveAll(root); err != nil {
			t.Fatalf("depth %d: RemoveAll = %v", depth, err)
		}
		if _, err := os.Lstat(root); !os.IsNotExist(err) {
			t.Fatalf("depth %d: tree still present: %v", depth, err)
		}
	}
}

// Rename moves an entry between directories without following links;
// RenameNoReplace refuses to replace an existing destination.
func TestRenameAcrossDirectories(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a", "f"), "one")
	mustWrite(t, filepath.Join(dir, "b", "g"), "two")
	if err := Rename(filepath.Join(dir, "a", "f"), filepath.Join(dir, "b", "f")); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, filepath.Join(dir, "b", "f")); got != "one" {
		t.Fatalf("moved file holds %q", got)
	}
	err := RenameNoReplace(filepath.Join(dir, "b", "f"), filepath.Join(dir, "b", "g"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("RenameNoReplace over an existing entry = %v, want fs.ErrExist", err)
	}
	if got := readBack(t, filepath.Join(dir, "b", "g")); got != "two" {
		t.Fatalf("destination replaced: %q", got)
	}
	if err := RenameNoReplace(filepath.Join(dir, "b", "f"), filepath.Join(dir, "a", "f2")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(dir, "b"), filepath.Join(dir, "link"))
	wantUnsafe(t, "Rename into a linked directory", Rename(filepath.Join(dir, "a", "f2"), filepath.Join(dir, "link", "f3")))
	wantUnsafe(t, "Rename out of a linked directory", Rename(filepath.Join(dir, "link", "g"), filepath.Join(dir, "a", "g")))
}

func TestWriteFileFromStreams(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big")
	n, err := WriteFileFrom(p, strings.NewReader(strings.Repeat("x", 1<<20)), 0o640)
	if err != nil || n != 1<<20 {
		t.Fatalf("WriteFileFrom = %d, %v", n, err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Size() != 1<<20 || fi.Mode().Perm() != 0o640 {
		t.Fatalf("result: %v, %v", fi, err)
	}
	// A failing reader leaves the destination as it was.
	if _, err := WriteFileFrom(p, iotestErrReader{}, 0o644); err == nil {
		t.Fatal("WriteFileFrom with a failing reader succeeded")
	}
	if fi2, _ := os.Lstat(p); fi2.Size() != 1<<20 {
		t.Fatal("a failed write changed the destination")
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("simulated read error") }

// ownPath hands over a socket only: a regular file (possibly a hard link
// to a file root owns elsewhere) or a link at the name is refused.
func TestOwnPathOnlyChownsSockets(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		skipOrFail(t, "cannot bind a unix socket here: %v", err)
	}
	defer l.Close()
	if err := ownPath(sock, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, sock); uid != testUID {
		t.Fatalf("socket owner = %d, want %d", uid, testUID)
	}
	secret := filepath.Join(dir, "secret")
	mustWrite(t, secret, "root-only")
	hard := filepath.Join(dir, "hard.sock")
	if err := os.Link(secret, hard); err != nil {
		t.Fatal(err)
	}
	wantUnsafe(t, "ownPath(hard link)", ownPath(hard, testUID, testUID))
	link := filepath.Join(dir, "link.sock")
	mustSymlink(t, sock, link)
	wantUnsafe(t, "ownPath(link)", ownPath(link, testUID, testUID))
	if uid := ownerOf(t, secret); uid != 0 {
		t.Fatalf("hard-linked file was chowned to %d", uid)
	}
}

// The handover guard also refuses paths inside sealed's state directory
// and inside the package directory of a binary sealed runs.
func TestHandoverGuardProtectsTrees(t *testing.T) {
	for _, p := range []string{StateDir, StateDir + "/log", "/var/lib", "/var"} {
		wantUnsafe(t, "guardHandover("+p+")", guardHandover("chown", p))
	}
	rb := rootOnlyBase(t)
	pkg := filepath.Join(rb, "lib", "node_modules", "faketool")
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"faketool"}`)
	writeExe(t, filepath.Join(pkg, "bin", "faketool.js"), "true")
	bin := filepath.Join(rb, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(pkg, "bin", "faketool.js"), filepath.Join(bin, "faketool"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	prev := protectedTools
	protectedTools = append([]string{"faketool"}, prev...)
	t.Cleanup(func() { protectedTools = prev })
	for _, p := range []string{pkg, filepath.Join(pkg, "lib"), filepath.Join(pkg, "bin")} {
		wantUnsafe(t, "guardHandover("+p+")", guardHandover("chown", p))
	}
	if err := guardHandover("chown", filepath.Join(rb, "lib", "node_modules", "other")); err != nil {
		t.Fatalf("a sibling package was refused: %v", err)
	}
}

// EnsureDir makes the directories below base real ones whatever sits at
// their names — the entry itself is removed, never what it points at — and
// handles base and above as MkdirAll does.
func TestEnsureDirReplacesNonDirectories(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "home")
	outside := filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(outside, "keep"), "outside")
	if err := os.MkdirAll(filepath.Join(base, "ws"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A link at the leaf, and at a component above it.
	mustSymlink(t, outside, filepath.Join(base, "ws", "skills"))
	mustSymlink(t, outside, filepath.Join(base, "canvas"))
	// A regular file, and a socket.
	mustWrite(t, filepath.Join(base, "memories"), "not a dir")
	sock := filepath.Join(base, "sock")
	if l, err := net.Listen("unix", sock); err == nil {
		defer l.Close()
	} else {
		sock = ""
	}
	targets := []string{
		filepath.Join(base, "ws", "skills"),
		filepath.Join(base, "canvas", "sub"),
		filepath.Join(base, "memories"),
		filepath.Join(base, "new", "a", "b"),
		base,
	}
	if sock != "" {
		targets = append(targets, sock)
	}
	for _, p := range targets {
		if err := EnsureDir(base, p, 0o755); err != nil {
			t.Fatalf("EnsureDir(%s): %v", p, err)
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s = %v, %v; want a real directory", p, fi, err)
		}
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "outside" {
		t.Fatalf("link target changed: %q", got)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("link target gained entries: %v", ents)
	}

	// base itself, or a component above it, is never replaced.
	linkedBase := filepath.Join(dir, "linkedbase")
	mustSymlink(t, base, linkedBase)
	wantUnsafe(t, "EnsureDir under a linked base", EnsureDir(linkedBase, filepath.Join(linkedBase, "x"), 0o755))
	if fi, err := os.Lstat(linkedBase); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("a link at base was replaced: %v, %v", fi, err)
	}
	wantUnsafe(t, "EnsureDir outside base", EnsureDir(base, outside, 0o755))
	wantUnsafe(t, "EnsureDir of a sibling sharing base's prefix", EnsureDir(base, base+"x", 0o755))
}

// Directories EnsureDir creates, including replacements, take the owner of
// the directory they are created in.
func TestEnsureDirTakesParentOwner(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "agent")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(base, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "/etc", filepath.Join(base, "a"))
	if err := EnsureDir(base, filepath.Join(base, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a", "a/b"} {
		if uid := ownerOf(t, filepath.Join(base, p)); uid != testUID {
			t.Errorf("%s owner = %d, want %d (the parent's)", p, uid, testUID)
		}
	}
}

// A write over a directory replaces the directory with the file; a link
// inside the removed directory is removed, not followed.
func TestWriteFileReplacesADirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(outside, "keep"), "outside")
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, "full.yaml")
	mustWrite(t, filepath.Join(full, "sub", "f"), "x")
	mustSymlink(t, outside, filepath.Join(full, "sub", "link"))
	for _, p := range []string{empty, full} {
		if err := WriteFile(p, []byte("data"), 0o600); err != nil {
			t.Fatalf("WriteFile over a directory at %s: %v", p, err)
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || readBack(t, p) != "data" {
			t.Fatalf("%s = %v, %v; want the regular file written", p, fi, err)
		}
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "outside" {
		t.Fatalf("link target changed: %q", got)
	}
}

// Chmod applies the read rule for hard links: a multiply-linked file whose
// owner is not its directory's owner may be another name for a file
// elsewhere, and is refused.
func TestChmodRefusesAForeignHardLink(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "agent")
	if err := os.Mkdir(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agentDir, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "rootfile")
	mustWrite(t, rootFile, "x")
	if err := os.Chmod(rootFile, 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(agentDir, "hard")
	if err := os.Link(rootFile, hard); err != nil {
		skipOrFail(t, "cannot hard-link here: %v", err)
	}
	wantUnsafe(t, "Chmod(foreign hard link)", Chmod(hard, 0o666))
	fi, err := os.Lstat(rootFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("hard-linked root file mode = %v, %v; want 0600 unchanged", fi.Mode(), err)
	}

	// A multiply-linked file with its directory's owner is still changed.
	own := filepath.Join(agentDir, "own")
	mustWrite(t, own, "y")
	if err := os.Chown(own, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(own, filepath.Join(agentDir, "own2")); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(own, 0o640); err != nil {
		t.Fatalf("Chmod(own hard link) = %v", err)
	}
}

// deepTree builds root/d/d/.../d (depth levels) and returns the path of
// each level.
func deepTree(t *testing.T, root string, depth int) []string {
	t.Helper()
	levels := []string{root}
	p := root
	for i := 0; i < depth; i++ {
		p = filepath.Join(p, "d")
		levels = append(levels, p)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return levels
}

func withRemoveAllHook(t *testing.T, hook func(event, path string)) {
	t.Helper()
	prev := removeAllHook
	removeAllHook = hook
	t.Cleanup(func() { removeAllHook = prev })
}

// When RemoveAll climbs back to a parent whose descriptor it released, it
// reopens ".." of the directory just emptied and accepts it only if it is
// the parent it entered on the way down. If the subtree was moved
// meanwhile, ".." is another directory: RemoveAll stops with an error
// instead of removing the pending names of each ancestor there.
func TestRemoveAllStopsWhenTheTreeMoves(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "tree")
	levels := deepTree(t, root, maxHeldDirs+10)
	// Pending names in the ancestors: a file next to each level's child,
	// and the same names in the directory the subtree is moved into.
	other := filepath.Join(dir, "other")
	for _, l := range levels[:len(levels)-1] {
		mustWrite(t, filepath.Join(l, "f"), "tree")
	}
	mustWrite(t, filepath.Join(other, "f"), "keep")
	mustWrite(t, filepath.Join(other, "d", "f"), "keep")

	moved := ""
	withRemoveAllHook(t, func(event, path string) {
		if event != "reopen" || moved != "" {
			return
		}
		// path is the emptied directory whose parent was released: move it
		// into other, so its ".." is no longer the parent it was entered from.
		moved = path
		if err := os.Rename(path, filepath.Join(other, "moved")); err != nil {
			t.Errorf("moving %s: %v", path, err)
		}
	})
	err := RemoveAll(root)
	if moved == "" {
		t.Fatal("the hook never ran: the tree is not deep enough to release a parent")
	}
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("RemoveAll after the tree moved = %v, want the directory-moved error", err)
	}
	for _, p := range []string{filepath.Join(other, "f"), filepath.Join(other, "d", "f")} {
		if got, rerr := os.ReadFile(p); rerr != nil || string(got) != "keep" {
			t.Fatalf("%s = %q, %v; RemoveAll acted outside the tree", p, got, rerr)
		}
	}
}

// A directory refilled, or replaced, while RemoveAll empties it is entered
// again by name from its verified parent and removed; a link put there is
// removed itself, so nothing outside the tree is touched.
func TestRemoveAllReentryStaysInTheTree(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(outside, "keep"), "outside")
	root := filepath.Join(dir, "tree")
	levels := deepTree(t, root, maxHeldDirs+5)
	refills := 0
	withRemoveAllHook(t, func(event, path string) {
		if event != "rmdir" || refills >= 3 {
			return
		}
		refills++
		switch refills {
		case 1: // refill the directory about to be removed
			mustWrite(t, filepath.Join(path, "late"), "x")
			mustSymlink(t, outside, filepath.Join(path, "late-link"))
		case 2: // replace it with another directory holding a link out
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, outside, filepath.Join(path, "link"))
		}
	})
	if err := RemoveAll(levels[0]); err != nil {
		t.Fatalf("RemoveAll = %v", err)
	}
	if refills < 2 {
		t.Fatalf("hook ran %d times", refills)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("tree still present: %v", err)
	}
	if got := readBack(t, filepath.Join(outside, "keep")); got != "outside" {
		t.Fatalf("outside changed: %q", got)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("outside gained or lost entries: %v", ents)
	}
}
