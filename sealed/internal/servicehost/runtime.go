package servicehost

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/privsep"
	"seal-verify/internal/servicesandbox"
)

// RuntimeLease is trusted wiring, not a path or hash accepted from service code.
// AcquireRuntime verifies current listing and pins the verified package until
// its last sandbox process has exited. It may never fall back to an image base.
type RuntimeLease struct {
	Hash    string
	Dir     string
	Release func()
}

var runtimeDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// limits are what the resource watcher enforces for one service identity.
// Memory and disk have no kernel boundary here (no delegated cgroup, no
// mount), so the watcher kills the identity's processes when they exceed it.
type limits struct {
	residentBytes int64
	diskBytes     int64
	diskDirs      []string
}

type isolatedCommand struct {
	*exec.Cmd
	uid              uint32
	runtimeHash      string
	release          func()
	limits           limits
	cleanupResource  func(context.Context) error // private lifecycle hook; production reaps the identity
	cleanupOnce      sync.Once
	cleanupDone      chan struct{}
	cleanupErr       error
	onCleanupFailure func()
	// onLimit runs once, outside the manager lock, when the watcher stops the
	// identity for exceeding a limit ("memory_limit", "disk_limit").
	onLimit   func(reason string)
	limitOnce sync.Once
	watcher   *resourceWatcher
}

func (c *isolatedCommand) Start() error {
	err := c.Cmd.Start()
	if err != nil {
		c.beginCleanup()
		return err
	}
	if c.watcher != nil {
		c.watcher.add(c)
	}
	return nil
}

func (c *isolatedCommand) Wait() error {
	err := c.Cmd.Wait()
	c.beginCleanup()
	if c.cleanupErr != nil && c.onCleanupFailure != nil {
		c.onCleanupFailure()
	}
	<-c.cleanupDone
	return errors.Join(err, c.cleanupErr)
}

// exceeded stops the whole identity: the interpreter through the command's
// context, every descendant through the reap that cleanup runs.
func (c *isolatedCommand) exceeded(reason string) {
	c.limitOnce.Do(func() {
		if c.onLimit != nil {
			c.onLimit(reason)
		}
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	})
}

func (c *isolatedCommand) beginCleanup() {
	c.cleanupOnce.Do(func() {
		c.cleanupDone = make(chan struct{})
		finish := func() {
			if c.watcher != nil {
				c.watcher.remove(c)
			}
			if c.release != nil {
				c.release()
			}
			close(c.cleanupDone)
		}
		cleanupResource := c.cleanupResource
		if cleanupResource == nil && c.uid != 0 {
			uid := c.uid
			cleanupResource = func(ctx context.Context) error { return reapIdentity(ctx, uid) }
		}
		if cleanupResource == nil {
			finish()
			return
		}
		attempt := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return cleanupResource(ctx)
		}
		if err := attempt(); err == nil {
			finish()
			return
		} else {
			c.cleanupErr = err
		}
		// Keep the identity and runtime lease pinned while processes of this
		// identity may remain. No successful receipt is possible after even a
		// transient cleanup failure.
		go func() {
			for {
				timer := time.NewTimer(time.Second)
				<-timer.C
				if attempt() == nil {
					finish()
					return
				}
			}
		}()
	})
}

func (c *isolatedCommand) resourcesReleased() bool {
	if c.cleanupDone == nil {
		return false
	}
	select {
	case <-c.cleanupDone:
		return true
	default:
		return false
	}
}

// reapIdentity kills every process of one service identity through the
// trusted launcher (which becomes that identity to signal them all), then
// confirms from root that none is left.
func reapIdentity(ctx context.Context, uid uint32) error {
	cmd, err := privsep.RootCommand(ctx, "sealed-service-launcher", "reap", fmt.Sprintf("--uid=%d", uid))
	if err != nil {
		return err
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reap identity %d: %v: %s", uid, err, firstLine(out))
	}
	if left := servicesandbox.Scan(map[uint32]bool{uid: true})[uid].Processes; left != 0 {
		return fmt.Errorf("%d processes of identity %d remain", left, uid)
	}
	return nil
}

// removeInBackground removes a discarded directory (a variable so a test can
// show discardDir does not wait for it).
var removeInBackground = func(path string) { go privsep.RemoveAll(path) }

// discardDir moves dir aside and removes it in the background, so a service
// that filled it cannot hold callers (some under the manager lock) for the
// time a removal takes. Earlier discards left by a crash go the same way.
func discardDir(dir string) error {
	parent, name := filepath.Dir(dir), filepath.Base(dir)
	if entries, err := privsep.ReadDir(parent); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), name+".discard-") {
				removeInBackground(filepath.Join(parent, e.Name()))
			}
		}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	aside := filepath.Join(parent, fmt.Sprintf("%s.discard-%x", name, b))
	if err := privsep.Rename(dir, aside); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	removeInBackground(aside)
	return nil
}

// reapLeftoverIdentities stops every process of any service identity, before
// a manager hands identities out. It returns the identities it could not
// clear, with the cause, for the manager to quarantine.
func reapLeftoverIdentities() map[uint32]string {
	failed := map[uint32]string{}
	for _, uid := range servicesandbox.Identities() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := reapIdentity(ctx, uid); err != nil {
			failed[uid] = err.Error()
		}
		cancel()
	}
	return failed
}

func firstLine(b []byte) string {
	s := string(b)
	for i, r := range s {
		if r == '\n' || i >= 200 {
			return s[:i]
		}
	}
	return s
}

// resourceWatcher scans /proc once per tick for every running identity and
// walks private directories less often, so the cost does not grow with the
// number of tasks times the number of processes. On the same slower tick it
// checks the free space of the filesystem that holds the task directories:
// below diskReserveBytes it stops every service process, whatever space they
// hold that no walk can see (files deleted while open), since sealed and the
// owner need that space.
type resourceWatcher struct {
	mu      sync.Mutex
	active  map[uint32]*isolatedCommand
	started bool
	stop    chan struct{}
	disk    string
}

// diskReserveBytes is the free space service processes must leave on the
// filesystem of their task directories; new tasks are refused below it.
const diskReserveBytes = 1 << 30

func newResourceWatcher(stop chan struct{}, disk string) *resourceWatcher {
	return &resourceWatcher{active: map[uint32]*isolatedCommand{}, stop: stop, disk: disk}
}

func (w *resourceWatcher) add(c *isolatedCommand) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.active[c.uid] = c
	if !w.started {
		w.started = true
		go w.loop()
	}
}

func (w *resourceWatcher) remove(c *isolatedCommand) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active[c.uid] == c {
		delete(w.active, c.uid)
	}
}

func (w *resourceWatcher) loop() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-w.stop:
			return
		case <-tick.C:
		}
		w.mu.Lock()
		cmds := make([]*isolatedCommand, 0, len(w.active))
		uids := make(map[uint32]bool, len(w.active))
		for uid, c := range w.active {
			cmds, uids[uid] = append(cmds, c), true
		}
		w.mu.Unlock()
		if len(cmds) == 0 {
			continue
		}
		slow := n%4 == 0
		if slow && w.disk != "" && diskLow(w.disk) {
			for _, c := range cmds {
				c.exceeded("sandbox_disk_low")
			}
			continue
		}
		usage := servicesandbox.Scan(uids)
		for _, c := range cmds {
			if c.limits.residentBytes > 0 && usage[c.uid].RSSBytes > c.limits.residentBytes {
				c.exceeded("memory_limit")
				continue
			}
			if slow && c.limits.diskBytes > 0 && diskUsage(c.limits.diskDirs, c.limits.diskBytes) > c.limits.diskBytes {
				c.exceeded("disk_limit")
			}
		}
	}
}

// diskReserveInodes is the floor of free inodes, for filesystems that
// report a fixed inode count.
const diskReserveInodes = 65536

// diskLow reports whether the filesystem holding path has less than
// diskReserveBytes available or, where it counts inodes, fewer than
// diskReserveInodes free. An unreadable filesystem counts as low.
func diskLow(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return true
	}
	return int64(st.Bavail)*int64(st.Bsize) < diskReserveBytes || (st.Files > 0 && st.Ffree < diskReserveInodes)
}

// maxWalkDepth bounds how deep diskUsage descends (each level holds one open
// directory). A deeper tree counts as over any limit.
const maxWalkDepth = 64

// diskUsage sums the blocks allocated below dirs (st_blocks, so preallocated
// and sparse files count what they occupy), stopping once the sum passes
// stopAt. Each entry (empty files, sockets, links) counts at least one 4 KiB
// block, so the identity's entries in these directories are bounded too. Each directory is opened relative
// to its parent with O_NOFOLLOW, so a service that swaps a directory for a
// link cannot steer the walk outside its own tree.
func diskUsage(dirs []string, stopAt int64) int64 {
	var total int64
	for _, dir := range dirs {
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		if total = addBlocks(os.NewFile(uintptr(fd), dir), total, stopAt, 0); total > stopAt {
			break
		}
	}
	return total
}

func addBlocks(dir *os.File, total, stopAt int64, depth int) int64 {
	defer dir.Close()
	dirfd := int(dir.Fd())
	for {
		names, err := dir.Readdirnames(256)
		for _, name := range names {
			var st unix.Stat_t
			if unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				continue
			}
			total += max(st.Blocks*512, 4096)
			if total > stopAt {
				return total
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			if depth+1 >= maxWalkDepth {
				return stopAt + 1
			}
			fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			if total = addBlocks(os.NewFile(uintptr(fd), name), total, stopAt, depth+1); total > stopAt {
				return total
			}
		}
		if err != nil || len(names) == 0 {
			return total
		}
	}
}

func (m *Manager) acquireRuntime(ctx context.Context) (RuntimeLease, error) {
	if m.runtime == nil {
		if m.skipResourceLimitsForTests {
			return RuntimeLease{Release: func() {}}, nil
		}
		return RuntimeLease{}, fmt.Errorf("%w: a verified listed Harness runtime callback is required", ErrIsolationUnavailable)
	}
	r, err := m.runtime(ctx)
	if err != nil {
		return RuntimeLease{}, fmt.Errorf("service runtime unavailable: %w", err)
	}
	if !runtimeDigest.MatchString(r.Hash) || !filepath.IsAbs(r.Dir) || filepath.Base(r.Dir) != r.Hash || r.Release == nil {
		if r.Release != nil {
			r.Release()
		}
		return RuntimeLease{}, fmt.Errorf("invalid trusted runtime lease")
	}
	var once sync.Once
	release := r.Release
	r.Release = func() { once.Do(release) }
	return r, nil
}
