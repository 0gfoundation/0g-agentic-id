package servicehost

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

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
// number of tasks times the number of processes.
type resourceWatcher struct {
	mu      sync.Mutex
	active  map[uint32]*isolatedCommand
	started bool
	stop    chan struct{}
}

func newResourceWatcher(stop chan struct{}) *resourceWatcher {
	return &resourceWatcher{active: map[uint32]*isolatedCommand{}, stop: stop}
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
		usage := servicesandbox.Scan(uids)
		for _, c := range cmds {
			if c.limits.residentBytes > 0 && usage[c.uid].RSSBytes > c.limits.residentBytes {
				c.exceeded("memory_limit")
				continue
			}
			if n%4 == 0 && c.limits.diskBytes > 0 && diskUsage(c.limits.diskDirs, c.limits.diskBytes) > c.limits.diskBytes {
				c.exceeded("disk_limit")
			}
		}
	}
}

// diskUsage sums allocated blocks below dirs, stopping once the sum passes
// stopAt. Each entry is charged at least one block, so an identity cannot
// exhaust inodes with empty files either.
func diskUsage(dirs []string, stopAt int64) int64 {
	var total int64
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			size := int64(4096)
			if info, err := d.Info(); err == nil && info.Size() > size {
				size = info.Size()
			}
			total += size
			if total > stopAt {
				return filepath.SkipAll
			}
			return nil
		})
		if total > stopAt {
			break
		}
	}
	return total
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
