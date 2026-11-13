package servicehost

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"seal-verify/internal/servicecgroup"
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

type isolatedCommand struct {
	*exec.Cmd
	runtimeHash      string
	release          func()
	resources        *servicecgroup.Lease
	cleanupResource  func(context.Context) error // private lifecycle hook; production uses the verified lease
	cleanupOnce      sync.Once
	cleanupDone      chan struct{}
	cleanupErr       error
	onCleanupFailure func()
}

func (c *isolatedCommand) Start() error {
	err := c.Cmd.Start()
	if err != nil {
		c.beginCleanup()
	}
	return err
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

func (c *isolatedCommand) beginCleanup() {
	c.cleanupOnce.Do(func() {
		c.cleanupDone = make(chan struct{})
		finish := func() {
			if c.release != nil {
				c.release()
			}
			close(c.cleanupDone)
		}
		cleanupResource := c.cleanupResource
		if cleanupResource == nil && c.resources != nil {
			cleanupResource = c.resources.KillAndRemove
		}
		if cleanupResource == nil {
			finish()
			return
		}
		attempt := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			return cleanupResource(ctx)
		}
		if err := attempt(); err == nil {
			finish()
			return
		} else {
			c.cleanupErr = err
		}
		// Keep the UID slot, cgroup and runtime lease pinned while the kernel
		// cannot prove the entire process tree empty. No successful receipt is
		// possible after even a transient resource cleanup failure.
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
