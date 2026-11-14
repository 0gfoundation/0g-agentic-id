package servicehost

// A coordinator is an ordinary isolated service program. It has durable,
// service-private work and a narrowly scoped process-control socket, never
// the owner's home, model keys, signing tools or credential interfaces.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/net/netutil"

	"seal-verify/internal/privsep"
	"seal-verify/internal/serviceidentity"
)

type coordinator struct {
	cancel context.CancelFunc
	done   chan struct{}
	server *http.Server
	cmd    *isolatedCommand
	// held marks a coordinator whose start failed: it only keeps the identity
	// until cleanup is proven. started and reason are set under m.mu.
	held    bool
	started time.Time
	reason  string // why it ended, when sealed ended it: a limit or readiness_timeout
}

const (
	minRestartDelay = 2 * time.Second
	maxRestartDelay = 60 * time.Second
	// A coordinator that stayed up this long restarts after minRestartDelay
	// again; one that keeps failing sooner backs off up to maxRestartDelay.
	stableCoordinator = 60 * time.Second
)

func nextRestartDelay(prev, uptime time.Duration) time.Duration {
	if uptime >= stableCoordinator || prev < minRestartDelay {
		return minRestartDelay
	}
	return min(2*prev, maxRestartDelay)
}

func (m *Manager) coordinatorDir(id string) string {
	return filepath.Join(m.programs, id, "coordinator")
}

// coordinatorRunDir holds a coordinator's sockets. It is keyed by identity
// under a short root, so every socket path stays within the 107 bytes a Unix
// socket address allows whatever the service id (TestSocketPathsFit).
func (m *Manager) coordinatorRunDir(uid uint32) string {
	return filepath.Join(m.programs, runDirName, strconv.FormatUint(uint64(uid), 10))
}
func (m *Manager) coordinatorSocket(uid uint32) string {
	return filepath.Join(m.coordinatorRunDir(uid), "service.sock")
}

func (m *Manager) prepareCoordinatorWork(e *entry) error {
	base := m.coordinatorDir(e.ID)
	if err := privsep.MkdirAll(base, 0755); err != nil {
		return err
	}
	work := filepath.Join(base, "work")
	if err := privsep.MkdirAll(work, 0700); err != nil {
		return err
	}
	return os.Lchown(work, int(e.ControllerUID), int(e.ControllerUID))
}

// errCoordinatorHeld reports a previous coordinator of the entry whose
// identity is still being cleaned up.
var errCoordinatorHeld = errors.New("the previous coordinator is still being cleaned up")

// startCoordinator makes one attempt for this generation of e: the slow
// preparation (probe, free space, runtime pin) runs without the manager lock,
// the start under it, and only while the entry is still wanted. A failure is
// recorded on the entry.
func (m *Manager) startCoordinator(e *entry, gen uint64) error {
	lease, err := m.prepareLaunch(context.Background())
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries[e.ID] != e || e.generation != gen || !e.Desired || m.closed || e.controller != nil {
		if err == nil {
			lease.Release()
		}
		if e.controller != nil && e.controller.held {
			return errCoordinatorHeld
		}
		return nil
	}
	if err == nil {
		if cause := m.quarantined[e.ControllerUID]; cause != "" {
			lease.Release()
			err = fmt.Errorf("coordinator identity %d is quarantined: %s", e.ControllerUID, cause)
		}
	}
	if err == nil {
		err = m.startCoordinatorLocked(e, lease)
	}
	if err != nil {
		e.State, e.Error = "restarting", err.Error()
		if errors.Is(err, ErrIsolationUnavailable) {
			e.State = "unsupported"
		}
	}
	return err
}

// launchCoordinator makes the first attempt now and, if it fails, keeps
// trying in the background.
func (m *Manager) launchCoordinator(e *entry, gen uint64) error {
	err := m.startCoordinator(e, gen)
	if err != nil {
		go m.keepCoordinator(e, gen, minRestartDelay)
	}
	return err
}

// keepCoordinator retries a wanted coordinator's start, backing off from
// delay up to maxRestartDelay, for as long as this generation of e stays
// wanted: admission can fail for a while (free space, the process budget, a
// probe or a runtime listing), and a failed start holds its identity until
// cleanup is proven. Stop, Close and Publish end it; a started coordinator's
// supervisor takes over (a start advances the generation).
func (m *Manager) keepCoordinator(e *entry, gen uint64, delay time.Duration) {
	m.mu.Lock()
	if e.keeping && e.keepingGen == gen {
		m.mu.Unlock()
		return
	}
	e.keeping, e.keepingGen = true, gen
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if e.keepingGen == gen {
			e.keeping = false
		}
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		if m.entries[e.ID] != e || e.generation != gen || !e.Desired || m.closed {
			m.mu.Unlock()
			return
		}
		var held chan struct{}
		if c := e.controller; c != nil {
			if !c.held {
				m.mu.Unlock()
				return
			}
			held = c.done
		}
		e.restartDelay = delay
		m.mu.Unlock()
		if held != nil {
			select {
			case <-held:
			case <-m.stopGC:
				return
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-m.stopGC:
			timer.Stop()
			return
		}
		_ = m.startCoordinator(e, gen)
		delay = min(2*delay, maxRestartDelay)
	}
}

// startCoordinatorLocked owns lease: released on failure, else after the
// coordinator's identity has been reaped.
func (m *Manager) startCoordinatorLocked(e *entry, lease RuntimeLease) (err error) {
	started := false
	defer func() {
		if !started && lease.Release != nil {
			lease.Release()
		}
	}()
	if !serviceidentity.Valid(int(e.ControllerUID)) {
		return fmt.Errorf("invalid coordinator identity")
	}
	if e.controller != nil {
		return nil
	}
	if m.processesInUseLocked()+e.Manifest.Processes > MaxServiceProcesses {
		return ErrProcessBudget
	}
	base := m.coordinatorDir(e.ID)
	run := m.coordinatorRunDir(e.ControllerUID)
	if err := discardDir(run); err != nil {
		return err
	}
	if err := privateDir(run, e.ControllerUID); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &coordinator{cancel: cancel, done: make(chan struct{})}
	socket := filepath.Join(run, "control.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		cancel()
		return err
	}
	if err = os.Lchown(socket, int(e.ControllerUID), int(e.ControllerUID)); err != nil {
		cancel()
		ln.Close()
		return err
	}
	if err = privsep.Chmod(socket, 0600); err != nil {
		cancel()
		ln.Close()
		return err
	}
	c.server = &http.Server{Handler: m.ExecutionHandler(e.ID), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = c.server.Serve(netutil.LimitListener(ln, maxControlConns)) }()
	started = true // command owns the lease from here
	cmd, err := m.command(ctx, e, e.ControllerUID, base, coordinatorCommand, lease)
	if err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader([]byte("{}")), io.Discard, io.Discard
		cmd.WaitDelay = 250 * time.Millisecond
		cmd.onCleanupFailure = func() {
			m.mu.Lock()
			e.State, e.Error = "quarantined", "resource cleanup failed; identity and runtime remain pinned"
			m.mu.Unlock()
		}
		cmd.onLimit = func(reason string) {
			m.mu.Lock()
			c.reason, e.Error = reason, reason
			m.mu.Unlock()
		}
		err = cmd.Start()
	}
	if err != nil {
		cancel()
		c.server.Close()
		m.holdFailedCoordinator(e, c, cmd)
		return fmt.Errorf("start isolated coordinator: %w", err)
	}
	c.cmd, c.started = cmd, time.Now()
	e.generation++
	gen := e.generation
	e.controller, e.State, e.Error = c, "starting", ""
	go m.superviseCoordinator(ctx, e, c, gen)
	return nil
}

// Called with m.mu held. Stable service identities cannot be restarted or
// handed to another process while processes of the old one may remain.
func (m *Manager) holdFailedCoordinator(e *entry, c *coordinator, cmd *isolatedCommand) {
	if cmd == nil || cmd.resourcesReleased() {
		return
	}
	c.cmd, c.held = cmd, true
	e.controller = c
	go func() {
		<-cmd.cleanupDone
		m.mu.Lock()
		if e.controller == c {
			e.controller = nil
		}
		m.mu.Unlock()
		close(c.done)
	}()
}

func (m *Manager) superviseCoordinator(ctx context.Context, e *entry, c *coordinator, gen uint64) {
	readyDone := make(chan struct{})
	go func() {
		defer close(readyDone)
		tick := time.NewTicker(30 * time.Millisecond)
		defer tick.Stop()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.done:
				return
			case <-deadline.C:
				m.mu.Lock()
				if c.reason == "" {
					c.reason = "readiness_timeout"
				}
				m.mu.Unlock()
				c.cancel()
				return
			case <-tick.C:
				conn, err := net.DialTimeout("unix", m.coordinatorSocket(e.ControllerUID), 20*time.Millisecond)
				if err != nil {
					continue
				}
				conn.Close()
				m.mu.Lock()
				if e.generation == gen && e.Desired && !m.closed {
					e.State = "running"
				}
				m.mu.Unlock()
				return
			}
		}
	}()
	err := c.cmd.Wait()
	c.cancel()
	c.server.Close()
	<-readyDone
	m.mu.Lock()
	if e.controller == c {
		e.controller = nil
	}
	restart := m.entries[e.ID] == e && e.generation == gen && e.Desired && !m.closed
	var delay time.Duration
	if restart {
		// The reason sealed ended it (a limit, readiness) stays visible.
		reason := c.reason
		if reason == "" {
			reason = "coordinator_exit"
		}
		e.State, e.Error = "restarting", reason
		delay = nextRestartDelay(e.restartDelay, time.Since(c.started))
	} else if m.entries[e.ID] == e && !e.Desired {
		// Ended because it is no longer wanted. Wait returned only once its
		// identity was proven empty, so no stopping or cleanup error is left.
		e.State, e.Error = "stopped", ""
	} else if err != nil && e.State != "stopped" {
		e.State = "stopped"
	}
	m.mu.Unlock()
	// Stop waits for this signal before a subsequent Start. Publish the cleared
	// controller/state first so Start cannot mistake an exited process for a
	// live one. Cancellation already stops the readiness watcher above.
	close(c.done)
	if restart {
		m.keepCoordinator(e, gen, delay)
	}
}

func (t *taskTransport) coordinatorRoundTrip(req *http.Request) (*http.Response, error) {
	m := t.manager
	m.mu.Lock()
	e := m.entries[t.id]
	ready := e != nil && e.Desired && e.State == "running" && !m.closed
	version := ""
	if e != nil {
		version = e.Version
	}
	m.mu.Unlock()
	if !ready {
		return response(req, 503, "service unavailable"), nil
	}
	if code, message := checkPrivateInputVersion(req, version); code != 0 {
		return response(req, code, message), nil
	}
	req = req.Clone(req.Context())
	// Caller-controlled references are never trusted. A fresh reference is
	// minted only after validating the private input on this very request.
	req.Header.Del(InputHandleHeader)
	values := req.Header.Values(RuntimeInputHeader)
	req.Header.Del(RuntimeInputHeader)
	req.Header.Del(ServiceVersionHeader)
	if len(values) > 0 {
		if len(values) != 1 || len(values[0]) > base64.StdEncoding.EncodedLen(MaxRuntimeInput) {
			return response(req, 400, "invalid runtime input"), nil
		}
		input, err := base64.StdEncoding.Strict().DecodeString(values[0])
		var fields map[string]string
		if err != nil || len(input) > MaxRuntimeInput || json.Unmarshal(input, &fields) != nil || fields == nil {
			return response(req, 400, "invalid runtime input"), nil
		}
		handle, cleanup, err := m.handoffForVersion(t.id, version, input)
		if err != nil {
			return response(req, 503, "private input admission unavailable"), nil
		}
		defer cleanup()
		req.Header.Set(InputHandleHeader, handle)
	}
	m.mu.Lock()
	e = m.entries[t.id]
	ready = e != nil && e.Desired && e.State == "running" && e.Version == version && !m.closed
	var uid uint32
	if ready {
		uid = e.ControllerUID
	}
	m.mu.Unlock()
	if !ready {
		return response(req, 503, "service release admission changed"), nil
	}
	return Client(m.coordinatorSocket(uid)).Transport.RoundTrip(req)
}
