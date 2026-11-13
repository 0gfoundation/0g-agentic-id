package servicehost

// A coordinator is an ordinary isolated service program. It has durable,
// service-private work and a narrowly scoped process-control socket, never
// the owner's home, model keys, signing tools or credential interfaces.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"seal-verify/internal/privsep"
)

type coordinator struct {
	cancel context.CancelFunc
	done   chan struct{}
	server *http.Server
	cmd    *exec.Cmd
}

func (m *Manager) coordinatorDir(id string) string {
	return filepath.Join(m.programs, id, "coordinator")
}
func (m *Manager) coordinatorSocket(id string) string {
	return filepath.Join(m.coordinatorDir(id), "run", "service.sock")
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
	return os.Chown(work, int(e.ControllerUID), int(e.ControllerUID))
}

func (m *Manager) startCoordinatorLocked(e *entry) error {
	if e.ControllerUID < 200000 || e.ControllerUID >= 200000+MaxServices {
		return fmt.Errorf("invalid coordinator identity")
	}
	if e.controller != nil {
		return nil
	}
	base := m.coordinatorDir(e.ID)
	run := filepath.Join(base, "run")
	if err := privsep.RemoveAll(run); err != nil {
		return err
	}
	if err := privsep.MkdirAll(run, 0700); err != nil {
		return err
	}
	if err := os.Chown(run, int(e.ControllerUID), int(e.ControllerUID)); err != nil {
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
	if err = os.Chown(socket, int(e.ControllerUID), int(e.ControllerUID)); err != nil {
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
	go func() { _ = c.server.Serve(ln) }()
	cmd, err := m.command(ctx, e, e.ControllerUID, base, true)
	if err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader([]byte("{}")), io.Discard, io.Discard
		cmd.WaitDelay = 250 * time.Millisecond
		err = cmd.Start()
	}
	if err != nil {
		cancel()
		c.server.Close()
		return fmt.Errorf("start isolated coordinator")
	}
	c.cmd = cmd
	e.generation++
	gen := e.generation
	e.controller, e.State, e.Error = c, "starting", ""
	go m.superviseCoordinator(ctx, e, c, gen)
	return nil
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
				c.cancel()
				return
			case <-tick.C:
				conn, err := net.DialTimeout("unix", m.coordinatorSocket(e.ID), 20*time.Millisecond)
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
	restart := e.generation == gen && e.Desired && !m.closed
	if restart {
		e.State, e.Error = "restarting", "coordinator_exit"
	} else if err != nil && e.State != "stopped" {
		e.State = "stopped"
	}
	m.mu.Unlock()
	// Stop waits for this signal before a subsequent Start. Publish the cleared
	// controller/state first so Start cannot mistake an exited process for a
	// live one. Cancellation already stops the readiness watcher above.
	close(c.done)
	if !restart {
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-m.stopGC:
		return
	case <-timer.C:
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.generation == gen && e.Desired && !m.closed {
		if err := m.startCoordinatorLocked(e); err != nil {
			e.State, e.Error = "failed", "coordinator_start_failed"
		}
	}
}

func (t *taskTransport) coordinatorRoundTrip(req *http.Request) (*http.Response, error) {
	m := t.manager
	m.mu.Lock()
	e := m.entries[t.id]
	ready := e != nil && e.Desired && e.State == "running" && !m.closed
	m.mu.Unlock()
	if !ready {
		return response(req, 503, "service unavailable"), nil
	}
	req = req.Clone(req.Context())
	// Caller-controlled references are never trusted. A fresh reference is
	// minted only after validating the private input on this very request.
	req.Header.Del(InputHandleHeader)
	values := req.Header.Values(RuntimeInputHeader)
	req.Header.Del(RuntimeInputHeader)
	if len(values) > 0 {
		if len(values) != 1 || len(values[0]) > base64.StdEncoding.EncodedLen(MaxRuntimeInput) {
			return response(req, 400, "invalid runtime input"), nil
		}
		input, err := base64.StdEncoding.Strict().DecodeString(values[0])
		var fields map[string]string
		if err != nil || len(input) > MaxRuntimeInput || json.Unmarshal(input, &fields) != nil || fields == nil {
			return response(req, 400, "invalid runtime input"), nil
		}
		handle, cleanup, err := m.handoff(t.id, input)
		if err != nil {
			return response(req, 503, "private input admission unavailable"), nil
		}
		defer cleanup()
		req.Header.Set(InputHandleHeader, handle)
	}
	return Client(m.coordinatorSocket(t.id)).Transport.RoundTrip(req)
}
