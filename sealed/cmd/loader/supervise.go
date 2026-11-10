package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// stopGrace is how long sealed has to exit after a forwarded SIGTERM or
// SIGINT before the loader kills it. sealed spends up to its own stop budget
// (90s, sealed/shutdown.go) committing pending iData, so the loader waits
// longer than that; a platform stop timeout can still end the container
// sooner.
const stopGrace = 2 * time.Minute

// verifyFile checks that the file at path hashes to want, a lowercase hex
// sha256.
//
// The file is then started by path. Between this check and the exec only
// root could replace it, and the only root process at that point is the
// loader itself.
func verifyFile(path, want string) error {
	if want == "" {
		return errors.New("no sealed hash was built into the loader; refusing to run sealed")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(want) {
		return fmt.Errorf("%s hashes to %s, not the expected %s; refusing to run it", path, got, want)
	}
	return nil
}

// supervisor runs sealed as a child and waits for it. sealed inherits the
// loader's environment as it stands, container key included.
type supervisor struct {
	path   string
	stdout io.Writer
	stderr io.Writer

	// reapAll makes the supervisor collect every exited process, not just
	// sealed. As PID 1 the loader inherits orphans that nothing else waits
	// for; anywhere else (tests) it must leave other children alone.
	reapAll bool

	// sigs carries the signals the loader handles: SIGCHLD triggers a reap,
	// every other signal is forwarded to sealed.
	sigs <-chan os.Signal

	stopGrace time.Duration
	// poll reaps on a timer too, so a coalesced or missed SIGCHLD cannot
	// leave sealed's exit unnoticed.
	poll time.Duration
	logf func(string, ...any)
}

// run starts sealed and blocks until it exits. It returns the code the
// loader should exit with: sealed's own, 128+signal when a signal ended it,
// and 1 when sealed could not be started.
func (s *supervisor) run() int {
	cmd := exec.Command(s.path)
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		s.logf("FAIL start %s: %v", s.path, err)
		return 1
	}
	pid := cmd.Process.Pid
	s.logf("OK   started %s (pid %d)", s.path, pid)

	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	var deadline <-chan time.Time
	for {
		select {
		case sig := <-s.sigs:
			if sig != syscall.SIGCHLD {
				s.forward(pid, sig)
				if deadline == nil && (sig == syscall.SIGTERM || sig == syscall.SIGINT) {
					deadline = time.After(s.stopGrace)
				}
			}
		case <-ticker.C:
		case <-deadline:
			s.logf("sealed did not exit within %v of the stop signal; killing it", s.stopGrace)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			deadline = nil
		}
		if code, done := s.reap(pid); done {
			s.logf("sealed exited with code %d", code)
			return code
		}
	}
}

func (s *supervisor) forward(pid int, sig os.Signal) {
	ss, ok := sig.(syscall.Signal)
	if !ok {
		return
	}
	s.logf("forwarding %v to sealed", ss)
	if err := syscall.Kill(pid, ss); err != nil && err != syscall.ESRCH {
		s.logf("forward %v: %v", ss, err)
	}
}

// reap collects exited children without blocking and reports sealed's exit
// code once sealed has exited.
func (s *supervisor) reap(sealed int) (int, bool) {
	target := sealed
	if s.reapAll {
		target = -1
	}
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(target, &ws, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return 0, false
		}
		if pid == sealed {
			return exitCode(ws), true
		}
	}
}

func exitCode(ws syscall.WaitStatus) int {
	switch {
	case ws.Exited():
		return ws.ExitStatus()
	case ws.Signaled():
		return 128 + int(ws.Signal())
	}
	return 1
}
