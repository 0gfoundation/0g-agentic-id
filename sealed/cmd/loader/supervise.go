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
// SIGINT before the loader kills it. sealed's own stop budget is 90 s
// (sealed/shutdown.go), so the loader waits longer; a platform stop timeout
// can still end the container sooner.
const stopGrace = 2 * time.Minute

// Restarts of a sealed that exits on its own, under the layered flow: at
// most maxRestarts within restartWindow, the loader exits after that.
const (
	maxRestarts   = 5
	restartWindow = 10 * time.Minute
)

// The environment the loader sets for the sealed it starts
// (sealed/internal/layers; keep in step).
const (
	// sealedHashEnv carries the hash the loader verified.
	sealedHashEnv = "SEALED_HASH"
	// trialEnv is "1" for a version the loader switched to and has not seen
	// confirmed.
	trialEnv = "SEALED_TRIAL"
)

// verifyFile checks that the file at path hashes to want, a lowercase hex
// sha256.
//
// The file is then started by path. Between this check and the exec only
// root could replace it, and the only root processes at that point are the
// loader itself and, for a staged version, the sealed that staged it, which
// has exited.
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

// version is one sealed program: its hash and where it is.
type version struct {
	hash string
	path string
}

// supervisor runs sealed as a child and waits for it. sealed inherits the
// loader's environment as it stands, container key included, plus
// sealedHashEnv and trialEnv.
type supervisor struct {
	// builtin is the image's own sealed, whose hash is built into the
	// loader. It runs when nothing else was switched to, and is what a
	// failed switch falls back to last.
	builtin version
	// state is the directory shared with sealed (state.go). Empty, the
	// loader runs builtin only, and exits when it exits.
	state stateDir
	// allow is the sealed allowlist on chain (allowlist.go); nil checks
	// nothing.
	allow *allowlist

	stdout io.Writer
	stderr io.Writer

	// reapAll makes the supervisor collect every exited process, not just
	// sealed, and end what sealed leaves behind before another sealed
	// starts. As PID 1 the loader inherits orphans that nothing else waits
	// for; anywhere else (tests) it must leave other processes alone.
	reapAll bool

	// sigs carries the signals the loader handles: SIGCHLD triggers a reap,
	// SIGUSR1 is sealed asking to switch versions, every other signal is
	// forwarded to sealed.
	sigs <-chan os.Signal

	stopGrace time.Duration
	// poll reaps on a timer too, so a coalesced or missed SIGCHLD cannot
	// leave sealed's exit unnoticed.
	poll time.Duration
	// backoff is the wait before the n-th restart within the window.
	backoff func(n int) time.Duration
	// window is restartWindow (tests shorten it).
	window time.Duration
	logf   func(string, ...any)
}

// outcome is how one run of sealed ended.
type outcome int

const (
	stopped       outcome = iota // a stop signal from outside ended it
	switching                    // it exited after asking to switch versions
	exited                       // it exited on its own
	failedToStart                // it could not be verified or started
)

type runResult struct {
	outcome outcome
	code    int
	next    version
}

// run supervises sealed until the loader should exit, and returns the code
// to exit with: sealed's own, 128+signal when a signal ended it, and 1 when
// sealed could not be started.
func (s *supervisor) run() int {
	cur := s.current()
	var restarts []time.Time
	for {
		chosen, ok := s.allowed(cur)
		if !ok {
			s.logf("FAIL no sealed version this container has is on the sealed list; the agent needs a reset onto a current image")
			return 1
		}
		if chosen.hash != cur.hash {
			s.record(chosen.hash, "")
			cur = chosen
		}
		trial := s.trial(cur)
		res := s.runOnce(cur, trial)
		switch res.outcome {
		case stopped:
			return res.code
		case switching:
			s.killLeftovers()
			s.logf("switching sealed from %s to %s, on trial", short(cur.hash), short(res.next.hash))
			// What a failed switch goes back to is a version that came up:
			// the one switched from, unless it was itself still on trial.
			back := cur.hash
			if trial && s.state.read("confirmed") != cur.hash {
				back = s.state.hash("previous")
			}
			s.record(res.next.hash, back)
			cur = res.next
			continue
		}
		s.killLeftovers()
		if cur.hash != s.builtin.hash && (res.outcome == failedToStart || (trial && s.state.read("confirmed") != cur.hash)) {
			prev := s.previous(cur)
			s.logf("sealed %s did not come up (exit %d); going back to %s", short(cur.hash), res.code, short(prev.hash))
			if err := s.state.markFailed(cur.hash); err != nil {
				s.logf("record the failed version: %v", err)
			}
			s.record(prev.hash, "")
			cur = prev
			continue
		}
		if res.outcome == failedToStart || s.state == "" || !s.state.layered() {
			s.logf("sealed exited with code %d", res.code)
			return res.code
		}
		now := time.Now()
		recent := restarts[:0]
		for _, at := range restarts {
			if now.Sub(at) < s.window {
				recent = append(recent, at)
			}
		}
		restarts = recent
		if len(restarts) >= maxRestarts {
			s.logf("sealed exited %d times within %v; giving up (exit %d)", len(restarts)+1, s.window, res.code)
			return res.code
		}
		restarts = append(restarts, now)
		wait := s.backoff(len(restarts))
		s.logf("sealed exited with code %d; restarting it in %v", res.code, wait)
		if code, stop := s.pause(wait); stop {
			return code
		}
	}
}

// current is the version to run first: the one the loader last switched
// to, when its program is there, else builtin.
func (s *supervisor) current() version {
	if s.state == "" {
		return s.builtin
	}
	return s.byHash(s.state.hash("current"))
}

// previous is what a failed version falls back to: the version it replaced,
// unless that one failed too, else builtin.
func (s *supervisor) previous(failed version) version {
	h := s.state.hash("previous")
	if h == "" || h == failed.hash || s.state.failed(h) {
		return s.builtin
	}
	return s.byHash(h)
}

// byHash is version h: builtin for "" or builtin's hash, else the staged
// program.
func (s *supervisor) byHash(h string) version {
	if h == "" || h == s.builtin.hash {
		return s.builtin
	}
	return version{hash: h, path: s.state.staged(h)}
}

// allowed is the version to run: v, else the version it replaced, else
// builtin — the first one the allowlist on chain does not refuse. ok is
// false when it refuses every one. A version whose answer cannot be had
// runs (allowlist.go).
func (s *supervisor) allowed(v version) (version, bool) {
	candidates := []version{v}
	if s.state != "" && v.hash != s.builtin.hash {
		if p := s.previous(v); p.hash != v.hash {
			candidates = append(candidates, p)
		}
	}
	if candidates[len(candidates)-1].hash != s.builtin.hash {
		candidates = append(candidates, s.builtin)
	}
	for _, c := range candidates {
		refused, err := s.allow.refuses(c.hash)
		if err != nil {
			s.logf("the sealed list is unreadable for %s (%v); running it, the attestor checks it before any key", short(c.hash), err)
			return c, true
		}
		if !refused {
			return c, true
		}
		s.logf("sealed %s is not on the sealed list; not running it", short(c.hash))
	}
	return version{}, false
}

// trial reports whether v runs on trial: switched to, and not yet
// confirmed by sealed.
func (s *supervisor) trial(v version) bool {
	return s.state != "" && v.hash != s.builtin.hash && s.state.read("confirmed") != v.hash
}

// record writes which version runs and which it replaced.
func (s *supervisor) record(current, previous string) {
	if err := s.state.write("current", current); err != nil {
		s.logf("record the current version: %v", err)
	}
	if err := s.state.write("previous", previous); err != nil {
		s.logf("record the previous version: %v", err)
	}
}

// requested is the version sealed asked to switch to (SIGUSR1): another
// version than cur, not one the loader went back from, whose program hashes
// to its name.
func (s *supervisor) requested(cur version) (version, bool) {
	if s.state == "" {
		return version{}, false
	}
	h := s.state.hash("request")
	switch {
	case h == "":
		s.logf("SIGUSR1 without a valid request; ignored")
		return version{}, false
	case h == cur.hash:
		return version{}, false
	case s.state.failed(h):
		s.logf("refusing the switch to %s: it did not come up here before", short(h))
		return version{}, false
	}
	v := s.byHash(h)
	if err := verifyFile(v.path, v.hash); err != nil {
		s.logf("refusing the switch to %s: %v", short(h), err)
		return version{}, false
	}
	if refused, _ := s.allow.refuses(h); refused {
		s.logf("refusing the switch to %s: it is not on the sealed list", short(h))
		return version{}, false
	}
	return v, true
}

// runOnce verifies and starts v, and blocks until it exits.
func (s *supervisor) runOnce(v version, trial bool) runResult {
	if err := verifyFile(v.path, v.hash); err != nil {
		s.logf("FAIL %v", err)
		return runResult{outcome: failedToStart, code: 1}
	}
	_ = os.Setenv(sealedHashEnv, v.hash)
	if trial {
		_ = os.Setenv(trialEnv, "1")
	} else {
		_ = os.Unsetenv(trialEnv)
	}
	cmd := exec.Command(v.path)
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		s.logf("FAIL start %s: %v", v.path, err)
		return runResult{outcome: failedToStart, code: 1}
	}
	pid := cmd.Process.Pid
	onTrial := ""
	if trial {
		onTrial = ", on trial"
	}
	s.logf("OK   started %s (pid %d, sealed %s%s)", v.path, pid, short(v.hash), onTrial)

	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	var deadline <-chan time.Time
	var next *version
	stopping := false
	for {
		select {
		case sig := <-s.sigs:
			switch sig {
			case syscall.SIGCHLD:
			case syscall.SIGUSR1:
				if stopping || next != nil {
					break
				}
				if n, ok := s.requested(v); ok {
					next = &n
					s.logf("sealed asked to switch to %s; stopping it", short(n.hash))
					s.forward(pid, syscall.SIGTERM)
					if deadline == nil {
						deadline = time.After(s.stopGrace)
					}
				}
			default:
				s.forward(pid, sig)
				if sig == syscall.SIGTERM || sig == syscall.SIGINT {
					stopping = true
					if deadline == nil {
						deadline = time.After(s.stopGrace)
					}
				}
			}
		case <-ticker.C:
		case <-deadline:
			s.logf("sealed did not exit within %v of the stop signal; killing it", s.stopGrace)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			deadline = nil
		}
		if code, done := s.reap(pid); done {
			switch {
			case stopping:
				s.logf("sealed exited with code %d", code)
				return runResult{outcome: stopped, code: code}
			case next != nil:
				return runResult{outcome: switching, code: code, next: *next}
			}
			return runResult{outcome: exited, code: code}
		}
	}
}

// pause waits d before a restart. A stop signal meanwhile ends the loader:
// stop is true, with the code to exit with.
func (s *supervisor) pause(d time.Duration) (code int, stop bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return 0, false
		case sig := <-s.sigs:
			if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				s.logf("%v while waiting to restart sealed; exiting", sig)
				return 128 + int(sig.(syscall.Signal)), true
			}
			if sig == syscall.SIGCHLD {
				s.reapOthers()
			}
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

// reapOthers collects exited orphans while no sealed runs.
func (s *supervisor) reapOthers() {
	if !s.reapAll {
		return
	}
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return
		}
	}
}

// killLeftovers ends every process the sealed that exited left behind (the
// harness, the agent's own processes) before another sealed starts, so none
// of them holds the port or the files the next one needs. Only as PID 1,
// where every other process in the container descends from the loader and
// kill(-1) reaches exactly those.
func (s *supervisor) killLeftovers() {
	if !s.reapAll {
		return
	}
	_ = syscall.Kill(-1, syscall.SIGKILL)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err == syscall.ECHILD {
			return
		}
		if err != nil && err != syscall.EINTR {
			return
		}
		if pid <= 0 {
			time.Sleep(20 * time.Millisecond)
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

// short is a hash's first 8 digits, for log lines.
func short(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// restartBackoff is 1 s, 2 s, 4 s, ... up to 30 s.
func restartBackoff(n int) time.Duration {
	if n > 5 {
		return 30 * time.Second
	}
	return min(time.Second<<max(n-1, 0), 30*time.Second)
}
