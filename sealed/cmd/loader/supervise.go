package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// Restarts of a sealed that came up and then exits on its own: at most
// maxRestarts within restartWindow, the loader exits after that.
const (
	maxRestarts   = 5
	restartWindow = 10 * time.Minute
)

// A version on trial (one that has not come up in this container yet) must
// confirm within trialLimit of its start, or the loader stops it and treats
// it as failed. A version that exits with trialTransientExit is started again
// (transientBackoff); one on trial that has done so for transientLimit is
// treated as failed, where a listed version to go back to exists.
const (
	trialLimit     = 20 * time.Minute
	transientLimit = time.Hour
)

// The environment the loader sets for the sealed it starts
// (sealed/internal/layers; keep in step).
const (
	// sealedHashEnv carries the hash the loader verified.
	sealedHashEnv = "SEALED_HASH"
	// trialEnv is "1" for a version that has not come up in this container
	// yet (sealed has not confirmed it).
	trialEnv = "SEALED_TRIAL"
)

// The exit codes sealed tells the loader something with
// (sealed/internal/layers; keep in step). Any other exit of a version on
// trial before it confirms is that version failing.
const (
	// trialTransientExit: the boot failed for a reason outside the version
	// (an endpoint it could not reach, a download): start it again later.
	trialTransientExit = 69
	// restartRequestedExit: the owner asked for sealed to be restarted.
	restartRequestedExit = 76
)

// verifyFile checks that the file at path hashes to want, a lowercase hex
// sha256.
//
// The file is then started by path. It is a program in the loader's state
// directory, which only root can enter, downloaded by the loader or staged by
// a sealed that has exited by now: between this check and the exec no other
// root process runs (killLeftovers).
func verifyFile(path, want string) error {
	if want == "" {
		return errors.New("no sealed hash to check the program against; refusing to run it")
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
	// state is the directory shared with sealed (state.go).
	state stateDir
	// allow is the sealed list on chain (allowlist.go).
	allow sealedList
	// artifacts is the release versions are downloaded from (fetch.go), and
	// http the client that downloads them.
	artifacts string
	http      *http.Client

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
	// trialLimit and transientLimit are the constants of the same names;
	// transientBackoff is the wait before the n-th start of a version that
	// exited with trialTransientExit, and before the n-th read of a list
	// that names nothing to run (tests shorten all three).
	trialLimit       time.Duration
	transientLimit   time.Duration
	transientBackoff func(n int) time.Duration
	logf             func(string, ...any)
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
// to exit with: sealed's own, or 128+signal when a signal ended it.
//
// Each start runs the version choose picks. When nothing can run (the list
// cannot be read, or lists nothing this container can run) the loader reads
// the list again after a wait, and runs nothing meanwhile.
func (s *supervisor) run() int {
	var restarts []time.Time
	// transient counts the starts of a version that keeps exiting with
	// trialTransientExit, transientSince is since when it has; any other end
	// of a run resets both. idle counts the reads that found nothing to run.
	var transient, idle int
	var transientSince time.Time
	for {
		cur, ok := s.choose()
		if !ok {
			idle++
			wait := s.transientBackoff(idle)
			s.logf("no sealed version can run now; reading the sealed list again in %v", wait)
			if code, stop := s.pause(wait); stop {
				return code
			}
			continue
		}
		idle = 0
		if cur.hash != s.state.hash("current") {
			s.record(cur.hash, "")
		}
		// A download can take a while: a stop asked for meanwhile is kept.
		if code, stop := s.pendingStop(); stop {
			return code
		}
		trial := s.trial(cur)
		res := s.runOnce(cur, trial)
		switch res.outcome {
		case stopped:
			return res.code
		case switching:
			s.killLeftovers()
			s.logf("switching sealed from %s to %s", short(cur.hash), short(res.next.hash))
			// What a failed switch goes back to is a version that came up:
			// the one switched from, unless it was itself still on trial.
			back := cur.hash
			if trial && s.state.read("confirmed") != cur.hash {
				back = s.state.hash("previous")
			}
			s.record(res.next.hash, back)
			transient, transientSince = 0, time.Time{}
			continue
		}
		s.killLeftovers()
		if res.outcome == exited && res.code == restartRequestedExit {
			// Not a crash: started again at once, and not counted.
			s.logf("sealed exited for a restart its owner asked for; starting it again")
			transient, transientSince = 0, time.Time{}
			continue
		}
		if res.outcome == exited && res.code == trialTransientExit {
			// The boot failed for a reason outside the version: it is not
			// counted against the version, and runs again after a wait.
			now := time.Now()
			if transientSince.IsZero() {
				transientSince = now
			}
			if trial && now.Sub(transientSince) >= s.transientLimit {
				if prev := s.state.hash("previous"); prev != "" && prev != cur.hash && !s.state.failed(prev) && s.listed(prev) {
					s.logf("sealed %s has not come up for %v, for reasons outside it; going back to %s", short(cur.hash), s.transientLimit, short(prev))
					if err := s.state.markFailed(cur.hash); err != nil {
						s.logf("record the failed version: %v", err)
					}
					s.record(prev, "")
					transient, transientSince = 0, time.Time{}
					continue
				}
			}
			transient++
			wait := s.transientBackoff(transient)
			s.logf("sealed %s did not come up, for a reason outside it (exit %d); starting it again in %v", short(cur.hash), res.code, wait)
			if code, stop := s.pause(wait); stop {
				return code
			}
			continue
		}
		transient, transientSince = 0, time.Time{}
		if res.outcome == failedToStart || (trial && s.state.read("confirmed") != cur.hash) {
			// The next start takes the version it replaced, or the newest
			// other listed one.
			s.logf("sealed %s did not come up (exit %d); it does not run here again", short(cur.hash), res.code)
			if err := s.state.markFailed(cur.hash); err != nil {
				s.logf("record the failed version: %v", err)
			}
			continue
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

// choose picks the version to run: the recorded current while the chain
// lists it and it did not fail here; else the recorded previous, likewise;
// else the listed versions newest first, skipping those that failed here or
// whose download did not hash to its name. A version whose program is not
// here (or no longer hashes to its name) is downloaded. ok is false when
// nothing can run now: the list cannot be read, or lists nothing this
// container can run. Nothing runs without the chain's explicit "listed".
func (s *supervisor) choose() (version, bool) {
	listed, err := s.allow.listed()
	if err != nil {
		s.logf("the sealed list cannot be read (%v); nothing runs until it can", err)
		return version{}, false
	}
	on := make(map[string]bool, len(listed))
	for _, h := range listed {
		on[h] = true
	}
	cur := s.state.hash("current")
	order := []string{}
	seen := map[string]bool{}
	for _, h := range append([]string{cur, s.state.hash("previous")}, reversed(listed)...) {
		if h != "" && !seen[h] {
			seen[h] = true
			order = append(order, h)
		}
	}
	for _, h := range order {
		switch {
		case !on[h]:
			if h == cur {
				s.logf("sealed %s, which ran here, is not on the sealed list; not running it", short(h))
			}
			continue
		case s.state.failed(h) || s.state.mismatched(h):
			continue
		}
		v := version{hash: h, path: s.state.staged(h)}
		if verifyFile(v.path, v.hash) != nil {
			s.logf("downloading sealed %s from the artifacts release", short(h))
			if err := fetchSealed(s.http, s.artifacts, s.state, h); err != nil {
				s.logf("WARN download sealed %s: %v", short(h), err)
				continue
			}
			s.logf("OK   sealed %s downloaded; it hashes to its name", short(h))
		}
		return v, true
	}
	if len(listed) == 0 {
		s.logf("the sealed list is empty")
	} else {
		s.logf("no version on the sealed list can run here: each failed here or could not be downloaded")
	}
	return version{}, false
}

// reversed is a copy of hashes, last first.
func reversed(hashes []string) []string {
	out := make([]string, 0, len(hashes))
	for i := len(hashes) - 1; i >= 0; i-- {
		out = append(out, hashes[i])
	}
	return out
}

// listed reports whether the chain says hash is listed.
func (s *supervisor) listed(hash string) bool {
	refused, err := s.allow.refuses(hash)
	return err == nil && !refused
}

// trial reports whether v runs on trial: it has not come up in this
// container yet (sealed has not confirmed it).
func (s *supervisor) trial(v version) bool {
	return s.state.read("confirmed") != v.hash
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
// version than cur, not one that failed here, whose program hashes to its
// name and which the chain lists.
func (s *supervisor) requested(cur version) (version, bool) {
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
	v := version{hash: h, path: s.state.staged(h)}
	if err := verifyFile(v.path, v.hash); err != nil {
		s.logf("refusing the switch to %s: %v", short(h), err)
		return version{}, false
	}
	refused, err := s.allow.refuses(h)
	switch {
	case err != nil:
		s.logf("refusing the switch to %s: the sealed list cannot be read (%v)", short(h), err)
		return version{}, false
	case refused:
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
	s.logf("OK   started sealed %s (pid %d%s)", short(v.hash), pid, onTrial)

	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	// A version on trial that has not confirmed by trialEnd is stopped; its
	// exit then reads as a failure (run).
	var trialEnd <-chan time.Time
	if trial && s.trialLimit > 0 {
		t := time.NewTimer(s.trialLimit)
		defer t.Stop()
		trialEnd = t.C
	}
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
		case <-trialEnd:
			trialEnd = nil
			if !stopping && next == nil && s.state.read("confirmed") != v.hash {
				s.logf("sealed %s did not confirm within %v on trial; stopping it", short(v.hash), s.trialLimit)
				s.forward(pid, syscall.SIGTERM)
				if deadline == nil {
					deadline = time.After(s.stopGrace)
				}
			}
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

// pendingStop reports a stop signal that arrived while no sealed ran (a
// download): stop is true, with the code to exit with. Other signals then
// meant nothing and are dropped.
func (s *supervisor) pendingStop() (code int, stop bool) {
	for {
		select {
		case sig := <-s.sigs:
			if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				s.logf("%v before sealed started; exiting", sig)
				return 128 + int(sig.(syscall.Signal)), true
			}
			if sig == syscall.SIGCHLD {
				s.reapOthers()
			}
		default:
			return 0, false
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

// transientRetryBackoff is 30 s, 1 min, 2 min, 4 min, then 5 min.
func transientRetryBackoff(n int) time.Duration {
	if n > 4 {
		return 5 * time.Minute
	}
	return min(30*time.Second<<max(n-1, 0), 5*time.Minute)
}
