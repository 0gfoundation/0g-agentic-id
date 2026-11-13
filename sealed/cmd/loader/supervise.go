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

// A version on trial must confirm within trialLimit of its start, or the
// loader stops it and treats it as failed. A version that exits with
// trialTransientExit is started again (transientBackoff); one on trial that
// has done so for transientLimit is treated as failed, where a listed version
// to go back to exists.
const (
	trialLimit     = 20 * time.Minute
	transientLimit = time.Hour
)

// The environment the loader sets for the sealed it starts
// (sealed/internal/layers; keep in step).
const (
	// sealedHashEnv carries the hash the loader verified.
	sealedHashEnv = "SEALED_HASH"
	// trialEnv is "1" for a version the loader switched to and has not seen
	// confirmed.
	trialEnv = "SEALED_TRIAL"
	// insteadOfEnv names the version the image's own sealed runs in place
	// of: the one the loader would have run, had the sealed list been
	// readable.
	insteadOfEnv = "SEALED_INSTEAD_OF"
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
// sealedHashEnv, trialEnv and insteadOfEnv.
type supervisor struct {
	// builtin is the image's own sealed, whose hash is built into the
	// loader. It runs when nothing else was switched to, when the sealed
	// list cannot be read, and is what a failed switch falls back to last.
	builtin version
	// state is the directory shared with sealed (state.go). Empty, the
	// loader runs builtin only, and exits when it exits.
	state stateDir
	// allow is the sealed list on chain (allowlist.go).
	allow sealedList

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
	// exited with trialTransientExit (tests shorten all three).
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
// to exit with: sealed's own, 128+signal when a signal ended it, and 1 when
// sealed could not be started.
//
// cur is the version the loader means to run, the one its state records.
// What runs is cur, unless the sealed list cannot be read for it: then the
// image's own sealed runs in its place, cur stays recorded, and the next
// start (or sealed itself, once the list reads again) comes back to it.
func (s *supervisor) run() int {
	cur := s.current()
	var restarts []time.Time
	// transient counts the starts of a version that keeps exiting with
	// trialTransientExit, transientSince is since when it has; any other end
	// of a run resets both.
	var transient int
	var transientSince time.Time
	for {
		p, found := s.allowed(cur)
		switch found {
		case runNone:
			s.logf("FAIL no sealed version this container has is on the sealed list; the agent needs a reset onto a current image")
			return 1
		case runLater:
			transient++
			wait := s.transientBackoff(transient)
			s.logf("the sealed list could not be read to confirm a version this container has; reading it again in %v", wait)
			if code, stop := s.pause(wait); stop {
				return code
			}
			continue
		}
		insteadOf := ""
		switch {
		case p.v.hash == cur.hash:
		case p.standIn:
			insteadOf = cur.hash
		default:
			s.record(p.v.hash, "")
			cur = p.v
		}
		ran := p.v
		trial := insteadOf == "" && s.trial(ran)
		res := s.runOnce(ran, trial, insteadOf)
		switch res.outcome {
		case stopped:
			return res.code
		case switching:
			s.killLeftovers()
			s.logf("switching sealed from %s to %s", short(ran.hash), short(res.next.hash))
			// What a failed switch goes back to is a version that came up:
			// the one switched from, unless it was itself still on trial.
			// Back to the version the image's own stood in for, that one
			// keeps the version it replaced.
			back := ran.hash
			if (insteadOf != "" && res.next.hash == cur.hash) || (trial && s.state.read("confirmed") != ran.hash) {
				back = s.state.hash("previous")
			}
			s.record(res.next.hash, back)
			cur = res.next
			transient, transientSince = 0, time.Time{}
			continue
		}
		s.killLeftovers()
		layered := s.state != "" && s.state.layered()
		if res.outcome == exited && layered && res.code == restartRequestedExit {
			// Not a crash: started again at once, and not counted.
			s.logf("sealed exited for a restart its owner asked for; starting it again")
			transient, transientSince = 0, time.Time{}
			continue
		}
		if res.outcome == exited && layered && res.code == trialTransientExit {
			// The boot failed for a reason outside the version: it is not
			// counted against the version, and runs again after a wait.
			now := time.Now()
			if transientSince.IsZero() {
				transientSince = now
			}
			if trial && now.Sub(transientSince) >= s.transientLimit {
				if prev := s.previous(ran); s.listed(prev) {
					s.logf("sealed %s has not come up for %v, for reasons outside it; going back to %s", short(ran.hash), s.transientLimit, short(prev.hash))
					s.goBack(ran, prev)
					cur = prev
					transient, transientSince = 0, time.Time{}
					continue
				}
			}
			transient++
			wait := s.transientBackoff(transient)
			s.logf("sealed %s did not come up, for a reason outside it (exit %d); starting it again in %v", short(ran.hash), res.code, wait)
			if code, stop := s.pause(wait); stop {
				return code
			}
			continue
		}
		transient, transientSince = 0, time.Time{}
		if insteadOf == "" && ran.hash != s.builtin.hash && (res.outcome == failedToStart || (trial && s.state.read("confirmed") != ran.hash)) {
			prev := s.previous(ran)
			s.logf("sealed %s did not come up (exit %d); going back to %s", short(ran.hash), res.code, short(prev.hash))
			s.goBack(ran, prev)
			cur = prev
			continue
		}
		// LEGACY(pre-1.4.0): without the layered flow (an attestor that does
		// not declare it: a chain whose AgenticID names no trust registry)
		// the loader stops with sealed, as when sealed is PID 1.
		if res.outcome == failedToStart || !layered {
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

// goBack records that failed did not come up and that prev runs from now on.
func (s *supervisor) goBack(failed, prev version) {
	if err := s.state.markFailed(failed.hash); err != nil {
		s.logf("record the failed version: %v", err)
	}
	s.record(prev.hash, "")
}

// pick is the version allowed chose, and whether it runs in place of the one
// asked for only because the sealed list could not be read (standIn).
type pick struct {
	v       version
	standIn bool
}

// found is what allowed found.
type found int

const (
	runIt    found = iota // run the version picked
	runNone               // the chain lists none of the versions this container has
	runLater              // the chain could not be read for a version it may list
)

// allowed picks the version to run for v: v, else the version it replaced,
// else builtin — the first one the chain lists. A staged version runs only
// on the chain's explicit "listed"; once no answer can be had for one, no
// staged version runs this time, and builtin runs in its place (standIn).
// The image hash covers builtin, which the attestor checks from the
// container certificate, so builtin needs no answer: only a "not listed"
// keeps it from running.
func (s *supervisor) allowed(v version) (pick, found) {
	candidates := []version{v}
	if s.state != "" && v.hash != s.builtin.hash {
		if p := s.previous(v); p.hash != v.hash {
			candidates = append(candidates, p)
		}
	}
	if candidates[len(candidates)-1].hash != s.builtin.hash {
		candidates = append(candidates, s.builtin)
	}
	unread := false
	for _, c := range candidates {
		isBuiltin := c.hash == s.builtin.hash
		if unread && !isBuiltin {
			continue
		}
		refused, err := s.allow.refuses(c.hash)
		switch {
		case err != nil && isBuiltin:
			s.logf("the sealed list is unreadable (%v); running the image's own sealed %s, which the image hash covers", err, short(c.hash))
			return pick{v: c, standIn: unread}, runIt
		case err != nil:
			s.logf("the sealed list is unreadable for %s (%v); a downloaded version runs only once the chain lists it", short(c.hash), err)
			unread = true
		case refused:
			s.logf("sealed %s is not on the sealed list; not running it", short(c.hash))
		default:
			return pick{v: c, standIn: unread && isBuiltin}, runIt
		}
	}
	if unread {
		return pick{}, runLater
	}
	return pick{}, runNone
}

// listed reports whether the chain says v is listed.
func (s *supervisor) listed(v version) bool {
	refused, err := s.allow.refuses(v.hash)
	return err == nil && !refused
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
// to its name and which the chain lists.
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

// runOnce verifies and starts v, and blocks until it exits. insteadOf names
// the version v runs in place of, "" for none.
func (s *supervisor) runOnce(v version, trial bool, insteadOf string) runResult {
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
	if insteadOf != "" {
		_ = os.Setenv(insteadOfEnv, insteadOf)
	} else {
		_ = os.Unsetenv(insteadOfEnv)
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
	if insteadOf != "" {
		onTrial += ", in place of " + short(insteadOf)
	}
	s.logf("OK   started %s (pid %d, sealed %s%s)", v.path, pid, short(v.hash), onTrial)

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
