package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Committing the agent's data to chain (handleDrift → upload.Apply) runs on
// the watcher's 30 s tick. A commit that keeps failing (an unfunded seal
// wallet, a storage node down) used to be retried on every tick, forever;
// each retry is a storage submit or an update the seal wallet may pay for.
// commitBackoff spaces the retries out: after n consecutive failures of the
// same content the next attempt waits commitRetryFirst·2^(n-1), at most
// commitRetryMax. A success, or new content to commit (the agent changed
// something since), starts over.

const (
	commitRetryFirst = 30 * time.Second
	commitRetryMax   = 30 * time.Minute
)

type commitBackoff struct {
	mu       sync.Mutex
	failures int
	content  string    // the drift the failures were for
	next     time.Time // no attempt for that content before then
	told     bool      // the wait after the last failure was logged
}

var commitRetry = &commitBackoff{}

// delayAfter is how long to wait after n consecutive failures.
func delayAfter(n int) time.Duration {
	d := commitRetryFirst
	for i := 1; i < n && d < commitRetryMax; i++ {
		d *= 2
	}
	if d > commitRetryMax {
		d = commitRetryMax
	}
	return d
}

// Wait reports how long an attempt to commit content must still wait (0: try
// now), and whether this is the first wait since the last failure (to log it
// once, not on every tick). New content does not wait.
func (b *commitBackoff) Wait(now time.Time, content string) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures == 0 || content != b.content || !now.Before(b.next) {
		return 0, false
	}
	first := !b.told
	b.told = true
	return b.next.Sub(now), first
}

// Failed records a failed attempt for content and returns the wait before
// the next one.
func (b *commitBackoff) Failed(now time.Time, content string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if content != b.content {
		b.failures, b.content = 0, content
	}
	b.failures++
	d := delayAfter(b.failures)
	b.next = now.Add(d)
	b.told = false
	return d
}

// Succeeded starts over.
func (b *commitBackoff) Succeeded() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures, b.content, b.next, b.told = 0, "", time.Time{}, false
}

// driftKey names what a tick would commit: each role's content hash.
func driftKey(plaintexts map[string][]byte) string {
	roles := make([]string, 0, len(plaintexts))
	for r := range plaintexts {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	h := sha256.New()
	for _, r := range roles {
		sum := sha256.Sum256(plaintexts[r])
		fmt.Fprintf(h, "%s\x00%x\x00", r, sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// commitFailureStatus is the status a failed commit puts the agent in ("" for
// no change yet). A failed commit is never an "error": the agent runs and
// answers; only its latest data is not on chain yet, and an "error" report
// makes the attestor show the agent offline (its container stage failed),
// which blocked the owner's chat (dev, 2026-11-17). It is a "warning", which
// keeps the agent running for the attestor and carries the reason to the
// owner: at once for an owner-recoverable cause (the seal wallet cannot pay,
// severityOf), after failureEscalateAt consecutive failures otherwise, so a
// transient blip does not show.
func commitFailureStatus(err error, consecutive int) (level, message string) {
	summary := summarizeError(err)
	if severityOf(err) == "warning" {
		return "warning", "agent data not committed to chain: " + summary
	}
	if consecutive < failureEscalateAt {
		return "", ""
	}
	return "warning", fmt.Sprintf("agent data not committed to chain (%d attempts): %s", consecutive, summary)
}
