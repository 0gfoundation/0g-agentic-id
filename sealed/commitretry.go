package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"seal-verify/internal/logger"
	"seal-verify/internal/uploader"
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
// severityOf, or short: the wallet holds less than the failed step needs,
// fundsShortfall), after failureEscalateAt consecutive failures otherwise,
// so a transient blip does not show.
func commitFailureStatus(err error, consecutive int, short string) (level, message string) {
	if short != "" {
		return "warning", short
	}
	summary := summarizeError(err)
	if severityOf(err) == "warning" {
		return "warning", "agent data not committed to chain: " + summary
	}
	if consecutive < failureEscalateAt {
		return "", ""
	}
	return "warning", fmt.Sprintf("agent data not committed to chain (%d attempts): %s", consecutive, summary)
}

// fundsShortfall says, for a failed commit whose error does not name the
// cause, whether the seal wallet cannot pay the step it failed at. A wallet
// short of gas does not always fail as "insufficient funds": on Galileo at
// 2000 gwei a storage submit's gas estimate came back as a bare
// "execution reverted" (dev, 2026-11-17, 0.1041 OG against ~0.9 OG needed),
// which counted as an "other" failure and showed only at the fifth, about
// ten minutes later with the backoff. read is the uploader's FundsFor. ""
// when the wallet holds enough, the error already says funds (severityOf), or
// the read fails: the count rule then stands.
func fundsShortfall(ctx context.Context, read func(context.Context, error) (uploader.WalletFunds, error), err error) string {
	if severityOf(err) == "warning" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	f, rerr := read(ctx, err)
	if rerr != nil {
		logger.Logf("drift: cannot read the seal wallet's balance (%v); the failure is graded by its error", rerr)
		return ""
	}
	if f.Balance == nil || f.Need == nil || f.Balance.Cmp(f.Need) >= 0 {
		return ""
	}
	return fmt.Sprintf("agent data not committed to chain: the agent's wallet %s has %s OG, about %s OG is needed for its next transaction",
		f.Address.Hex(), formatOG(f.Balance), formatOG(f.Need))
}

// formatOG writes a wei amount in OG: two decimals, four under 0.01.
func formatOG(wei *big.Int) string {
	og := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	if og.Sign() > 0 && og.Cmp(big.NewFloat(0.01)) < 0 {
		return og.Text('f', 4)
	}
	return og.Text('f', 2)
}
