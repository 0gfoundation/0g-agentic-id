// POST /_seal/compact — compact the agent's ONE persisted conversation in place
// (CONVERSATION.md): the framework's own compaction summarizes the older part
// of the history, so later requests carry less of it while the conversation
// goes on — the middle ground between doing nothing and /_seal/clear, which
// discards it. Owner-signed with the body digest bound into the message (tag
// "0GSealCompact"), the /_seal/clear grammar; the body is unused and MAY be
// empty.
//
// Three guards /_seal/clear does not need:
//
//   - Single flight. A compaction makes one or more model calls and can take
//     minutes; a second request while one runs is answered 409 rather than
//     queued.
//   - Replay. The signed message carries no nonce, and unlike a clear a
//     compaction is NOT idempotent — every run is more model calls and
//     another round of summarizing what is left — so a signed message is
//     accepted once: a repeat inside the freshness window is refused (409).
//   - No live turn. openclaw's compaction aborts a running turn in the
//     session, so while a turn on the synthesized responses door is queued
//     or running, the request is refused (409) instead of killing the task —
//     and, the other way round, a turn sent to that door while a compaction
//     runs is refused (409) rather than admitted into it (admitSynthTurn).
//
// The compaction is detached from the request's cancellation: the sandbox's
// preview proxy caps how long a request may live (~300s on mainnet,
// 0g-sandbox#122), and an owner whose connection drops should not abort a
// compaction that is mid-summary. It runs under its own deadline, and the
// outcome is logged, so a client that gave up can read it from /log.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
)

const (
	// maxCompactBody bounds the (normally empty) request body.
	maxCompactBody = 4 * 1024
	// compactTimeout bounds one compaction end to end. A summary of a long
	// history by a reasoning model takes minutes; this is the ceiling, not the
	// expectation.
	compactTimeout = 15 * time.Minute
)

// CompactApplier runs the framework's compaction and returns an owner-facing
// note on the outcome. Installed by main.go from a framework.SessionCompactor;
// nil when the adapter cannot compact on demand, in which case the route
// answers 501.
type CompactApplier func(ctx context.Context) (string, error)

// compactState is the route's private state, under its own lock so a
// minutes-long compaction never holds the server's.
type compactState struct {
	mu      sync.Mutex
	apply   CompactApplier
	running bool
	// used remembers each accepted signed message (keyed by its digest) for
	// as long as its timestamp could still pass the freshness check, so it
	// cannot be replayed into a second compaction.
	used map[string]int64
}

// busy reports whether any turn on the synthesized responses door is queued
// or running. No turn can be created while handleCompact checks this and
// claims the slot: both hold compact.mu, and admitSynthTurn is the only way a
// turn record is made. The one blind spot is eviction — the hub keeps the
// last synthMaxRecords turns, so a still-running turn is missed only if that
// many newer turns were created while it ran.
func (h *synthHub) busy() bool {
	h.mu.Lock()
	recs := make([]*synthRecord, 0, len(h.byID))
	for _, rec := range h.byID {
		recs = append(recs, rec)
	}
	h.mu.Unlock()
	for _, rec := range recs {
		rec.mu.Lock()
		status := rec.status
		rec.mu.Unlock()
		if status == "queued" || status == "in_progress" {
			return true
		}
	}
	return false
}

// admitSynthTurn creates a synthesized-door turn record unless a compaction
// is running. It takes the compaction lock, the same one handleCompact holds
// across its busy() check and claiming the slot, so the two admissions are
// atomic with respect to each other: whichever comes first, the other is
// refused, and a compaction never starts under a turn it would abort.
func (s *Server) admitSynthTurn() (*synthRecord, bool) {
	s.compact.mu.Lock()
	defer s.compact.mu.Unlock()
	if s.compact.running {
		return nil, false
	}
	return s.synth.create(), true
}

// SetCompact installs the applier. Late-bound like the settings appliers.
func (s *Server) SetCompact(apply CompactApplier) {
	s.compact.mu.Lock()
	defer s.compact.mu.Unlock()
	s.compact.apply = apply
}

func (s *Server) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}
	// A compaction is a driving action: it belongs to whoever holds the seat.
	if !s.occupancyGate(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCompactBody+1))
	if err != nil || len(body) > maxCompactBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	now, ok := s.verifyOwnerSig(w, r, "0GSealCompact", sealID, owner, hex.EncodeToString(sum[:]))
	if !ok {
		return
	}
	// Keyed on the signed MESSAGE, never on the signature: verifyOwnerSig
	// accepts one signature in several encodings (with or without 0x, any hex
	// case, v as 0/1 or 27/28), and ECDSA malleability gives anyone a second
	// valid signature (r, N-s, v^1) without the key — SigToPub does not
	// enforce low s — so a key over the signature would let each variant
	// replay as "new". The message already
	// binds the timestamp, seal, body digest and audience; two genuine
	// compactions signed in the same second share it, and the second is asked
	// to sign again.
	used := sha256.Sum256([]byte(r.Header.Get("X-Auth-Message")))
	usedKey := hex.EncodeToString(used[:])

	s.compact.mu.Lock()
	apply := s.compact.apply
	if apply == nil {
		s.compact.mu.Unlock()
		http.Error(w, "this framework does not support on-demand compaction", http.StatusNotImplemented)
		return
	}
	// A message older than 2×window can no longer pass verifyOwnerSig (its
	// timestamp was within ±window of the moment it was first accepted), so
	// forgetting it is safe.
	for k, at := range s.compact.used {
		if now-at > 2*authWindowSec {
			delete(s.compact.used, k)
		}
	}
	if _, seen := s.compact.used[usedKey]; seen {
		s.compact.mu.Unlock()
		http.Error(w, "this signed request was already used; sign a fresh one to compact again", http.StatusConflict)
		return
	}
	if s.compact.running {
		s.compact.mu.Unlock()
		http.Error(w, "a compaction is already running", http.StatusConflict)
		return
	}
	// Never under a live turn: openclaw's sessions.compact ABORTS an active
	// run in the session (interruptSessionRunIfActive), so compacting now
	// would silently kill the owner's task. A turn on this door is one the
	// proxy tracks; dsh (native door) queues its compaction behind the turn
	// in the bridge instead, so nothing is tracked here for it.
	if s.synth != nil && s.synth.busy() {
		s.compact.mu.Unlock()
		http.Error(w, "a turn is in progress; wait for it to finish (or interrupt it), then compact", http.StatusConflict)
		return
	}
	if s.compact.used == nil {
		s.compact.used = map[string]int64{}
	}
	s.compact.used[usedKey] = now
	s.compact.running = true
	s.compact.mu.Unlock()
	defer func() {
		s.compact.mu.Lock()
		s.compact.running = false
		s.compact.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), compactTimeout)
	defer cancel()
	note, err := apply(ctx)
	if errors.Is(err, framework.ErrCompactUnsupported) {
		logger.Logf("compact: unsupported: %v", err)
		http.Error(w, "this framework does not support on-demand compaction ("+err.Error()+")", http.StatusNotImplemented)
		return
	}
	if errors.Is(err, framework.ErrCompactRefused) {
		logger.Logf("compact: refused: %v", err)
		http.Error(w, "the framework did not compact and nothing changed; try again shortly ("+err.Error()+")", http.StatusConflict)
		return
	}
	if err != nil {
		logger.Logf("compact: failed: %v", err)
		http.Error(w, "compact failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Logf("compact: %s", note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "note": note})
}
