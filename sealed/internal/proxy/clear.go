// POST /_seal/clear — wipe the agent's ONE persisted conversation and restart
// the framework so a fresh one is presented immediately (CONVERSATION.md §2
// invariant 5). Owner-signed with the body digest bound into the message (tag
// "0GSealClear"), the settings-push grammar; the body is unused today and MAY
// be empty — the digest binding is kept anyway so the grammar stays uniform
// across the owner container ops.
//
// This clears WORKING CONTEXT only: the chain-tracked memory roles — the
// durable knowledge — are untouched, which is exactly the difference between
// /clear and a container reset.
//
// Replay posture (review #169 item 8): the signed message carries no nonce,
// so a captured clear is replayable within the auth window — deliberately
// accepted because a replayed clear is IDEMPOTENT (the store is already
// gone), matching the settings route's posture.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

// maxClearBody bounds the (normally empty) request body.
const maxClearBody = 4 * 1024

// ClearApplier wipes the persisted conversation and restarts the framework.
// Installed by main.go, which owns both the adapter and the manager; nil when
// the adapter holds no conversation (client-held history), in which case the
// route answers 501 — "nothing here to clear" is information, not an error to
// hide.
type ClearApplier func(ctx context.Context) error

// SetClear installs the applier. Late-bound like the settings appliers.
func (s *Server) SetClear(apply ClearApplier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyClear = apply
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}
	// A clear is a driving action: it belongs to whoever holds the seat.
	if !s.occupancyGate(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxClearBody+1))
	if err != nil || len(body) > maxClearBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	if _, ok := s.verifyOwnerSig(w, r, "0GSealClear", sealID, owner, hex.EncodeToString(sum[:])); !ok {
		return
	}

	s.mu.Lock()
	apply := s.applyClear
	s.mu.Unlock()
	if apply == nil {
		http.Error(w, "this framework holds no server-side conversation (history is client-held); nothing to clear", http.StatusNotImplemented)
		return
	}
	if err := apply(r.Context()); err != nil {
		http.Error(w, "clear failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"note": "conversation cleared; the framework process was restarted — chain-tracked memory is untouched",
	})
}
