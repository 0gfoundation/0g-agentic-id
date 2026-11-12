// POST /_seal/restart — the owner restarts the harness or sealed itself
// (sealed/LAYERS.md §3, §10). Body {"layer": "harness"} or
// {"layer": "sealed"}.
//
// Owner-signed like the other owner container ops (tag "0GSealRestart", the
// body digest bound into the message; verifyOwnerSig). Unlike /_seal/clear,
// a restart is not idempotent, so one signed request restarts once: a replay
// inside the auth window is refused (409), as /_seal/compact does.
//
// The answer (202) goes out before the restart begins. Only main.go knows how
// to restart (it owns the manager and the loader hand-off); without an applier
// — an adapter that runs no harness package — the route answers 501.
package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
)

// maxRestartBody bounds the request body.
const maxRestartBody = 1024

// OwnerRestarter starts restarting layer ("harness" or "sealed") and returns
// at once; an error says why that layer cannot be restarted now.
type OwnerRestarter func(layer string) error

// The errors an OwnerRestarter wraps, and the status each answers with.
var (
	// ErrRestartUnavailable: this runtime cannot restart that layer (501).
	ErrRestartUnavailable = errors.New("restart unavailable")
	// ErrRestartBusy: not now, try again in a moment (503).
	ErrRestartBusy = errors.New("restart busy")
	// ErrRestartLayer: not a layer (400).
	ErrRestartLayer = errors.New("unknown layer")
)

// ownerRestart is the route's state: the applier and the signed requests
// already used.
type ownerRestart struct {
	mu    sync.Mutex
	apply OwnerRestarter
	used  map[string]int64
}

// SetOwnerRestart installs the applier. Late-bound like the other appliers.
func (s *Server) SetOwnerRestart(apply OwnerRestarter) {
	s.restart.mu.Lock()
	defer s.restart.mu.Unlock()
	s.restart.apply = apply
}

func (s *Server) handleOwnerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}
	// A restart interrupts whoever is driving: it belongs to the seat holder.
	if !s.occupancyGate(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRestartBody+1))
	if err != nil || len(body) > maxRestartBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	now, ok := s.verifyOwnerSig(w, r, "0GSealRestart", sealID, owner, hex.EncodeToString(sum[:]))
	if !ok {
		return
	}
	var req struct {
		Layer string `json:"layer"`
	}
	if err := json.Unmarshal(body, &req); err != nil || (req.Layer != "harness" && req.Layer != "sealed") {
		http.Error(w, `body must be {"layer": "harness"} or {"layer": "sealed"}`, http.StatusBadRequest)
		return
	}
	// Keyed on the signed message, never on the signature (see compact.go).
	used := sha256.Sum256([]byte(r.Header.Get("X-Auth-Message")))
	usedKey := hex.EncodeToString(used[:])

	s.restart.mu.Lock()
	apply := s.restart.apply
	if apply == nil {
		s.restart.mu.Unlock()
		http.Error(w, "this framework has no owner restart; stop and start the agent instead", http.StatusNotImplemented)
		return
	}
	if s.restart.used == nil {
		s.restart.used = map[string]int64{}
	}
	for k, at := range s.restart.used {
		if now-at > 2*authWindowSec {
			delete(s.restart.used, k)
		}
	}
	if _, seen := s.restart.used[usedKey]; seen {
		s.restart.mu.Unlock()
		http.Error(w, "this signed request was already used; sign a fresh one to restart again", http.StatusConflict)
		return
	}
	err = apply(req.Layer)
	if err == nil {
		s.restart.used[usedKey] = now
	}
	s.restart.mu.Unlock()

	switch {
	case err == nil:
		note := "restarting the harness; the conversation and the disk stay"
		if req.Layer == "sealed" {
			note = "restarting sealed; the agent is away for about one start, and the disk stays"
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "layer": req.Layer, "note": note})
	case errors.Is(err, ErrRestartUnavailable):
		http.Error(w, err.Error(), http.StatusNotImplemented)
	case errors.Is(err, ErrRestartBusy):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case errors.Is(err, ErrRestartLayer):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "restart failed: "+err.Error(), http.StatusInternalServerError)
	}
}
