package proxy

// Single active owner client, WeChat-style: entering a session CLAIMS the
// agent (new login wins, no negotiation), and a displaced client learns the
// moment it next speaks — a 409 naming when it lost the seat — then re-enters
// deliberately to take the seat back.
//
// Why this exists: the agent is one shared thing behind many owner windows.
// Conversations interleave on the stateful bridges, and — on every framework —
// a settings push from window A restarts the harness under window B's feet
// and silently changes the model B is talking to. The durable stores were
// already safe (attestor CAS; the bridges' turn queue); what was missing is
// WHO IS DRIVING. One field answers it.
//
// Deliberately not a security boundary. Both windows hold the same owner key,
// so this is self-collision protection: requests without the header (SDK
// scripts, older CLIs, third parties calling agent services) bypass it
// untouched. The claim itself is owner-signed only to keep the /_seal/*
// discipline — everything under that prefix verifies the owner.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// clientInstanceHeader carries the caller's per-process id on chat and
// settings requests. Absent = the caller does not participate in occupancy.
const clientInstanceHeader = "X-Client-Instance"

// maxClaimBody bounds the claim payload ({"instance": "<uuid>"}).
const maxClaimBody = 4 << 10

// occupant is who currently drives this agent. Proxy-memory only: a container
// restart clears the seat, first to claim takes it — consistent with the rest
// of the session state, which dies with the process anyway.
type occupantSeat struct {
	id    string
	since time.Time
}

// handleClaim serves POST /_seal/claim: take the seat, displacing whoever
// held it. Owner-signed with the body digest bound into the message (tag
// "0GSealClaim"), same grammar as the settings push.
func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxClaimBody+1))
	if err != nil || len(body) > maxClaimBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	if _, ok := s.verifyOwnerSig(w, r, "0GSealClaim", sealID, owner, hex.EncodeToString(sum[:])); !ok {
		return
	}
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Instance) == "" {
		http.Error(w, "body must be {\"instance\": \"<id>\"}", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	prev := s.seat
	s.seat = occupantSeat{id: req.Instance, since: time.Now()}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"displaced": prev.id != "" && prev.id != req.Instance,
	})
}

// occupancyGate is called on the mutating owner surfaces (chat POSTs, the
// settings push). It returns false — after writing the 409 — when the caller
// participates in occupancy and the seat belongs to someone else.
func (s *Server) occupancyGate(w http.ResponseWriter, r *http.Request) bool {
	instance := r.Header.Get(clientInstanceHeader)
	if instance == "" {
		return true // not participating (scripts, older clients, services)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seat.id == "" || s.seat.id == instance {
		if s.seat.id == "" {
			// No claim yet (e.g. container restarted): first speaker sits down.
			s.seat = occupantSeat{id: instance, since: time.Now()}
		}
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write([]byte(`{"error":{"code":"displaced","message":"this agent is in use by another client since ` +
		s.seat.since.UTC().Format("15:04:05") + ` UTC — re-enter the session to take it over"}}`))
	return false
}
