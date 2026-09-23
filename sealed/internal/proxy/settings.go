package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// maxSettingsBody bounds the owner document. It holds a handful of scalars
// plus an opaque per-framework section; anything approaching this is a
// mistake, and an unbounded read on an owner-facing route is an easy denial.
const maxSettingsBody = 256 << 10

// SettingsApplier is what the platform does with a document the owner pushed:
// validate it, make it the one future renders use, render it now, and restart
// the framework process so it takes effect.
//
// main.go owns that sequence because it owns both the document and the
// manager; the proxy only authenticates the request.
type SettingsApplier func(ctx context.Context, doc settings.Doc) error

// SettingsReader returns the document currently in force, so an owner can read
// before writing without keeping an authoritative copy of their own.
type SettingsReader func() settings.Doc

// SetSettings installs the two halves. Late-bound like the adapter: both need
// state that only exists after chain bootstrap.
func (s *Server) SetSettings(read SettingsReader, apply SettingsApplier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readSettings, s.applySettings = read, apply
}

// handleSettings serves the owner's configuration channel.
//
//	GET   returns the document in force
//	POST  replaces it, then re-renders and restarts the framework process
//
// Both are owner-signed. POST additionally binds the signature to a sha256 of
// the request body: without that the signature attests only to who is calling,
// and anything able to alter the request in flight could keep a valid
// signature while substituting a different document.
//
// This is the hot path — it exists so changing a model or a thinking level
// stops requiring a container rebuild. It restarts the framework process, so
// it interrupts whatever the agent is doing; the response says so rather than
// pretending the change was free.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}

	s.mu.RLock()
	read, apply := s.readSettings, s.applySettings
	s.mu.RUnlock()
	if read == nil || apply == nil {
		http.Error(w, "settings channel not ready", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if _, ok := s.verifyOwnerSig(w, r, "0GSealSettings", sealID, owner, ""); !ok {
			return
		}
		writeJSON(w, http.StatusOK, read())

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSettingsBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > maxSettingsBody {
			http.Error(w, "settings document too large", http.StatusRequestEntityTooLarge)
			return
		}
		sum := sha256.Sum256(body)
		if _, ok := s.verifyOwnerSig(w, r, "0GSealSettings", sealID, owner, hex.EncodeToString(sum[:])); !ok {
			return
		}

		doc, err := settings.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := doc.Validate(); err != nil {
			// Rejected before anything is applied, so the running agent keeps
			// the configuration it has. A push that cannot take effect must
			// not be able to take the agent down.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := apply(r.Context(), doc); err != nil {
			logger.Logf("settings: apply failed: %v", err)
			http.Error(w, "apply failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"note": "applied; the framework process was restarted, so any task in flight was interrupted",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── agent-facing half ────────────────────────────────────────────────────────

// SessionSettingsApplier applies a change the AGENT asked for. Unlike the
// owner path it does not persist: the change lives as long as this container
// does and is gone after a restart.
//
// That asymmetry is deliberate and is what makes the agent's access safe to
// grant. The agent's legitimate use is "think harder on this task", not
// "permanently reconfigure yourself" — the money and the asset are the
// owner's. Because nothing it writes survives, an agent cannot configure
// itself into a state it will not boot from, which is how an agent bricked
// itself once by hand-editing its framework config.
type SessionSettingsApplier func(ctx context.Context, doc settings.Doc) error

// SetSessionSettings installs the agent-facing applier (see sign.go for why
// the socket needs no signature: the unix socket IS the credential).
func (s *Server) SetSessionSettings(apply SessionSettingsApplier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applySession = apply
}

// handleAgentSettings serves POST $SEAL_SIGN_SOCK/settings.
//
// Reachable only over the 0600 unix socket inside the container, so the agent
// process is the only possible caller and no signature is involved — the same
// basis on which that socket already hands out agentSeal signatures.
//
// The response says plainly that the change is not durable, because the agent
// reads it and would otherwise have no way to know.
func (s *Server) handleAgentSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	read, apply := s.readSettings, s.applySession
	s.mu.RUnlock()
	if read == nil || apply == nil {
		http.Error(w, "settings channel not ready", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxSettingsBody+1))
	if err != nil || len(body) > maxSettingsBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Start from what is in force and let the agent change a field, rather
	// than making it restate the whole document: it does not own the parts it
	// did not ask about, and a partial document would otherwise blank the pin.
	doc := read()
	if err := json.Unmarshal(body, &doc); err != nil {
		http.Error(w, "parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := doc.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := apply(r.Context(), doc); err != nil {
		http.Error(w, "apply failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"durable":  false,
		"note":     "applied for this container's lifetime only; a restart restores your owner's settings",
		"settings": doc,
	})
}
