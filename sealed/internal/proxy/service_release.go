package proxy

import (
	"encoding/json"
	"io"
	"net/http"

	"seal-verify/internal/servicehost"
)

// Bound concurrent public source snapshots and their signed response buffers.
// This is per sealed process and cannot be increased by an owner manifest.
var serviceReleaseSlots = make(chan struct{}, 2)

// handleServiceRelease is a root-owned audit surface, never a request to the
// owner program. It precedes readiness/method checks for a published service.
func (s *Server) handleServiceRelease(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()["sealed-release"]
	if r.Method != http.MethodGet || len(values) != 1 || values[0] != "1" {
		http.Error(w, "use GET with sealed-release=1", http.StatusBadRequest)
		return
	}
	if len(r.Header.Values(servicehost.RuntimeInputHeader)) != 0 {
		http.Error(w, "release audit does not accept runtime input", http.StatusBadRequest)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			http.Error(w, "release audit does not accept a request body", http.StatusBadRequest)
			return
		}
	}
	host := s.getServiceHost()
	if host == nil {
		http.Error(w, "isolated service hosting unavailable", http.StatusServiceUnavailable)
		return
	}
	status, ok := host.Match(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	select {
	case serviceReleaseSlots <- struct{}{}:
		defer func() { <-serviceReleaseSlots }()
	default:
		http.Error(w, "service release audit concurrency limit", http.StatusServiceUnavailable)
		return
	}
	release, err := host.Release(status.ID)
	if err != nil {
		http.Error(w, "service release unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := json.Marshal(release)
	if err != nil || len(body) > servicehost.MaxReleaseBytes {
		http.Error(w, "service release exceeds response limits", http.StatusServiceUnavailable)
		return
	}
	priv, _, _, _, dataHashes := s.agent.Snapshot()
	if priv == nil {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}
	agentID, frameworkHash := s.agent.ProofIdentity()
	chainID, identityAddr, validator := s.agent.ProofDomain()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.serveWithProof(w, r, priv, nil, body, dataHashes, http.StatusOK, agentID, frameworkHash, chainID, identityAddr, validator); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
