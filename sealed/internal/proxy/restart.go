package proxy

// POST /harness/restart on the sign socket: the harness asks sealed to
// restart it (sealed/LAYERS.md §5.3). sealed stops the process and starts it
// again from the package it is set to run; the agent's files stay on disk,
// and what the agent changed since its last commit is committed by the
// watcher as usual. Wired only for adapters whose framework is a harness
// official version package (framework.LayeredRuntime); 501 otherwise.
//
// The answer (202) goes out before the restart begins: the process asking
// is the one being stopped.

import (
	"context"
	"net/http"

	"seal-verify/internal/logger"
)

// SetHarnessRestart installs what POST /harness/restart runs.
func (s *Server) SetHarnessRestart(restart func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restartHarness = restart
}

func (s *Server) handleHarnessRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	restart := s.restartHarness
	s.mu.RUnlock()
	if restart == nil {
		http.Error(w, "this framework has no harness restart", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"restarting":true}` + "\n"))
	go func() {
		logger.Logf("harness: restart requested over the sign socket")
		if err := restart(context.Background()); err != nil {
			logger.Logf("harness: requested restart: %v", err)
		}
	}()
}
