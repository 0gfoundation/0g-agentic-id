// POST /_seal/secrets — refresh the agent's owner secrets in a RUNNING
// container without a restart (SECRETS.md §6). Owner-signed with the body
// digest bound in (tag "0GSealSecrets"), the settings-push grammar. The body
// is the base64 secrets document, already sealed to agentSeal by the SDK; the
// applier (installed by main.go) opens it with agentSeal_priv + the live owner
// and swaps the in-memory store. The owner also persists it to the attestor so
// it survives a reset; this endpoint is only the immediate-effect path.
//
// Replay posture matches /_seal/clear and /_seal/settings: no nonce, because
// applying the same document twice is idempotent (the store ends identical).
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

// maxSecretsBody bounds the base64 secrets blob.
const maxSecretsBody = 256 * 1024

// SecretsApplier opens a base64 secrets document (sealed to agentSeal) and
// installs it. Installed by main.go, which holds agentSeal_priv and the live
// owner. nil until wired; the route then answers 503.
type SecretsApplier func(ctx context.Context, blob string) error

// SetSecrets installs the applier. Late-bound like the other appliers.
func (s *Server) SetSecrets(apply SecretsApplier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applySecrets = apply
}

// SetSecretProxyPort records the loopback egress-proxy port so /services can
// refuse an agent that tries to register it as its own service — that would
// front the secret-substituting proxy through sealed's signed surface.
func (s *Server) SetSecretProxyPort(port string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secretProxyPort = port
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if sealID == "" {
		http.Error(w, "agent not bootstrapped yet", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSecretsBody+1))
	if err != nil || len(body) > maxSecretsBody {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	if _, ok := s.verifyOwnerSig(w, r, "0GSealSecrets", sealID, owner, hex.EncodeToString(sum[:])); !ok {
		return
	}
	s.mu.RLock()
	apply := s.applySecrets
	s.mu.RUnlock()
	if apply == nil {
		http.Error(w, "secrets not ready", http.StatusServiceUnavailable)
		return
	}
	if err := apply(r.Context(), string(body)); err != nil {
		// Names/reasons only — the applier never puts a value in its error.
		http.Error(w, "secrets apply failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
