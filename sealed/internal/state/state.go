// Package state holds protocol-level agent state shared across modules:
// identity material (agent_seal_priv, sealID, owner), runtime endpoint
// (upstreamURL), and the iData snapshot pair used by serve-proof and the
// evolution flow.
//
// Framework-specific configuration (openclaw / eliza / etc.) lives inside
// the respective adapter package -- this state package never imports
// framework-specific types and is agnostic to which framework is loaded.
//
// Two snapshots are tracked side-by-side per dimension:
//
//	chainSnapshot   -- last state confirmed on chain. Updated only after
//	                  uploader receives a tx receipt.
//	currentSnapshot -- agent's actual runtime state. Updated whenever a
//	                  watcher detects an in-memory state change.
//
// Bootstrap seeds both snapshots from the same chain entry so they start
// equal. Agent self-modification (e.g. dashboard upgrade) drifts current
// ahead of chain. The evaluator periodically diffs the two snapshots and
// decides when to push current -> chain via the uploader, which then
// re-syncs chainSnapshot. serve-proof always signs the current snapshot
// so responses reflect the agent's truest state.
package state

import (
	"sort"
	"sync"

	"seal-verify/internal/logger"
)

// Phase reflects where in the bootstrap/run lifecycle the agent is.
type Phase int

const (
	PhaseBootstrapping Phase = iota
	PhaseRunning
	PhaseRestarting
	PhaseEvolving
	PhaseFailed
)

// DimEntry captures a single dimension's state in either snapshot.
//
//   - ContentHash is sha256 of the dimension's plaintext (in-memory canonical
//     bytes). Used by serve-proof and by the evaluator's diff.
//   - DataHash is the 0g-storage root hash on chain. Empty in current
//     snapshot until the dim has been uploaded; equals chain's storage root
//     in chain snapshot.
type DimEntry struct {
	ContentHash string // sha256 hex of plaintext
	DataHash    string // 0g-storage root hex (chain), "" if not yet uploaded
}

// DimHashes is the serve-proof-facing view of one dim's local state.
// ContentHash is always present (sha256 of whatever the agent is running
// right now, including adapter defaults). DataHash is the chain pin and
// is omitted from JSON when the dim isn't on chain yet -- verifiers
// treat its absence as "this dim is running off the adapter default".
type DimHashes struct {
	ContentHash string `json:"content_hash"`
	DataHash    string `json:"data_hash,omitempty"`
}

// Snapshot bundles the per-dim DimEntry map plus a sorted view used for
// serve-proof's data_hashes field.
type Snapshot struct {
	PerDim map[string]DimEntry
}

// Agent is the live shared state.
//
// Framework-specific configuration and credentials are NOT stored here --
// they live inside the adapter and surface via the framework interface's
// AuthResponse / EvolutionFor methods. This package stays agnostic.
type Agent struct {
	mu            sync.RWMutex
	phase         Phase
	agentSealPriv []byte
	upstreamURL   string
	sealID        string
	owner         string
	// Serve-proof identity (Phase 2 chain bootstrap outputs). agentID is the
	// on-chain token id (decimal string); frameworkHash is the sealed image
	// hash ("0x"+sha256), i.e. the AgenticID Framework code running in the TEE.
	agentID       string
	frameworkHash string
	// Serve-proof domain (Phase 2). chainID (decimal) and identityAddr (the
	// AgenticID contract) are signed into the proof digest so a copied proof
	// can't be replayed across chains or protocol deployments.
	chainID      string
	identityAddr string

	// Two snapshots; see package doc.
	chainSnapshot   Snapshot
	currentSnapshot Snapshot
}

// New constructs an Agent in PhaseBootstrapping.
func New() *Agent {
	return &Agent{
		phase:           PhaseBootstrapping,
		chainSnapshot:   Snapshot{PerDim: map[string]DimEntry{}},
		currentSnapshot: Snapshot{PerDim: map[string]DimEntry{}},
	}
}

// ── Identity / lifecycle accessors ──────────────────────────────────────────

// Snapshot returns a copy of the agent's current identity material plus the
// current sorted data hashes (for serve-proof). Callers cannot mutate the
// returned slice.
func (a *Agent) Snapshot() (priv []byte, upstream, sealID, owner string, dataHashes map[string]DimHashes) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]byte(nil), a.agentSealPriv...), a.upstreamURL, a.sealID, a.owner, a.currentMapLocked()
}

// Phase returns the current lifecycle phase.
func (a *Agent) Phase() Phase {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.phase
}

// SetPhase updates the lifecycle phase.
func (a *Agent) SetPhase(p Phase) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.phase = p
}

// Set arms identity + runtime fields (called by manager on start / restart).
// Snapshot data is NOT touched here -- bootstrap seeds chainSnapshot via
// SeedChainSnapshot and the watcher advances currentSnapshot via
// UpdateCurrentSnapshot.
//
// Transitions phase to PhaseRunning.
func (a *Agent) Set(priv []byte, upstream, sealID, owner, agentID, frameworkHash, chainID, identityAddr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentSealPriv = append([]byte(nil), priv...)
	a.upstreamURL = upstream
	a.sealID = sealID
	a.owner = owner
	a.agentID = agentID
	a.frameworkHash = frameworkHash
	a.chainID = chainID
	a.identityAddr = identityAddr
	a.phase = PhaseRunning
}

// ProofIdentity returns the serve-proof identity fields (agentID decimal
// string, frameworkHash "0x"+sha256). Empty when not minted / no image hash.
func (a *Agent) ProofIdentity() (agentID, frameworkHash string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.agentID, a.frameworkHash
}

// ProofDomain returns the serve-proof domain fields (chainID decimal string,
// identityAddr the AgenticID contract). Signed into the proof digest for
// cross-chain / cross-deployment separation. Empty in local dev without a chain.
func (a *Agent) ProofDomain() (chainID, identityAddr string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.chainID, a.identityAddr
}

// Clear resets identity fields and snapshots. Used when the agent process
// exits and the proxy must stop accepting requests. Phase -> Bootstrapping.
func (a *Agent) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentSealPriv = nil
	a.upstreamURL = ""
	a.sealID = ""
	a.owner = ""
	a.agentID = ""
	a.frameworkHash = ""
	a.chainID = ""
	a.identityAddr = ""
	a.chainSnapshot = Snapshot{PerDim: map[string]DimEntry{}}
	a.currentSnapshot = Snapshot{PerDim: map[string]DimEntry{}}
	a.phase = PhaseBootstrapping
}

// ── Snapshot management ─────────────────────────────────────────────────────

// SeedChainSnapshot installs the chain side of a dim's snapshot. Bootstrap
// calls this exactly once per known role:
//
//   - role present on chain: contentHash = sha256(decrypted plaintext from
//     chain), dataHash = chain entry's 0g-storage root hex.
//   - role absent from chain: contentHash = sha256(adapter.Defaults(role)),
//     dataHash = "" (sentinel for "no entry yet"). This makes §16.10's
//     invariant "plaintext = defaults ↔ no chain entry" naturally express
//     itself in the reconcile loop: when disk hashes to Defaults the
//     comparison against chainSnapshot is automatically equal.
//
// currentSnapshot is left alone — phase 1 seed reads disk via EvolutionFor
// and calls UpdateCurrentSnapshot per role to populate it.
//
// chainSnapshot is otherwise advanced only by RecordChainUpload after a
// confirmed chain.Update tx.
func (a *Agent) SeedChainSnapshot(dim, contentHash, dataHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev, exists := a.chainSnapshot.PerDim[dim]
	a.chainSnapshot.PerDim[dim] = DimEntry{ContentHash: contentHash, DataHash: dataHash}

	status := "placeholder (no on-chain entry)"
	if dataHash != "" {
		status = "pinned (data=" + shortHash(dataHash) + ")"
	}
	switch {
	case !exists:
		logger.Logf("iData chain: dim=%s hash=%s %s", dim, shortHash(contentHash), status)
	case prev.ContentHash == contentHash && prev.DataHash == dataHash:
		logger.Logf("iData chain: dim=%s hash=%s %s (no change)", dim, shortHash(contentHash), status)
	default:
		logger.Logf("iData chain: dim=%s hash=%s (was %s) %s",
			dim, shortHash(contentHash), shortHash(prev.ContentHash), status)
	}
}

// UpdateCurrentSnapshot advances currentSnapshot for a dim. Always writes
// the new contentHash; returns true iff it diverges from chainSnapshot
// (current ≠ chain — the canonical "drift" signal driving Apply retries).
//
// This is reconciliation semantics, not change-tracking: returning false
// means "in sync with chain" even when the value did change between two
// polls (e.g. settle drift bounced back to chain's value). Returning true
// means "chain.Update should be attempted to push the new contentHash";
// failed Apply leaves chainSnapshot stale, so the next tick will still
// see drift and retry automatically.
//
// chainSnapshot is intentionally NOT touched — only RecordChainUpload
// advances it, and only after a confirmed tx.
func (a *Agent) UpdateCurrentSnapshot(dim, contentHash string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.currentSnapshot.PerDim[dim]
	chain := a.chainSnapshot.PerDim[dim]

	// DataHash carries forward from prev; RecordChainUpload bumps it after
	// upload. Fallback: when our plaintext matches chain and we have no
	// own-upload record, adopt chain's DataHash — that storage root
	// genuinely backs our current plaintext, so serve-proof can attest
	// to it. Without this, a role that never drifts reports an empty
	// data_hash and the verifier judges it ✗.
	dataHash := prev.DataHash
	if dataHash == "" && contentHash == chain.ContentHash && chain.DataHash != "" {
		dataHash = chain.DataHash
	}
	a.currentSnapshot.PerDim[dim] = DimEntry{
		ContentHash: contentHash,
		DataHash:    dataHash,
	}

	drifted := chain.ContentHash != contentHash
	if prev.ContentHash != contentHash {
		chainLabel := "placeholder"
		if chain.DataHash != "" {
			chainLabel = "pinned"
		}
		verdict := "MATCH"
		if drifted {
			verdict = "DRIFT"
		}
		if prev.ContentHash == "" {
			logger.Logf("iData local[init]: dim=%s hash=%s chain=%s (%s) -> %s",
				dim, shortHash(contentHash),
				shortHash(chain.ContentHash), chainLabel, verdict)
		} else {
			logger.Logf("iData local[change]: dim=%s hash=%s (prev=%s) chain=%s (%s) -> %s",
				dim, shortHash(contentHash), shortHash(prev.ContentHash),
				shortHash(chain.ContentHash), chainLabel, verdict)
		}
	}
	return drifted
}

// ChainEntry returns a copy of the chainSnapshot entry for a dim, or
// zero-value DimEntry when no entry exists.
func (a *Agent) ChainEntry(dim string) DimEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.chainSnapshot.PerDim[dim]
}

// CurrentEntry returns a copy of the currentSnapshot entry for a dim.
func (a *Agent) CurrentEntry(dim string) DimEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentSnapshot.PerDim[dim]
}

// RecordChainUpload syncs the chain snapshot for a dimension. Called by the
// uploader after a sealUpdate tx receipt confirms.
//
// Updates BOTH snapshots: chainSnapshot reflects the new on-chain state,
// and currentSnapshot's DataHash is also bumped (current's ContentHash
// already matches what was uploaded; we just attach the new storage root).
func (a *Agent) RecordChainUpload(dim, contentHash, dataHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.chainSnapshot.PerDim[dim]
	a.chainSnapshot.PerDim[dim] = DimEntry{ContentHash: contentHash, DataHash: dataHash}
	if cur, ok := a.currentSnapshot.PerDim[dim]; ok && cur.ContentHash == contentHash {
		a.currentSnapshot.PerDim[dim] = DimEntry{ContentHash: contentHash, DataHash: dataHash}
	}
	logger.Logf("iData chain uploaded: dim=%s content=%s chain_root=%s -> %s",
		dim, shortHash(contentHash), shortHash(prev.DataHash), shortHash(dataHash))
}

// CurrentDataHashes returns the sorted hex content-hashes of the current
// snapshot, for serve-proof's data_hashes field. Hashes reflect agent's
// truest in-memory state at the moment of the call.
func (a *Agent) CurrentDataHashes() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sortedCurrentLocked()
}

// ChainDataHashes returns the sorted hex content-hashes that are confirmed
// on chain. Used by the evaluator's diff and for diagnostics.
func (a *Agent) ChainDataHashes() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.chainSnapshot.PerDim))
	for _, e := range a.chainSnapshot.PerDim {
		out = append(out, e.ContentHash)
	}
	sort.Strings(out)
	return out
}

// HasChanges reports whether currentSnapshot differs from chainSnapshot in
// any dimension. Used by the evaluator as a fast pre-check before any
// strategy evaluation.
func (a *Agent) HasChanges() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.currentSnapshot.PerDim) != len(a.chainSnapshot.PerDim) {
		return true
	}
	for dim, cur := range a.currentSnapshot.PerDim {
		ch, ok := a.chainSnapshot.PerDim[dim]
		if !ok || ch.ContentHash != cur.ContentHash {
			return true
		}
	}
	return false
}

// ── Internal helpers ────────────────────────────────────────────────────────

// sortedCurrentLocked must be called with a.mu held (read or write).
func (a *Agent) sortedCurrentLocked() []string {
	out := make([]string, 0, len(a.currentSnapshot.PerDim))
	for _, e := range a.currentSnapshot.PerDim {
		out = append(out, e.ContentHash)
	}
	sort.Strings(out)
	return out
}

// currentMapLocked returns a fresh per-dim view of currentSnapshot for
// serve-proof. EVERY dim the agent is tracking is included, even ones
// without a chain pin yet -- their ContentHash commits the local default
// state so a verifier can detect tampering of adapter defaults too.
//
// DataHash is included only when non-empty; the omitempty tag turns
// absent dims into "no chain pin yet" rather than '"data_hash": ""'.
//
// Returns an empty map when nothing qualifies, never nil, so JSON
// marshals to "{}" not "null".
func (a *Agent) currentMapLocked() map[string]DimHashes {
	out := make(map[string]DimHashes, len(a.currentSnapshot.PerDim))
	for dim, e := range a.currentSnapshot.PerDim {
		out[dim] = DimHashes{ContentHash: e.ContentHash, DataHash: e.DataHash}
	}
	return out
}

// shortHash returns the first 10 chars of a hex string (with optional 0x
// prefix preserved) for log-friendly output. Empty input -> "(none)".
func shortHash(h string) string {
	if h == "" {
		return "(none)"
	}
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
