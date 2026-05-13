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
	return a.agentSealPriv, a.upstreamURL, a.sealID, a.owner, a.currentMapLocked()
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
// Snapshot data is NOT touched here -- bootstrap seeds via SeedSnapshots and
// runtime watchers update via UpdateCurrent.
//
// Transitions phase to PhaseRunning.
func (a *Agent) Set(priv []byte, upstream, sealID, owner string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentSealPriv = priv
	a.upstreamURL = upstream
	a.sealID = sealID
	a.owner = owner
	a.phase = PhaseRunning
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
	a.chainSnapshot = Snapshot{PerDim: map[string]DimEntry{}}
	a.currentSnapshot = Snapshot{PerDim: map[string]DimEntry{}}
	a.phase = PhaseBootstrapping
}

// ── Snapshot management ─────────────────────────────────────────────────────

// SeedSnapshots initialises both chainSnapshot and currentSnapshot for a
// dimension. Called by bootstrap once per dim. Both snapshots start equal
// so subsequent watcher tick comparisons see no drift on first poll.
//
// contentHash is sha256(plaintext). dataHash is the 0g-storage root hex
// from the iData entry on chain -- or "" when the dim is not on chain
// (default mint may produce only framework + persona; absent dims have
// empty dataHash and uploader will add them on first meaningful drift).
//
// Logs also show whether this is a no-op (re-seed with identical content,
// e.g. baseline didn't shift between pre- and post-settle pass) for
// debug clarity.
func (a *Agent) SeedSnapshots(dim, contentHash, dataHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev, exists := a.currentSnapshot.PerDim[dim]
	entry := DimEntry{ContentHash: contentHash, DataHash: dataHash}
	a.chainSnapshot.PerDim[dim] = entry
	a.currentSnapshot.PerDim[dim] = entry

	chainStatus := "off-chain"
	if dataHash != "" {
		chainStatus = "on-chain " + shortHash(dataHash)
	}
	switch {
	case !exists:
		logger.Logf("iData seed[init]: dim=%s content=%s %s", dim, shortHash(contentHash), chainStatus)
	case prev.ContentHash == contentHash:
		logger.Logf("iData seed[stable]: dim=%s content=%s %s (no shift)", dim, shortHash(contentHash), chainStatus)
	default:
		logger.Logf("iData seed[shift]: dim=%s content %s -> %s %s",
			dim, shortHash(prev.ContentHash), shortHash(contentHash), chainStatus)
	}
}

// UpdateCurrent advances the current snapshot for a dimension. Returns
// true if the content hash actually changed (caller can use this for
// summary logging). Called by the watcher when adapter.EvolutionFor
// reveals a content hash that differs from currentSnapshot's last value.
//
// chain snapshot is intentionally NOT touched -- only RecordChainUpload
// can move it forward, and only after a confirmed tx.
func (a *Agent) UpdateCurrent(dim, contentHash string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.currentSnapshot.PerDim[dim]
	if prev.ContentHash == contentHash {
		return false
	}
	chain := a.chainSnapshot.PerDim[dim]
	a.currentSnapshot.PerDim[dim] = DimEntry{
		ContentHash: contentHash,
		// DataHash carries forward; it'll be replaced once this contentHash
		// gets uploaded and chain confirms a new storage root.
		DataHash: prev.DataHash,
	}
	logger.Logf("iData drift: dim=%s content %s -> %s (chain still %s, dataHash=%s)",
		dim, shortHash(prev.ContentHash), shortHash(contentHash),
		shortHash(chain.ContentHash), shortHash(chain.DataHash))
	return true
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
