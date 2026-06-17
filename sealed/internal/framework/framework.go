// Package framework defines the adapter contract that abstracts agent
// frameworks (openclaw, eliza, ...) behind a uniform interface used by the
// rest of the sealed bootstrap pipeline.
//
// See sealed/ARCHITECTURE.zh.md §3 for the full contract specification.
//
// In the current single-config implementation the only meaningful dimension
// is "config" (mapped from the existing iData role); knowledge / skills / ops
// are scaffolded for forward compatibility but not wired through yet.
package framework

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Shape declares how a role's plaintext maps to 0g-storage blobs.
//
// Leaf: iData points to one encrypted blob whose plaintext is the role's
// canonical bytes (e.g. a JSON config file).
//
// DirectoryManifest: iData points to a manifest plaintext whose entries
// each reference their own content blob. Supports per-entry incremental
// upload. See sealed/internal/manifest.
type Shape string

const (
	Leaf              Shape = "leaf"
	DirectoryManifest Shape = "directory_manifest"
)

// RoleSpec declares one role this adapter handles. Returned from
// Framework.Roles(); used by main bootstrap to enumerate roles and by
// the uploader to pick a per-role encoding path.
//
// There is intentionally no "Required" field: sealed treats every role
// as optional and falls back to adapter defaults when chain has no entry.
// Mint-time "what owner must provide" is enforced by attestor (a separate
// codebase and concern), not by the sealed protocol layer. See
// ARCHITECTURE.zh.md §5 (wholesale-replace + isDefault semantics).
type RoleSpec struct {
	Name  string
	Shape Shape
}

// Framework is the adapter interface every agent framework must implement.
type Framework interface {
	// Name returns the static framework identifier, e.g. "openclaw".
	Name() string

	// Version returns the runtime-detected framework version (best-effort,
	// may exec a CLI to probe). Used in serve-proof metadata and reporter
	// status payloads.
	Version(ctx context.Context) (string, error)

	// Roles returns every role this adapter declares — INCLUDING the
	// protocol-reserved "framework" role. See ARCHITECTURE.zh.md §6
	// (role table) for the current openclaw adapter's 5 roles.
	Roles() []RoleSpec

	// Defaults returns the canonical "empty/zero" plaintext for a role.
	// For DirectoryManifest roles this is an empty manifest (schema_version=1
	// kind=directory_manifest entries=[]). For Leaf roles that have no
	// meaningful default (e.g. required roles), implementations return nil.
	//
	// Used by:
	//   - bootstrap: Restore(role, Defaults(role)) when chain lacks the role
	//   - uploader: compare against EvolutionFor output to decide "plaintext
	//     equals default → skip upload / delete chain entry"
	Defaults(role string) []byte


	// Restore applies the plaintext bytes for a single dimension to the
	// adapter's in-memory composed state. Multiple Restore calls must
	// commute and be idempotent (see ARCHITECTURE.zh.md §3 closing
	// paragraph on Restore commutativity).
	//
	// For path-driven roles (§16): Leaf roles write the plaintext directly.
	// DirectoryManifest roles parse the manifest plaintext but do NOT
	// fetch entry blobs themselves — caller (bootstrap / uploader) iterates
	// the parsed manifest and calls RestoreEntry per entry.
	Restore(ctx context.Context, dim string, plaintext []byte) error

	// LoadEntry returns the plaintext bytes for one entry inside a
	// DirectoryManifest role. Inverse of RestoreEntry.
	//
	// For EntryFile entries, this is the file's raw bytes (with any
	// adapter-specific stripping, e.g. TOOLS.md platform-injection).
	// For EntryDir entries, this is the deterministic tar.gz of the
	// subtree.
	//
	// Returns ErrUnsupportedDim if role isn't a DirectoryManifest role.
	// Returns an OS error if the entry's disk source is missing.
	LoadEntry(ctx context.Context, role string, path string) ([]byte, error)

	// RestoreEntry writes one entry's plaintext under the role's disk
	// location. Inverse of LoadEntry. Order-independent and idempotent
	// across multiple calls (see ARCHITECTURE.zh.md §3 closing paragraph
	// on Restore commutativity).
	//
	// For EntryFile-style paths (no trailing "/"): plaintext is the file
	// bytes; written verbatim.
	// For EntryDir-style paths (trailing "/"): plaintext is a tar.gz
	// produced by manifest.PackDir; extracted to <role disk>/<path>.
	//
	// Returns ErrUnsupportedDim if role isn't a DirectoryManifest role.
	RestoreEntry(ctx context.Context, role string, path string, plaintext []byte) error

	// EvolutionFor returns the canonical plaintext bytes representing the
	// agent's current state for the given dimension. Used by the watcher
	// to detect drift against state.currentSnapshot, and by the uploader
	// to encrypt + push to chain.
	//
	// MUST be deterministic: same in-memory state must produce identical
	// bytes (so sha256 comparisons work). Implementations marshal with
	// stable field ordering.
	//
	// Returns ErrUnsupportedDim for dim names the adapter doesn't handle.
	EvolutionFor(ctx context.Context, dim string) ([]byte, error)

	// HandleLegacy is called by bootstrap once for every chain iData entry
	// whose role is NOT in Roles(). Mint-only "ingestion" roles (e.g.
	// openclaw's `persona`) live here: the adapter translates the legacy
	// plaintext into the path-driven on-disk artifacts that subsequent
	// reconciliation cycles will manage.
	//
	// Invoked AFTER Restore() for all declared roles (so legacy translation
	// reliably overwrites adapter Defaults written by Restore(role, nil)).
	// Idempotent: re-invoking with the same plaintext must produce the same
	// disk state.
	//
	// Unknown legacy role names should be logged and ignored (return nil),
	// not error — chains may carry experimental roles a given adapter
	// version doesn't understand, and refusing to start over it is worse
	// than running with a partial migration.
	HandleLegacy(ctx context.Context, role string, plaintext []byte) error

	// Start spawns the agent process based on the previously-Restored state.
	// Returns the upstream URL the proxy should forward to.
	Start(ctx context.Context, rt RuntimeContext) (StartResult, error)

	// AuthResponse returns the framework-specific JSON-encodable payload
	// to hand back to a verified owner via /_seal/auth. proxy is responsible
	// for the EIP-191 verification and serve-proof signing; adapter only
	// decides what payload the verified owner should receive (e.g. control-UI
	// token + redirect URL). Different frameworks return different shapes.
	AuthResponse(ctx context.Context) (any, error)

	// Stop gracefully terminates the agent process. SIGTERM-then-SIGKILL
	// pattern is acceptable; honour gracefulTimeout before escalating.
	Stop(ctx context.Context, gracefulTimeout time.Duration) error

	// Liveness reports whether the agent process is alive and listening.
	// Non-nil error means the manager should consider restarting.
	Liveness(ctx context.Context) error

	// Readiness reports whether the agent is ready to handle requests
	// (process up AND initialised). Non-nil error means /hello / proxy
	// should return 503 even though the process is alive.
	Readiness(ctx context.Context) error
}

// Reloadable is an optional interface adapters may implement to enable
// hot-reload semantics during evolution updates. Manager will prefer
// Reload over Stop+Start when available.
type Reloadable interface {
	Reload(ctx context.Context, changedDim string) error
}

// ErrUnsupportedDim is returned by EvolutionFor / Restore when an adapter
// is asked to act on a dim label it doesn't understand.
var ErrUnsupportedDim = fmt.Errorf("framework: dim not supported by this adapter")

// RuntimeContext is the per-Start environment passed to adapters. Owners of
// secrets (API keys etc.) populate it before calling Start.
//
// Phase 2 chain bootstrap outputs (AgentID, Owner, ChainRPC, etc.) are
// included here so framework adapters can inject them into the agent's
// workspace context (e.g. platform.RuntimeSnapshot). They are not secrets
// — they are public on-chain data that the agent benefits from knowing.
type RuntimeContext struct {
	APIKey       string // inference provider API key from env (e.g. ANTHROPIC_API_KEY)
	PublicURL    string // externally-reachable URL prefix for this sandbox; empty in local dev
	SealSignSock string // unix socket path for agent-only sign endpoint (agentSeal identity)
	AgentSeal    string // 0x-prefixed address derived from agent_seal_priv pubkey

	// Chain bootstrap outputs (Phase 2). Populated by main.go from
	// chainBootstrapResult. Empty/zero in local dev without a chain.
	AgentID      string // on-chain AgenticID token ID (decimal string); empty if not minted
	Owner        string // 0x-prefixed owner address from OwnerOf; empty if lookup failed
	ChainRPC     string // RPC endpoint used for chain queries
	ContractAddr string // AgenticID contract address
	AttestorURL  string // attestor endpoint URL

	// Inference routing (populated by spawn.go after resolving provider).
	Provider        string // inference provider (e.g. "openai")
	Model           string // inference model name (e.g. "glm-5.2")
	ZGComputeRouted bool // whether 0g-compute augmentation was applied

	// Sealed runtime metadata.
	SealedVersion string // git short hash of sealed binary; empty if unavailable
}

// StartResult is what an adapter returns when its agent process is up and
// listening. Bootstrap arms state.Agent with these values.
//
// Framework-specific credentials (control-UI tokens etc.) are NOT exposed
// here — adapter retains them privately and surfaces them via AuthResponse.
type StartResult struct {
	Upstream string // e.g. "http://127.0.0.1:3284"
	PID      int
}

// ── Registry ─────────────────────────────────────────────────────────────────
//
// Adapter packages register themselves via init() side-effect. Bootstrap
// resolves "openclaw" -> *openclawAdapter via Get().

var (
	registryMu sync.RWMutex
	registry   = map[string]Framework{}
)

// Register makes adapter retrievable by name. Adapters call this from their
// own init() function. A second registration for the same name overwrites
// (callers are expected to register exactly once at process start).
func Register(name string, fw Framework) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = fw
}

// Get retrieves a previously-registered adapter by name. Returns an error
// when no matching adapter is registered.
func Get(name string) (Framework, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	fw, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("framework not registered: %q", name)
	}
	return fw, nil
}
