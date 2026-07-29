// Package framework defines the adapter contract that abstracts agent
// frameworks (openclaw, eliza, ...) behind a uniform interface used by the
// rest of the sealed bootstrap pipeline.
//
// See sealed/FRAMEWORK_ADAPTER.md for the full contract specification
// (per-method semantics, invariants, call-site map, porting checklist);
// sealed/ARCHITECTURE.md §3 has the architectural overview.
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

	"seal-verify/internal/platform"
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
	// may exec a CLI to probe). Declared for serve-proof metadata and
	// reporter status payloads; not consumed by core code yet (the openclaw
	// adapter probes its own version inside EvolutionFor("framework")).
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

	// FrameworkFacts returns the framework-authored half of the agent doc
	// (§9 part 2) as VALUES filling the shared template, not prose: which of
	// ITS paths are chain-tracked and where durable state belongs, its
	// version whitelist, its config-key allowlist. platform owns every
	// sentence of platform mechanics and renders them identically for all
	// frameworks (platform.RenderFrameworkFacts); this method supplies only
	// what differs by framework, so an adapter can neither restate a platform
	// mechanism wrong nor silently drop one.
	//
	// MUST return a non-empty Tracked set (conformance enforces it): an
	// adapter with no tracked paths ships an agent that doesn't know where
	// its own memory persists.
	FrameworkFacts() platform.FrameworkFacts

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

// ── Optional capability interfaces ───────────────────────────────────────────
//
// Discovered while porting the second adapter (claudecode): several
// behaviours main.go used to invoke on the concrete *openclaw.Adapter are
// really per-framework capabilities. They live here as optional interfaces
// so the core stays framework-agnostic: callers type-assert and degrade
// gracefully when an adapter doesn't implement one.

// VersionReconciler is implemented by adapters that can force the installed
// framework back to a version sealed trusts (typically the max of a version
// allowlist). main.go's drift handler invokes it when the protocol-reserved
// "framework" role drifts, before reloading the agent process.
//
// Adapters that cannot reconcile (no package manager, pinned-image
// framework) simply don't implement this; the drift handler then commits
// the observed version on chain as-is and logs that no reconcile ran.
type VersionReconciler interface {
	ReconcileFramework(ctx context.Context) error
}

// Service exposure used to be a per-adapter capability (a
// ServicesManifestProvider pointing at e.g. ~/.openclaw/services.json).
// It was lifted into sealed: agents register services over
// POST $SEAL_SIGN_SOCK/services and proxy builds /hello from that
// registry (see proxy/services.go), so adapters no longer declare a
// manifest path.

// SubprocessLogProvider is implemented by adapters that pipe their agent
// process's stdout/stderr to a known file. proxy serves it live on
// /log/agent (owner-only). Without this, the subprocess log pages report
// "not available".
type SubprocessLogProvider interface {
	SubprocessLogPath() string
}

// SettleDelayer is implemented by adapters whose framework rewrites its
// own config once on first boot (applying defaults to sections Restore
// didn't populate). Bootstrap waits this long after Start before capturing
// the watcher baseline so those self-applied defaults aren't reported as
// drift. Adapters without the behaviour don't implement this; bootstrap
// falls back to a conservative default.
type SettleDelayer interface {
	SettleDelay() time.Duration
}

// Route is one path prefix a framework exposes through the sealed proxy.
//
// The proxy forwards a request to the framework upstream ONLY if its path
// matches a declared route (longest-prefix wins); every other path 404s
// instead of being blind-forwarded. This bounds the framework's public
// surface — and, via Signed, the serve-proof signing surface — to what the
// adapter deliberately declares, so a framework upgrade can't silently widen
// either. Routes are trusted input: only the audited, in-tree adapter code
// constructs them (contrast agent-registered /api/* services in
// proxy/services.go, which are untrusted runtime input and always exact-match
// + signed).
type Route struct {
	// Prefix is the public path prefix this route claims, e.g. "/" (a
	// framework that owns the root, like a dashboard SPA) or "/v1/" (a
	// scoped API surface). Matched by longest prefix.
	Prefix string
	// Kind is a discovery hint surfaced in /hello, e.g. "dashboard" or
	// "chat". Opaque to the proxy; clients (the SDK session) use it to pick
	// an interaction affordance.
	Kind string
	// Auth tells a client how to present the /_seal/auth token on this
	// route: "token-fragment" (append #token=… and open in a browser),
	// "bearer" (Authorization: Bearer …), or "none".
	Auth string
	// Signed selects whether responses on this route carry an X-Agent-Proof
	// serve-proof. True for attributable API responses; false for static UI
	// assets, which shouldn't bear the agent's on-chain signature.
	Signed bool
	// Backend is the loopback upstream this route forwards to, e.g.
	// "http://127.0.0.1:9119". Empty = the adapter's single StartResult
	// Upstream (the common case: one framework process owning every route,
	// like openclaw's gateway). A non-empty value is for frameworks whose
	// surfaces are separate processes on separate ports (e.g. hermes: chat
	// API on :8642, dashboard on :9119) — the proxy then routes per matched
	// route rather than to one upstream. Mirrors an agent service's
	// per-backend routing, which the proxy already does.
	Backend string
	// Description is a one-line human summary for /hello.
	Description string
}

// RouteProvider is implemented by adapters that declare their public HTTP
// surface to the proxy. When an adapter implements it, the proxy routes only
// declared prefixes (404ing the rest) and signs per Route.Signed. Adapters
// that don't implement it fall back to legacy behaviour: every path is
// forwarded to the upstream and every response is signed.
type RouteProvider interface {
	FrameworkRoutes() []Route
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
	FrameworkHash string // "0x"+sha256 sealed image hash; signed into serve-proofs as the AgenticID Framework code hash
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
