// Sealed container bootstrap (orchestrator).
//
// Phase 0  attest         - parse env, verify SANDBOX_SEAL_KEY ↔ attestation.pubkey,
//                           recover TEE signer (and match TEE_SIGNER_ADDRESS if set)
// Phase 1  provision      - POST /provision -> ECIES-decrypt agent_seal_priv
// Phase 2  chain bootstrap - getAgentIdBySealId + intelligentDatasOf +
//                           loadSealedKeys + per-entry download + AES-GCM decrypt
// Phase 3  framework      - adapter.Restore each decrypted entry; adapter.Start
// Phase 4  status report  - notify attestor only on full pipeline success
//
// Long-running:
//   - HTTP server on :8080 (proxy package)
//   - manager monitors agent process exit and clears shared state
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/chain"
	"seal-verify/internal/config"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/framework/openclaw"
	"seal-verify/internal/logger"
	"seal-verify/internal/manager"
	"seal-verify/internal/manifest"
	"seal-verify/internal/provision"
	"seal-verify/internal/proxy"
	"seal-verify/internal/report"
	"seal-verify/internal/state"
	"seal-verify/internal/uploader"
	"seal-verify/internal/watcher"
)

const bootstrapTimeout = 10 * time.Minute

// sealSignSockPath is the unix domain socket path where the agent-only
// signing endpoint listens. Mounted at /run (tmpfs in containers, no risk
// of stale state across restarts). Hardcoded — operators don't need to
// configure this; the agent discovers it via SEAL_SIGN_SOCK env var.
const sealSignSockPath = "/run/seal-sign.sock"

// decryptedEntry is the post-bootstrap representation of one iData
// chain entry: role tag + dataHash + decrypted plaintext + the role-level
// data_key + indexer URL used to download it.
//
// DataKey + Indexer are retained because manifest-shape roles need them
// to fetch child entry blobs from 0g-storage with the same crypto key
// the parent manifest was sealed under.
type decryptedEntry struct {
	Role      string
	DataHash  [32]byte
	Plaintext []byte
	DataKey   []byte
	Indexer   string
	// ContentHash is sha256(Plaintext) in lowercase hex. Computed once here
	// at bootstrap so SeedChainSnapshot can record the authoritative "chain
	// content hash" without re-decrypting later.
	ContentHash string
}

// storageDescription is the JSON wrapper inside dataDescription that points
// to the encrypted blob in 0g-storage and tags this entry's role.
type storageDescription struct {
	Role       string `json:"role"`
	StoragePtr struct {
		Indexer  string `json:"indexer"`
		RootHash string `json:"root_hash"`
	} `json:"storage_ptr"`
}

func main() {
	// Register adapters (side-effect of New()).
	openclawAdapter := openclaw.New()

	// Shared agent state -- read by proxy, written by main + manager.
	agent := state.New()

	// Phase 0: parse env + verify attestation. Done BEFORE starting the HTTP
	// server because we need cfg.PublicURL to construct proxy.Server.
	cfg, err := config.Load()
	if err != nil {
		logger.Fail("%v", err)
	}

	// Start the HTTP server now (after we know our public URL but before the
	// rest of bootstrap so /healthz and /log are reachable while the chain
	// scan + agent spawn are still in flight).
	//
	// :8080  → public mux (proxy + serve-proof)
	// unix:///run/seal-sign.sock → agent-only sign endpoint. Starts even
	//   before provision completes; handlers return 503 until agent_seal_priv
	//   is loaded into state.Agent.
	sealedProxy := proxy.New(agent, openclawAdapter, cfg.PublicURL, openclaw.ServicesFilePath())
	sealedProxy.Listen()
	sealedProxy.ListenInternal(sealSignSockPath)
	if cfg.APIKey != "" {
		logger.Logf("API_KEY (from env): <set, %d chars>", len(cfg.APIKey))
	} else {
		logger.Logf("API_KEY (from env): <unset>")
	}
	logger.Logf("")

	// Phase 1+2+3: provision + bootstrap from chain + start agent.
	// Each phase is best-effort; if any fails we report error to attestor
	// and continue to serve /healthz, /log so operators can inspect.
	if cfg.AttestorURL == "" {
		logger.Logf("ATTESTOR_URL unset -- skipping provision / bootstrap / status")
	} else if cfg.ChainRPC == "" || cfg.ContractAddr == "" || cfg.FallbackIndexer == "" {
		logger.Logf("missing required env (CHAIN_RPC_URL=%q AGENTIC_ID_ADDR=%q INDEXER_URL=%q) -- skipping provision / bootstrap / status",
			cfg.ChainRPC, cfg.ContractAddr, cfg.FallbackIndexer)
	} else {
		runMainPipeline(cfg, agent, openclawAdapter)
	}

	logger.Logf("")
	logger.Logf("ALL DONE")
	logger.Flush()

	// Block forever -- HTTP server runs in its own goroutine.
	select {}
}

// runMainPipeline encapsulates Phases 1-4. Errors are logged and reported
// but never crash the process (main keeps the HTTP server up so /log is
// reachable even when bootstrap can't complete).
func runMainPipeline(cfg *config.Bootstrap, agent *state.Agent, adapter *openclaw.Adapter) {
	logger.Logf("--- Provisioning from attestor: %s ---", cfg.AttestorURL)
	agentSealPriv := provision.FromAttestor(cfg.AttestorURL, cfg.SealKeyBytes, cfg.Attestation)
	if agentSealPriv == nil {
		return
	}
	// SANDBOX_SEAL_KEY is consumed; scrub before any agent process spawns.
	config.ScrubProvisioningSecrets(cfg.SealKeyBytes)

	logger.Logf("")
	logger.Logf("--- Bootstrap from AgenticID %s (rpc %s, fallback indexer %s) ---",
		cfg.ContractAddr, cfg.ChainRPC, cfg.FallbackIndexer)

	res, err := chainBootstrap(cfg.ChainRPC, cfg.ContractAddr, cfg.Attestation.SealID, agentSealPriv, cfg.FallbackIndexer)
	if err != nil {
		logger.Logf("FAIL bootstrap: %v", err)
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", "bootstrap: "+err.Error())
		return
	}

	logger.Logf("")
	logger.Logf("--- Starting agent ---")
	// onFailed is invoked by the manager exactly once if the supervisor
	// exhausts restart retries. Reports an "error" status to the attestor
	// so the platform can decide whether to recreate the sandbox.
	onFailed := func(err error) {
		logger.Logf("FAIL supervisor: max retries exceeded: %v", err)
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", "supervisor exhausted retries: "+err.Error())
	}
	if err := startAgent(cfg, adapter, agent, res, agentSealPriv, onFailed); err != nil {
		logger.Logf("FAIL agent: %v", err)
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", err.Error())
		return
	}
	logger.Logf("OK   agent ready (upstream listening, agentState armed, supervisor active)")

	report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "running", "")
}

// chainBootstrapResult bundles the outputs of Phase 2.
//
// client is intentionally NOT closed by chainBootstrap — the uploader
// reuses it long-term. The container blocks forever, so the client never
// actually needs to be released.
type chainBootstrapResult struct {
	entries []decryptedEntry
	owner   string
	agentID *big.Int
	client  *chain.Client
}

// chainBootstrap executes Phase 2 (mint observation, intelligentDatasOf,
// sealedKey scan, per-entry download + decrypt). Returns nil + error on
// any unrecoverable failure.
func chainBootstrap(rpcURL, contractHex, sealIDHex string, agentSealPriv []byte, fallbackIndexer string) (*chainBootstrapResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	c, err := chain.Dial(ctx, rpcURL, contractHex)
	if err != nil {
		return nil, err
	}
	// NOTE: client lifetime intentionally extends past this function so
	// the uploader can reuse it. The bootstrap process never exits cleanly,
	// so there's no leak to worry about.

	sealID32, err := chain.HexSealID(sealIDHex)
	if err != nil {
		c.Close()
		return nil, err
	}

	agentID, err := c.WaitForMint(ctx, sealID32)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("wait for mint: %w", err)
	}
	logger.Logf("OK   minted agent_id: %s", agentID.String())

	iDatas, err := c.IntelligentDatasOf(ctx, agentID)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("intelligentDatasOf: %w", err)
	}
	logger.Logf("OK   intelligent_datas: %d entries", len(iDatas))

	sealedKeys, err := c.SealedKeysOf(ctx, agentID)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("sealedKeysOf: %w", err)
	}
	logger.Logf("OK   sealedKeys collected: %d entries", len(sealedKeys))

	entries := make([]decryptedEntry, 0, len(iDatas))
	allOK := true
	for i, d := range iDatas {
		sealed, ok := sealedKeys[d.DataHash]
		if !ok {
			logger.Logf("FAIL bootstrap[%d]: no sealedKey for dataHash 0x%s", i, hex.EncodeToString(d.DataHash[:]))
			allOK = false
			continue
		}
		entry, ok := decryptEntry(ctx, i, d, sealed, agentSealPriv, fallbackIndexer)
		if !ok {
			allOK = false
			continue
		}
		entries = append(entries, entry)
	}
	if !allOK {
		return nil, fmt.Errorf("one or more iData entries failed to decrypt")
	}

	owner, err := c.OwnerOf(ctx, agentID)
	ownerHex := ""
	if err != nil {
		logger.Logf("warn: ownerOf(%s) failed: %v", agentID.String(), err)
	} else {
		ownerHex = owner.Hex()
		logger.Logf("OK   agent owner: %s", ownerHex)
	}

	logger.Logf("OK   bootstrap complete")
	return &chainBootstrapResult{
		entries: entries,
		owner:   ownerHex,
		agentID: agentID,
		client:  c,
	}, nil
}

// decryptEntry resolves dataDescription -> indexer + role, downloads the
// ciphertext, ECIES-unseals the data_key, AES-GCM decrypts the body, and
// removes the temp file before any agent process spawns.
func decryptEntry(ctx context.Context, idx int, d chain.IntelligentData, sealedKey, agentSealPriv []byte, fallbackIndexer string) (decryptedEntry, bool) {
	tag := fmt.Sprintf("[%d]", idx)
	dataHashHex := "0x" + hex.EncodeToString(d.DataHash[:])

	var desc storageDescription
	if err := json.Unmarshal([]byte(d.DataDescription), &desc); err != nil {
		logger.Logf("FAIL bootstrap%s parse dataDescription: %v", tag, err)
		return decryptedEntry{}, false
	}
	indexer := desc.StoragePtr.Indexer
	if indexer == "" {
		indexer = fallbackIndexer
	}
	if indexer == "" {
		logger.Logf("FAIL bootstrap%s no indexer (description.storage_ptr.indexer empty and no fallback)", tag)
		return decryptedEntry{}, false
	}
	logger.Logf("bootstrap%s data=%s role=%q indexer=%s", tag, dataHashHex, desc.Role, indexer)

	outPath := fmt.Sprintf("/tmp/idata-%s.bin", hex.EncodeToString(d.DataHash[:]))
	if err := dataplane.Download(ctx, dataHashHex, indexer, outPath); err != nil {
		logger.Logf("FAIL bootstrap%s download: %v", tag, err)
		return decryptedEntry{}, false
	}
	defer removeFile(outPath)

	blob, err := readFile(outPath)
	if err != nil {
		logger.Logf("FAIL bootstrap%s read downloaded file: %v", tag, err)
		return decryptedEntry{}, false
	}

	dataKey, err := dataplane.UnsealDataKey(sealedKey, agentSealPriv)
	if err != nil {
		logger.Logf("FAIL bootstrap%s ECIES decrypt sealedKey: %v", tag, err)
		return decryptedEntry{}, false
	}
	plaintext, err := dataplane.Decrypt(blob, dataKey)
	if err != nil {
		logger.Logf("FAIL bootstrap%s AES-GCM decrypt: %v", tag, err)
		return decryptedEntry{}, false
	}

	logger.Logf("OK   bootstrap%s decrypted (%d bytes, role=%q)", tag, len(plaintext), desc.Role)
	return decryptedEntry{
		Role:        desc.Role,
		DataHash:    d.DataHash,
		Plaintext:   plaintext,
		DataKey:     dataKey,
		Indexer:     indexer,
		ContentHash: sha256Hex(plaintext),
	}, true
}

// startAgent dispatches each decrypted entry to the framework adapter, seeds
// per-dim iData snapshots into shared state, then hands off to the manager
// which spawns the process and supervises it.
//
// Each iData entry is routed by its role string (see ARCHITECTURE.zh.md §6
// for the openclaw adapter's 5-role set). Every entry contributes one
// (dim, contentHash, dataHash) tuple to both chainSnapshot and currentSnapshot.
//
// The supervisor (manager) handles process death, liveness probes, restart
// backoff, and the Failed-phase escalation. onFailed fires once if max
// retries are exhausted.
func startAgent(
	cfg *config.Bootstrap,
	adapter *openclaw.Adapter,
	agent *state.Agent,
	res *chainBootstrapResult,
	agentSealPriv []byte,
	onFailed func(err error),
) error {
	apiKey := cfg.APIKey
	publicURL := cfg.PublicURL
	sealID := cfg.Attestation.SealID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Path-driven role set. sealed enforces no "required" roles —
	// missing roles fall back to adapter defaults. Mint-time owner-side
	// requirements are an attestor concern, not sealed's.
	//
	// Duplicate role entries on chain are a hard fail (see
	// ARCHITECTURE.zh.md §5 "duplicate-role hard-fail" bullet) — same
	// role with two different storage_roots leaves agent identity
	// undefined, so we fail loud at bootstrap.
	roles := adapter.Roles()
	declared := make(map[string]bool, len(roles))
	for _, r := range roles {
		declared[r.Name] = true
	}

	// Phase A: declared roles — Restore plaintext, seed chainSnapshot with
	// the authoritative sha256(plaintext) so subsequent reconcile ticks
	// can compare disk against the true chain content (not a "best-guess"
	// disk-derived hash).
	//
	// Phase B: declared roles missing from chain — Restore(nil) writes
	// adapter defaults to disk, chainSnapshot is seeded with sha256(Defaults)
	// so §16.10's "plaintext = defaults ↔ no chain entry" invariant holds
	// naturally in the reconcile loop.
	//
	// Phase C: legacy chain entries (roles outside adapter.Roles(), e.g.
	// mint-only `persona`) — fire HandleLegacy to translate their content
	// into path-driven on-disk artifacts. Runs AFTER all declared-role
	// Restores so legacy translation reliably overwrites any defaults
	// Phase B may have written.
	seen := map[string]bool{}
	for i := range res.entries {
		role := res.entries[i].Role
		if seen[role] {
			return fmt.Errorf("duplicate iData entry for role=%q", role)
		}
		seen[role] = true
	}

	// Phase A
	for _, r := range roles {
		entry := findEntry(res.entries, r.Name)
		if entry == nil {
			continue
		}
		if err := adapter.Restore(ctx, r.Name, entry.Plaintext); err != nil {
			return fmt.Errorf("restore %s: %w", r.Name, err)
		}
		if r.Shape == framework.DirectoryManifest && len(entry.Plaintext) > 0 {
			if err := restoreManifestEntries(ctx, adapter, r.Name, entry.Plaintext, entry.DataKey, entry.Indexer); err != nil {
				return fmt.Errorf("restore manifest entries for %s: %w", r.Name, err)
			}
		}
		dataHashHex := "0x" + hex.EncodeToString(entry.DataHash[:])
		// Manifest-shape plaintext from 0g-storage carries filled StoragePtr
		// fields, but evoXxx() at watcher tick time produces the empty-ptr
		// form — those two are the canonical pair (push_manifest.go:22-26).
		// Seed chainSnapshot with sha256(empty-ptr) so drift detection
		// compares apples to apples; otherwise every restart shows phantom
		// drift on manifest roles and re-uploads them.
		contentHashForSeed := entry.ContentHash
		if r.Shape == framework.DirectoryManifest && len(entry.Plaintext) > 0 {
			stripped, err := manifest.StripStoragePtrs(entry.Plaintext)
			if err != nil {
				return fmt.Errorf("normalize manifest contentHash for %s: %w", r.Name, err)
			}
			contentHashForSeed = sha256Hex(stripped)
		}
		agent.SeedChainSnapshot(r.Name, contentHashForSeed, dataHashHex)
	}

	// Phase B
	for _, r := range roles {
		if findEntry(res.entries, r.Name) != nil {
			continue
		}
		if err := adapter.Restore(ctx, r.Name, nil); err != nil {
			return fmt.Errorf("restore %s (defaults): %w", r.Name, err)
		}
		defaultHash := sha256Hex(adapter.Defaults(r.Name))
		agent.SeedChainSnapshot(r.Name, defaultHash, "")
		logger.Logf("iData entry %q absent on chain — Restored to defaults; will appear on chain when disk diverges", r.Name)
	}

	// Phase C
	for i := range res.entries {
		role := res.entries[i].Role
		if declared[role] {
			continue
		}
		if err := adapter.HandleLegacy(ctx, role, res.entries[i].Plaintext); err != nil {
			return fmt.Errorf("HandleLegacy %s: %w", role, err)
		}
	}

	// Build the uploader. The watcher tick handler reuses this single
	// instance to call upload.Apply each cycle.
	upload, err := uploader.New(adapter, agent, res.client, res.agentID,
		agentSealPriv, cfg.ChainRPC, cfg.FallbackIndexer)
	if err != nil {
		return fmt.Errorf("init uploader: %w", err)
	}

	// Phase 1 seed: capture post-Restore + post-HandleLegacy disk state
	// into currentSnapshot so /hello can report non-empty dataHashes
	// immediately after mgr.Start arms phase=Running. chainSnapshot is
	// untouched here — Phase A/B already seeded it with chain truth.
	logger.Logf("--- iData seed phase 1: post-Restore (pre-Start) ---")
	if err := seedCurrentSnapshots(ctx, adapter, agent); err != nil {
		return err
	}

	// Derive agentSeal address from priv so the framework adapter can surface
	// it to the agent (via AGENT_SEAL env var + TOOLS.md identity section).
	agentSealAddr := ""
	if pk, err := ethcrypto.ToECDSA(agentSealPriv); err == nil {
		agentSealAddr = ethcrypto.PubkeyToAddress(pk.PublicKey).Hex()
	}

	mgr := manager.New(adapter, agent, manager.Config{
		OnFailed: onFailed,
	})
	if err := mgr.Start(context.Background(), manager.StartParams{
		Runtime: framework.RuntimeContext{
			APIKey:       apiKey,
			PublicURL:    publicURL,
			SealSignSock: sealSignSockPath,
			AgentSeal:    agentSealAddr,
		},
		AgentSealPriv: agentSealPriv,
		SealID:        sealID,
		Owner:         res.owner,
	}); err != nil {
		return err
	}

	// Once openclaw has spawned, give it a few seconds to apply its own
	// defaults to whatever sections we didn't pre-populate (e.g. memory
	// engine, session config, plugins on a fresh install). Then re-seed:
	// the post-settle disk state is the baseline the watcher compares
	// against so openclaw's natural defaults aren't reported as drift.
	//
	// During the gap between mgr.Start returning and re-seeding, /hello
	// continues to serve the pre-seed values. Slightly stale but valid.
	logger.Logf("--- iData seed phase 2: waiting %s for openclaw to settle ---", openclawSettleDelay)
	time.Sleep(openclawSettleDelay)
	logger.Logf("--- iData seed phase 2: post-settle baseline capture ---")
	if err := seedCurrentSnapshots(ctx, adapter, agent); err != nil {
		return fmt.Errorf("re-seed after settle: %w", err)
	}
	logger.Logf("OK   baseline captured: %d roles total", len(roles))

	// Start the iData watcher. OnDrift fires whenever a tick discovers any
	// role whose disk hash diverges from chainSnapshot (current != chain).
	// The handler routes framework drift to ReconcileFramework + Reload,
	// then asks the uploader to push the entire post-reconcile state in
	// one wholesale chain.Update via upload.Apply.
	watchCtx := context.Background()
	go watcher.New(adapter, agent, watcher.Config{
		OnDrift: func(plaintexts map[string][]byte, drifted []string) {
			handleDrift(watchCtx, plaintexts, drifted, adapter, agent, mgr, upload,
				cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID)
		},
	}).Run(watchCtx)

	// Heartbeat: report.Status("running") on a slow ticker so the attestor
	// can tell a healthy sandbox from one whose process is alive but stuck.
	// 5 min keeps signed-tx volume low; first beat fires immediately after
	// the initial "running" report from runMainPipeline so the cadence is
	// regular regardless of when this goroutine starts.
	go runHeartbeat(watchCtx, cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID)

	return nil
}

// runHeartbeat re-reports the current runtime status every
// heartbeatInterval. Stops when ctx is cancelled. Failures inside
// report.Status are already logged by that package, so we don't
// decorate them here.
//
// Previously this hard-coded "running", which silently overwrote any
// "error" state handleDrift had reported. It now reads currentStatus
// so a heartbeat keeps confirming the *actual* level (running,
// warning, or error) and never clobbers a real failure.
const heartbeatInterval = 5 * time.Minute

func runHeartbeat(ctx context.Context, attestorURL string, agentSealPriv []byte, sealID string) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			level, msg := currentStatus.Get()
			report.Status(attestorURL, agentSealPriv, sealID, level, msg)
		}
	}
}

// handleDrift is the watcher's per-tick callback. Fires only on ticks
// where at least one role's disk hash differs from chainSnapshot.
//
// Two-step:
//
//  1. If framework drifted, reconcile to whitelistMax (npm install +
//     in-memory binding bump) and reload the manager so the running
//     process actually uses the new binary. Then re-read framework's
//     plaintext so upload.Apply sees the post-reconcile version, not
//     the pre-reconcile one we captured at tick start.
//
//  2. Call upload.Apply with the (possibly framework-refreshed)
//     plaintexts map. Apply constructs newDatas wholesale from declared-
//     role disk content + reused chain entries, drops anything outside
//     adapter.Roles(), submits one chain.Update tx. On failure: the
//     next watcher tick re-detects divergence (chainSnapshot stays
//     stale, currentSnapshot still differs) and Apply re-runs naturally.
//
// All errors are logged. Error classification follows severityOf:
//   - "warning" (owner-recoverable, e.g. insufficient funds): reported
//     to the attestor immediately on first occurrence so the UI can
//     surface the owner-action prompt without delay; the failure
//     counter is NOT advanced (it's not a system failure).
//   - "error" (genuine system failure): reported after failureEscalateAt
//     consecutive Apply failures so transient blips don't false-alarm.
const failureEscalateAt = 5

var consecutiveApplyFailures int

func handleDrift(
	ctx context.Context,
	plaintexts map[string][]byte,
	drifted []string,
	adapter *openclaw.Adapter,
	agent *state.Agent,
	mgr *manager.Manager,
	upload *uploader.Uploader,
	attestorURL string,
	agentSealPriv []byte,
	sealID string,
) {
	defer func() {
		if r := recover(); r != nil {
			logger.Logf("drift: handleDrift PANIC: %v", r)
		}
	}()

	for _, dim := range drifted {
		if dim != "framework" {
			continue
		}
		// framework drift = a different openclaw binary version landed on
		// disk. openclaw can't swap itself out, so sealed npm-installs
		// whitelistMax + reloads. Then refresh plaintexts["framework"] so
		// Apply pushes the post-reconcile version.
		if err := adapter.ReconcileFramework(ctx); err != nil {
			logger.Logf("drift: ReconcileFramework: %v", err)
			return
		}
		if err := mgr.Reload(ctx); err != nil {
			logger.Logf("drift: manager.Reload: %v", err)
			return
		}
		logger.Logf("drift: framework reconciled + reloaded")
		newFW, err := adapter.EvolutionFor(ctx, "framework")
		if err == nil {
			plaintexts["framework"] = newFW
			agent.UpdateCurrentSnapshot("framework", sha256Hex(newFW))
		}
	}

	// No top-level Apply timeout — dataplane.Upload enforces a per-blob
	// 90s deadline so a hung CLI invocation is still bounded, but Apply
	// itself runs as long as needed. Capping Apply at 2 min used to kill
	// the last entry whenever a manifest had many blobs (10s/entry × 11
	// entries hit the budget mid-way), and a failed Apply means no
	// chain.Update, which means the next tick re-uploads everything from
	// zero — a death loop of "10 OKs + 1 kill" with no progress to chain.
	// Inheriting ctx (watchCtx) here is effectively unbounded, gated only
	// by the per-blob timeout downstream.
	if err := upload.Apply(ctx, plaintexts); err != nil {
		sev := severityOf(err)
		summary := summarizeError(err)
		logger.Logf("drift: upload.Apply: %v (severity=%s)", err, sev)

		if sev == "warning" {
			// Owner-recoverable. Don't count it toward the system-failure
			// threshold (a chronically-unfunded agent shouldn't ratchet
			// up consecutiveApplyFailures forever). Push the status
			// immediately on the first transition so the UI prompts the
			// owner without waiting for the next heartbeat.
			if prev := currentStatus.Set("warning", summary); prev != "warning" {
				report.Status(attestorURL, agentSealPriv, sealID, "warning", summary)
			}
			return
		}

		// Real system error: keep the 5-failure threshold to ride out
		// transient network / chain blips.
		consecutiveApplyFailures++
		if consecutiveApplyFailures == failureEscalateAt {
			msg := fmt.Sprintf("upload.Apply failed %d times: %s", failureEscalateAt, summary)
			currentStatus.Set("error", msg)
			report.Status(attestorURL, agentSealPriv, sealID, "error", msg)
		}
		return
	}
	consecutiveApplyFailures = 0
	// Success: if we were previously in warning / error, push a "running"
	// status now so the UI clears without waiting for the next heartbeat.
	if prev := currentStatus.Set("running", ""); prev != "running" {
		report.Status(attestorURL, agentSealPriv, sealID, "running", "")
	}
}

// openclawSettleDelay is how long bootstrap waits after mgr.Start succeeds
// before snapshotting the disk state as the watcher's drift baseline.
// openclaw may rewrite openclaw.json once on first boot to apply defaults
// to sections we didn't populate; capturing too early treats those
// auto-applied defaults as false drift on the first watcher tick.
const openclawSettleDelay = 5 * time.Second

// seedCurrentSnapshots reads disk via adapter.EvolutionFor for each
// declared role, hashes the output, and pushes it into currentSnapshot.
// chainSnapshot is untouched (it's seeded once at bootstrap by Phase A/B
// of startAgent and thereafter only advances via uploader RecordChainUpload
// after a confirmed chain.Update tx).
//
// Used by both phase 1 (pre-Start) and phase 2 (post-settle) seeding —
// they share the same "snapshot disk truth into currentSnapshot" logic.
func seedCurrentSnapshots(ctx context.Context, adapter *openclaw.Adapter, agent *state.Agent) error {
	for _, r := range adapter.Roles() {
		bytes, err := adapter.EvolutionFor(ctx, r.Name)
		if err != nil {
			if errors.Is(err, framework.ErrUnsupportedDim) {
				continue
			}
			return fmt.Errorf("EvolutionFor[%s] (seed): %w", r.Name, err)
		}
		agent.UpdateCurrentSnapshot(r.Name, sha256Hex(bytes))
	}
	return nil
}

// sha256Hex computes hex-encoded sha256 over data. Used for iData content
// hashes recorded in the snapshot pair.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
func removeFile(path string)                { _ = os.Remove(path) }

// findEntry returns the entry with the matching role, or nil if absent.
// Caller is expected to have validated presence beforehand.
func findEntry(entries []decryptedEntry, role string) *decryptedEntry {
	for i := range entries {
		if entries[i].Role == role {
			return &entries[i]
		}
	}
	return nil
}

// restoreManifestEntries fetches each child blob referenced by a manifest
// plaintext and feeds it to adapter.RestoreEntry. Used at bootstrap time
// for DirectoryManifest-shape roles whose parent iData has already been
// downloaded and decrypted by chainBootstrap; this step writes the child
// content blobs to disk.
//
// All child blobs share the parent role's data_key (manifest mode reuses
// one key across the role's blob set). Indexer URL is the one resolved
// for the parent entry — manifest child entries don't carry per-entry
// indexer overrides.
//
// Best-effort per entry: a single child failure aborts so the caller
// (bootstrap) can report a clean error rather than half-restore the role.
func restoreManifestEntries(
	ctx context.Context,
	adapter *openclaw.Adapter,
	role string,
	manifestPT []byte,
	dataKey []byte,
	indexer string,
) error {
	m, err := manifest.Unmarshal(manifestPT)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	for _, entry := range m.Entries {
		rootHex := entry.StoragePtr.RootHash
		if rootHex == "" {
			return fmt.Errorf("entry %q has empty storage_ptr.root_hash", entry.Path)
		}
		outPath := fmt.Sprintf("/tmp/idata-entry-%s.bin", sha256Hex([]byte(role+"/"+entry.Path)))
		if err := dataplane.Download(ctx, rootHex, indexer, outPath); err != nil {
			return fmt.Errorf("download entry %q: %w", entry.Path, err)
		}
		ct, err := readFile(outPath)
		removeFile(outPath)
		if err != nil {
			return fmt.Errorf("read entry %q ciphertext: %w", entry.Path, err)
		}
		pt, err := dataplane.Decrypt(ct, dataKey)
		if err != nil {
			return fmt.Errorf("decrypt entry %q: %w", entry.Path, err)
		}
		if err := adapter.RestoreEntry(ctx, role, entry.Path, pt); err != nil {
			return fmt.Errorf("RestoreEntry %q: %w", entry.Path, err)
		}
	}
	return nil
}
