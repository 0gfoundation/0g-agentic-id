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

// decryptedEntry mirrors the legacy bootstrap.go decryptedEntry, used to
// pass around an iData entry's plaintext + role tag while we still operate
// on a single role="config" entry. Phase 4 will move all dispatch into the
// framework adapter.
type decryptedEntry struct {
	Role      string
	DataHash  [32]byte
	Plaintext []byte
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
	sealedProxy := proxy.New(agent, openclawAdapter, cfg.PublicURL)
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
	return decryptedEntry{Role: desc.Role, DataHash: d.DataHash, Plaintext: plaintext}, true
}

// startAgent dispatches each decrypted entry to the framework adapter, seeds
// per-dim iData snapshots into shared state, then hands off to the manager
// which spawns the process and supervises it.
//
// Currently each iData entry is routed by its role string. Long-term this
// becomes label-based dispatch (EVOLUTION_DESIGN section 4) but the
// snapshot-seeding pattern is already correct: every entry contributes one
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

	// Required dims: framework + persona. Other adapter dims (knowledge /
	// skills / ops) are optional -- a default mint may produce only the
	// minimum and rely on adapter defaults for the rest. When the agent
	// later self-modifies an absent dim (e.g. writes its first MEMORY.md),
	// the uploader detects drift on a dim with empty chain dataHash and
	// adds a new entry via the contract's sealUpdate ADD path.
	//
	// Duplicates are a hard fail per EVOLUTION_DESIGN §8.1.
	required := []string{"framework", "persona"}
	allDims := append([]string{"framework"}, adapter.Dimensions()...)

	dataHashByDim := map[string]string{}
	for i := range res.entries {
		role := res.entries[i].Role
		if _, dup := dataHashByDim[role]; dup {
			return fmt.Errorf("duplicate iData entry for role=%q", role)
		}
		dataHashByDim[role] = "0x" + hex.EncodeToString(res.entries[i].DataHash[:])
	}
	for _, r := range required {
		if _, ok := dataHashByDim[r]; !ok {
			return fmt.Errorf("missing required iData entry: role=%q", r)
		}
	}
	for _, dim := range allDims {
		if _, ok := dataHashByDim[dim]; !ok {
			logger.Logf("iData entry %q absent on chain -- using adapter defaults; "+
				"uploader will add this dim on first drift", dim)
		}
	}

	// Restore framework first so its schema_version check fails fast.
	frameworkEntry := findEntry(res.entries, "framework")
	if err := adapter.Restore(ctx, "framework", frameworkEntry.Plaintext); err != nil {
		return fmt.Errorf("restore framework: %w", err)
	}

	// Restore EVERY adapter dim, even when absent on chain (plaintext=nil).
	// Adapters use zero-value config for nil and still write their disk
	// artifacts — empty workspace markdown / empty openclaw.json sections.
	// This pre-empts openclaw's `writeFileIfMissing` template auto-install
	// (~8KB AGENTS.md / 650B USER.md per absent dim) which would otherwise
	// fire on first agent activity and drift the dim falsely.
	//
	// Dim order is irrelevant per EVOLUTION_DESIGN §7.2 (Restore must commute).
	for _, dim := range adapter.Dimensions() {
		var pt []byte
		if e := findEntry(res.entries, dim); e != nil {
			pt = e.Plaintext
		}
		if err := adapter.Restore(ctx, dim, pt); err != nil {
			return fmt.Errorf("restore %s: %w", dim, err)
		}
	}

	// Pre-seed every dim from post-Restore disk state. This gives /hello
	// non-empty dataHashes immediately after mgr.Start arms phase=Running,
	// even though openclaw hasn't finished its own initialisation yet.
	logger.Logf("--- iData seed phase 1: post-Restore (pre-Start) ---")
	if err := seedAllDims(ctx, adapter, agent, allDims, dataHashByDim); err != nil {
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
	if err := seedAllDims(ctx, adapter, agent, allDims, dataHashByDim); err != nil {
		return fmt.Errorf("re-seed after settle: %w", err)
	}
	logger.Logf("OK   baseline captured: %d dims total, %d on chain, %d absent (will add on drift)",
		len(allDims), len(dataHashByDim), len(allDims)-len(dataHashByDim))

	// Build the uploader once after baseline is captured. It owns the
	// chain.Client returned by chainBootstrap (no Close — process lives
	// forever). Each drift-handler invocation reuses it; per-Push the
	// uploader dials a separate 0g-storage web3 instance because the SDK
	// insists on its own.
	upload, err := uploader.New(adapter, agent, res.client, res.agentID,
		agentSealPriv, cfg.ChainRPC, cfg.FallbackIndexer)
	if err != nil {
		return fmt.Errorf("init uploader: %w", err)
	}

	// Start the iData watcher inside startAgent so the OnDimDrift callback
	// closes over the real manager (for Reload), adapter (for
	// ReconcileFramework), and uploader.
	watchCtx := context.Background()
	go watcher.New(adapter, agent, watcher.Config{
		OnDimDrift: func(dim string) {
			handleDimDrift(watchCtx, dim, adapter, mgr, upload, cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID)
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

// runHeartbeat re-reports "running" status every heartbeatInterval. Stops
// when ctx is cancelled. Failures inside report.Status are already logged
// by that package, so we don't decorate them here.
const heartbeatInterval = 5 * time.Minute

func runHeartbeat(ctx context.Context, attestorURL string, agentSealPriv []byte, sealID string) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report.Status(attestorURL, agentSealPriv, sealID, "running", "")
		}
	}
}

// handleDimDrift is the bootstrap-side reaction to a watcher-detected
// drift event. Currently it covers two paths:
//
//   - framework drift: reconcile to the validated whitelist max version
//     (npm-install if needed, update in-memory pin), then reload the
//     manager so the running process actually uses the new binary.
//
//   - any other drift: log a "[mock uploader]" note. The real uploader
//     (encrypt + 0g-storage upload + chain.update + state.RecordChainUpload)
//     replaces this stub once built; until then iData on chain stays at
//     whatever it was at mint time.
//
// Errors are logged but never crash the watcher — drift handling is
// best-effort (next tick will retry if the condition persists). After
// pushFailureEscalateAt consecutive failures for the same dim, the
// handler reports an "error" status to the attestor so the platform can
// step in (the watcher itself keeps retrying — the report is informative).
const pushFailureEscalateAt = 5

func handleDimDrift(
	ctx context.Context,
	dim string,
	adapter *openclaw.Adapter,
	mgr *manager.Manager,
	upload *uploader.Uploader,
	attestorURL string,
	agentSealPriv []byte,
	sealID string,
) {
	// 0g-storage Go SDK has panic-prone call sites (e.g. blockchain.MustNewWeb3,
	// logrus.Fatal in some error paths). Without recover, a panic here kills
	// the whole sealed process and the operator loses /log + /healthz too.
	defer func() {
		if r := recover(); r != nil {
			logger.Logf("drift: handleDimDrift[%s] PANIC: %v", dim, r)
		}
	}()
	if dim == "framework" {
		// framework drift is a different openclaw binary version -- openclaw
		// can't swap itself out, so sealed has to npm-install and restart it.
		// Every other dim (persona/knowledge/skills/ops) is openclaw's own
		// config and is left for openclaw to hot-apply; sealed only pins
		// the new state to chain via upload.Push below.
		if err := adapter.ReconcileFramework(ctx); err != nil {
			logger.Logf("drift: ReconcileFramework: %v", err)
			return
		}
		if err := mgr.Reload(ctx); err != nil {
			logger.Logf("drift: manager.Reload: %v", err)
			return
		}
		logger.Logf("drift: framework reconciled + reloaded; will upload new pin")
	}
	// Bound the upload so a stuck SDK call cannot wedge the drift handler
	// forever (next tick fires every 30s).
	pushCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	err := upload.Push(pushCtx, dim)
	if err != nil {
		logger.Logf("drift: uploader.Push[%s]: %v", dim, err)
		// Escalate exactly at the threshold (not on every subsequent
		// failure) to avoid flooding the attestor with identical reports.
		if upload.FailureCount(dim) == pushFailureEscalateAt {
			logger.Logf("drift: uploader.Push[%s] failed %d consecutive times; reporting error",
				dim, pushFailureEscalateAt)
			report.Status(attestorURL, agentSealPriv, sealID, "error",
				fmt.Sprintf("uploader.Push[%s] failed %d times: %v", dim, pushFailureEscalateAt, err))
		}
	}
}

// openclawSettleDelay is how long bootstrap waits after mgr.Start succeeds
// before snapshotting the disk state as the watcher's drift baseline.
// openclaw may rewrite openclaw.json once on first boot to apply defaults
// to sections we didn't populate; capturing too early treats those
// auto-applied defaults as false drift on the first watcher tick.
const openclawSettleDelay = 5 * time.Second

// seedAllDims runs adapter.EvolutionFor for each dim, hashes the output,
// and seeds both chainSnapshot and currentSnapshot. dataHashByDim carries
// the on-chain storage root per dim; absent dims get "" (uploader will
// detect them by empty DataHash and add new chain entries on first drift).
func seedAllDims(
	ctx context.Context,
	adapter *openclaw.Adapter,
	agent *state.Agent,
	dims []string,
	dataHashByDim map[string]string,
) error {
	for _, dim := range dims {
		bytes, err := adapter.EvolutionFor(ctx, dim)
		if err != nil {
			if errors.Is(err, framework.ErrUnsupportedDim) {
				continue
			}
			return fmt.Errorf("EvolutionFor[%s] (seed): %w", dim, err)
		}
		agent.SeedSnapshots(dim, sha256Hex(bytes), dataHashByDim[dim])
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
