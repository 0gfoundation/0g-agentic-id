// Sealed container bootstrap (orchestrator).
//
//	Phase 0  attest          parse env; verify the v3 container certificate:
//	                         SANDBOX_SEAL_KEY ↔ certificate pubkey, recover the
//	                         provider signer (the anchor of the attestor TLS
//	                         statement, internal/attestorhttp)
//	Phase 1  provision       GET + POST /provision, retried with backoff up to
//	                         10 minutes after sealed starts -> ECIES-decrypt
//	                         agent_seal_priv
//	Phase 2  chain bootstrap getAgentIdBySealId + intelligentDatasOf +
//	                         loadSealedKeys + per-entry download + AES-GCM decrypt
//	Phase 3  framework       adapter.Restore each decrypted entry; adapter.Start
//	Phase 4  status report   notify attestor only on full pipeline success
//
// Long-running:
//   - HTTP server on :8080 (proxy package)
//   - manager monitors agent process exit and clears shared state
//
// sealed is PID 1, except in the 0g-harness image, where the loader
// (cmd/loader) checks it and runs it as its child; only there does sealed
// handle a stop signal (shutdown.go).
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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/attestorhttp"
	"seal-verify/internal/chain"
	"seal-verify/internal/config"
	"seal-verify/internal/credentials"
	"seal-verify/internal/credproxy"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/manager"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
	"seal-verify/internal/provision"
	"seal-verify/internal/proxy"
	"seal-verify/internal/report"
	"seal-verify/internal/scrub"
	"seal-verify/internal/secretenv"
	"seal-verify/internal/servicehost"
	"seal-verify/internal/settings"
	"seal-verify/internal/state"
	"seal-verify/internal/uploader"
	"seal-verify/internal/watcher"
)

const bootstrapTimeout = 10 * time.Minute

// sealedVersion is the git short hash injected at build time via
// -ldflags "-X main.sealedVersion=$(git rev-parse --short HEAD)".
// Empty if the binary was built without ldflags (e.g. go run / IDE).
var sealedVersion = ""

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
	// Register the adapters this build bundles (adapters.go, or
	// adapters_harnessonly.go for the 0g-harness image). Which one this
	// deployment uses is resolved after the chain bootstrap, from the
	// on-chain framework binding (resolveAdapter).
	registerAdapters()

	// agent_seal_priv lives only in this process's memory: make it
	// non-dumpable before anything else runs, so no sibling process can
	// ptrace it or read /proc/<pid>/mem even if it shares our uid. With the
	// uid split, root's home is also made root-only here — the agent may
	// traverse it to reach the framework trees handed to it, but must not
	// create, rename or replace anything directly inside it, since root runs
	// toolchains from there — and anything an earlier sealed let the agent
	// leave in it is moved out (the adapters registered above have declared
	// their own trees, which stay). Enforced rather than trusted to the base
	// image: privsep.Required (the provision gate below) refuses until that
	// has succeeded, so a boot that skips this call is never provisioned.
	// It also checks sealed's own time zone (privsep.ScrubTimeEnv) and
	// removes its CA locations (privsep.ScrubTrustEnv) before the first TLS
	// connection and before its first log line, which is what first reads
	// the time zone: nothing may log before this call.
	privsep.Harden()
	// Under the loader (cmd/loader) sealed is not PID 1, and a stop signal
	// gets a graceful stop: the agent is stopped before sealed exits
	// (shutdown.go). As PID 1 nothing changes (LEGACY(v1): images without
	// the loader).
	if os.Getpid() != 1 {
		stopSigs := make(chan os.Signal, 2)
		signal.Notify(stopSigs, syscall.SIGTERM, syscall.SIGINT)
		go handleStopSignals(stopSigs, &sealedStop, stopBudget, logger.Flush, os.Exit)
	}
	// Provisioning gives up a fixed time after this start.
	started := time.Now()

	// Shared agent state -- read by proxy, written by main + manager.
	agent := state.New()

	// Phase 0: parse env + verify the container certificate. Done BEFORE
	// starting the HTTP server because we need cfg.PublicURL to construct
	// proxy.Server. The provider that signed the certificate is the only
	// key whose statement can pin the attestor's TLS key.
	cfg, err := config.Load()
	if err != nil {
		logger.Fail("%v", err)
	}
	attestorhttp.Configure(cfg.AttestorAnchor())

	// Start the HTTP server now (after we know our public URL but before the
	// rest of bootstrap so /healthz and /log are reachable while the chain
	// scan + agent spawn are still in flight). The framework adapter is
	// late-bound (SetAdapter) once Phase 2 has read the framework binding
	// from chain; until then adapter-backed endpoints degrade to 503 /
	// empty, same as the pre-armed agent state.
	//
	// :8080  → public mux (proxy + serve-proof)
	// unix:///run/seal-sign.sock → agent-only sign endpoint. Starts even
	//   before provision completes; handlers return 503 until agent_seal_priv
	//   is loaded into state.Agent.
	sealedProxy := proxy.New(agent, cfg.PublicURL)
	// For an adapter that declares framework.SigningRules (0g-harness), what
	// the sign socket signs is recorded for the owner and it does not sign
	// AgenticID's iData writes (the watcher's); both are set up before it
	// listens.
	sealedProxy.EnableSignLog()
	sealedProxy.SetAgenticID(cfg.ContractAddr)
	sealedProxy.Listen()
	sealedProxy.ListenInternal(sealSignSockPath)
	// LEGACY(model-key): the key handed over at create/reset.
	if cfg.APIKey != "" {
		logger.Logf("API_KEY (from env): <set, %d chars>", len(cfg.APIKey))
	} else {
		logger.Logf("API_KEY (from env): <unset>")
	}
	if cfg.SecretEnv != "" {
		logger.Logf("%s (from env): <set, %d chars sealed to agentSeal; opened after provisioning>", secretenv.EnvVar, len(cfg.SecretEnv))
	}
	logger.Logf("")

	// Phase 1+2+3: provision + bootstrap from chain + start agent.
	// Each phase is best-effort; if any fails we report error to attestor
	// and continue to serve /healthz, /log so operators can inspect.
	if skip := provisionGate(cfg, privsep.Required); skip != "" {
		logger.Logf("%s", skip)
	} else {
		runMainPipeline(cfg, agent, sealedProxy, started)
	}

	logger.Logf("")
	logger.Logf("ALL DONE")
	logger.Flush()

	// Block forever -- HTTP server runs in its own goroutine.
	select {}
}

// provisionGate decides whether this boot runs the provisioning pipeline
// (runMainPipeline): "" to proceed, else the line main logs instead. The
// privsep check runs last and fails closed — agent_seal_priv is never
// fetched into a container whose framework would share sealed's uid (it
// could read the key out of this process). Nothing reaches attestor on that
// path, since /status is signed with the key this boot refuses to fetch: the
// refusal (cause + fix, from privsep.Required) is visible only in /log, and
// attestor's provision-timeout sweep fails the container stage (deployment
// phase offline) when /provision never arrives.
func provisionGate(cfg *config.Bootstrap, privsepRequired func() error) string {
	if cfg.AttestorURL == "" {
		return "ATTESTOR_URL unset -- skipping provision / bootstrap / status"
	}
	if cfg.ChainRPC == "" || cfg.ContractAddr == "" || cfg.FallbackIndexer == "" {
		return fmt.Sprintf("missing required env (CHAIN_RPC_URL=%q AGENTIC_ID_ADDR=%q INDEXER_URL=%q) -- skipping provision / bootstrap / status",
			cfg.ChainRPC, cfg.ContractAddr, cfg.FallbackIndexer)
	}
	if err := privsepRequired(); err != nil {
		return "FAIL provision refused: " + err.Error()
	}
	return ""
}

// runMainPipeline encapsulates Phases 1-4. Errors are logged and reported
// but never crash the process (main keeps the HTTP server up so /log is
// reachable even when bootstrap can't complete).
func runMainPipeline(cfg *config.Bootstrap, agent *state.Agent, sealedProxy *proxy.Server, started time.Time) {
	logger.Logf("--- Provisioning from attestor: %s ---", cfg.AttestorURL)
	prov := provision.FromAttestor(provision.Boot{
		AttestorURL:     cfg.AttestorURL,
		SealKey:         cfg.SealKeyBytes,
		Certificate:     cfg.Attestation,
		CertificateJSON: cfg.Certificate,
		Ticket:          cfg.BootTicket,
		Started:         started,
		SealedHash:      cfg.SealedHash,
	})
	agentSealPriv := prov.AgentSealPriv
	if agentSealPriv == nil {
		// A version the attestor no longer provisions (taken off the sealed
		// list) still hands over to the newest listed one.
		if prov.Layered {
			switchAfterRefusal(cfg)
		}
		var cause error = errors.New("the attestor did not provision this boot")
		if prov.Unanswered {
			cause = transient(errors.New("the attestor gave no answer within the provision window"))
		}
		failTrial(cfg, "provisioning", cause)
		return
	}
	cfg.StatusBinding = report.NewBinding(prov.StatusToken)
	// SANDBOX_SEAL_KEY is consumed; scrub before any agent process spawns.
	config.ScrubProvisioningSecrets(cfg.SealKeyBytes)

	logger.Logf("")
	logger.Logf("--- Bootstrap from AgenticID %s (rpc %s, fallback indexer %s) ---",
		cfg.ContractAddr, cfg.ChainRPC, cfg.FallbackIndexer)

	onDial := func(ctx context.Context, c *chain.Client) {
		// The HTML log pages link hex tokens to this chain's explorer (none
		// for a chain they don't know). Recorded as soon as the client has
		// dialled, so a later bootstrap failure still renders linked.
		if c.ChainID() != nil {
			sealedProxy.SetChainID(c.ChainID().String())
		}
		// Never sign for a validator that does not verify against this
		// container's AgenticID: unanchored ⇒ "" ⇒ the no-proof path.
		cfg.VerifiedFeedbackAddr = anchorValidator(ctx, c.IdentityRegistryOf, c.ContractAddr(),
			cfg.VerifiedFeedbackAddr, validatorAnchorAttempts, validatorAnchorBackoff)
	}
	res, err := chainBootstrap(cfg.ChainRPC, cfg.ContractAddr, cfg.Attestation.SealID, agentSealPriv, cfg.FallbackIndexer, onDial)
	if err != nil {
		logger.Logf("FAIL bootstrap: %v", err)
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", "bootstrap: "+err.Error(), cfg.StatusBinding)
		// The chain and storage reads are outside this sealed version.
		failTrial(cfg, "chain bootstrap", transient(err))
		return
	}

	// The owner's sealed secret env needs both agentSeal_priv (Phase 1) and
	// the on-chain owner (Phase 2), so it opens here, before any adapter
	// reads the inference key.
	applySecretEnv(cfg, agentSealPriv, res)

	// The on-chain framework binding is the authoritative adapter
	// selector — the agent's identity, not deploy config, decides which
	// framework interprets its iData. AGENT_FRAMEWORK survives only as
	// the fallback for chains without a binding (local dev, pre-binding
	// deployments).
	adapter, err := resolveAdapter(res.entries, cfg.Framework)
	if err != nil {
		logger.Logf("FAIL framework resolve: %v", err)
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", "framework resolve: "+err.Error(), cfg.StatusBinding)
		failTrial(cfg, "framework resolve", err)
		return
	}
	sealedProxy.SetAdapter(adapter)

	// The layered runtime (layered.go): when the rule picks a sealed version
	// other than this program (the owner's pick, the newest listed one once
	// this one is delisted, or the one this program runs in place of), it is
	// handed to the loader before the agent starts; when the loader does not
	// switch, the boot carries on with this version. The harness starts on
	// the package the rule picks.
	var lr *layeredRuntime
	var picks settings.Versions
	if prov.Layered {
		if doc, err := settings.Parse(prov.Settings); err == nil && doc.Versions != nil {
			picks = *doc.Versions
		}
		lr = newLayeredRuntime(cfg, res.client)
		ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
		if target, ok := lr.sealedTarget(ctx, picks.Sealed); ok && lr.switchSealed(ctx, target) {
			lr.awaitHandOver()
		}
		cancel()
	}
	if h, ok := any(adapter).(framework.LayeredRuntime); ok {
		// LEGACY(pre-1.4.0): without the layered flow, base's package.
		hash, dir := baseHarness()
		if lr != nil {
			ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
			hash, dir, err = lr.chooseHarness(ctx, picks.Harness, hash)
			cancel()
			if err != nil {
				logger.Logf("FAIL harness: %v", err)
				report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, "error", "harness: "+err.Error(), cfg.StatusBinding)
				failTrial(cfg, "harness choice", err)
				if isTransient(err) {
					exitForRetry("harness choice", err)
				}
				return
			}
		}
		h.UseHarness(hash, dir)
	}

	// Owner-gated endpoints now ask the chain on every call instead of
	// trusting the address read once here — see proxy.verifyOwnerSig for the
	// two failures that forced it (a sold agent still answering its seller,
	// and one failed lookup at boot locking the owner out for the container's
	// life). Nil client means local dev without a chain; the resolver is then
	// left unset and the bootstrap value stands.
	if res.client != nil && res.agentID != nil {
		client, agentID := res.client, res.agentID
		sealedProxy.SetLiveOwner(func(ctx context.Context) (string, error) {
			owner, err := client.OwnerOf(ctx, agentID)
			if err != nil {
				return "", err
			}
			return owner.Hex(), nil
		})
		// The container serves the owner it was started for; once the agent
		// belongs to someone else it closes for good (proxy/ownerlock.go).
		// Its status says so; after a transfer the attestor no longer takes
		// this container's reports, so this is for the container's own log.
		sealedProxy.SetBootOwner(res.owner)
		go sealedProxy.WatchOwner(context.Background(), ownerWatchInterval, func() {
			currentStatus.OwnerChanged("the agent now belongs to another owner: this container no longer serves it; reset the agent to run it")
			level, m := currentStatus.Get()
			report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, level, m, cfg.StatusBinding)
		})
	}

	// The credential proxy and store come up before the framework, so the
	// framework's first environment already points its tools at them.
	credRT, credValues, credStore := startCredentials(cfg, res, agentSealPriv, prov, sealedProxy)

	logger.Logf("")
	logger.Logf("--- Starting agent ---")
	// onFailed is invoked by the manager exactly once if the supervisor
	// exhausts restart retries. Reports an "error" status to the attestor
	// so the platform can decide whether to recreate the sandbox.
	// Reports from the supervisor and the model key paths go through one
	// sender, in order, each with the effective status when it leaves.
	statusReports := newStatusReporter(func(level, msg string) {
		report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, level, msg, cfg.StatusBinding)
	})
	onFailed := func(err error) {
		logger.Logf("FAIL supervisor: max retries exceeded: %v", err)
		currentStatus.SupervisorFailed("supervisor exhausted retries: " + err.Error())
		statusReports.Soon()
	}
	if err := startAgent(cfg, adapter, agent, res, agentSealPriv, prov.Settings, credRT, credValues, credStore, sealedProxy, onFailed, statusReports, lr); err != nil {
		logger.Logf("FAIL agent: %v", err)
		// Recorded, so a later report (a recovery, a model key retry) does
		// not read "running" past it.
		currentStatus.SupervisorFailed(err.Error())
		statusReports.Soon()
		// A version on trial goes back to the previous one, which reports;
		// or, failing for a reason outside it, starts again later.
		failTrial(cfg, "agent start", err)
		return
	}
	logger.Logf("OK   agent ready (upstream listening, agentState armed, supervisor active)")

	// "running" unless something is already wrong, e.g. a pinned
	// secret_env_not_applied warning (applySecretEnv).
	level, msg := currentStatus.Get()
	report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, level, msg, cfg.StatusBinding)
	confirmTrial(cfg)
	sealedSettled.Store(true)
	if lr != nil {
		// Versions nothing here runs any more, and what a cut-off download
		// left, go (layered.go).
		lr.prune()
	}
}

// applySecretEnv opens SEAL_SECRET_ENV (issue #166) and makes its inference
// key the one the adapters use; see secretenv.ResolveCredential for precedence
// and failure behavior. When the owner supplied a sealed key that did not
// apply, it refuses plaintext fallback and pins a "warning" status naming the reason
// class (never a value), so the attestor and owner see why the agent
// cannot call its model instead of a healthy "running". The ciphertext is
// dropped from memory either way.
//
// LEGACY(model-key): the key handed over at create/reset (internal/secretenv).
func applySecretEnv(cfg *config.Bootstrap, agentSealPriv []byte, res *chainBootstrapResult) {
	if cfg.SecretEnv == "" {
		return
	}
	var readOwner func() (string, error)
	if res.client != nil && res.agentID != nil {
		readOwner = func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			owner, err := res.client.OwnerOf(ctx, res.agentID)
			if err != nil {
				return "", err
			}
			return owner.Hex(), nil
		}
	}
	chainOwner := secretenv.LiveOwner(res.owner, readOwner, 3, 2*time.Second, logger.Logf)
	credential, issue := secretenv.ResolveCredential(cfg.APIKey, cfg.SecretEnv, agentSealPriv, chainOwner, logger.Logf)
	cfg.APIKey = credential.APIKey
	cfg.InferenceCredential = &credential
	cfg.SecretEnv = ""
	if issue != "" {
		currentStatus.Pin(issue)
	}
}

// ── framework adapter resolution ─────────────────────────────────────────────

// bindingFrameworkName extracts the `name` field from the decrypted
// on-chain framework binding. Returns "" when the framework role is
// absent or its plaintext doesn't parse (logged; the env fallback then
// applies and the selected adapter's own Restore validation still gates
// the malformed binding).
func bindingFrameworkName(entries []decryptedEntry) string {
	e := findEntry(entries, "framework")
	if e == nil {
		return ""
	}
	var fb struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(e.Plaintext, &fb); err != nil {
		logger.Logf("warn: framework binding unparseable (%v); falling back to AGENT_FRAMEWORK", err)
		return ""
	}
	return strings.TrimSpace(fb.Name)
}

// pickFrameworkName applies the selection precedence:
//
//	on-chain binding name  >  AGENT_FRAMEWORK env  >  "openclaw"
//
// The binding is authoritative because it IS the agent's identity — a
// deploy-config knob must never reinterpret minted iData under a
// different framework. The env survives only for chains without a
// binding (local dev, pre-binding deployments). Returns the chosen name
// plus a human-readable source for logs.
func pickFrameworkName(bindingName, envName string) (name, source string) {
	if bindingName != "" {
		return bindingName, "on-chain framework binding"
	}
	if envName != "" {
		return envName, "AGENT_FRAMEWORK env (no on-chain binding)"
	}
	return "openclaw", "default (no binding, no AGENT_FRAMEWORK)"
}

// resolveAdapter turns the Phase 2 outputs into a supervisable adapter.
// Fails loud on an unregistered name — a binding naming a framework this
// binary doesn't bundle means the deployment is broken, and starting an
// arbitrary other framework over the agent's iData would forge identity.
func resolveAdapter(entries []decryptedEntry, envName string) (manager.Adapter, error) {
	bindingName := bindingFrameworkName(entries)
	if bindingName != "" && envName != "" && !strings.EqualFold(bindingName, envName) {
		logger.Logf("warn: AGENT_FRAMEWORK=%q disagrees with on-chain binding %q — binding wins", envName, bindingName)
	}
	name, source := pickFrameworkName(bindingName, envName)

	fw, err := framework.Get(name)
	if err != nil {
		return nil, fmt.Errorf("framework %q (from %s): %w", name, source, err)
	}
	adapter, ok := fw.(manager.Adapter)
	if !ok {
		return nil, fmt.Errorf("framework %q does not implement MonitorExit (required for supervision)", name)
	}
	logger.Logf("framework adapter: %s (selected from %s)", adapter.Name(), source)
	return adapter, nil
}

// validatorAnchorAttempts / validatorAnchorBackoff bound the
// getIdentityRegistry() read in anchorValidator, so one transient RPC error
// does not cost the container its serve-proofs.
const (
	validatorAnchorAttempts = 3
	validatorAnchorBackoff  = 2 * time.Second
)

// anchorValidator checks that the serve-proof validator (VERIFIED_FEEDBACK_ADDR,
// already format-checked by config) is a VerifiedFeedbackRegistry whose
// getIdentityRegistry() is this container's AgenticID. It returns validator
// when anchored and "" otherwise — "" is the same no-proof path as an unset
// VERIFIED_FEEDBACK_ADDR, so the runtime never signs proofs that no
// registry bound to this AgenticID would accept (a pasted impl/beacon
// address, another environment's registry). A read error is retried
// attempts times, backoff apart; a definite mismatch is not.
func anchorValidator(ctx context.Context, read func(context.Context, common.Address) (common.Address, error),
	identity common.Address, validator string, attempts int, backoff time.Duration) string {
	if validator == "" {
		return ""
	}
	v := common.HexToAddress(validator)
	var lastErr error
attempt:
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				break attempt
			case <-time.After(backoff):
			}
		}
		got, err := read(ctx, v)
		if err != nil {
			lastErr = err
			continue
		}
		if got != identity {
			logger.Logf("WARN serve-proof validator %s is anchored to AgenticID %s, not AGENTIC_ID_ADDR %s -- serve-proofs disabled (no X-Agent-Proof)",
				v.Hex(), got.Hex(), identity.Hex())
			return ""
		}
		logger.Logf("OK   serve-proof validator %s anchored to AGENTIC_ID_ADDR %s (getIdentityRegistry)", v.Hex(), identity.Hex())
		return validator
	}
	logger.Logf("WARN serve-proof validator %s: getIdentityRegistry() unreadable (%v) -- not anchored to AGENTIC_ID_ADDR %s, serve-proofs disabled (no X-Agent-Proof)",
		v.Hex(), lastErr, identity.Hex())
	return ""
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
// any unrecoverable failure. onDial (may be nil) runs once the chain client
// has dialled, before any later step can fail.
func chainBootstrap(rpcURL, contractHex, sealIDHex string, agentSealPriv []byte, fallbackIndexer string, onDial func(context.Context, *chain.Client)) (*chainBootstrapResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	c, err := chain.Dial(ctx, rpcURL, contractHex)
	if err != nil {
		return nil, err
	}
	if onDial != nil {
		onDial(ctx, c)
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
// ciphertext (dataplane.Download stages it in a root-only scratch directory
// and removes it), ECIES-unseals the data_key and AES-GCM decrypts the body.
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

	blob, err := dataplane.Download(ctx, dataHashHex, indexer)
	if err != nil {
		logger.Logf("FAIL bootstrap%s download: %v", tag, err)
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
	adapter manager.Adapter,
	agent *state.Agent,
	res *chainBootstrapResult,
	agentSealPriv []byte,
	settingsBlob []byte,
	credRT framework.RuntimeContext,
	credValues *credproxy.Registry,
	credStore *credentials.Store,
	sealedProxy *proxy.Server,
	onFailed func(err error),
	statusReports *statusReporter,
	lr *layeredRuntime,
) error {
	apiKey := cfg.APIKey // LEGACY(model-key): the key handed over at create/reset
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

	// What the watcher hashes and the uploader commits is scrubbed of the
	// credential values sealed holds (internal/scrub). Built before Phase A,
	// which reads the disk the way the watcher does to find the agent's
	// uncommitted edits. The drift handler keeps the adapter itself: it asks
	// it for optional interfaces.
	var idata framework.Framework = adapter
	if credValues != nil {
		idata = scrub.Wrap(adapter, credValues)
	}

	// An adapter whose roles keep the agent's uncommitted edits
	// (framework.UncommittedKeeper) reads what this container last had in
	// sync with the chain (synced.go).
	keeper, _ := any(adapter).(framework.UncommittedKeeper)
	var (
		prevSynced     syncedRecord
		havePrevSynced bool
	)
	if keeper != nil {
		prevSynced, havePrevSynced = loadSynced()
	}

	// Phase A
	type restoreRole struct {
		role                            framework.RoleSpec
		entry                           *decryptedEntry
		contentHashForSeed, dataHashHex string
	}
	var restores []restoreRole
	for _, r := range roles {
		entry := findEntry(res.entries, r.Name)
		if entry == nil {
			continue
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
		// The agent changed this role after its last commit, and the chain
		// has not moved since: the disk stays, and the watcher's first tick
		// commits it.
		if keeper != nil && keeper.KeepsUncommitted(r.Name) {
			if disk := diskContentHash(ctx, idata, r.Name); keepsUncommitted(prevSynced, havePrevSynced, sealID, res.owner, r.Name, contentHashForSeed, disk) {
				logger.Logf("iData %s: keeping the agent's edits made after its last commit (disk %s, chain %s as last synced); the watcher commits them",
					r.Name, shortHex(disk), shortHex(contentHashForSeed))
				agent.SeedChainSnapshot(r.Name, contentHashForSeed, dataHashHex)
				continue
			}
		}
		restores = append(restores, restoreRole{role: r, entry: entry, contentHashForSeed: contentHashForSeed, dataHashHex: dataHashHex})
	}
	// What is restored from chain leaves the record first (synced.go).
	if keeper != nil && havePrevSynced {
		names := make([]string, len(restores))
		for i, x := range restores {
			names[i] = x.role.Name
		}
		forgetSynced(prevSynced, names)
	}
	for _, x := range restores {
		r, entry := x.role, x.entry
		if err := adapter.Restore(ctx, r.Name, entry.Plaintext); err != nil {
			return fmt.Errorf("restore %s: %w", r.Name, err)
		}
		if r.Shape == framework.DirectoryManifest && len(entry.Plaintext) > 0 {
			if err := restoreManifestEntries(ctx, adapter, r.Name, entry.Plaintext, entry.DataKey, entry.Indexer); err != nil {
				return fmt.Errorf("restore manifest entries for %s: %w", r.Name, err)
			}
		}
		agent.SeedChainSnapshot(r.Name, x.contentHashForSeed, x.dataHashHex)
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

	// ── Owner settings ──────────────────────────────────────────────────
	//
	// The document attestor handed down at /provision, or — for an agent
	// minted before the settings channel existed — whatever the adapter just
	// recovered from the legacy config role in Phase C.
	//
	// The recovery has to happen HERE, between Phase C and the watcher
	// starting. The uploader rebuilds the chain entry list from Roles() and
	// commits it wholesale, so the first tick drops the now-undeclared config
	// role; if the pin has not been read out and persisted by then it is gone,
	// and two adapters refuse to start without one.
	settingsDoc, err := settings.Parse(settingsBlob)
	if err != nil {
		return fmt.Errorf("owner settings: %w", err)
	}
	provisionedSettingsUsed := settingsDoc.Model != ""
	if settingsDoc.Model == "" {
		if seeder, ok := any(adapter).(framework.LegacySettingsSeeder); ok {
			if recovered, found := seeder.SeededSettings(); found {
				settingsDoc = recovered
				// The adapter does not say WHICH retired role it read (config role or
				// the mint persona seed) — claiming one here misled a live drill.
				logger.Logf("owner settings: recovered from a retired chain role (provider=%s model=%s)",
					recovered.Provider, recovered.Model)
				if blob, err := recovered.Marshal(); err == nil {
					report.SeedSettings(cfg.AttestorURL, agentSealPriv, sealID, blob)
				}
			}
		}
	}
	// Held behind a mutex because two goroutines reach it: the manager's
	// PreStart hook on every spawn, and an owner push arriving on the proxy.
	live := &liveSettings{doc: settingsDoc}
	// The model key: the owner's for the settings' provider from the
	// credential set, else (LEGACY(model-key)) the one handed over at
	// create/reset (modelkey.go).
	keys := &modelKeys{boot: inference.ProviderCredential{Provider: inference.ZGComputeProvider, APIKey: apiKey}}
	if credStore != nil {
		keys.store = credStore
	}
	if cfg.InferenceCredential != nil { // LEGACY(model-key)
		keys.boot = *cfg.InferenceCredential
	}
	if res.client != nil && res.client.ChainID() != nil && res.client.ChainID().IsUint64() {
		chainID := res.client.ChainID().Uint64()
		keys.loadPinned = func(ctx context.Context, c inference.ProviderCredential) (*inference.Registry, error) {
			return inference.LoadPinnedRegistry(ctx, cfg.AttestorURL, chainID, cfg.ContractAddr, c)
		}
	}
	// applied is the choice the framework was last rendered with.
	var appliedMu sync.Mutex
	var applied modelChoice
	reportStatus := statusReports.Soon
	// markInUse tells the owner which key the framework runs on, once it
	// runs: after a start, a restart or a reload, not when it renders.
	markInUse := func() {
		if credStore == nil {
			return
		}
		appliedMu.Lock()
		c := applied
		appliedMu.Unlock()
		if c.source != stoppedChoice.source {
			credStore.SetModelInUse(c.inUse())
		}
	}
	renderResolved := func(ctx context.Context, choice modelChoice, resolved settings.Resolved) error {
		if err := adapter.RenderSettings(ctx, resolved); err != nil {
			return err
		}
		live.applied(proxy.RuntimeSettingsFor(resolved, choice.credential))
		appliedMu.Lock()
		applied = choice
		appliedMu.Unlock()
		// A key renders: whatever stopped the framework over its model key
		// is over, whichever start path got here.
		changed := currentStatus.ModelKeyIssue("")
		// A key from the set: the boot's own key (secretenv) not applying no
		// longer keeps the agent from its model. Falling back to that key
		// fails to resolve, which the model key status reports instead.
		if choice.source == "credentials" && currentStatus.Pin("") {
			changed = true
		}
		if changed {
			reportStatus()
		}
		return nil
	}
	renderSettings := func(ctx context.Context, doc settings.Doc) error {
		choice := keys.choose(doc)
		resolved, err := keys.resolve(ctx, choice)
		if err != nil {
			return err
		}
		return renderResolved(ctx, choice, resolved)
	}

	if err := settingsDoc.Validate(); err != nil {
		// Loud, not silent: an agent with no usable pin will fail to start on
		// two of the four adapters, and "why is it offline" must not require
		// reading adapter internals. Where it does start (e.g. a clone whose
		// new owner has written no settings yet), it cannot answer, so it
		// reports a warning rather than a healthy "running" until a settings
		// push applies.
		logger.Logf("WARN owner settings invalid: %v", err)
		currentStatus.SettingsIssue(fmt.Sprintf("owner settings unusable (%v); write the agent's settings (provider and model)", err))
	}

	// The record of what this container has in sync with the chain starts
	// from what Phase A and B seeded, and follows every confirmed commit.
	if keeper != nil {
		synced := newSyncedStore(sealID, res.owner)
		inSync := make(map[string]string, len(roles))
		for _, r := range roles {
			inSync[r.Name] = agent.ChainEntry(r.Name).ContentHash
		}
		synced.setAll(inSync)
		agent.SetChainUploadHook(synced.set)
	}

	// Build the uploader. The watcher tick handler reuses this single
	// instance to call upload.Apply each cycle.
	upload, err := uploader.New(idata, agent, res.client, res.agentID,
		agentSealPriv, cfg.ChainRPC, cfg.FallbackIndexer)
	if err != nil {
		return fmt.Errorf("init uploader: %w", err)
	}
	if pc, ok := any(adapter).(framework.PlaintextCommitter); ok && pc.CommitsPlaintext() {
		upload.SetPlaintextCommitments(true)
	}
	// An upload under way when the agent changes owner is not committed.
	upload.SetCommitGate(func() error {
		if sealedProxy.OwnerLocked() {
			return errors.New("the agent now belongs to another owner; not committed")
		}
		return nil
	})

	// Phase 1 seed: capture post-Restore + post-HandleLegacy disk state
	// into currentSnapshot so /hello can report non-empty dataHashes
	// immediately after mgr.Start arms phase=Running. chainSnapshot is
	// untouched here — Phase A/B already seeded it with chain truth.
	logger.Logf("--- iData seed phase 1: post-Restore (pre-Start) ---")
	if err := seedCurrentSnapshots(ctx, idata, agent); err != nil {
		return err
	}

	// Derive agentSeal address from priv so the framework adapter can surface
	// it to the agent (via AGENT_SEAL env var + TOOLS.md identity section).
	agentSealAddr := ""
	if pk, err := ethcrypto.ToECDSA(agentSealPriv); err == nil {
		agentSealAddr = ethcrypto.PubkeyToAddress(pk.PublicKey).Hex()
	}

	// Chain id for the serve-proof domain (fetched once at dial). Empty here
	// only in the degenerate no-chain path, where no proof is signed anyway.
	chainIDStr := ""
	if res.client != nil && res.client.ChainID() != nil {
		chainIDStr = res.client.ChainID().String()
	}

	// Resume untrusted services only after the live owner and identity have
	// been restored. Each program has its own filesystem/process sandbox.
	if adapter.Name() == "0g-harness" || adapter.Name() == "dsh" {
		host, err := servicehost.New(privsep.StateDir+"/services", strings.ToLower(res.owner)+":"+sealID)
		if err != nil {
			logger.Logf("service hosting unavailable: %v", err)
		} else {
			sealedProxy.SetServiceHost(host)
			sealedStop.add(func(context.Context) { host.Close() })
			host.Resume()
		}
	}
	mgr := manager.New(adapter, agent, manager.Config{
		OnFailed: onFailed,
		// A confirmed start, whoever brought it up, clears an earlier
		// supervisor failure.
		OnRecovered: func() {
			markInUse()
			if currentStatus.SupervisorRecovered() {
				reportStatus()
			}
		},
	})
	// Under the layered flow every serve-proof is v2 from the first one: its
	// layers are set before the agent starts, and until the harness has
	// started nothing is signed (proxy.SetProofLayers).
	harness, isLayeredRuntime := any(adapter).(framework.LayeredRuntime)
	if isLayeredRuntime && lr != nil {
		sealedHash := cfg.SealedHash
		sealedProxy.SetProofLayers(func() (proxy.ProofLayers, bool) {
			h := harness.HarnessHash()
			if h == "" {
				return proxy.ProofLayers{}, false
			}
			url, model := harness.InferenceTarget()
			return proxy.ProofLayers{SealedHash: "0x" + sealedHash, HarnessHash: "0x" + h, InferenceURL: url, Model: model}, true
		})
	}
	startParams := manager.StartParams{
		Runtime: framework.RuntimeContext{
			APIKey:       apiKey, // LEGACY(model-key)
			PublicURL:    publicURL,
			SealSignSock: sealSignSockPath,
			AgentSeal:    agentSealAddr,

			// Chain bootstrap context (public on-chain data, not secrets).
			AgentID:      res.agentID.String(),
			Owner:        res.owner,
			ChainRPC:     cfg.ChainRPC,
			ContractAddr: cfg.ContractAddr,
			ChainID:      chainIDStr,
			AttestorURL:  cfg.AttestorURL,
			// Serve-proof validator (VerifiedFeedbackRegistry proxy); config
			// already normalized it to "" when unusable.
			VerifiedFeedbackAddr: cfg.VerifiedFeedbackAddr,

			// Sealed runtime metadata.
			SealedVersion: sealedVersion,
			// AgenticID Framework code hash = the sealed image measurement
			// the provider certified (image_hash), as the contract's bytes32.
			FrameworkHash: cfg.Attestation.FrameworkHash(),
		}.WithCredentials(credRT), // credential proxy, sockets, CredHold (startCredentials); empty when off
		AgentSealPriv: agentSealPriv,
		SealID:        sealID,
		Owner:         res.owner,

		// Re-render the owner's settings into the framework's own dialect
		// before every spawn — the first one, a reload, and a crash-restart.
		//
		// Not once at boot, and not through RuntimeContext: that struct is
		// captured at the initial Start and replayed verbatim afterwards, so
		// anything carried in it is frozen for the container's life and a
		// change applied at runtime gets silently reverted by the next
		// restart. Re-rendering also rebuilds a config file the agent may
		// have corrupted, instead of leaving it unable to start.
		//
		// Resolve runs each time too: endpoint, output budget and whether the
		// model accepts a reasoning bound come from the live router catalog,
		// and a stored copy of those goes stale and then fights the computed
		// one.
		//
		// The model key sealed held for the previous process goes first: the
		// new one holds it again only if it still needs it, so a switch to a
		// framework built-in provider or a removed key leaves nothing behind.
		PreStart: func(ctx context.Context) error {
			if credStore != nil {
				credStore.ReleaseSystem("sealed:inference")
			}
			return renderSettings(ctx, live.get())
		},
	}
	start := func() error { return mgr.Start(context.Background(), startParams) }
	if isLayeredRuntime && lr != nil {
		// A package chosen at boot that does not start gives way to the next
		// version (layered.go).
		fctx, fcancel := context.WithTimeout(context.Background(), applyTimeout)
		err = lr.startFirst(fctx, harness, start, func(ctx context.Context) { _ = adapter.Stop(ctx, 10*time.Second) })
		fcancel()
	} else {
		err = start()
	}
	if err != nil {
		return err
	}
	markInUse()

	// Confirm only the document used by the successful initial framework start,
	// before registering runtime settings mutation callbacks.
	if provisionedSettingsUsed {
		cfg.StatusBinding.AdoptSettings(settingsBlob)
	}

	// A framework that runs from a package can ask to be restarted over the
	// sign socket, and its owner over /_seal/restart (ownerrestart.go); under
	// the layered flow the owner's version picks apply (layered.go).
	if isLayeredRuntime {
		sealedProxy.SetHarnessRestart(mgr.Reload)
	}
	if lr != nil {
		lr.started(adapter, mgr, func() settings.Versions {
			if v := live.get().Versions; v != nil {
				return *v
			}
			return settings.Versions{}
		})
	}
	if isLayeredRuntime {
		// The requests used are kept on disk: the sealed a restart starts
		// refuses them too.
		sealedProxy.SetOwnerRestartRecord(framework.StatePath(ownerRestartsFile))
		sealedProxy.SetOwnerRestart(ownerRestarter(mgr, lr))
	}

	// The owner's hot path: push a document, have it take effect without
	// rebuilding the container. Registered only now because applying one
	// needs the manager.
	//
	// Order matters. The document is swapped first, then rendered, then the
	// process is restarted — and if the render fails the swap is rolled back,
	// so a document that cannot be rendered never becomes the one the next
	// crash-restart would pick up.
	var settingsApply sync.Mutex
	sealedProxy.SetSettings(live.get, func(ctx context.Context, doc settings.Doc) (bool, error) {
		settingsApply.Lock()
		defer settingsApply.Unlock()
		// Under the layered flow a push that changes only the version picks
		// restarts nothing here: the version rule switches what it must, and
		// restarts only the layer it changes (layered.go).
		if lr != nil && doc.OnlyVersionsChanged(live.get()) {
			live.set(doc)
			logger.Logf("settings: version picks applied (no framework restart)")
			go lr.recheck()
			return false, nil
		}
		choice := keys.choose(doc)
		resolved, err := keys.resolve(ctx, choice)
		if err != nil {
			return false, err
		}
		prev := live.get()
		live.set(doc)
		if err := renderResolved(ctx, choice, resolved); err != nil {
			live.set(prev)
			return false, fmt.Errorf("render: %w", err)
		}
		if err := mgr.Reload(ctx); err != nil {
			return true, fmt.Errorf("restart: %w", err)
		}
		if agent.Phase() == state.PhaseRunning {
			currentStatus.SupervisorRecovered()
		}
		logger.Logf("settings: applied (provider=%s model=%s thinking=%s)", doc.Provider, doc.Model, doc.Thinking)
		// The owner's version picks take effect now (layered.go).
		if lr != nil {
			go lr.recheck()
		}
		// A document that applied clears a boot-time settings warning; say
		// so now rather than at the next heartbeat.
		if doc.Validate() == nil && currentStatus.SettingsIssue("") != "running" {
			if level, msg := currentStatus.Get(); level == "running" {
				go report.Status(cfg.AttestorURL, agentSealPriv, sealID, level, msg, cfg.StatusBinding)
			}
		}
		return true, nil
	})
	sealedProxy.SetRuntimeSettings(live.runtime)

	// A model key the owner pushes (cred set model) takes effect now: where
	// sealed holds the key for the framework and only the key changed, it
	// is swapped in place; otherwise the framework is rendered with it and
	// restarted, as a settings push is. A key for a provider the settings do
	// not use is only kept.
	if credStore != nil {
		pushed := modelApply{
			keys:    keys,
			current: live.get,
			applied: func() modelChoice {
				appliedMu.Lock()
				defer appliedMu.Unlock()
				return applied
			},
			setApplied: func(c modelChoice) {
				appliedMu.Lock()
				defer appliedMu.Unlock()
				applied = c
			},
			render:   renderResolved,
			swap:     func(host string, v []byte) bool { return credStore.SwapSystemValue("sealed:inference", host, v) },
			reload:   mgr.Reload,
			busy:     mgr.Busy,
			failed:   func() bool { return agent.Phase() == state.PhaseFailed },
			setInUse: credStore.SetModelInUse,
		}
		var applyModelKeys func()
		// One retry pending at a time, touched under settingsApply only: it
		// backs off while a key cannot be used (an attestor that cannot serve
		// its registry version, say); a (re)start under way is waited out
		// briefly.
		var retryTimer *time.Timer
		retry := 30 * time.Second
		again := func(d time.Duration) {
			if retryTimer != nil {
				retryTimer.Stop()
			}
			retryTimer = time.AfterFunc(d, applyModelKeys)
		}
		applyModelKeys = func() {
			settingsApply.Lock()
			defer settingsApply.Unlock()
			if sealedProxy.OwnerLocked() {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			switch outcome := pushed.apply(ctx); outcome {
			case "unchanged":
				// Whatever recovered the framework (its own restart, a
				// settings push), the next outage starts the backoff anew,
				// and a running framework clears a failed restart.
				retry = 30 * time.Second
				if agent.Phase() == state.PhaseRunning && currentStatus.SupervisorRecovered() {
					reportStatus()
				}
			case "deferred":
				again(5 * time.Second)
			case "stopped", "restart_failed":
				if outcome == "stopped" {
					logger.Logf("warn: model key: the key the settings choose cannot be used; the framework is stopped until it can (cred <agent> shows why); trying again in %s", retry)
					currentStatus.ModelKeyIssue("the agent's model key cannot be used: the framework is stopped until it can (cred <agent> shows why)")
				} else {
					logger.Logf("warn: model key: the framework did not restart (cred <agent> shows why); trying again in %s", retry)
					currentStatus.SupervisorFailed("the framework did not restart; sealed keeps trying (cred <agent> shows why)")
				}
				reportStatus()
				again(retry)
				if retry *= 2; retry > 10*time.Minute {
					retry = 10 * time.Minute
				}
			default:
				retry = 30 * time.Second
				if agent.Phase() == state.PhaseRunning && currentStatus.SupervisorRecovered() {
					reportStatus()
				}
				logger.Logf("OK   model key: applied (%s)", outcome)
			}
		}
		credStore.OnModelKeys(applyModelKeys)
		// A set loaded between the first render and now.
		go applyModelKeys()
	}

	// The agent's own lever: same validation, same render, same restart —
	// but nothing is persisted, so the owner's document is what comes back
	// after a container restart. See proxy.SessionSettingsApplier for why.
	sealedProxy.SetSessionSettings(func(ctx context.Context, requested settings.Doc) error {
		settingsApply.Lock()
		defer settingsApply.Unlock()
		// Re-read inside the apply lock: an owner push between the socket's
		// read and this callback must not be undone by a thinking-only change.
		doc := live.get()
		doc.Thinking = requested.Thinking
		choice := keys.choose(doc)
		resolved, err := keys.resolve(ctx, choice)
		if err != nil {
			return err
		}
		prev := live.get()
		appliedMu.Lock()
		running := applied
		appliedMu.Unlock()
		live.set(doc)
		if err := renderResolved(ctx, choice, resolved); err != nil {
			// Re-render the owner's document so a rejected agent attempt
			// cannot leave the framework configured from a half-applied one.
			live.set(prev)
			_ = renderSettings(ctx, prev)
			// Nothing restarted: the process still runs on what it ran on,
			// so a model key change waiting behind this is still applied.
			appliedMu.Lock()
			applied = running
			appliedMu.Unlock()
			return fmt.Errorf("render: %w", err)
		}
		err = mgr.Reload(ctx)
		if err == nil && agent.Phase() == state.PhaseRunning {
			currentStatus.SupervisorRecovered()
		}
		return err
	})

	// /clear (CONVERSATION.md invariant 5): wipe the framework's persisted
	// conversation, then restart so the fresh one is presented NOW. Only wired
	// for adapters that hold a conversation; the proxy answers 501 otherwise.
	// Stateful responses door: adapters whose framework holds the
	// conversation server-side bind each upstream call to it and follow
	// rotation (hermes: X-Hermes-Session-Id, rotated at compaction).
	if cs, ok := adapter.(framework.ConversationSession); ok {
		sealedProxy.SetConversationSession(cs.ConversationHeaders, cs.ObserveConversation)
	}
	// Frameworks whose stateful turns must not carry the client's history: the
	// door sends the prior turns the adapter returns — none for openclaw,
	// whose gateway replays its own session — then only the current turn.
	if ch, ok := adapter.(framework.ConversationHistory); ok {
		sealedProxy.SetConversationHistory(func(ctx context.Context) ([]proxy.ConversationTurn, error) {
			turns, err := ch.ConversationHistory(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]proxy.ConversationTurn, len(turns))
			for i, t := range turns {
				out[i] = proxy.ConversationTurn{Role: t.Role, Text: t.Text}
			}
			return out, nil
		})
	}

	if clearer, ok := adapter.(framework.SessionClearer); ok {
		sealedProxy.SetClear(func(ctx context.Context) error {
			if err := clearer.ClearSession(ctx); err != nil {
				return err
			}
			if err := mgr.Reload(ctx); err != nil {
				return fmt.Errorf("restart: %w", err)
			}
			if agent.Phase() == state.PhaseRunning {
				currentStatus.SupervisorRecovered()
			}
			logger.Logf("conversation cleared by owner; framework restarted fresh")
			return nil
		})
	}

	// Compaction runs inside the live framework process — no restart, the
	// conversation continues from the compacted history.
	if compactor, ok := adapter.(framework.SessionCompactor); ok {
		sealedProxy.SetCompact(compactor.CompactSession)
	}

	// Once the agent has spawned, give the framework a moment to apply its
	// own defaults to whatever sections we didn't pre-populate (e.g. memory
	// engine, session config, plugins on a fresh install). Then re-seed:
	// the post-settle disk state is the baseline the watcher compares
	// against so the framework's natural defaults aren't reported as drift.
	// Adapters whose framework rewrites config on first boot declare their
	// own delay via framework.SettleDelayer.
	//
	// During the gap between mgr.Start returning and re-seeding, /hello
	// continues to serve the pre-seed values. Slightly stale but valid.
	settle := defaultSettleDelay
	if sd, ok := any(adapter).(framework.SettleDelayer); ok {
		settle = sd.SettleDelay()
	}
	logger.Logf("--- iData seed phase 2: waiting %s for %s to settle ---", settle, adapter.Name())
	time.Sleep(settle)
	logger.Logf("--- iData seed phase 2: post-settle baseline capture ---")
	if err := seedCurrentSnapshots(ctx, idata, agent); err != nil {
		return fmt.Errorf("re-seed after settle: %w", err)
	}
	logger.Logf("OK   baseline captured: %d roles total", len(roles))

	// Start the iData watcher. OnDrift fires whenever a tick discovers any
	// role whose disk hash diverges from chainSnapshot (current != chain).
	// The handler routes framework drift to ReconcileFramework + Reload,
	// then asks the uploader to push the entire post-reconcile state in
	// one wholesale chain.Update via upload.Apply.
	watchCtx := context.Background()
	w := watcher.New(idata, agent, watcher.Config{
		OnDrift: func(plaintexts map[string][]byte, drifted []string) {
			// An agent that belongs to another owner now is not written to
			// from this container.
			if sealedProxy.OwnerLocked() {
				return
			}
			handleDrift(watchCtx, plaintexts, drifted, adapter, agent, mgr, upload,
				cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, cfg.StatusBinding)
		},
	})
	go w.Run(watchCtx)
	// A stop (shutdown.go) stops the agent before sealed exits. What the
	// agent changed since its last commit stays on disk for the next boot
	// (synced.go).
	sealedStop.add(func(ctx context.Context) {
		stopAgent(ctx, w, mgr)
	})

	// Heartbeat: report.Status("running") on a slow ticker so the attestor
	// can tell a healthy sandbox from one whose process is alive but stuck.
	// 5 min keeps signed-tx volume low; first beat fires immediately after
	// the initial "running" report from runMainPipeline so the cadence is
	// regular regardless of when this goroutine starts.
	// Under the layered flow every beat also applies the version rule, so a
	// delisted version is left within one interval (layered.go).
	var onBeat func()
	if lr != nil {
		onBeat = lr.recheck
	}
	go runHeartbeat(watchCtx, cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, cfg.StatusBinding, onBeat)

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

func runHeartbeat(ctx context.Context, attestorURL string, agentSealPriv []byte, sealID string, binding *report.Binding, onBeat func()) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			level, msg := currentStatus.Get()
			report.Status(attestorURL, agentSealPriv, sealID, level, msg, binding)
			if onBeat != nil {
				go onBeat()
			}
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
	adapter manager.Adapter,
	agent *state.Agent,
	mgr *manager.Manager,
	upload *uploader.Uploader,
	attestorURL string,
	agentSealPriv []byte,
	sealID string,
	binding *report.Binding,
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
		// framework drift = a different framework binary version landed on
		// disk. The running process can't swap itself out, so adapters that
		// support it reconcile back to their allowlisted target version,
		// then we reload so the new binary actually takes effect. Then
		// refresh plaintexts["framework"] so Apply pushes the
		// post-reconcile version.
		//
		// Adapters without framework.VersionReconciler can't pull the
		// version back; the observed drift is committed on chain as-is,
		// which keeps the audit trail honest even when enforcement isn't
		// possible.
		rec, canReconcile := any(adapter).(framework.VersionReconciler)
		if !canReconcile {
			logger.Logf("drift: adapter %s has no version reconciler; committing framework drift as-is", adapter.Name())
			break
		}
		if err := rec.ReconcileFramework(ctx); err != nil {
			logger.Logf("drift: ReconcileFramework: %v", err)
			return
		}
		// Reload only if reconcile actually changed the installed framework.
		// Framework drift is often chain-side only: version-less bindings
		// (attestor default) make "chain has no version, disk runs
		// whitelistMax" the NORMAL first-boot state, and until the first
		// chain.Update lands, every tick re-detects it. Reloading on a
		// no-op reconcile restarted the agent process every 30s for as
		// long as the storage upload kept failing (observed live: an
		// unfunded agentSeal wallet turned that into a restart loop).
		newFW, err := adapter.EvolutionFor(ctx, "framework")
		if err == nil && sha256Hex(newFW) == sha256Hex(plaintexts["framework"]) {
			logger.Logf("drift: framework reconcile was a no-op (chain-side drift only); skipping reload")
			break
		}
		if err := mgr.Reload(ctx); err != nil {
			logger.Logf("drift: manager.Reload: %v", err)
			return
		}
		if agent.Phase() == state.PhaseRunning {
			currentStatus.SupervisorRecovered()
		}
		logger.Logf("drift: framework reconciled + reloaded")
		if err == nil {
			plaintexts["framework"] = newFW
			agent.UpdateCurrentSnapshot("framework", sha256Hex(newFW))
		}
	}

	// No top-level Apply timeout — dataplane.Upload enforces a per-blob
	// 90s deadline so a hung upload is still bounded, but Apply
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
				level, msg := currentStatus.Get()
				report.Status(attestorURL, agentSealPriv, sealID, level, msg, binding)
			}
			return
		}

		// Real system error: keep the 5-failure threshold to ride out
		// transient network / chain blips.
		consecutiveApplyFailures++
		if consecutiveApplyFailures == failureEscalateAt {
			msg := fmt.Sprintf("upload.Apply failed %d times: %s", failureEscalateAt, summary)
			currentStatus.Set("error", msg)
			report.Status(attestorURL, agentSealPriv, sealID, "error", msg, binding)
		}
		return
	}
	consecutiveApplyFailures = 0
	// Success: if we were previously in warning / error, push a "running"
	// status now so the UI clears without waiting for the next heartbeat.
	// A pinned warning (applySecretEnv) survives this: report the effective
	// status, not a literal "running".
	if prev := currentStatus.Set("running", ""); prev != "running" {
		level, msg := currentStatus.Get()
		report.Status(attestorURL, agentSealPriv, sealID, level, msg, binding)
	}
}

// defaultSettleDelay is how long bootstrap waits after mgr.Start succeeds
// before snapshotting the disk state as the watcher's drift baseline, for
// adapters that don't declare their own via framework.SettleDelayer.
// Frameworks may rewrite their config once on first boot to apply defaults
// to sections we didn't populate; capturing too early treats those
// auto-applied defaults as false drift on the first watcher tick.
const defaultSettleDelay = 5 * time.Second

// seedCurrentSnapshots reads disk via adapter.EvolutionFor for each
// declared role, hashes the output, and pushes it into currentSnapshot.
// chainSnapshot is untouched (it's seeded once at bootstrap by Phase A/B
// of startAgent and thereafter only advances via uploader RecordChainUpload
// after a confirmed chain.Update tx).
//
// Used by both phase 1 (pre-Start) and phase 2 (post-settle) seeding —
// they share the same "snapshot disk truth into currentSnapshot" logic.
func seedCurrentSnapshots(ctx context.Context, adapter framework.Framework, agent *state.Agent) error {
	for _, r := range adapter.Roles() {
		bytes, err := adapter.EvolutionFor(ctx, r.Name)
		if err != nil {
			if errors.Is(err, framework.ErrUnsupportedDim) {
				continue
			}
			if errors.Is(err, privsep.ErrTooLarge) {
				// A leaf role's file over its size limit (which an older
				// sealed could commit, and restore now writes back): the
				// role keeps its committed version, as the watcher does,
				// rather than failing the boot. (A manifest role holds such
				// an entry by itself, manifest.Held, and does not fail.)
				logger.Logf("seed: EvolutionFor[%s]: %v; the role keeps its committed version until the file is back under the limit", r.Name, err)
				agent.UpdateCurrentSnapshot(r.Name, agent.ChainEntry(r.Name).ContentHash)
				continue
			}
			if errors.Is(err, privsep.ErrBusy) {
				// A tracked file whose owner — an agent process, by the
				// time phase 2 runs — holds a lease on it: the read is
				// refused for now, which says nothing about the content.
				// The role keeps its committed version, as the watcher
				// keeps it for a pass, and the watcher reads it again on
				// its next tick; failing here would take the agent offline
				// over a lease its own process holds.
				logger.Logf("seed: EvolutionFor[%s]: %v; the role keeps its committed version until the file can be read", r.Name, err)
				agent.UpdateCurrentSnapshot(r.Name, agent.ChainEntry(r.Name).ContentHash)
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
	adapter framework.Framework,
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
		ct, err := dataplane.Download(ctx, rootHex, indexer)
		if err != nil {
			// Storage is outside this sealed version (layered.go).
			return transient(fmt.Errorf("download entry %q: %w", entry.Path, err))
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

// liveSettings is the owner document currently in force, shared between the
// manager's PreStart hook and an owner push arriving on the proxy.
type liveSettings struct {
	mu   sync.RWMutex
	doc  settings.Doc
	view proxy.RuntimeSettings
}

func (l *liveSettings) get() settings.Doc {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.doc
}

func (l *liveSettings) set(d settings.Doc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.doc = d
}

func (l *liveSettings) applied(view proxy.RuntimeSettings) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.view = view
}

func (l *liveSettings) runtime() proxy.RuntimeSettings {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.view
}
