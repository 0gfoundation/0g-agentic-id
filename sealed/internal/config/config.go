// Package config loads bootstrap inputs from environment variables and
// performs the Phase 0 certificate self-check.
//
// Env vars consumed:
//
//	SANDBOX_SEAL_KEY            (required) hex-encoded container private key, written
//	                            by the sandbox provider at sealed create
//	SANDBOX_SEAL_ATTESTATION    (required) the provider's v3 container certificate
//	                            (EIP-712, internal/provision/attestation.go)
//	SEAL_BOOT_TICKET            boot ticket, written by the attestor at create
//	API_KEY                     (optional, legacy) inference provider API key in clear
//	SEAL_SECRET_ENV             (optional) the owner's secret env (API_KEY) sealed to the
//	                            agentSeal key; opened after provisioning, wins over API_KEY
//	                            (internal/secretenv, issue #166)
//	ATTESTOR_URL                (optional) provisioning endpoint root URL (https); its TLS
//	                            key is pinned by internal/attestorhttp
//	ATTESTOR_ALLOW_UNPINNED_DEV  explicit development-only bypass ("true"); the provider
//	                            removes it, with every caller SANDBOX_* key, from each
//	                            sealed container it certifies (every container the
//	                            attestor creates)
//	CHAIN_RPC_URL               (optional) AgenticID RPC endpoint
//	AGENTIC_ID_ADDR             (optional) AgenticID contract address
//	VERIFIED_FEEDBACK_ADDR      (optional) VerifiedFeedbackRegistry proxy address — the
//	                            EIP-191 v0x00 intended validator every serve-proof is
//	                            bound to. Unset, malformed or zero ⇒ no X-Agent-Proof
//	                            is emitted (never a legacy-wrap fallback); so too when
//	                            its getIdentityRegistry() is not AGENTIC_ID_ADDR
//	                            (main.anchorValidator, checked once the chain is dialled)
//	INDEXER_URL                 (optional) 0g-storage indexer fallback URL
//	AGENT_FRAMEWORK             (optional) adapter-name fallback for chains without a
//	                            framework binding (local dev); the binding is authoritative
//	SANDBOX_PROXY_DOMAIN,       (optional) compose the public URL (composePublicURL)
//	DAYTONA_SANDBOX_ID
//
// CHAIN_RPC_URL and INDEXER_URL are public and must not embed credentials
// (an API token in the URL's userinfo, path or query). sealed prints both in
// its boot log, which the proxy serves without authentication at /log and
// /log.html. INDEXER_URL is also recorded in each uploaded entry's on-chain
// dataDescription, and downloads pass it (the indexer recorded on chain, or
// this fallback) to the 0g-storage-client CLI as a command-line argument,
// which every process in the container can read through /proc/<pid>/cmdline.
// The attestor forwards them from ATTESTOR_CHAIN_RPC (which it also serves
// in GET /config) and ATTESTOR_STORAGE_INDEXER (which it also records on
// chain at mint).
//
// After provisioning succeeds, SEAL_BOOT_TICKET / SANDBOX_SEAL_KEY /
// SANDBOX_SEAL_ATTESTATION / API_KEY / SEAL_SECRET_ENV MUST be cleared from
// the environment to deny a malicious or prompt-injected agent the ability
// to read them via /proc/self/environ or shell helpers — see
// ScrubProvisioningSecrets.
package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/attestorhttp"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/provision"
	"seal-verify/internal/report"
)

// Bootstrap holds all parsed and validated startup inputs.
type Bootstrap struct {
	// Phase 0 outputs (always populated)
	SealKeyBytes []byte
	Attestation  provision.Attestation
	// Certificate is SANDBOX_SEAL_ATTESTATION as the provider wrote it; the
	// first /provision forwards it verbatim. It is public.
	Certificate json.RawMessage
	// ProviderSigner is the key that signed the certificate. Phase 0 does
	// not pin it: the attestor decides at first /provision whether it is a
	// provider it trusts. It anchors the attestor TLS statement.
	ProviderSigner common.Address

	// Optional pipeline knobs
	APIKey              string
	InferenceCredential *inference.ProviderCredential
	StatusBinding       *report.Binding
	BootTicket          string
	AttestorURL         string
	ChainRPC            string
	ContractAddr        string
	FallbackIndexer     string

	// VerifiedFeedbackAddr is the VerifiedFeedbackRegistry proxy address
	// (VERIFIED_FEEDBACK_ADDR, injected by the attestor worker next to
	// AGENTIC_ID_ADDR), checksummed — or "" when unset, malformed or the
	// zero address, in which case the proxy signs no serve-proofs. See
	// verifiedFeedbackAddr. main.anchorValidator also resets it to "" when
	// the registry is not anchored to AGENTIC_ID_ADDR on chain.
	VerifiedFeedbackAddr string

	// SecretEnv is the raw SEAL_SECRET_ENV value: ciphertext only. It can
	// be opened only after Phase 1 (it is sealed to agentSeal_priv) and is
	// bound to the on-chain owner, so main opens it after Phase 2 and
	// overwrites APIKey with the result (internal/secretenv).
	SecretEnv string

	// Framework is the raw AGENT_FRAMEWORK env value (may be empty). The
	// authoritative adapter selector is the on-chain framework binding
	// (main.resolveAdapter); this env is only the fallback for chains
	// without a binding — local dev, pre-binding deployments. attestor
	// does NOT inject it.
	Framework string

	// PublicURL is the externally-reachable URL prefix for this sandbox,
	// composed from DAYTONA_SANDBOX_ID + SANDBOX_PROXY_DOMAIN. Empty when
	// SANDBOX_PROXY_DOMAIN is unset (e.g. local dev outside the sandbox
	// proxy infrastructure). See ARCHITECTURE.zh.md §8
	// (AGENT_PUBLIC_URL 怎么暴露给 agent).
	PublicURL string
}

// Load reads env vars and runs the certificate self-check (Phase 0). Returns
// an error if SANDBOX_SEAL_KEY / SANDBOX_SEAL_ATTESTATION are missing, the
// certificate is not a well-formed v3 certificate, or it certifies a key
// other than SANDBOX_SEAL_KEY.
func Load() (*Bootstrap, error) {
	sealKey := os.Getenv("SANDBOX_SEAL_KEY")
	attestRaw := os.Getenv("SANDBOX_SEAL_ATTESTATION")
	if sealKey == "" {
		return nil, fmt.Errorf("SANDBOX_SEAL_KEY not set")
	}
	if attestRaw == "" {
		return nil, fmt.Errorf("SANDBOX_SEAL_ATTESTATION not set")
	}

	a, err := provision.ParseAttestation([]byte(attestRaw))
	if err != nil {
		return nil, fmt.Errorf("SANDBOX_SEAL_ATTESTATION: %w", err)
	}
	// Never echo the key, or any part of it, into an error: /log is public.
	keyBytes, err := hex.DecodeString(strings.TrimPrefix(sealKey, "0x"))
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("SANDBOX_SEAL_KEY must be 32 bytes of hex")
	}

	signer, err := verifyAttestation(keyBytes, a)
	if err != nil {
		return nil, err
	}
	// ParseAttestation accepted exactly one JSON value, so this cannot fail;
	// the compact form is what the first /provision forwards.
	var certificate bytes.Buffer
	if err := json.Compact(&certificate, []byte(attestRaw)); err != nil {
		return nil, fmt.Errorf("SANDBOX_SEAL_ATTESTATION: %w", err)
	}

	return &Bootstrap{
		SealKeyBytes:         keyBytes,
		BootTicket:           os.Getenv("SEAL_BOOT_TICKET"),
		Attestation:          a,
		Certificate:          json.RawMessage(certificate.Bytes()),
		ProviderSigner:       signer,
		APIKey:               os.Getenv("API_KEY"),
		SecretEnv:            os.Getenv("SEAL_SECRET_ENV"),
		AttestorURL:          os.Getenv("ATTESTOR_URL"),
		ChainRPC:             os.Getenv("CHAIN_RPC_URL"),
		ContractAddr:         os.Getenv("AGENTIC_ID_ADDR"),
		VerifiedFeedbackAddr: verifiedFeedbackAddr(os.Getenv("VERIFIED_FEEDBACK_ADDR")),
		FallbackIndexer:      os.Getenv("INDEXER_URL"),
		Framework:            strings.TrimSpace(os.Getenv("AGENT_FRAMEWORK")),
		PublicURL:            composePublicURL(),
	}, nil
}

// AttestorAnchor is what the attestor TLS statement must be signed under:
// the certificate's chain and TappRegistry, and the provider that signed it.
func (b *Bootstrap) AttestorAnchor() attestorhttp.Anchor {
	return attestorhttp.Anchor{ChainID: b.Attestation.ChainID, Registry: b.Attestation.Registry(), Provider: b.ProviderSigner}
}

// verifiedFeedbackAddr validates VERIFIED_FEEDBACK_ADDR, the
// VerifiedFeedbackRegistry proxy that every serve-proof signature is bound to
// (EIP-191 version 0x00 intended validator — see proxy.serveProofDigest).
// Returns the checksummed address, or "" when the value is unset, not a hex
// address, or the zero address. "" disables serve-proofs entirely: the proxy
// takes the same no-proof path as an agent without a chain identity, and
// never falls back to the legacy personal_sign wrap the registry rejects.
//
// Logs exactly once (here, at boot) so an unusable value is visible in /log
// without a line per request. Never fatal — a missing validator costs the
// agent its proofs, not its liveness. This is a format check only: whether
// the address is a VerifiedFeedbackRegistry anchored to AGENTIC_ID_ADDR is
// checked on chain once the client has dialled (main.anchorValidator).
func verifiedFeedbackAddr(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		logger.Logf("WARN VERIFIED_FEEDBACK_ADDR unset -- serve-proofs disabled (no X-Agent-Proof)")
		return ""
	}
	if !common.IsHexAddress(v) {
		logger.Logf("WARN VERIFIED_FEEDBACK_ADDR=%q is not a hex address -- serve-proofs disabled (no X-Agent-Proof)", raw)
		return ""
	}
	addr := common.HexToAddress(v)
	if addr == (common.Address{}) {
		logger.Logf("WARN VERIFIED_FEEDBACK_ADDR is the zero address -- serve-proofs disabled (no X-Agent-Proof)")
		return ""
	}
	logger.Logf("OK   serve-proof validator (VERIFIED_FEEDBACK_ADDR) well-formed: %s (on-chain anchor checked at bootstrap)", addr.Hex())
	return addr.Hex()
}

// composePublicURL builds the externally-reachable URL prefix from the two
// pieces the sealing infra provides: SANDBOX_PROXY_DOMAIN (injected by the
// 0g-sandbox proxy at create time) and DAYTONA_SANDBOX_ID (Daytona's
// auto-injected metadata env). Returns "" when either is missing.
//
// The :8080 port suffix is hardcoded — that's the bootstrap proxy.Server's
// port, the only externally-bound listen socket and the only one carrying
// X-Agent-Proof.
//
// Scheme inference mirrors attestor/shared/agent_card::build_agent_url:
// a bare host (e.g. "art.0g.ai") yields https://…, while a host:port
// form (e.g. "sandbox.example:4000", dev/IP) stays http://…. The
// rule keeps AGENT_PUBLIC_URL canonical for TLS-fronted production
// domains so the agent doesn't hand users URLs that only "work" via an
// HTTP→HTTPS redirect.
func composePublicURL() string {
	domain := os.Getenv("SANDBOX_PROXY_DOMAIN")
	id := os.Getenv("DAYTONA_SANDBOX_ID")
	if domain == "" || id == "" {
		return ""
	}
	scheme := "https"
	if strings.Contains(domain, ":") {
		scheme = "http"
	}
	return scheme + "://8080-" + id + "." + domain
}

// verifyAttestation runs the Phase 0 check and returns the provider signer:
//
//  1. SANDBOX_SEAL_KEY derives the compressed pubkey the certificate names
//  2. the certificate's EIP-712 signature recovers a signer
//
// There is no local signer pin; the attestor checks the signer and scope
// against the provider it trusts. Logs public certificate fields only.
func verifyAttestation(keyBytes []byte, a provision.Attestation) (common.Address, error) {
	recovered, err := a.RecoverSigner()
	if err != nil {
		return common.Address{}, err
	}
	logger.Logf("--- Sealed Container Bootstrap ---")
	logger.Logf("seal_id:    %s", a.SealID)
	logger.Logf("pubkey:     %s", a.Pubkey)
	logger.Logf("image_hash: %s", a.ImageHash)
	logger.Logf("ts:         %d", a.Ts)

	priv, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("SANDBOX_SEAL_KEY is not a secp256k1 private key")
	}
	derived := "0x" + hex.EncodeToString(crypto.CompressPubkey(&priv.PublicKey))
	if !strings.EqualFold(derived, a.Pubkey) {
		return common.Address{}, fmt.Errorf("keypair mismatch: derived %s, certificate %s", derived, a.Pubkey)
	}
	logger.Logf("OK   keypair match: SANDBOX_SEAL_KEY -> %s", derived)
	logger.Logf("OK   v3 container certificate signed by provider %s (chain %d, registry %s, app %q, registered_at %d)",
		recovered.Hex(), a.ChainID, a.Registry().Hex(), a.AppID, a.RegisteredAt)
	return recovered, nil
}

// ScrubProvisioningSecrets clears the env vars that contain provisioning
// secrets, AND zeroes the in-memory keyBytes slice. Call this AFTER
// provisioning succeeds and before spawning any agent process.
//
// Caveat: Linux exposes the *initial* environment on /proc/<pid>/environ,
// which os.Unsetenv doesn't rewrite. To fully purge we'd have to fork+exec
// a clean self — out of scope for v1. The defence-in-depth here pairs with
// the env whitelist applied when spawning openclaw.
func ScrubProvisioningSecrets(keyBytes []byte) {
	os.Unsetenv("SEAL_BOOT_TICKET")
	os.Unsetenv("SANDBOX_SEAL_KEY")
	os.Unsetenv("SANDBOX_SEAL_ATTESTATION")
	os.Unsetenv("API_KEY")
	os.Unsetenv("SEAL_SECRET_ENV")
	for i := range keyBytes {
		keyBytes[i] = 0
	}
}
