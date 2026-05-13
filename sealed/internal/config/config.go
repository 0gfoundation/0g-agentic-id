// Package config loads bootstrap inputs from environment variables and
// performs the Phase 0 attestation self-check.
//
// Env vars consumed:
//
//   SANDBOX_SEAL_KEY            (required) hex-encoded ephemeral private key
//   SANDBOX_SEAL_ATTESTATION    (required) JSON envelope from sealing layer
//   TEE_SIGNER_ADDRESS          (optional) 0x-prefixed Ethereum address; if set,
//                               the attestation signer must match exactly
//   API_KEY                     (optional) inference provider API key (anthropic/openai)
//   ATTESTOR_URL                (optional) provisioning endpoint root URL
//   CHAIN_RPC_URL               (optional) AgenticID RPC endpoint
//   AGENTIC_ID_ADDR             (optional) AgenticID contract address
//   INDEXER_URL                 (optional) 0g-storage indexer fallback URL
//
// After provisioning succeeds, SANDBOX_SEAL_KEY / SANDBOX_SEAL_ATTESTATION /
// API_KEY MUST be cleared from the environment to deny a malicious or
// prompt-injected agent the ability to read them via /proc/self/environ
// or shell helpers — see ScrubProvisioningSecrets.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/logger"
	"seal-verify/internal/provision"
)

// Bootstrap holds all parsed and validated startup inputs.
type Bootstrap struct {
	// Phase 0 outputs (always populated)
	SealKeyBytes []byte
	Attestation  provision.Attestation
	TEESigner    *common.Address // nil if not enforced

	// Optional pipeline knobs
	APIKey          string
	AttestorURL     string
	ChainRPC        string
	ContractAddr    string
	FallbackIndexer string

	// PublicURL is the externally-reachable URL prefix for this sandbox,
	// composed from DAYTONA_SANDBOX_ID + SANDBOX_PROXY_DOMAIN. Empty when
	// SANDBOX_PROXY_DOMAIN is unset (e.g. local dev outside the sandbox
	// proxy infrastructure). See EVOLUTION_DESIGN section 15.5.
	PublicURL string
}

// Load reads env vars and runs the attestation self-check (Phase 0). Returns
// an error if SANDBOX_SEAL_KEY / SANDBOX_SEAL_ATTESTATION are missing or the
// keypair-attestation signature pair fails to verify.
func Load() (*Bootstrap, error) {
	sealKey := os.Getenv("SANDBOX_SEAL_KEY")
	attestRaw := os.Getenv("SANDBOX_SEAL_ATTESTATION")
	if sealKey == "" {
		return nil, fmt.Errorf("SANDBOX_SEAL_KEY not set")
	}
	if attestRaw == "" {
		return nil, fmt.Errorf("SANDBOX_SEAL_ATTESTATION not set")
	}

	var a provision.Attestation
	if err := json.Unmarshal([]byte(attestRaw), &a); err != nil {
		return nil, fmt.Errorf("SANDBOX_SEAL_ATTESTATION not valid JSON: %w", err)
	}
	if a.SealID == "" || a.Pubkey == "" || a.ImageHash == "" || a.Signature == "" {
		return nil, fmt.Errorf("attestation missing required fields")
	}

	keyBytes, err := hex.DecodeString(strings.TrimPrefix(sealKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode SANDBOX_SEAL_KEY: %w", err)
	}

	var teeSignerPtr *common.Address
	if v := os.Getenv("TEE_SIGNER_ADDRESS"); v != "" {
		addr := common.HexToAddress(v)
		teeSignerPtr = &addr
	}

	if err := verifyAttestation(keyBytes, a, teeSignerPtr); err != nil {
		return nil, err
	}

	return &Bootstrap{
		SealKeyBytes:    keyBytes,
		Attestation:     a,
		TEESigner:       teeSignerPtr,
		APIKey:          os.Getenv("API_KEY"),
		AttestorURL:     os.Getenv("ATTESTOR_URL"),
		ChainRPC:        os.Getenv("CHAIN_RPC_URL"),
		ContractAddr:    os.Getenv("AGENTIC_ID_ADDR"),
		FallbackIndexer: os.Getenv("INDEXER_URL"),
		PublicURL:       composePublicURL(),
	}, nil
}

// composePublicURL builds the externally-reachable URL prefix from the two
// pieces the sealing infra provides: SANDBOX_PROXY_DOMAIN (injected by the
// 0g-sandbox proxy at create time) and DAYTONA_SANDBOX_ID (Daytona's
// auto-injected metadata env). Returns "" when either is missing.
//
// The :8080 port suffix is hardcoded — that's the bootstrap proxy.Server's
// port, the only externally-bound listen socket and the only one carrying
// X-Agent-Proof.
func composePublicURL() string {
	domain := os.Getenv("SANDBOX_PROXY_DOMAIN")
	id := os.Getenv("DAYTONA_SANDBOX_ID")
	if domain == "" || id == "" {
		return ""
	}
	return "http://8080-" + id + "." + domain
}

// verifyAttestation runs the two-part Phase 0 check:
//
//  1. SANDBOX_SEAL_KEY derives the same compressed pubkey as attestation.pubkey
//  2. attestation.signature recovers the TEE signer address (and matches
//     expectedSigner when supplied)
//
// On success logs the recovered signer + image_hash for forensic visibility.
func verifyAttestation(keyBytes []byte, a provision.Attestation, expectedSigner *common.Address) error {
	logger.Logf("--- Sealed Container Bootstrap ---")
	logger.Logf("seal_id:    %s", a.SealID)
	logger.Logf("pubkey:     %s", a.Pubkey)
	logger.Logf("image_hash: %s", a.ImageHash)
	logger.Logf("ts:         %d", a.Ts)

	priv, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return fmt.Errorf("parse SANDBOX_SEAL_KEY: %w", err)
	}
	derived := "0x" + hex.EncodeToString(crypto.CompressPubkey(&priv.PublicKey))
	if !strings.EqualFold(derived, a.Pubkey) {
		return fmt.Errorf("keypair mismatch: derived %s, attestation %s", derived, a.Pubkey)
	}
	logger.Logf("OK   keypair match: SANDBOX_SEAL_KEY -> %s", derived)

	canonical := fmt.Sprintf("ImageAttestation:%s:%s:%s:%d", a.SealID, a.Pubkey, a.ImageHash, a.Ts)
	hash := crypto.Keccak256Hash([]byte(canonical))
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(a.Signature, "0x"))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("signature must be 65 bytes, got %d", len(sigBytes))
	}
	sigBytes[64] -= 27
	pub, err := crypto.SigToPub(hash[:], sigBytes)
	if err != nil {
		return fmt.Errorf("recover TEE signer: %w", err)
	}
	recovered := crypto.PubkeyToAddress(*pub).Hex()
	logger.Logf("OK   TEE signature valid, signer: %s", recovered)
	if expectedSigner != nil {
		if !strings.EqualFold(recovered, expectedSigner.Hex()) {
			return fmt.Errorf("TEE signer mismatch: recovered %s, expected %s", recovered, expectedSigner.Hex())
		}
		logger.Logf("OK   TEE signer matches TEE_SIGNER_ADDRESS: %s", expectedSigner.Hex())
	}
	return nil
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
	os.Unsetenv("SANDBOX_SEAL_KEY")
	os.Unsetenv("SANDBOX_SEAL_ATTESTATION")
	os.Unsetenv("API_KEY")
	for i := range keyBytes {
		keyBytes[i] = 0
	}
}
