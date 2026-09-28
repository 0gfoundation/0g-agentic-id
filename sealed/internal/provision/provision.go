// Package provision implements Phase 1 of bootstrap: hand the attestor proof
// of our identity (seal_id, container pubkey, image hash, sandbox signature)
// and receive back an ECIES-encrypted agent_seal_priv that only this sealed
// container can unlock.
package provision

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/logger"
)

// Attestation is the sandbox-injected SANDBOX_SEAL_ATTESTATION envelope.
// Reproduced here so this package depends only on logger; bootstrap parses
// it from env at startup and hands the parsed struct in.
type Attestation struct {
	SealID    string `json:"seal_id"`
	Pubkey    string `json:"pubkey"`
	ImageHash string `json:"image_hash"`
	Signature string `json:"signature"`
	Ts        int64  `json:"ts"`
}

// Result is what /provision hands the container.
type Result struct {
	// AgentSealPriv is the agent's signing key. Nil on any failure.
	AgentSealPriv []byte
	// Settings is the owner's configuration document, or nil when this
	// agent has none stored yet. attestor keeps it as an opaque blob and
	// encrypts it to the same container pubkey as the key above, so it
	// rides the channel that already exists rather than needing a new one.
	//
	// It comes down on EVERY boot, including a resume — which is the whole
	// reason it is here and not in the sandbox env: env is supplied only on
	// container create, so a resumed container would come up with no
	// configuration at all.
	Settings []byte
}

// FromAttestor calls attestorURL/provision with the sandbox's identity proof
// and returns the decrypted payload.
//
// On any failure (HTTP error, malformed response, ECIES decrypt failure) the
// key is nil; details are logged. A settings blob that fails to decrypt is
// logged and dropped rather than being fatal: an agent that boots on its
// last-good configuration beats one that refuses to boot.
func FromAttestor(attestorURL string, sealKeyBytes []byte, a Attestation) Result {
	imageHashHex := strings.TrimPrefix(a.ImageHash, "sha256:")
	reqBody, _ := json.Marshal(map[string]any{
		"seal_id":           "0x" + a.SealID,
		"container_pubkey":  a.Pubkey,
		"image_hash":        "0x" + imageHashHex,
		"issued_at":         a.Ts,
		"sandbox_signature": a.Signature,
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(attestorURL+"/provision", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		logger.Logf("FAIL provision: POST error: %v", err)
		return Result{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logger.Logf("FAIL provision: HTTP %d: %s", resp.StatusCode, string(body))
		return Result{}
	}
	var out struct {
		EncryptedAgentSealPriv string `json:"encrypted_agent_seal_priv"`
		EncryptedSettings      string `json:"encrypted_settings"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		logger.Logf("FAIL provision: decode response: %v", err)
		return Result{}
	}
	if out.EncryptedAgentSealPriv == "" {
		logger.Logf("FAIL provision: empty encrypted_agent_seal_priv")
		return Result{}
	}
	priv := eciesgo.NewPrivateKeyFromBytes(sealKeyBytes)

	ctBytes, err := hex.DecodeString(strings.TrimPrefix(out.EncryptedAgentSealPriv, "0x"))
	if err != nil {
		logger.Logf("FAIL provision: decode ciphertext hex: %v", err)
		return Result{}
	}
	plaintext, err := eciesgo.Decrypt(priv, ctBytes)
	if err != nil {
		logger.Logf("FAIL provision: ECIES decrypt: %v", err)
		return Result{}
	}

	var settingsBlob []byte
	if out.EncryptedSettings != "" {
		if ct, err := hex.DecodeString(strings.TrimPrefix(out.EncryptedSettings, "0x")); err != nil {
			logger.Logf("warn: provision: decode settings hex: %v (booting without owner settings)", err)
		} else if pt, err := eciesgo.Decrypt(priv, ct); err != nil {
			logger.Logf("warn: provision: settings ECIES decrypt: %v (booting without owner settings)", err)
		} else {
			settingsBlob = pt
			logger.Logf("OK   provisioned owner settings (%d bytes)", len(pt))
		}
	}
	// Confirm size + derived address only — never log the priv bytes.
	if len(plaintext) > 0 {
		if pk, err := crypto.ToECDSA(plaintext); err == nil {
			logger.Logf("OK   provisioned agent_seal_priv (%d bytes), addr=%s",
				len(plaintext), crypto.PubkeyToAddress(pk.PublicKey).Hex())
		} else {
			logger.Logf("OK   provisioned agent_seal_priv (%d bytes)", len(plaintext))
		}
	}
	return Result{AgentSealPriv: plaintext, Settings: settingsBlob}
}

// fmt is referenced indirectly via fmt.Errorf elsewhere in this package once
// outbound provisioning is added; kept silent here for now.
var _ = fmt.Errorf
