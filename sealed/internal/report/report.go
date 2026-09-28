// Package report sends post-bootstrap status updates back to the attestor.
//
// Canonical message: "StatusReport:<seal_id_0x>:<status>:<error_detail>"
// hashed with raw keccak256 (NOT EIP-191), V=27/28. Signed by agent_seal_priv.
//
// Services declarations are NOT shipped here — /hello carries them
// instead (proxy.handleHello builds the array from sealed's service
// registry and embeds it in the signed envelope). The Service wire type
// lives in services.go so the /hello path can reuse it.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/logger"
)

// Status posts a status report (running / error / warning / starting / stopping)
// for a sealId. Failures are logged; this is a best-effort notification.
func Status(attestorURL string, agentSealPriv []byte, sealID, status, errorDetail string) {
	msg := fmt.Sprintf("StatusReport:0x%s:%s:%s", sealID, status, errorDetail)
	hash := crypto.Keccak256([]byte(msg))
	priv, err := crypto.ToECDSA(agentSealPriv)
	if err != nil {
		logger.Logf("FAIL status: parse agent priv: %v", err)
		return
	}
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		logger.Logf("FAIL status: sign: %v", err)
		return
	}
	sig[64] += 27

	reqBody, _ := json.Marshal(map[string]any{
		"seal_id":              "0x" + sealID,
		"status":               status,
		"error_detail":         errorDetail,
		"agent_seal_signature": "0x" + hex.EncodeToString(sig),
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(attestorURL+"/status", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		logger.Logf("FAIL status: POST error: %v", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logger.Logf("FAIL status: HTTP %d: %s", resp.StatusCode, string(respBody))
		return
	}
	logger.Logf("OK   status reported: %s", status)
}

// SeedSettings hands attestor a configuration document recovered from a
// pre-settings-channel chain role, so it survives the container being
// recreated.
//
// This exists only for the migration. Before the settings channel, an agent's
// model pin lived in a chain-tracked config role; that role is gone, and the
// adapter recovers the pin from the old chain entry once, on the first boot of
// the new image (bootstrap Phase C → HandleLegacy). Without this call the pin
// would live only in the running container and vanish the next time the
// sandbox was recreated — two adapters hard-fail startup without one, so that
// agent would come up offline.
//
// It is signed with the agentSeal, not the owner key, because no owner is
// present at boot. attestor must therefore treat it as strictly weaker than an
// owner write: SEED ONLY. A row that already has settings must reject it. The
// container can recover a lost document; it must never be able to change one
// the owner authored.
//
// Best-effort by design: a failure here is logged, not fatal. The agent runs
// on the recovered pin either way, and the next boot retries.
func SeedSettings(attestorURL string, agentSealPriv []byte, sealID string, doc []byte) {
	if len(doc) == 0 {
		return
	}
	sum := sha256.Sum256(doc)
	msg := fmt.Sprintf("SettingsSeed:0x%s:%s", sealID, hex.EncodeToString(sum[:]))
	hash := crypto.Keccak256([]byte(msg))
	priv, err := crypto.ToECDSA(agentSealPriv)
	if err != nil {
		logger.Logf("FAIL settings seed: parse agent priv: %v", err)
		return
	}
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		logger.Logf("FAIL settings seed: sign: %v", err)
		return
	}
	sig[64] += 27

	reqBody, _ := json.Marshal(map[string]any{
		"seal_id":              "0x" + sealID,
		"settings":             json.RawMessage(doc),
		"agent_seal_signature": "0x" + hex.EncodeToString(sig),
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(attestorURL+"/settings/seed", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		logger.Logf("warn: settings seed: POST error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logger.Logf("warn: settings seed: HTTP %d: %s", resp.StatusCode, string(body))
		return
	}
	logger.Logf("OK   seeded recovered settings to attestor (%d bytes)", len(doc))
}
