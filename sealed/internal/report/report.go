// Package report sends post-bootstrap status updates back to the attestor.
//
// Canonical message: "StatusReport:<seal_id_0x>:<status>:<error_detail>"
// hashed with raw keccak256 (NOT EIP-191), V=27/28. Signed by agent_seal_priv.
package report

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/logger"
)

// Status posts a status report (running / error) for a sealId. Failures are
// logged; this is a best-effort notification.
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
