package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"seal-verify/internal/servicehost"
)

// Distinct from ServeProof and from every preimage exposed by the sign socket.
// In particular personal_sign and EIP-712 cannot forge this v0x00 domain.
const executionReceiptTag = "0G.SealedExecution.v1\x00"

type executionReceipt struct {
	Version          int                          `json:"version"`
	ChainID          string                       `json:"chain_id"`
	IdentityRegistry string                       `json:"identity_registry"`
	AgentID          string                       `json:"agent_id"`
	Validator        string                       `json:"validator"`
	SealedHash       string                       `json:"sealed_hash,omitempty"`
	HarnessHash      string                       `json:"harness_hash,omitempty"`
	Execution        servicehost.ExecutionStatus  `json:"execution"`
	Isolation        servicehost.IsolationProfile `json:"isolation"`
}

func executionReceiptDigest(validator common.Address, payload []byte) []byte {
	return serveProofDigest(validator, crypto.Keccak256([]byte(executionReceiptTag), payload))
}

func (s *Server) signExecutionReceipt(status servicehost.ExecutionStatus, isolation servicehost.IsolationProfile) (string, error) {
	priv, _, _, _, _ := s.agent.Snapshot()
	agentID, _ := s.agent.ProofIdentity()
	chainID, identity, validator := s.agent.ProofDomain()
	v, valid := parseValidator(validator)
	if len(priv) != 32 || !valid || agentID == "" || agentID == "0" || chainID == "" || !common.IsHexAddress(identity) {
		return "", fmt.Errorf("execution attestation unavailable")
	}
	status.Receipt = ""
	status.OutputAvailable = false // availability is transient, not an execution fact
	env := executionReceipt{Version: 1, ChainID: chainID, IdentityRegistry: identity, AgentID: agentID, Validator: v.Hex(), Execution: status, Isolation: isolation}
	if layers := s.layersForProof(); layers != nil {
		env.SealedHash, env.HarnessHash = layers.SealedHash, layers.HarnessHash
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	key, err := crypto.ToECDSA(priv)
	if err != nil {
		return "", err
	}
	sig, err := crypto.Sign(executionReceiptDigest(v, payload), key)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return "0x" + hex.EncodeToString(sig) + "." + base64.RawURLEncoding.EncodeToString(payload), nil
}
