package proxy

// LEGACY(v1): ServeProof v1 (sealed/LAYERS.md §7, §8), what a sealed outside
// the layered runtime signs: the images without the loader (openclaw, hermes
// and prime-agent, built from this source too, and 0g-harness images from
// before the loader), and a loader image whose attestor does not declare the
// layered flow (a chain whose AgenticID names no trust registry). A v1
// envelope carries no version.
//
// Delete this file, and every branch marked LEGACY(v1)
// (`git grep -n 'LEGACY(v1)'`), once every running image has the loader and
// signs v2 — openclaw, hermes and prime-agent retired or moved onto the
// loader, the older 0g-harness images reset, every environment on AgenticID
// 1.4.0 — and make writeServeProofLayered's layers required. The registry
// keeps its v1 entry points; the SDK's, console's and script's v1 copies go
// at the same time.

import (
	"bytes"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/state"
)

// writeServeProof is writeServeProofLayered for a v1 proof.
func writeServeProof(w http.ResponseWriter, r *http.Request, priv, reqBody, body []byte, dataHashes map[string]state.DimHashes, statusCode int, agentID, frameworkHash, chainID, identityAddr, validator string) error {
	return writeServeProofLayered(w, r, priv, reqBody, body, dataHashes, statusCode, agentID, frameworkHash, chainID, identityAddr, validator, nil)
}

// serveProofHash is the inner v1 ServeProof hash, keccak256(abi.encode(
// chainId, identityRegistry, submitter, agentId, timestamp, deadline,
// taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash)). Every
// field is a static 32-byte word, so abi.encode is a plain concatenation.
// identityRegistry and submitter are abi address words (addrWord);
// dataHashesPacked is abi.encodePacked(bytes32[]) — the on-chain roots back
// to back.
//
// Consensus-critical: byte-identical to VerifiedFeedbackRegistry, the SDK
// (sdk/typescript/src/legacy/serveProofV1.ts), the attestor console's say-hi
// check and attestor/scripts/verify-agent.sh check 3b (the five copies in
// AGENTS.md).
func serveProofHash(chainID *big.Int, identityRegistry, submitter []byte, agentID *big.Int, timestamp, deadline int64, taskHash, dataHashesPacked, frameworkHash []byte) []byte {
	return crypto.Keccak256(bytes.Join([][]byte{
		word256(chainID),
		identityRegistry,
		submitter,
		word256(agentID),
		word256(big.NewInt(timestamp)),
		word256(big.NewInt(deadline)),
		taskHash,
		crypto.Keccak256(dataHashesPacked),
		frameworkHash,
	}, nil))
}
