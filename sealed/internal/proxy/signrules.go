package proxy

// The rules the sign socket applies before it signs (sealed/LAYERS.md §4.3),
// for an adapter that declares them (framework.SigningRules; 0g-harness). A
// rule kept in the framework is the agent's to remove; these run in sealed.
// There is one so far: agentSeal does not sign a call to AgenticID update or
// updateAt. iData writes are the drift watcher's channel, and the
// watcher signs its commits itself, from its own state, without the socket.
// What else agentSeal may sign — by target, method, amount or domain — is
// the signing policy, not decided yet (LAYERS.md §9 item 4).
//
// The rule is complete for this contract: update and updateAt check
// msg.sender against the agent's seal, so only a transaction agentSeal
// sends straight to AgenticID can reach them, and the socket signs no
// EIP-7702 authorization that would lend agentSeal's account to code.

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/evmsign"
	"seal-verify/internal/framework"
)

// iDataWrites are AgenticID's iData write methods, by selector.
var iDataWrites = map[[4]byte]string{
	selector("update(uint256,(string,bytes32)[],bytes[])"):       "update",
	selector("updateAt(uint256,uint256,(string,bytes32),bytes)"): "updateAt",
}

func selector(signature string) (s [4]byte) {
	copy(s[:], crypto.Keccak256([]byte(signature))[:4])
	return s
}

// SetAgenticID names the AgenticID contract (the chain-configured address)
// whose iData writes the sign socket does not sign. Unset, the rule is off.
func (s *Server) SetAgenticID(addr string) {
	if !common.IsHexAddress(addr) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agenticID = common.HexToAddress(addr)
}

// appliesSigningRules reports whether the bound adapter holds its agent to
// the runtime's signing rules and record (framework.SigningRules).
func (s *Server) appliesSigningRules() bool {
	r, ok := s.getAdapter().(framework.SigningRules)
	return ok && r.AppliesSigningRules()
}

// checkTransaction is the sign socket's rule on a transaction it is about to
// sign.
func (s *Server) checkTransaction(tx *types.Transaction) error {
	s.mu.RLock()
	id := s.agenticID
	s.mu.RUnlock()
	to := tx.To()
	if id == (common.Address{}) || to == nil || *to != id || len(tx.Data()) < 4 {
		return nil
	}
	var sel [4]byte
	copy(sel[:], tx.Data()[:4])
	if name, ok := iDataWrites[sel]; ok {
		return &evmsign.Refused{Reason: "AgenticID " + name + " writes your iData, which the runtime commits itself; the sign socket does not sign it"}
	}
	return nil
}
