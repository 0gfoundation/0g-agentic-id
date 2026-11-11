package main

// The sealed allowlist on chain (AgenticID.isValidSealedHash), read by the
// loader before it runs a sealed version, with the standard library alone: a
// JSON-RPC eth_call to CHAIN_RPC_URL, the endpoint sealed itself reads the
// chain through.
//
// Only an explicit "not listed" keeps a version from running. An answer the
// loader cannot get (the endpoint unreachable, a contract without the
// function, which is what an AgenticID before the layered runtime is) runs
// the version: the attestor checks the same allowlist before it hands out the
// agent key, so a version it refuses gets no key either way.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// isValidSealedHashSelector is the first four bytes of
// keccak256("isValidSealedHash(bytes32)").
const isValidSealedHashSelector = "5fde5c50"

// The environment the loader reads the chain endpoint from (the same
// variables sealed reads; sealed/internal/config).
const (
	chainRPCEnv  = "CHAIN_RPC_URL"
	contractEnv  = "AGENTIC_ID_ADDR"
	rpcTimeout   = 10 * time.Second
	rpcMaxAnswer = 64 << 10
)

// allowlist reads AgenticID's sealed allowlist.
type allowlist struct {
	rpc      string
	contract string
	client   *http.Client
}

// newAllowlist is the allowlist at rpc and contract, or nil when either is
// unset (nothing is checked).
func newAllowlist(rpc, contract string) *allowlist {
	if rpc == "" || contract == "" {
		return nil
	}
	return &allowlist{rpc: rpc, contract: contract, client: &http.Client{Timeout: rpcTimeout}}
}

// refuses reports whether the chain says hash is not listed. err is set
// when no answer could be had; refuses is then false.
func (a *allowlist) refuses(hash string) (refuses bool, err error) {
	if a == nil {
		return false, nil
	}
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != 32 {
		return false, fmt.Errorf("not a sealed hash: %q", hash)
	}
	call, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": a.contract, "data": "0x" + isValidSealedHashSelector + hash},
			"latest",
		},
	})
	resp, err := a.client.Post(a.rpc, "application/json", bytes.NewReader(call))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, rpcMaxAnswer))
	if err != nil {
		return false, err
	}
	var answer struct {
		Result string          `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return false, fmt.Errorf("HTTP %d: not a JSON-RPC answer", resp.StatusCode)
	}
	if len(answer.Error) > 0 && string(answer.Error) != "null" {
		return false, fmt.Errorf("eth_call: %s", answer.Error)
	}
	word, err := hex.DecodeString(strings.TrimPrefix(answer.Result, "0x"))
	if err != nil || len(word) != 32 {
		return false, fmt.Errorf("eth_call returned %q, not one ABI word", answer.Result)
	}
	for _, x := range word[:31] {
		if x != 0 {
			return false, fmt.Errorf("eth_call returned %q, not a bool", answer.Result)
		}
	}
	switch word[31] {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("eth_call returned %q, not a bool", answer.Result)
}
