package main

// The sealed list on chain, read by the loader before it runs a sealed
// version, with the standard library alone: JSON-RPC eth_calls to
// CHAIN_RPC_URL, the endpoint sealed itself reads the chain through. First
// AgenticID.trustRegistry() names the trust registry, then its
// isListed(SEALED, hash) answers (sealed/LAYERS.md §2, §10).
//
// Only an explicit "not listed" keeps a version from running. An answer the
// loader cannot get (the endpoint unreachable, an AgenticID that names no
// trust registry yet, which is what one before 1.4.0 is) runs the version:
// the attestor checks the same list before it hands out the agent key, so a
// version it refuses gets no key either way.

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

const (
	// trustRegistrySelector is keccak256("trustRegistry()")[:4].
	trustRegistrySelector = "9b835427"
	// isListedSelector is keccak256("isListed(bytes32,bytes32)")[:4].
	isListedSelector = "38fd4d0d"
	// sealedKind is keccak256("sealed"), the trust registry's SEALED kind.
	sealedKind = "2969d9028950bc77b790113fba8fea120169b18909fd67661a56ef98be3b78b0"
)

// The environment the loader reads the chain endpoint from (the same
// variables sealed reads; sealed/internal/config).
const (
	chainRPCEnv  = "CHAIN_RPC_URL"
	contractEnv  = "AGENTIC_ID_ADDR"
	rpcTimeout   = 10 * time.Second
	rpcMaxAnswer = 64 << 10
)

// allowlist reads the trust registry's sealed list.
type allowlist struct {
	rpc      string
	contract string
	client   *http.Client
}

// newAllowlist is the allowlist behind AgenticID at contract, read through
// rpc, or nil when either is unset (nothing is checked).
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
	word, err := a.call(a.contract, trustRegistrySelector)
	if err != nil {
		return false, fmt.Errorf("trustRegistry(): %w", err)
	}
	if !zero(word[:12]) || zero(word[12:]) {
		return false, fmt.Errorf("trustRegistry() names no trust registry")
	}
	registry := "0x" + hex.EncodeToString(word[12:])
	word, err = a.call(registry, isListedSelector+sealedKind+hash)
	if err != nil {
		return false, fmt.Errorf("isListed: %w", err)
	}
	if !zero(word[:31]) || word[31] > 1 {
		return false, fmt.Errorf("isListed returned %x, not a bool", word)
	}
	return word[31] == 0, nil
}

// call runs one eth_call of data (hex, no 0x) on to, at the latest block,
// and returns its one ABI word.
func (a *allowlist) call(to, data string) ([]byte, error) {
	call, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": to, "data": "0x" + data},
			"latest",
		},
	})
	resp, err := a.client.Post(a.rpc, "application/json", bytes.NewReader(call))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, rpcMaxAnswer))
	if err != nil {
		return nil, err
	}
	var answer struct {
		Result string          `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("HTTP %d: not a JSON-RPC answer", resp.StatusCode)
	}
	if len(answer.Error) > 0 && string(answer.Error) != "null" {
		return nil, fmt.Errorf("eth_call: %s", answer.Error)
	}
	word, err := hex.DecodeString(strings.TrimPrefix(answer.Result, "0x"))
	if err != nil || len(word) != 32 {
		return nil, fmt.Errorf("eth_call returned %q, not one ABI word", answer.Result)
	}
	return word, nil
}

func zero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
