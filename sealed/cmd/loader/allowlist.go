package main

// The sealed list on chain, read by the loader before it runs a sealed
// version, with the standard library's HTTP client: JSON-RPC eth_calls to
// CHAIN_RPC_URL, the endpoint sealed itself reads the chain through. First
// AgenticID.trustRegistry() names the trust registry, then its
// listed(SEALED) (every listed version, oldest first) and
// isListed(SEALED, hash) answer (sealed/LAYERS.md §2, §10).
//
// A version runs only on the chain's explicit "listed" (supervise.go). When
// no answer can be had — the endpoint unreachable, any JSON-RPC error, an
// AgenticID that names no trust registry (one before 1.4.0) — nothing runs:
// the loader reads again later. The image holds no sealed of its own, so
// there is nothing to fall back to that the list does not vouch for.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// sealedList is the chain's sealed list as the loader reads it: *allowlist,
// or a stand-in in tests.
type sealedList interface {
	// listed returns every version the chain lists, oldest first (64
	// lowercase hex each). err is set when no answer could be had.
	listed() ([]string, error)
	// refuses reports whether the chain says hash is not listed. err is set
	// when no answer could be had; refuses is then false.
	refuses(hash string) (refuses bool, err error)
}

const (
	// trustRegistrySelector is keccak256("trustRegistry()")[:4].
	trustRegistrySelector = "9b835427"
	// isListedSelector is keccak256("isListed(bytes32,bytes32)")[:4].
	isListedSelector = "38fd4d0d"
	// listedSelector is keccak256("listed(bytes32)")[:4].
	listedSelector = "bf7e3b60"
	// sealedKind is keccak256("sealed"), the trust registry's SEALED kind.
	sealedKind = "2969d9028950bc77b790113fba8fea120169b18909fd67661a56ef98be3b78b0"
)

// The environment the loader reads the chain endpoint from (the same
// variables sealed reads; sealed/internal/config).
const (
	chainRPCEnv  = "CHAIN_RPC_URL"
	contractEnv  = "AGENTIC_ID_ADDR"
	rpcTimeout   = 10 * time.Second
	rpcMaxAnswer = 256 << 10
	// maxListed bounds the versions one listed() answer may name.
	maxListed = 4096
)

// allowlist reads the trust registry's sealed list.
type allowlist struct {
	rpc      string
	contract string
	client   *http.Client
}

// newAllowlist is the allowlist behind AgenticID at contract, read through
// rpc, or nil when either is unset: then no answer can be had.
func newAllowlist(rpc, contract string) *allowlist {
	if rpc == "" || contract == "" {
		return nil
	}
	return &allowlist{rpc: rpc, contract: contract, client: &http.Client{Timeout: rpcTimeout}}
}

// registry reads AgenticID.trustRegistry(): the trust registry's address.
func (a *allowlist) registry() (string, error) {
	if a == nil {
		return "", fmt.Errorf("%s or %s is unset: the sealed list cannot be read", chainRPCEnv, contractEnv)
	}
	word, err := a.word(a.contract, trustRegistrySelector)
	if err == nil && (!zero(word[:12]) || zero(word[12:])) {
		err = fmt.Errorf("it names none")
	}
	if err != nil {
		return "", fmt.Errorf("trustRegistry(): %w (this image runs only on a chain whose AgenticID, 1.4.0 or later, names its trust registry)", err)
	}
	return "0x" + hex.EncodeToString(word[12:]), nil
}

// listed returns every version the chain lists, oldest first.
func (a *allowlist) listed() ([]string, error) {
	registry, err := a.registry()
	if err != nil {
		return nil, err
	}
	out, err := a.call(registry, listedSelector+sealedKind)
	if err != nil {
		return nil, fmt.Errorf("listed: %w", err)
	}
	hashes, err := decodeBytes32Array(out)
	if err != nil {
		return nil, fmt.Errorf("listed: %w", err)
	}
	return hashes, nil
}

// decodeBytes32Array decodes the ABI encoding of one bytes32[] return: the
// offset of the array (32), its length, then the elements.
func decodeBytes32Array(out []byte) ([]string, error) {
	if len(out) < 64 || len(out)%32 != 0 {
		return nil, fmt.Errorf("return of %d bytes is not a bytes32[]", len(out))
	}
	if offset := new(big.Int).SetBytes(out[:32]); offset.Cmp(big.NewInt(32)) != 0 {
		return nil, fmt.Errorf("return is not a bytes32[] (offset %s)", offset)
	}
	n := new(big.Int).SetBytes(out[32:64])
	if !n.IsInt64() || n.Int64() > maxListed || int64(len(out)) != 64+32*n.Int64() {
		return nil, fmt.Errorf("return of %d bytes does not hold %s bytes32", len(out), n)
	}
	hashes := make([]string, 0, n.Int64())
	for i := 64; i < len(out); i += 32 {
		hashes = append(hashes, hex.EncodeToString(out[i:i+32]))
	}
	return hashes, nil
}

// refuses reports whether the chain says hash is not listed. err is set
// when no answer could be had; refuses is then false.
func (a *allowlist) refuses(hash string) (refuses bool, err error) {
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != 32 {
		return false, fmt.Errorf("not a sealed hash: %q", hash)
	}
	registry, err := a.registry()
	if err != nil {
		return false, err
	}
	word, err := a.word(registry, isListedSelector+sealedKind+hash)
	if err != nil {
		return false, fmt.Errorf("isListed: %w", err)
	}
	if !zero(word[:31]) || word[31] > 1 {
		return false, fmt.Errorf("isListed returned %x, not a bool", word)
	}
	return word[31] == 0, nil
}

// word runs one eth_call whose return is one ABI word.
func (a *allowlist) word(to, data string) ([]byte, error) {
	out, err := a.call(to, data)
	if err != nil {
		return nil, err
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("eth_call returned %d bytes, not one ABI word", len(out))
	}
	return out, nil
}

// call runs one eth_call of data (hex, no 0x) on to, at the latest block,
// and returns what it returned.
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, rpcMaxAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(body) > rpcMaxAnswer {
		return nil, fmt.Errorf("answer larger than %d bytes", rpcMaxAnswer)
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
	out, err := hex.DecodeString(strings.TrimPrefix(answer.Result, "0x"))
	if err != nil {
		return nil, fmt.Errorf("eth_call returned %q, not hex", answer.Result)
	}
	return out, nil
}

func zero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
