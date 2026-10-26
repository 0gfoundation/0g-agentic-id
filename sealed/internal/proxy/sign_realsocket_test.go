package proxy

import (
	"bytes"
	"context"

	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"

	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/state"
)

// The mjs regression (seal_tools_regression.mjs) drives the real plugin
// against a FAKE socket. This is the other leg: the REAL sign handlers on a
// REAL unix socket, driven by plain HTTP — the exact bytes the tool channel
// produces. Guards the socket-side invariants the tools lean on:
//   - a malformed value must 400, never sign 0 wei silently;
//   - chain_id 0 must 400 with a readable message, not panic the signer;
//   - well-formed dynamic and legacy txs sign, and the signatures recover
//     to the agent's own address;
//   - typed data REQUIRES the EIP712Domain entry in types (the tool injects
//     it; a viem-style payload without it is rejected, not mis-hashed).
//
// A fresh ephemeral key per run — the assertions are self-referential
// (signature recovers to THIS test key's address), so nothing here depends
// on external state.
func newRealSocketSignServer(t *testing.T) (sockPath, sealAddr string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv := crypto.FromECDSA(key)
	sealAddr = crypto.PubkeyToAddress(key.PublicKey).Hex()

	st := state.New()
	st.Set(priv, "http://upstream", "seal-id", "0xowner", "466", "fw-hash", "16602", "0xident")

	dir := t.TempDir()
	sockPath = filepath.Join(dir, "sign.sock")
	New(st, "http://x").ListenInternal(sockPath)

	// ListenInternal serves from a goroutine; wait until the socket accepts.
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", sockPath); err == nil {
			c.Close()
			return sockPath, sealAddr
		}
	}
	t.Fatal("sign socket never came up")
	return "", ""
}

func sockClient(sockPath string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("unix", sockPath)
		},
	}}
}

func sockPost(t *testing.T, sockPath, path string, body any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://unix"+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := sockClient(sockPath).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("non-JSON response (HTTP %d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, out
}

func senderOf(tx *types.Transaction, chainID int64) common.Address {
	s, err := types.Sender(types.LatestSignerForChainID(big.NewInt(chainID)), tx)
	if err != nil {
		return common.Address{}
	}
	return s
}

func TestSignTransactionRealSocket(t *testing.T) {
	sock, seal := newRealSocketSignServer(t)
	to := "0x2ce80374318b1d7fb3345724457a182e0ad165c9"

	// Malformed value: "1.5" must be a 400 naming the field — never a
	// silently-signed 0-wei tx.
	code, out := sockPost(t, sock, "/sign/transaction", map[string]any{
		"chain_id": "16602", "nonce": 1, "to": to,
		"value": "1.5", "data": "0x", "gas_limit": 21000, "type": "legacy", "gas_price": "7",
	})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["error"]), "value") {
		t.Fatalf("value \"1.5\": got %d %v, want 400 naming value", code, out)
	}

	// chain_id 0: readable 400, not a signer panic ("socket hang up").
	code, out = sockPost(t, sock, "/sign/transaction", map[string]any{
		"chain_id": "0", "nonce": 1, "to": to,
		"data": "0x", "gas_limit": 21000, "type": "legacy", "gas_price": "7",
	})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["error"]), "positive") {
		t.Fatalf("chain_id 0: got %d %v, want 400 with a positive-chain-id message", code, out)
	}

	// Well-formed legacy tx: 200, raw decodes, signature recovers to the seal.
	code, out = sockPost(t, sock, "/sign/transaction", map[string]any{
		"chain_id": "16602", "nonce": 1, "to": to,
		"value": "1000", "data": "0x", "gas_limit": 21000, "type": "legacy", "gas_price": "7",
	})
	if code != http.StatusOK {
		t.Fatalf("legacy tx: got %d %v", code, out)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(common.FromHex(fmt.Sprint(out["raw_tx"]))); err != nil {
		t.Fatalf("legacy raw_tx does not decode: %v", err)
	}
	if got := senderOf(&tx, 16602).Hex(); got != seal {
		t.Fatalf("legacy tx signed by %s, want the seal %s", got, seal)
	}

	// Well-formed dynamic tx: same.
	code, out = sockPost(t, sock, "/sign/transaction", map[string]any{
		"chain_id": "16602", "nonce": 2, "to": to,
		"data": "0x", "gas_limit": 21000, "max_fee_per_gas": "1000", "max_priority_fee_per_gas": "1",
	})
	if code != http.StatusOK {
		t.Fatalf("dynamic tx: got %d %v", code, out)
	}
	var tx2 types.Transaction
	if err := tx2.UnmarshalBinary(common.FromHex(fmt.Sprint(out["raw_tx"]))); err != nil {
		t.Fatalf("dynamic raw_tx does not decode: %v", err)
	}
	if got := senderOf(&tx2, 16602).Hex(); got != seal {
		t.Fatalf("dynamic tx signed by %s, want the seal %s", got, seal)
	}

	// Contract creation with the explicit "" sentinel still signs.
	code, _ = sockPost(t, sock, "/sign/transaction", map[string]any{
		"chain_id": "16602", "nonce": 3, "to": "", "data": "0x6001", "gas_limit": 200000,
		"max_fee_per_gas": "1000", "max_priority_fee_per_gas": "1",
	})
	if code != http.StatusOK {
		t.Fatalf("creation tx: got %d", code)
	}
}

func TestSignTypedDataRealSocket(t *testing.T) {
	sock, seal := newRealSocketSignServer(t)

	// A viem/ethers-style payload WITHOUT the EIP712Domain entry is rejected
	// with a readable error — the tool channel injects it; the socket must
	// never mis-hash a domain-less payload.
	code, out := sockPost(t, sock, "/sign/typed_data", map[string]any{
		"domain":      map[string]any{"name": "x", "version": "1"},
		"types":       map[string]any{"Mail": []map[string]string{{"name": "a", "type": "uint256"}}},
		"primaryType": "Mail",
		"message":     map[string]any{"a": "1"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("domain-less typed data: got %d %v, want 400", code, out)
	}

	// With the injected EIP712Domain (canonical order), it signs and the
	// reported address is the seal.
	code, out = sockPost(t, sock, "/sign/typed_data", map[string]any{
		"domain": map[string]any{"name": "x", "version": "1", "chainId": "16602"},
		"types": map[string]any{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
			},
			"Mail": []map[string]string{{"name": "a", "type": "uint256"}},
		},
		"primaryType": "Mail",
		"message":     map[string]any{"a": "1"},
	})
	if code != http.StatusOK {
		t.Fatalf("typed data: got %d %v", code, out)
	}
	if fmt.Sprint(out["address"]) != seal {
		t.Fatalf("typed data address %v, want the seal %s", out["address"], seal)
	}
}

// The mjs regression's recipe, documented: the real-socket leg runs as a
// plain Go test (`go test ./internal/proxy/ -run RealSocket`); no extra
// environment is needed.
