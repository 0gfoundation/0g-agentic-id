package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/chain"
)

func TestAnchorValidator(t *testing.T) {
	identity := common.HexToAddress("0x00000000000000000000000000000000000000A9")
	other := common.HexToAddress("0x00000000000000000000000000000000000000C3")
	validator := "0x00000000000000000000000000000000000000B7"
	errRPC := errors.New("rpc down")

	cases := []struct {
		name      string
		validator string
		results   []error // per call: nil ⇒ answer with answer, else fail
		answer    common.Address
		want      string
		wantCalls int
	}{
		{name: "anchored", validator: validator, results: []error{nil}, answer: identity, want: validator, wantCalls: 1},
		{name: "other registry", validator: validator, results: []error{nil}, answer: other, want: "", wantCalls: 1},
		{name: "transient then anchored", validator: validator, results: []error{errRPC, nil}, answer: identity, want: validator, wantCalls: 2},
		{name: "unreadable", validator: validator, results: []error{errRPC, errRPC, errRPC}, want: "", wantCalls: 3},
		{name: "no validator", validator: "", want: "", wantCalls: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			read := func(_ context.Context, v common.Address) (common.Address, error) {
				if v != common.HexToAddress(tc.validator) {
					t.Fatalf("read %s, want %s", v.Hex(), tc.validator)
				}
				err := tc.results[calls]
				calls++
				if err != nil {
					return common.Address{}, err
				}
				return tc.answer, nil
			}
			got := anchorValidator(context.Background(), read, identity, tc.validator, 3, time.Millisecond)
			if got != tc.want {
				t.Fatalf("anchorValidator = %q, want %q", got, tc.want)
			}
			if calls != tc.wantCalls {
				t.Fatalf("read called %d times, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// A cancelled context stops the retries: unanchored, no further reads.
func TestAnchorValidator_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	read := func(context.Context, common.Address) (common.Address, error) {
		calls++
		cancel()
		return common.Address{}, errors.New("rpc down")
	}
	if got := anchorValidator(ctx, read, common.Address{1}, "0x00000000000000000000000000000000000000B7", 3, time.Hour); got != "" {
		t.Fatalf("anchorValidator = %q, want \"\"", got)
	}
	if calls != 1 {
		t.Fatalf("read called %d times, want 1", calls)
	}
}

// chainBootstrap hands the dialled client to onDial before any later step can
// fail, so /log.html still learns the chain id (explorer links) when the
// bootstrap itself fails — here at the seal-id parse right after the dial.
func TestChainBootstrap_OnDialRunsBeforeLaterFailure(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if req.Method == "eth_chainId" {
			resp["result"] = "0x40da" // 16602
		} else {
			resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer rpc.Close()

	var dialled string
	onDial := func(_ context.Context, c *chain.Client) { dialled = c.ChainID().String() }
	res, err := chainBootstrap(rpc.URL, "0x00000000000000000000000000000000000000A9", "not-a-seal-id", nil, "", onDial)
	if err == nil || res != nil {
		t.Fatalf("chainBootstrap = %v, %v; want a seal-id error", res, err)
	}
	if dialled != "16602" {
		t.Fatalf("onDial saw chain id %q, want 16602", dialled)
	}
}
