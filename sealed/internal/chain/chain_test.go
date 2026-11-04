package chain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// rpcStub is a minimal JSON-RPC endpoint: eth_chainId, eth_getCode and
// eth_call answer from the fields; anything else is a method-not-found error.
type rpcStub struct {
	code    string // eth_getCode result
	call    string // eth_call result ("" ⇒ revert error)
	gotCall json.RawMessage
}

func (s *rpcStub) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		switch req.Method {
		case "eth_chainId":
			resp["result"] = "0x40da" // 16602
		case "eth_getCode":
			resp["result"] = s.code
		case "eth_call":
			s.gotCall = req.Params[0]
			if s.call == "" {
				resp["error"] = map[string]any{"code": 3, "message": "execution reverted"}
			} else {
				resp["result"] = s.call
			}
		default:
			resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

const (
	stubIdentity  = "0x00000000000000000000000000000000000000A9"
	stubValidator = "0x00000000000000000000000000000000000000B7"
)

func word(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(addr, "0x"))
}

func TestIdentityRegistryOf(t *testing.T) {
	cases := []struct {
		name    string
		stub    rpcStub
		want    string
		wantErr string
	}{
		{name: "anchored", stub: rpcStub{code: "0x6080", call: word(stubIdentity)}, want: stubIdentity},
		{name: "other registry", stub: rpcStub{code: "0x6080", call: word("0x00000000000000000000000000000000000000C3")},
			want: "0x00000000000000000000000000000000000000C3"},
		{name: "no code", stub: rpcStub{code: "0x", call: word(stubIdentity)}, wantErr: "no contract code"},
		{name: "reverts", stub: rpcStub{code: "0x6080"}, wantErr: "getIdentityRegistry()"},
		{name: "not an address", stub: rpcStub{code: "0x6080", call: "0x01"}, wantErr: "not an address"},
		{name: "dirty high bytes", stub: rpcStub{code: "0x6080", call: "0xff" + strings.Repeat("0", 62)}, wantErr: "not an address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := tc.stub
			c, err := Dial(context.Background(), stub.serve(t), stubIdentity)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()
			if c.ChainID().Int64() != 16602 {
				t.Fatalf("chain id = %s", c.ChainID())
			}
			got, err := c.IdentityRegistryOf(context.Background(), common.HexToAddress(stubValidator))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("IdentityRegistryOf: %v", err)
			}
			if got != common.HexToAddress(tc.want) {
				t.Fatalf("got %s, want %s", got.Hex(), tc.want)
			}
			// The call goes to the validator with the getIdentityRegistry() selector.
			var call struct {
				To    string `json:"to"`
				Input string `json:"input"`
				Data  string `json:"data"`
			}
			_ = json.Unmarshal(stub.gotCall, &call)
			if !strings.EqualFold(call.To, stubValidator) {
				t.Fatalf("eth_call to %s, want %s", call.To, stubValidator)
			}
			if in := call.Input + call.Data; !strings.Contains(in, "bc4d861b") {
				t.Fatalf("eth_call input %q lacks getIdentityRegistry() selector", in)
			}
		})
	}
}
