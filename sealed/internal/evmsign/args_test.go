package evmsign

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func testKey(t *testing.T) KeyFunc {
	t.Helper()
	key, _ := crypto.GenerateKey()
	return func() ([]byte, error) { return crypto.FromECDSA(key), nil }
}

func decodeTyped(t *testing.T, s string) apitypes.TypedData {
	t.Helper()
	var td apitypes.TypedData
	if err := json.Unmarshal([]byte(s), &td); err != nil {
		t.Fatal(err)
	}
	return td
}

// Left out, the domain's own type is the domain's fields in EIP-712 order:
// the digest equals the one with the type written out.
func TestWithDomainType(t *testing.T) {
	k := testKey(t)
	const msg = `"primaryType":"M","domain":{"name":"N","version":"1","chainId":5,"verifyingContract":"0x0000000000000000000000000000000000000001"},"message":{"n":1}`
	with, err := TypedData(decodeTyped(t, `{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"M":[{"name":"n","type":"uint256"}]},`+msg+`}`), k)
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"types":{"M":[{"name":"n","type":"uint256"}]},` + msg + `}`))
	dec.UseNumber()
	if err := dec.Decode(&args); err != nil {
		t.Fatal(err)
	}
	if err := WithDomainType(args); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(args)
	without, err := TypedData(decodeTyped(t, string(b)), k)
	if err != nil {
		t.Fatal(err)
	}
	if with["digest"] != without["digest"] {
		t.Fatalf("digest %v with the derived domain type, %v with it written out", without["digest"], with["digest"])
	}
}

// A check refusing the assembled transaction stops it before the key is
// asked for, and answers 403.
func TestTransactionChecked_Refusal(t *testing.T) {
	asked := false
	k := func() ([]byte, error) { asked = true; return nil, errors.New("unused") }
	var saw *types.Transaction
	_, err := TransactionChecked(TransactionRequest{ChainID: "1", GasLimit: 21000, To: "0x0000000000000000000000000000000000000002", MaxFeePerGas: "2", MaxPriorityFeePerGas: "1"}, k,
		func(tx *types.Transaction) error { saw = tx; return &Refused{Reason: "no"} })
	if Status(err) != http.StatusForbidden || asked || saw == nil || saw.To().Hex() != "0x0000000000000000000000000000000000000002" {
		t.Fatalf("err %v status %d, key asked %v", err, Status(err), asked)
	}
}

func TestTransactionArgs(t *testing.T) {
	args := func(s string) map[string]any {
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	body, err := TransactionArgs(args(`{"chain_id":16602,"nonce":"0x3","to":"","gas_limit":21000,"value":"5"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	var req TransactionRequest
	if err := json.Unmarshal(b, &req); err != nil || req.ChainID != "16602" || req.Nonce != 3 || req.GasLimit != 21000 || req.Value != "5" || req.To != "" {
		t.Fatalf("decoded %+v (%v) from %s", req, err, b)
	}
	for in, want := range map[string]string{
		`{"chain_id":"1","nonce":0,"gas_limit":1}`:                                  "give to",
		`{"chain_id":"1","nonce":0,"to":5,"gas_limit":1}`:                           "to:",
		`{"chain_id":"1","nonce":-1,"to":"","gas_limit":1}`:                         "nonce",
		`{"chain_id":"1","nonce":0,"to":"","gas_limit":1,"value":1e18}`:             "value",
		`{"chain_id":"1","nonce":0,"to":"","gas_limit":1,"value":9007199254740993}`: "2^53",
		`{"chain_id":"1","nonce":0,"to":"","gas_limit":1,"value":true}`:             "value",
	} {
		if _, err := TransactionArgs(args(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
}

func TestSafeNumbers(t *testing.T) {
	var v any
	dec := json.NewDecoder(strings.NewReader(`{"a":[1,{"b":9007199254740993}]}`))
	dec.UseNumber()
	_ = dec.Decode(&v)
	if err := SafeNumbers(v, "message"); err == nil || !strings.Contains(err.Error(), "message.a[1].b") {
		t.Fatalf("err %v", err)
	}
	if err := SafeNumbers(map[string]any{"a": json.Number("9007199254740991"), "s": "99999999999999999999"}, "m"); err != nil {
		t.Fatal(err)
	}
}
