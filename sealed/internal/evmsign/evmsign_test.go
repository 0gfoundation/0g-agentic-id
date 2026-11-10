package evmsign

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// A message go-ethereum panics on (a null inside a uint256[]) is the
// caller's bad request, not a crash of the process that holds the key.
func TestTypedDataMalformedIsABadRequest(t *testing.T) {
	var td apitypes.TypedData
	if err := json.Unmarshal([]byte(`{
		"types": {"EIP712Domain": [{"name": "name", "type": "string"}], "M": [{"name": "a", "type": "uint256[]"}]},
		"primaryType": "M", "domain": {"name": "x"}, "message": {"a": [null]}}`), &td); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateKey()
	_, err := TypedData(td, func() ([]byte, error) { return crypto.FromECDSA(key), nil })
	if err == nil || Status(err) != http.StatusBadRequest {
		t.Fatalf("got %v (status %d)", err, Status(err))
	}
}
