package evmsign

// Checks for signing requests that arrive as tool arguments (MCP), where the
// client parsed the JSON before sealed sees it. A JavaScript client holds a
// JSON number in a float64: an integer above 2^53 reaches sealed already
// rounded, and nothing in the request shows it. So in tool arguments an
// amount is a string, and a JSON number must be a safe integer.

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// maxSafeInteger is the largest integer a float64 holds exactly (2^53 - 1).
var maxSafeInteger = big.NewInt(1<<53 - 1)

// SafeInteger reads a JSON number that is an integer no client can have
// rounded.
func SafeInteger(n json.Number) (*big.Int, error) {
	i, ok := new(big.Int).SetString(n.String(), 10)
	if !ok {
		return nil, fmt.Errorf("%s is not an integer", n)
	}
	if new(big.Int).Abs(i).Cmp(maxSafeInteger) > 0 {
		return nil, fmt.Errorf("%s is above 2^53; write it as a decimal string", n)
	}
	return i, nil
}

// SafeNumbers refuses a JSON number anywhere in v that is not a safe
// integer; path names v in the error.
func SafeNumbers(v any, path string) error {
	switch x := v.(type) {
	case json.Number:
		if _, err := SafeInteger(x); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
	case map[string]any:
		for k, e := range x {
			if err := SafeNumbers(e, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range x {
			if err := SafeNumbers(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// TransactionArgs turns transaction tool arguments (numbers as json.Number)
// into the body TransactionRequest decodes: amounts and the chain id as
// strings, nonce and gas limit as integers. `to` must be there: "" deploys a
// contract, and an argument a model left out must not.
func TransactionArgs(args map[string]any) (map[string]any, error) {
	for _, k := range []string{"chain_id", "nonce", "to", "gas_limit"} {
		if v, ok := args[k]; !ok || v == nil {
			return nil, fmt.Errorf("give %s", k)
		}
	}
	if _, ok := args["to"].(string); !ok {
		return nil, fmt.Errorf("to: an address, or \"\" to deploy a contract")
	}
	body := map[string]any{}
	for k, v := range args {
		body[k] = v
	}
	for _, k := range []string{"chain_id", "value", "gas_price", "max_fee_per_gas", "max_priority_fee_per_gas"} {
		v, ok := args[k]
		if !ok || v == nil {
			continue
		}
		switch n := v.(type) {
		case string:
		case json.Number:
			i, err := SafeInteger(n)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			body[k] = i.String()
		default:
			return nil, fmt.Errorf("%s: a decimal or 0x string", k)
		}
	}
	for _, k := range []string{"nonce", "gas_limit"} {
		var i *big.Int
		switch n := args[k].(type) {
		case json.Number:
			i, _ = SafeInteger(n)
		case string:
			i, _ = new(big.Int).SetString(strings.TrimSpace(n), 0)
		}
		if i == nil || i.Sign() < 0 || !i.IsUint64() {
			return nil, fmt.Errorf("%s: a non-negative integer", k)
		}
		body[k] = json.Number(i.String())
	}
	return body, nil
}

// WithDomainType adds the EIP712Domain type to typed data given as tool
// arguments when it is left out, as viem and ethers leave it out: the
// domain's fields, in the order EIP-712 lists them. The socket itself takes
// only typed data that names its domain type, so nothing it signs was hashed
// under a domain type the caller did not write or ask for this way.
func WithDomainType(td map[string]any) error {
	types, ok := td["types"].(map[string]any)
	if !ok {
		return fmt.Errorf("types: an object")
	}
	if _, ok := types["EIP712Domain"]; ok {
		return nil
	}
	domain, ok := td["domain"].(map[string]any)
	if !ok {
		return fmt.Errorf("domain: an object")
	}
	fields := []any{}
	for _, f := range []struct{ name, typ string }{
		{"name", "string"}, {"version", "string"}, {"chainId", "uint256"},
		{"verifyingContract", "address"}, {"salt", "bytes32"},
	} {
		if _, ok := domain[f.name]; ok {
			fields = append(fields, map[string]any{"name": f.name, "type": f.typ})
		}
	}
	with := map[string]any{"EIP712Domain": fields}
	for k, v := range types {
		with[k] = v
	}
	td["types"] = with
	return nil
}
