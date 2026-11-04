package credentials

import (
	"net/http"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/evmsign"
)

// SignRequest is one wallet signature the harness asks for: exactly one of
// the three shapes the agentSeal sign socket offers.
type SignRequest struct {
	Name         string                       `json:"name"`
	PersonalSign *evmsign.PersonalSignRequest `json:"personal_sign,omitempty"`
	TypedData    *apitypes.TypedData          `json:"typed_data,omitempty"`
	Transaction  *evmsign.TransactionRequest  `json:"transaction,omitempty"`
}

// WalletSign signs with a wallet entry's key and returns the signature; the
// key never leaves. What is signed is not restricted: the owner chose to
// give the agent this wallet.
func (s *Store) WalletSign(in SignRequest) (map[string]any, *credproxy.Error) {
	e := s.reg.Get(in.Name)
	switch {
	case e == nil:
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", in.Name)
	case e.Use != credproxy.UseSign || e.Signer == nil || e.Signer.Method != credproxy.SignWallet:
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q is not a wallet", in.Name)
	case !e.ExpiresAt.IsZero() && s.now().After(e.ExpiresAt):
		return nil, tokenErr(http.StatusGone, "expired", "credential %q has expired", in.Name)
	}
	n := 0
	for _, set := range []bool{in.PersonalSign != nil, in.TypedData != nil, in.Transaction != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, tokenErr(http.StatusBadRequest, "bad_request", "give exactly one of personal_sign, typed_data or transaction")
	}
	key := func() ([]byte, error) { return credproxy.WalletKey(e.Value) }
	var out map[string]any
	var err error
	op := "sign"
	switch {
	case in.PersonalSign != nil:
		out, err = evmsign.PersonalSign(*in.PersonalSign, key)
		op = "sign personal_sign"
	case in.TypedData != nil:
		out, err = evmsign.TypedData(*in.TypedData, key)
		op = "sign typed_data"
	default:
		out, err = evmsign.Transaction(*in.Transaction, key)
		op = "sign transaction"
	}
	if err != nil {
		status := evmsign.Status(err)
		code := "sign_failed"
		if status == http.StatusBadRequest {
			code = "bad_request"
		}
		s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{in.Name}, Result: code})
		return nil, tokenErr(status, code, "%s", err.Error())
	}
	s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{in.Name}, Result: "signed"})
	return out, nil
}
