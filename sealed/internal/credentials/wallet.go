package credentials

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strings"

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
// give the agent this wallet. The owner's audit log says what was signed.
// A wallet holding the owner's own key is refused: the agent could sign as
// its owner.
func (s *Store) WalletSign(ctx context.Context, in SignRequest) (map[string]any, *credproxy.Error) {
	if err := s.ensureOwner(ctx); err != nil {
		return nil, err
	}
	e := s.reg.Get(in.Name)
	switch {
	case e == nil:
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", in.Name)
	case e.Use != credproxy.UseSign || e.Signer == nil || e.Signer.Method != credproxy.SignWallet:
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q is not a wallet", in.Name)
	case !e.ExpiresAt.IsZero() && s.now().After(e.ExpiresAt):
		return nil, tokenErr(http.StatusGone, "expired", "credential %q has expired", in.Name)
	}
	s.mu.Lock()
	owner := s.owner
	s.mu.Unlock()
	if addr, err := WalletAddress(e.Value); err == nil && addr == owner {
		s.addAudit(AuditRecord{Time: s.now(), Op: "sign", Names: []string{in.Name}, Result: "refused: the wallet is the owner's own key", repeat: true})
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q holds the owner's own key and does not sign", in.Name)
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
	var op, what string
	switch {
	case in.PersonalSign != nil:
		out, err = evmsign.PersonalSign(*in.PersonalSign, key)
		op, what = "sign personal_sign", personalSignSummary(in.PersonalSign)
	case in.TypedData != nil:
		out, err = evmsign.TypedData(*in.TypedData, key)
		op, what = "sign typed_data", typedDataSummary(in.TypedData)
	default:
		out, err = evmsign.Transaction(*in.Transaction, key)
		op, what = "sign transaction", transactionSummary(in.Transaction)
	}
	if err != nil {
		status := evmsign.Status(err)
		code := "sign_failed"
		if status == http.StatusBadRequest {
			code = "bad_request"
		}
		// The harness can fail as often as it likes: counted by kind.
		s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{in.Name}, Result: code, repeat: true})
		return nil, tokenErr(status, code, "%s", err.Error())
	}
	s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{in.Name}, Result: "signed: " + what})
	return out, nil
}

func personalSignSummary(r *evmsign.PersonalSignRequest) string {
	n := len(r.Message)
	if r.MessageHex != "" {
		n = len(strings.TrimPrefix(r.MessageHex, "0x")) / 2
	}
	return fmt.Sprintf("message of %d bytes", n)
}

func typedDataSummary(td *apitypes.TypedData) string {
	chain := "-"
	if td.Domain.ChainId != nil {
		chain = (*big.Int)(td.Domain.ChainId).String()
	}
	return fmt.Sprintf("%s in domain %q, chain %s, contract %s", clip(td.PrimaryType, 64), clip(td.Domain.Name, 64), chain, clip(td.Domain.VerifyingContract, 42))
}

func transactionSummary(t *evmsign.TransactionRequest) string {
	to := t.To
	if to == "" {
		to = "(contract creation)"
	}
	value := t.Value
	if value == "" {
		value = "0"
	}
	selector := "-"
	if d := strings.TrimPrefix(t.Data, "0x"); len(d) >= 8 {
		selector = "0x" + d[:8]
	}
	return fmt.Sprintf("chain %s, to %s, value %s, selector %s", clip(t.ChainID, 32), clip(to, 42), clip(value, 80), clip(selector, 10))
}

// clip keeps what the harness sent short and on one line for the log.
func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return '?'
		}
		return r
	}, s)
}
