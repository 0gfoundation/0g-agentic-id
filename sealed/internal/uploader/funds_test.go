package uploader

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
)

// fundsChain is a mockChain that reads balances.
type fundsChain struct {
	*mockChain
	balance, price *big.Int
	err            error
	asked          common.Address
}

func (f *fundsChain) BalanceAndGasPrice(_ context.Context, addr common.Address) (*big.Int, *big.Int, error) {
	f.asked = addr
	return f.balance, f.price, f.err
}

func TestFundsForReadsTheSealWalletForTheFailedStep(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "framework", Shape: framework.Leaf}})
	fc := &fundsChain{mockChain: h.chain, balance: big.NewInt(7), price: big.NewInt(2000_000_000_000)}
	h.with(t, h.storage, fc)
	priv, _ := crypto.ToECDSA(h.up.agentSealPriv)
	want := crypto.PubkeyToAddress(priv.PublicKey)

	f, err := h.up.FundsFor(context.Background(), errors.New("uploader.Apply: upload framework: 0g-storage upload: execution reverted"))
	if err != nil {
		t.Fatal(err)
	}
	if fc.asked != want || f.Address != want || f.Balance.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("read %s for the seal wallet %s: %+v", fc.asked.Hex(), want.Hex(), f)
	}
	if f.Need.Cmp(new(big.Int).Mul(fc.price, big.NewInt(StorageSubmitGas))) != 0 {
		t.Errorf("a failed upload needs %s; want a storage submit's gas", f.Need)
	}
	f, err = h.up.FundsFor(context.Background(), errors.New("uploader.Apply: chain.Update: execution reverted"))
	if err != nil || f.Need.Cmp(new(big.Int).Mul(fc.price, big.NewInt(UpdateGas))) != 0 {
		t.Errorf("a failed update needs %v (%v); want an update's gas", f.Need, err)
	}

	fc.err = errors.New("dial tcp: connection refused")
	if _, err := h.up.FundsFor(context.Background(), errors.New("x")); err == nil {
		t.Error("a failed read reported funds")
	}
	h.with(t, h.storage, h.chain) // no balance read
	if _, err := h.up.FundsFor(context.Background(), errors.New("x")); err == nil {
		t.Error("a chain client without balance reads reported funds")
	}
}
