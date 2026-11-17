package uploader

import (
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// FundsReader is the chain client's balance read (chain.Client implements
// it): the seal wallet's balance and the gas price the chain suggests now.
type FundsReader interface {
	BalanceAndGasPrice(ctx context.Context, addr common.Address) (balance, gasPrice *big.Int, err error)
}

// Gas a commit's transactions take, from the largest measured on Galileo
// (2026-11-11, agent 532: storage submits 284k–421k, AgenticID updates
// 275k–326k), rounded up.
const (
	StorageSubmitGas = 450_000
	UpdateGas        = 350_000
)

// WalletFunds is what the seal wallet holds and what the commit step that
// failed needs: its gas at the current gas price (the storage fee, a few
// wei per blob on Galileo, is left out).
type WalletFunds struct {
	Address common.Address
	Balance *big.Int
	Need    *big.Int
}

// FundsFor reads the seal wallet for the step applyErr (an Apply error)
// failed at: the update transaction, or else a storage submit. An error means
// it could not tell.
func (u *Uploader) FundsFor(ctx context.Context, applyErr error) (WalletFunds, error) {
	r, ok := u.chain.(FundsReader)
	if !ok {
		return WalletFunds{}, errors.New("the chain client cannot read balances")
	}
	priv, err := crypto.ToECDSA(u.agentSealPriv)
	if err != nil {
		return WalletFunds{}, err
	}
	addr := crypto.PubkeyToAddress(priv.PublicKey)
	balance, price, err := r.BalanceAndGasPrice(ctx, addr)
	if err != nil {
		return WalletFunds{}, err
	}
	gas := int64(StorageSubmitGas)
	if applyErr != nil && strings.Contains(applyErr.Error(), "chain.Update") {
		gas = UpdateGas
	}
	return WalletFunds{Address: addr, Balance: balance, Need: new(big.Int).Mul(price, big.NewInt(gas))}, nil
}
