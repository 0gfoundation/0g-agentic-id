// Package chain wraps AgenticID contract reads used by the bootstrap pipeline:
// resolve agentId from sealId, list intelligent data, scan ITransferred for
// the latest sealedKey set, and fetch ownerOf.
//
// All functions take an ABI-bound *Client, dialled once at startup.
package chain

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"seal-verify/internal/logger"
)

// AgenticIDABI is the minimal subset bootstrap + uploader need.
//
// SealedKeys live in contract state since the storage upgrade; sealedKeysOf
// returns them directly so we don't have to scan ITransferred / Updated
// events at boot anymore. The event is still in the ABI for completeness /
// future indexer use, but is not parsed by sealed today.
const AgenticIDABI = `[
  {"type":"function","name":"getAgentIdBySealId","stateMutability":"view","inputs":[{"name":"sealId","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}]},
  {"type":"function","name":"ownerOf","stateMutability":"view","inputs":[{"name":"tokenId","type":"uint256"}],"outputs":[{"name":"","type":"address"}]},
  {"type":"function","name":"intelligentDatasOf","stateMutability":"view","inputs":[{"name":"tokenId","type":"uint256"}],"outputs":[{"name":"","type":"tuple[]","components":[{"name":"dataDescription","type":"string"},{"name":"dataHash","type":"bytes32"}]}]},
  {"type":"function","name":"sealedKeysOf","stateMutability":"view","inputs":[{"name":"tokenId","type":"uint256"}],"outputs":[{"name":"","type":"bytes[]"}]},
  {"type":"function","name":"update","stateMutability":"nonpayable","inputs":[{"name":"tokenId","type":"uint256"},{"name":"newDatas","type":"tuple[]","components":[{"name":"dataDescription","type":"string"},{"name":"dataHash","type":"bytes32"}]},{"name":"sealedKeys","type":"bytes[]"}],"outputs":[]},
  {"type":"event","name":"ITransferred","anonymous":false,"inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"tokenId","type":"uint256","indexed":true},{"name":"entries","type":"tuple[]","indexed":false,"components":[{"name":"dataHash","type":"bytes32"},{"name":"sealedKey","type":"bytes"}]}]}
]`

// transferScanChunk is the backward-scan window for ITransferred. 0G testnet
// RPC rejects spans larger than 1000 with "query set is too large".
const transferScanChunk = 1000

// mintPollEvery is the polling interval for waitForMint.
const mintPollEvery = 5 * time.Second

// IntelligentData mirrors the on-chain struct returned by intelligentDatasOf.
type IntelligentData struct {
	DataDescription string
	DataHash        [32]byte
}

// SealedKeyEntry is one element of the ITransferred event's entries[] tuple.
type SealedKeyEntry struct {
	DataHash  [32]byte
	SealedKey []byte
}

// Client wraps an ethclient + parsed ABI + contract address. Construct once
// per process via Dial.
type Client struct {
	eth      *ethclient.Client
	abi      abi.ABI
	contract common.Address
}

// Dial connects to rpcURL and binds the AgenticID ABI at contractHex.
// Caller is responsible for c.Close() when done.
func Dial(ctx context.Context, rpcURL, contractHex string) (*Client, error) {
	eth, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc: %w", err)
	}
	parsedABI, err := abi.JSON(strings.NewReader(AgenticIDABI))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse ABI: %w", err)
	}
	return &Client{
		eth:      eth,
		abi:      parsedABI,
		contract: common.HexToAddress(contractHex),
	}, nil
}

// Close releases the underlying RPC connection.
func (c *Client) Close() {
	if c.eth != nil {
		c.eth.Close()
	}
}

// WaitForMint polls getAgentIdBySealId(sealId) until non-zero or ctx is done.
// Returns the minted agentId.
func (c *Client) WaitForMint(ctx context.Context, sealID32 [32]byte) (*big.Int, error) {
	if id, err := c.GetAgentIdBySealId(ctx, sealID32); err == nil && id.Sign() > 0 {
		return id, nil
	}
	logger.Logf("waiting for mint (poll every %s)...", mintPollEvery)
	ticker := time.NewTicker(mintPollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
		if id, err := c.GetAgentIdBySealId(ctx, sealID32); err == nil && id.Sign() > 0 {
			return id, nil
		}
	}
}

// GetAgentIdBySealId returns the agentId bound to sealId, or zero if none.
func (c *Client) GetAgentIdBySealId(ctx context.Context, sealID32 [32]byte) (*big.Int, error) {
	data, err := c.abi.Pack("getAgentIdBySealId", sealID32)
	if err != nil {
		return nil, err
	}
	out, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.contract, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.abi.Unpack("getAgentIdBySealId", out)
	if err != nil || len(res) == 0 {
		return nil, fmt.Errorf("unpack")
	}
	return res[0].(*big.Int), nil
}

// IntelligentDatasOf reads the agent's iData array.
func (c *Client) IntelligentDatasOf(ctx context.Context, agentID *big.Int) ([]IntelligentData, error) {
	data, err := c.abi.Pack("intelligentDatasOf", agentID)
	if err != nil {
		return nil, err
	}
	out, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.contract, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	var arr []IntelligentData
	if err := c.abi.UnpackIntoInterface(&arr, "intelligentDatasOf", out); err != nil {
		return nil, err
	}
	return arr, nil
}

// OwnerOf returns the ERC-721 NFT owner of agentID.
func (c *Client) OwnerOf(ctx context.Context, agentID *big.Int) (common.Address, error) {
	data, err := c.abi.Pack("ownerOf", agentID)
	if err != nil {
		return common.Address{}, err
	}
	out, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.contract, Data: data}, nil)
	if err != nil {
		return common.Address{}, err
	}
	res, err := c.abi.Unpack("ownerOf", out)
	if err != nil || len(res) == 0 {
		return common.Address{}, fmt.Errorf("unpack ownerOf")
	}
	addr, ok := res[0].(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("ownerOf return type")
	}
	return addr, nil
}

// SealedKeysOf reads sealedKeys[] directly from contract state — one view
// call, no event scanning. Result is positional (sealedKeysOf[i] pairs
// with intelligentDatasOf[i].dataHash). Returns a map keyed by dataHash
// for legacy callers that prefer the lookup shape; ordering can be
// recovered from intelligentDatasOf if needed.
func (c *Client) SealedKeysOf(ctx context.Context, tokenID *big.Int) (map[[32]byte][]byte, error) {
	data, err := c.abi.Pack("sealedKeysOf", tokenID)
	if err != nil {
		return nil, fmt.Errorf("pack sealedKeysOf: %w", err)
	}
	out, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.contract, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("call sealedKeysOf: %w", err)
	}
	res, err := c.abi.Unpack("sealedKeysOf", out)
	if err != nil || len(res) == 0 {
		return nil, fmt.Errorf("unpack sealedKeysOf: %v", err)
	}
	keys, ok := res[0].([][]byte)
	if !ok {
		return nil, fmt.Errorf("sealedKeysOf return type: %T", res[0])
	}

	// Pair positionally with intelligentDatasOf to produce the lookup map.
	iDatas, err := c.IntelligentDatasOf(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("intelligentDatasOf for SealedKeysOf pairing: %w", err)
	}
	if len(iDatas) != len(keys) {
		return nil, fmt.Errorf("sealedKeysOf length mismatch: iDatas=%d keys=%d", len(iDatas), len(keys))
	}
	result := make(map[[32]byte][]byte, len(keys))
	for i, e := range iDatas {
		result[e.DataHash] = keys[i]
	}
	return result, nil
}

// Update calls AgenticID.update(tokenId, newDatas, sealedKeys) using
// signerPriv (the agent_seal_priv — only address allowed by the contract's
// authz check) to sign. Returns the tx hash once the transaction has been
// mined and the receipt indicates success.
//
// Arrays are positional: newDatas[i].DataHash pairs with sealedKeys[i].
// Caller is expected to have constructed both arrays with matching length
// and consistent label ordering.
func (c *Client) Update(
	ctx context.Context,
	tokenID *big.Int,
	newDatas []IntelligentData,
	sealedKeys [][]byte,
	signerPriv []byte,
) (common.Hash, error) {
	if len(newDatas) != len(sealedKeys) {
		return common.Hash{}, fmt.Errorf("chain.Update: arity mismatch (newDatas=%d sealedKeys=%d)",
			len(newDatas), len(sealedKeys))
	}

	priv, err := crypto.ToECDSA(signerPriv)
	if err != nil {
		return common.Hash{}, fmt.Errorf("parse signer priv: %w", err)
	}
	from := crypto.PubkeyToAddress(priv.PublicKey)

	data, err := c.abi.Pack("update", tokenID, newDatas, sealedKeys)
	if err != nil {
		return common.Hash{}, fmt.Errorf("pack update: %w", err)
	}

	chainID, err := c.eth.ChainID(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("ChainID: %w", err)
	}
	nonce, err := c.eth.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, fmt.Errorf("nonce: %w", err)
	}
	gasPrice, err := c.eth.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("suggest gas price: %w", err)
	}
	gas, err := c.eth.EstimateGas(ctx, ethereum.CallMsg{
		From: from,
		To:   &c.contract,
		Data: data,
	})
	if err != nil {
		return common.Hash{}, fmt.Errorf("estimate gas: %w", err)
	}
	// 25% headroom — chain update touches variable-length storage; estimate
	// can underestimate when the slot was previously zeroed.
	gas = gas * 5 / 4

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       &c.contract,
		Value:    big.NewInt(0),
		Data:     data,
	})
	signed, err := types.SignTx(tx, types.NewEIP155Signer(chainID), priv)
	if err != nil {
		return common.Hash{}, fmt.Errorf("sign tx: %w", err)
	}
	if err := c.eth.SendTransaction(ctx, signed); err != nil {
		return common.Hash{}, fmt.Errorf("send tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, c.eth, signed)
	if err != nil {
		return signed.Hash(), fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return signed.Hash(), fmt.Errorf("update tx reverted: status=%d hash=%s",
			receipt.Status, signed.Hash().Hex())
	}
	logger.Logf("chain.Update OK: tokenId=%s tx=%s gas_used=%d", tokenID.String(), signed.Hash().Hex(), receipt.GasUsed)
	return signed.Hash(), nil
}

// HexSealID parses a hex-encoded (with or without 0x prefix) seal_id to a
// fixed-size [32]byte. Convenience helper used at startup.
func HexSealID(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return out, fmt.Errorf("decode seal_id: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("seal_id must be 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
