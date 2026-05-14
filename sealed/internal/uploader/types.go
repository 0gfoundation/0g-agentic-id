package uploader

import (
	"context"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
)

// This file defines the dependency interfaces Uploader uses, plus default
// production wrappers that delegate to chain.Client / dataplane package.
// Tests provide their own implementations to drive Push behaviour without
// touching a real chain or 0g-storage.

// Adapter is the subset of framework.Framework that Uploader needs.
//
// Kept narrow so test fakes don't have to implement Start/Stop/Liveness
// just to exercise upload logic.
type Adapter interface {
	Roles() []framework.RoleSpec
	Defaults(role string) []byte
	EvolutionFor(ctx context.Context, role string) ([]byte, error)
	LoadEntry(ctx context.Context, role string, path string) ([]byte, error)
}

// ChainClient is the subset of chain.Client that Uploader needs.
type ChainClient interface {
	IntelligentDatasOf(ctx context.Context, agentID *big.Int) ([]chain.IntelligentData, error)
	SealedKeysOf(ctx context.Context, agentID *big.Int) (map[[32]byte][]byte, error)
	Update(
		ctx context.Context,
		agentID *big.Int,
		newDatas []chain.IntelligentData,
		sealedKeys [][]byte,
		agentSealPriv []byte,
	) (common.Hash, error)
}

// StorageClient abstracts the 0g-storage Upload + Download primitives so
// tests can substitute in-memory blob storage. Production wrapper delegates
// to the dataplane package's CLI-shelling implementation.
type StorageClient interface {
	Upload(ctx context.Context, ciphertext []byte) (root [32]byte, err error)
	Download(ctx context.Context, root [32]byte) ([]byte, error)
}

// ── default dataplane-backed StorageClient ──────────────────────────────────

// dataplaneStorage is the production StorageClient that wraps the CLI-based
// dataplane package. Captures the per-deployment indexerURL / rpcURL /
// signer key once at construction so individual calls have a clean
// (ctx, ciphertext) signature.
type dataplaneStorage struct {
	indexerURL    string
	rpcURL        string
	signerPrivHex string
}

func (d *dataplaneStorage) Upload(ctx context.Context, ciphertext []byte) ([32]byte, error) {
	return dataplane.Upload(ctx, ciphertext, d.indexerURL, d.rpcURL, d.signerPrivHex)
}

// Download fetches a blob from 0g-storage. The underlying dataplane.Download
// writes to a tempfile (because the CLI requires it); this wrapper reads
// the file back into memory and cleans up.
func (d *dataplaneStorage) Download(ctx context.Context, root [32]byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", "0g-download-*.bin")
	if err != nil {
		return nil, fmt.Errorf("dataplaneStorage: create tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	rootHex := "0x" + hexBytes(root[:])
	if err := dataplane.Download(ctx, rootHex, d.indexerURL, tmpPath); err != nil {
		return nil, fmt.Errorf("dataplaneStorage: download %s: %w", rootHex, err)
	}
	body, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("dataplaneStorage: read downloaded blob: %w", err)
	}
	return body, nil
}

// hexBytes encodes b as lowercase hex without the 0x prefix. Local helper
// so types.go doesn't import "encoding/hex" twice.
func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0xf]
	}
	return string(out)
}
