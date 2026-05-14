package uploader

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
)

// pushLeaf is the Push helper for Shape == Leaf. Encrypts the plaintext
// in one piece, uploads to 0g-storage, and returns a chain.IntelligentData
// pointing at the resulting ciphertext blob.
//
// Identical to the historical single-blob upload path; only dependency
// resolution (Encrypt + Upload via injected StorageClient) changed.
func (u *Uploader) pushLeaf(
	ctx context.Context,
	role string,
	plaintext []byte,
	dataKey []byte,
) (chain.IntelligentData, error) {
	ciphertext, err := dataplane.Encrypt(plaintext, dataKey)
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("encrypt %s: %w", role, err)
	}
	root, err := u.storage.Upload(ctx, ciphertext)
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("upload %s: %w", role, err)
	}
	descJSON, err := json.Marshal(onChainDescription{
		Role: role,
		StoragePtr: storagePtr{
			RootHash: "0x" + hex.EncodeToString(root[:]),
			Indexer:  u.indexerURL,
			Size:     len(ciphertext),
		},
		Encryption: "AES-GCM-256",
	})
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("marshal dataDescription: %w", err)
	}
	return chain.IntelligentData{
		DataDescription: string(descJSON),
		DataHash:        root,
	}, nil
}
