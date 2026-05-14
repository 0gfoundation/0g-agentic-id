package uploader

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/manifest"
)

// pushManifest is the Push helper for Shape == DirectoryManifest.
//
// The plaintext from adapter.EvolutionFor contains a manifest whose
// entries[].storage_ptr fields are zero — adapter doesn't know storage
// roots, only content. This helper fills them in by either reusing the
// prior storage_ptr (when content_hash is unchanged from chain's old
// manifest) or by uploading a fresh content blob.
//
// Final on-chain dataDescription points to the FILLED manifest's storage
// root, not the empty-ptr version. The watcher-facing contentHash (sha256
// of the empty-ptr plaintext) is computed by the caller in Push and is
// what RecordChainUpload records; the two values are intentionally
// different — see EVOLUTION_DESIGN §16.6.
//
// data_key is the role-level key (reused across all blobs under this role
// so a manifest entry's storage_ptr from a prior push still decrypts).
func (u *Uploader) pushManifest(
	ctx context.Context,
	role string,
	plaintext []byte,
	dataKey []byte,
	oldEntry *chain.IntelligentData,
) (chain.IntelligentData, error) {
	newManifest, err := manifest.Unmarshal(plaintext)
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("parse new manifest for %s: %w", role, err)
	}

	// Old manifest is optional: nil on first push for this role, present
	// on every subsequent push. Without it, every entry is treated as "new".
	var oldManifest *manifest.Manifest
	if oldEntry != nil {
		oldManifest, err = u.fetchOldManifest(ctx, oldEntry, dataKey)
		if err != nil {
			return chain.IntelligentData{}, fmt.Errorf("fetch prior manifest for %s: %w", role, err)
		}
	}

	reused, fresh := 0, 0
	for i := range newManifest.Entries {
		e := &newManifest.Entries[i]
		if oldManifest != nil {
			if oldE := oldManifest.EntryByPath(e.Path); oldE != nil && oldE.ContentHash == e.ContentHash {
				e.StoragePtr = oldE.StoragePtr
				reused++
				continue
			}
		}
		content, err := u.adapter.LoadEntry(ctx, role, e.Path)
		if err != nil {
			return chain.IntelligentData{}, fmt.Errorf("LoadEntry[%s] %s: %w", role, e.Path, err)
		}
		ct, err := dataplane.Encrypt(content, dataKey)
		if err != nil {
			return chain.IntelligentData{}, fmt.Errorf("encrypt %s entry %s: %w", role, e.Path, err)
		}
		root, err := u.storage.Upload(ctx, ct)
		if err != nil {
			return chain.IntelligentData{}, fmt.Errorf("upload %s entry %s: %w", role, e.Path, err)
		}
		e.StoragePtr = manifest.StoragePtr{
			RootHash: "0x" + hex.EncodeToString(root[:]),
			Size:     len(ct),
		}
		fresh++
	}

	// Marshal with all storage_ptrs filled in. This is the "stored" form
	// (what goes into 0g-storage); distinct from the drift form (empty
	// storage_ptrs) the watcher hashes.
	filled, err := newManifest.Marshal()
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("marshal filled manifest for %s: %w", role, err)
	}
	mCT, err := dataplane.Encrypt(filled, dataKey)
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("encrypt manifest for %s: %w", role, err)
	}
	mRoot, err := u.storage.Upload(ctx, mCT)
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("upload manifest for %s: %w", role, err)
	}

	descJSON, err := json.Marshal(onChainDescription{
		Role: role,
		StoragePtr: storagePtr{
			RootHash: "0x" + hex.EncodeToString(mRoot[:]),
			Indexer:  u.indexerURL,
			Size:     len(mCT),
		},
		Encryption: "AES-GCM-256",
	})
	if err != nil {
		return chain.IntelligentData{}, fmt.Errorf("marshal dataDescription: %w", err)
	}
	return chain.IntelligentData{
		DataDescription: string(descJSON),
		DataHash:        mRoot,
	}, nil
}

// fetchOldManifest downloads the prior manifest blob referenced by
// oldEntry and decrypts it with the role's data_key. Returns the parsed
// Manifest so pushManifest can look up per-entry storage_ptrs for reuse.
func (u *Uploader) fetchOldManifest(
	ctx context.Context,
	oldEntry *chain.IntelligentData,
	dataKey []byte,
) (*manifest.Manifest, error) {
	root, err := rootOf(oldEntry.DataDescription)
	if err != nil {
		return nil, err
	}
	ciphertext, err := u.storage.Download(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("download manifest blob: %w", err)
	}
	plaintext, err := dataplane.Decrypt(ciphertext, dataKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest blob: %w", err)
	}
	return manifest.Unmarshal(plaintext)
}
