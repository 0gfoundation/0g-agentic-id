package uploader

import (
	"crypto/sha256"
	"sync"

	"seal-verify/internal/chain"
	"seal-verify/internal/manifest"
)

// uploadedBlobs remembers, for this boot, every blob this uploader put in
// 0g-storage (or found in a committed manifest), by the data key that
// encrypted it and the plaintext it holds, so content that comes back is
// committed by reference instead of uploaded again.
//
// Content comes back: a memory the agent adds and then removes leaves the
// role exactly as an earlier commit had it, but that commit is no longer the
// one on chain, so neither the in-sync check (the chain's current content)
// nor the per-entry reuse of the chain's current manifest finds it, and
// pendingUploads keeps only what failed attempts uploaded. The blobs were
// encrypted afresh (a new nonce, so a new root that the storage client's
// skip-if-present cannot recognize) and submitted again (dev agent 625,
// 2026-11-18: memory/ went back to the content committed at 12:17 at
// 12:23, and its entry and manifest blobs were submitted again).
//
// A blob is reused only under the key that encrypted it: a role's key is the
// one sealed on chain for it (or minted for its first commit), and a role
// whose key changes (dropped and added again, or committed from elsewhere
// with another key) starts over. What is remembered, per role:
//
//   - each manifest entry blob, by the sha256 of its plaintext (the entry's
//     ContentHash), whatever path it was at;
//   - each leaf role's entry, by its plaintext's sha256;
//   - each manifest role's entry, by the sha256 of the filled manifest (with
//     every storage pointer in it), so a manifest identical to one uploaded
//     before is not uploaded again.
//
// It lives in memory only, at most maxRememberedPerRole items per role, and
// is dropped when commits stop (an owner change), like pendingUploads.
type uploadedBlobs struct {
	mu    sync.Mutex
	roles map[string]*roleBlobs
}

type roleBlobs struct {
	key     [32]byte // sha256 of the data key the blobs are encrypted with
	entries map[string]manifest.StoragePtr
	whole   map[string]chain.IntelligentData
}

// maxRememberedPerRole bounds what one role keeps; past it the role starts
// over, which costs at most one upload of content that comes back.
const maxRememberedPerRole = 512

func keyID(dataKey []byte) [32]byte { return sha256.Sum256(dataKey) }

// forRole returns role's items for key, starting the role over when its key
// changed. Caller holds mu.
func (u *uploadedBlobs) forRole(role string, key [32]byte) *roleBlobs {
	if u.roles == nil {
		u.roles = map[string]*roleBlobs{}
	}
	r := u.roles[role]
	if r == nil || r.key != key || len(r.entries)+len(r.whole) >= maxRememberedPerRole {
		r = &roleBlobs{key: key, entries: map[string]manifest.StoragePtr{}, whole: map[string]chain.IntelligentData{}}
		u.roles[role] = r
	}
	return r
}

// entry returns the blob holding a manifest entry's content, encrypted
// with key.
func (u *uploadedBlobs) entry(role string, key [32]byte, contentHash string) (manifest.StoragePtr, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.roles[role]
	if r == nil || r.key != key {
		return manifest.StoragePtr{}, false
	}
	p, ok := r.entries[contentHash]
	return p, ok
}

func (u *uploadedBlobs) keepEntry(role string, key [32]byte, contentHash string, p manifest.StoragePtr) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.forRole(role, key).entries[contentHash] = p
}

// whole returns the entry built before, under key, for a leaf role's
// plaintext or a manifest role's filled manifest with this sha256.
func (u *uploadedBlobs) whole(role string, key [32]byte, sum string) (chain.IntelligentData, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.roles[role]
	if r == nil || r.key != key {
		return chain.IntelligentData{}, false
	}
	e, ok := r.whole[sum]
	return e, ok
}

func (u *uploadedBlobs) keepWhole(role string, key [32]byte, sum string, e chain.IntelligentData) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.forRole(role, key).whole[sum] = e
}

// reset drops everything (commits stopped: an owner change).
func (u *uploadedBlobs) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.roles = nil
}
