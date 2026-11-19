package uploader

import (
	"sync"

	"seal-verify/internal/chain"
	"seal-verify/internal/manifest"
)

// pendingUploads keeps what a commit that did not reach the chain already
// put in 0g-storage, so the next attempt reuses it instead of paying for it
// again. A commit is one wholesale AgenticID update after a storage upload
// per changed blob; when a later upload or the update fails, the blobs
// uploaded before it were paid for (a storage submit is a transaction) but
// referenced by nothing, and the next tick used to encrypt and upload them
// again under new roots (dev, 2026-11-17: 0.6 OG for one framework blob at
// Galileo's gas price, then the same again on every retry).
//
// What is kept, per role:
//
//   - the data key minted for a role with no chain entry yet: a blob from
//     an earlier attempt is encrypted with it, so the retry must seal the
//     same key into the update (a role already on chain reuses the key
//     sealed there, which does not change between attempts);
//   - the entry built for a leaf role (or a manifest role's manifest blob),
//     for the plaintext it was built from;
//   - each manifest entry blob, for the content hash it holds.
//
// Each item records the basis it was built on: the DataHash of the role's
// chain entry ("" when it has none). A commit from elsewhere that changes
// the role's chain entry changes the basis, and the item is not reused. A
// newer plaintext replaces the item; nothing is kept past a successful
// update, which puts every item on chain.
//
// It lives in memory only, for this boot. The Uploader is built per boot for
// this agent's seal and token, so an item is always one this agent's key
// encrypted for this agent; an owner change stops commits (commitGate) and
// drops it. Keeping it across a restart would mean storing the data keys of
// uncommitted roles at rest, to save at most one re-upload per restart.
type pendingUploads struct {
	mu     sync.Mutex
	keys   map[string]pendingKey
	leaves map[string]pendingEntry
	blobs  map[string]pendingBlob // role + "\x00" + entry path
}

type pendingKey struct{ dataKey, sealedKey []byte }

type pendingEntry struct {
	basis       string
	contentHash string
	entry       chain.IntelligentData
}

type pendingBlob struct {
	basis       string
	contentHash string
	ptr         manifest.StoragePtr
}

func basisOf(chainEntry *chain.IntelligentData) string {
	if chainEntry == nil {
		return ""
	}
	return hexBytes(chainEntry.DataHash[:])
}

// key returns the data key kept for a role with no chain entry, if any.
func (p *pendingUploads) key(role string) (pendingKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.keys[role]
	return k, ok
}

func (p *pendingUploads) keepKey(role string, k pendingKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys == nil {
		p.keys = map[string]pendingKey{}
	}
	p.keys[role] = k
}

// leaf returns the entry built earlier for exactly this role, basis and
// plaintext.
func (p *pendingUploads) leaf(role, basis, contentHash string) (chain.IntelligentData, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.leaves[role]
	if !ok || e.basis != basis || e.contentHash != contentHash {
		return chain.IntelligentData{}, false
	}
	return e.entry, true
}

func (p *pendingUploads) keepLeaf(role, basis, contentHash string, entry chain.IntelligentData) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.leaves == nil {
		p.leaves = map[string]pendingEntry{}
	}
	p.leaves[role] = pendingEntry{basis: basis, contentHash: contentHash, entry: entry}
}

// blob returns the storage pointer of a manifest entry blob uploaded earlier
// for exactly this role, path, basis and content.
func (p *pendingUploads) blob(role, path, basis, contentHash string) (manifest.StoragePtr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.blobs[role+"\x00"+path]
	if !ok || b.basis != basis || b.contentHash != contentHash {
		return manifest.StoragePtr{}, false
	}
	return b.ptr, true
}

func (p *pendingUploads) keepBlob(role, path, basis, contentHash string, ptr manifest.StoragePtr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blobs == nil {
		p.blobs = map[string]pendingBlob{}
	}
	p.blobs[role+"\x00"+path] = pendingBlob{basis: basis, contentHash: contentHash, ptr: ptr}
}

// reset drops everything: after a successful update (all of it is on chain
// now) and when commits stop (an owner change).
func (p *pendingUploads) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys, p.leaves, p.blobs = nil, nil, nil
}
