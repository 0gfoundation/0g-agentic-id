package credentials

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// An owner route takes its lookup ticket before its signature check looks
// the owner up, so its answer never outranks a lookup begun after it.
func TestRouteLookupTicketTakenFirst(t *testing.T) {
	f := newFixture(t)
	a := crypto.PubkeyToAddress(f.owner.PublicKey)
	bKey, _ := crypto.GenerateKey()
	b := crypto.PubkeyToAddress(bKey.PublicKey)

	var live atomic.Value
	live.Store(a)
	var lookups atomic.Int32
	s, _, _ := f.store(t, nil, nil)
	s.env.LiveOwner = func(context.Context) (common.Address, error) {
		lookups.Add(1)
		return live.Load().(common.Address), nil
	}
	if _, err := s.Load(context.Background(), f.doc(t, 1, map[string]string{"github": "ghp_owner_a_value"}), 0); err != nil {
		t.Fatal(err)
	}

	// 1. A route takes its ticket and looks the owner up: A (the chain
	//    still says A).
	ticket := s.BeginOwnerLookup()
	proxyAnswer := a
	// 2. The agent is transferred; the watcher's lookup begins after the
	//    proxy's and records B.
	live.Store(b)
	if err := s.RefreshOwner(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 3. B loads a set.
	fb := *f
	fb.owner = bKey
	docB := fb.doc(t, 1, map[string]string{"gitlab": "glpat_owner_b_value"})
	docB.Set.OwnerEpoch = 9
	digest, _ := docB.Set.Digest(f.domain)
	docB.Signature = fb.sign(t, digest, bKey)
	if _, err := s.Load(context.Background(), docB, 0); err != nil {
		t.Fatalf("B's set: %v", err)
	}
	if len(s.List()) != 1 {
		t.Fatalf("B's set not loaded: %+v", s.List())
	}
	// 4. The route then records its (older) answer.
	changed := s.ObserveOwnerLookup(ticket, proxyAnswer)

	s.mu.Lock()
	owner := s.owner
	s.mu.Unlock()
	before := lookups.Load()
	freshErr := s.ensureOwner(context.Background())
	after := lookups.Load()
	t.Logf("changed=%v owner=%s (live %s) entries=%d ensureOwner looked up: %v",
		changed, owner.Hex(), b.Hex(), len(s.List()), after != before)
	if changed || owner != b || len(s.List()) != 1 {
		t.Fatalf("an older answer undid a newer lookup: the store's owner is %s (live %s), B's entries left: %d; "+
			"ensureOwner treats it as confirmed (err=%v, looked up again=%v)", owner.Hex(), b.Hex(), len(s.List()), freshErr, after != before)
	}
}
