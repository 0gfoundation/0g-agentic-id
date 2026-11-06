package credentials

import (
	"context"
	"errors"
	"testing"
)

// Two sets the owner signed at one version (one the attestor refused, kept
// and served later): only the one loaded first is taken, while running and
// across stop/start.
func TestSecondSetAtOneVersionRefused(t *testing.T) {
	f := newFixture(t)
	s, reg, p := f.store(t, nil, nil)
	ctx := context.Background()
	y := f.doc(t, 3, map[string]string{"github": "ghp_y"})
	x := f.doc(t, 3, map[string]string{"github": "ghp_x", "leaky": "lk_x"})
	if _, err := s.Load(ctx, y, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, x, 0); !errors.Is(err, ErrForked) || !errors.Is(err, ErrStale) {
		t.Fatalf("a second set at version 3 was taken: %v", err)
	}
	if reg.Get("leaky") != nil {
		t.Fatal("the refused set's entry is served")
	}
	// The same set again (a boot after a push) is taken.
	if _, err := s.Load(ctx, y, 0); err != nil {
		t.Fatalf("the loaded set itself was refused: %v", err)
	}
	// A restart: a new store with the persisted mark.
	s2, reg2, _ := f.store(t, nil, nil)
	s2.env.Persist = p
	if _, err := s2.Load(ctx, x, 0); !errors.Is(err, ErrForked) || reg2.Get("leaky") != nil {
		t.Fatalf("after a restart a second set at version 3 was taken: %v", err)
	}
}

// A mark persisted before digests were kept takes the next set at its
// version and records that set's digest.
func TestMarkWithoutDigestLearnsIt(t *testing.T) {
	f := newFixture(t)
	s, _, p := f.store(t, nil, nil)
	p.v = Mark{Epoch: 7, Version: 3}
	ctx := context.Background()
	if _, err := s.Load(ctx, f.doc(t, 3, map[string]string{"github": "ghp_y"}), 0); err != nil {
		t.Fatal(err)
	}
	if p.v.Digest == "" {
		t.Fatal("the digest was not recorded")
	}
	if _, err := s.Load(ctx, f.doc(t, 3, map[string]string{"leaky": "lk_x"}), 0); !errors.Is(err, ErrForked) {
		t.Fatalf("a second set at version 3 was taken: %v", err)
	}
}
