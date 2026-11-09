package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// chainOwner is a live-owner resolver whose answer a test moves.
type chainOwner struct {
	mu    sync.Mutex
	owner string
}

func (c *chainOwner) set(o string) { c.mu.Lock(); c.owner = o; c.mu.Unlock() }
func (c *chainOwner) get(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.owner, nil
}

func gated(s *Server, path string) int {
	w := httptest.NewRecorder()
	s.ownerGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code
}

// After a transfer the container serves neither owner: the new owner's
// signed request closes it at once, every route but the public ones is
// refused, and a transfer back opens it again.
func TestTransferLocksTheContainer(t *testing.T) {
	_, owner := mustKey(t)
	buyerSign, buyer := mustKey(t)
	s, _ := credServer(t, owner)
	chain := &chainOwner{owner: owner}
	s.SetLiveOwner(chain.get)
	s.SetBootOwner(owner)

	if code := gated(s, "/v1/chat/completions"); code != http.StatusOK {
		t.Fatalf("before the transfer: HTTP %d", code)
	}

	chain.set(buyer)
	w := httptest.NewRecorder()
	s.handleCredentials(w, credReq(buyerSign, http.MethodGet, "/_seal/credentials", "0GSealCredentials", ""))
	if w.Code != http.StatusLocked || !strings.Contains(w.Body.String(), `"owner_changed"`) {
		t.Fatalf("the new owner's request: HTTP %d %s", w.Code, w.Body.String())
	}
	for _, p := range []string{"/v1/chat/completions", "/v1/responses", "/_seal/auth", "/_seal/credentials", "/log/agent", "/api/task", "/sign/personal_sign"} {
		if code := gated(s, p); code != http.StatusLocked {
			t.Fatalf("%s while locked: HTTP %d", p, code)
		}
	}
	for _, p := range []string{"/hello", "/healthz", "/log", "/log.html"} {
		if code := gated(s, p); code != http.StatusOK {
			t.Fatalf("%s while locked: HTTP %d", p, code)
		}
	}

	// Back with the owner the container was started for.
	if locked, changed := s.ObserveOwner(owner); locked || !changed {
		t.Fatalf("after a transfer back: locked %v, changed %v", locked, changed)
	}
	if code := gated(s, "/v1/chat/completions"); code != http.StatusOK {
		t.Fatalf("after a transfer back: HTTP %d", code)
	}
}

// With no owner from the bootstrap lookup, the first one the chain answers
// is the container's.
func TestBootOwnerFromFirstAnswer(t *testing.T) {
	_, owner := mustKey(t)
	_, other := mustKey(t)
	s, _ := credServer(t, owner)
	s.SetBootOwner("")
	if locked, _ := s.ObserveOwner(strings.ToUpper(owner[:2]) + owner[2:]); locked {
		t.Fatal("the first answer locked the container")
	}
	if locked, _ := s.ObserveOwner(other); !locked {
		t.Fatal("another owner did not lock it")
	}
}

// The watcher reports each change once, also one an owner route found first.
func TestWatchOwnerReportsChanges(t *testing.T) {
	_, owner := mustKey(t)
	_, buyer := mustKey(t)
	s, _ := credServer(t, owner)
	chain := &chainOwner{owner: owner}
	s.SetLiveOwner(chain.get)
	s.SetBootOwner(owner)
	changes := make(chan bool, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.WatchOwner(ctx, 5*time.Millisecond, func(locked bool) { changes <- locked })

	chain.set(buyer)
	s.ObserveOwner(buyer) // an owner route saw it first
	if got := <-changes; !got {
		t.Fatal("the lock was not reported")
	}
	chain.set(owner)
	if got := <-changes; got {
		t.Fatal("the opening was not reported")
	}
	select {
	case extra := <-changes:
		t.Fatalf("reported again: %v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}
