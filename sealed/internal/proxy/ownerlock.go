package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/logger"
)

// The container serves the owner it was started for. When the chain says the
// agent belongs to someone else (it was transferred), the container closes
// for good: the new owner runs the agent in a container of their own (a
// reset), and the previous owner's container must not let the new owner
// steer an agent that may still hold what the previous owner gave it, nor
// keep acting as the agent. A closed container does not open again, even if
// the agent comes back: by then another container may be writing its state.
type ownerLock struct {
	mu      sync.Mutex
	boot    string // the owner the container was started for, lower-case hex
	locked  bool
	next    uint64
	cancels map[uint64]context.CancelFunc // requests in flight, ended when the lock closes
}

// lockExempt are the routes a closed container still serves: liveness, the
// public status log and the agent's public identity.
var lockExempt = map[string]bool{"/healthz": true, "/log": true, "/log.html": true, "/hello": true}

// SetBootOwner records the owner the container was started for. Empty (the
// bootstrap lookup failed) leaves it to the first owner the chain answers.
func (s *Server) SetBootOwner(owner string) {
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	if owner != "" && s.lock.boot == "" {
		s.lock.boot = strings.ToLower(owner)
	}
}

// ObserveOwner records the owner the chain answered and reports whether the
// container is closed now, and whether this answer closed it. Closing ends
// every request in flight (streams and upgraded connections included) and
// tells the credential store, which then clears the previous owner's state.
func (s *Server) ObserveOwner(owner string) (locked, changed bool) {
	if owner == "" {
		return s.OwnerLocked(), false
	}
	s.lock.mu.Lock()
	if s.lock.boot == "" {
		s.lock.boot = strings.ToLower(owner)
	}
	if s.lock.locked || strings.EqualFold(owner, s.lock.boot) {
		locked = s.lock.locked
		s.lock.mu.Unlock()
		return locked, false
	}
	s.lock.locked = true
	cancels := s.lock.cancels
	s.lock.cancels = nil
	s.lock.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	s.mu.RLock()
	c := s.credentials
	s.mu.RUnlock()
	if c != nil {
		c.ObserveOwnerLookup(c.BeginOwnerLookup(), common.HexToAddress(owner))
	}
	return true, true
}

// OwnerLocked reports whether the agent was found to belong to someone other
// than the owner the container was started for.
func (s *Server) OwnerLocked() bool {
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	return s.lock.locked
}

// WatchOwner asks the chain for the owner every interval, so a transfer
// closes the container within one interval even when nobody calls an owner
// route. onClose is told once, whichever lookup (this one or an owner
// route's) closed it.
func (s *Server) WatchOwner(ctx context.Context, interval time.Duration, onClose func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		owner, ok := s.resolveOwner(lctx, "")
		cancel()
		if ok {
			if locked, _ := s.ObserveOwner(owner); locked {
				logger.Logf("owner: the agent now belongs to another owner; this container no longer serves it")
				if onClose != nil {
					onClose()
				}
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ownerGate refuses every route but lockExempt once the container is closed,
// and ends a request still in flight when it closes.
func (s *Server) ownerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lockExempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		s.lock.mu.Lock()
		if s.lock.locked {
			s.lock.mu.Unlock()
			writeOwnerLocked(w)
			return
		}
		if s.lock.cancels == nil {
			s.lock.cancels = map[uint64]context.CancelFunc{}
		}
		s.lock.next++
		id := s.lock.next
		s.lock.cancels[id] = cancel
		s.lock.mu.Unlock()
		defer func() {
			s.lock.mu.Lock()
			delete(s.lock.cancels, id)
			s.lock.mu.Unlock()
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeOwnerLocked(w http.ResponseWriter) {
	writeJSON(w, http.StatusLocked, map[string]string{
		"code":    "owner_changed",
		"message": "this agent now belongs to another owner, and this container no longer serves it; the owner resets the agent to run it",
	})
}
