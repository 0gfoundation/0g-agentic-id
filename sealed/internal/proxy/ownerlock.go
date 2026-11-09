package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/logger"
)

// The container serves the owner it was started for. When the chain says the
// agent belongs to someone else (it was transferred), the container stops
// serving it: the new owner runs the agent in a container of their own (a
// reset), and the previous owner's container must not let the new owner
// steer an agent that may still hold what the previous owner gave it. The
// lock follows the chain: should the agent come back to the owner the
// container was started for, it opens again.
type ownerLock struct {
	mu     sync.Mutex
	boot   string // the owner the container was started for, lower-case hex
	locked bool
}

// lockExempt are the routes a locked container still serves: liveness, the
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
// container is locked now, and whether that changed.
func (s *Server) ObserveOwner(owner string) (locked, changed bool) {
	if owner == "" {
		return s.OwnerLocked(), false
	}
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	if s.lock.boot == "" {
		s.lock.boot = strings.ToLower(owner)
	}
	now := !strings.EqualFold(owner, s.lock.boot)
	changed = now != s.lock.locked
	s.lock.locked = now
	return now, changed
}

// OwnerLocked reports whether the agent belongs to someone other than the
// owner the container was started for.
func (s *Server) OwnerLocked() bool {
	s.lock.mu.Lock()
	defer s.lock.mu.Unlock()
	return s.lock.locked
}

// WatchOwner asks the chain for the owner every interval, so a transfer locks
// the container within one interval even when nobody calls an owner route.
// onChange is told each time the lock closes or opens, whichever lookup (this
// one or an owner route's) found it.
func (s *Server) WatchOwner(ctx context.Context, interval time.Duration, onChange func(locked bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	reported := false
	for {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		owner, ok := s.resolveOwner(lctx, "")
		cancel()
		if ok {
			if locked, _ := s.ObserveOwner(owner); locked != reported {
				reported = locked
				if locked {
					logger.Logf("owner: the agent now belongs to another owner; this container no longer serves it")
				} else {
					logger.Logf("owner: the agent is back with the owner this container was started for")
				}
				if onChange != nil {
					onChange(locked)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ownerGate refuses every route but lockExempt while the container is locked.
func (s *Server) ownerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.OwnerLocked() && !lockExempt[r.URL.Path] {
			writeOwnerLocked(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeOwnerLocked(w http.ResponseWriter) {
	writeJSON(w, http.StatusLocked, map[string]string{
		"code":    "owner_changed",
		"message": "this agent now belongs to another owner, and this container no longer serves it; the owner resets the agent to run it",
	})
}
