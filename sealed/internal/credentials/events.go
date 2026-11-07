package credentials

import (
	"context"
	"sync"
	"time"
)

// Event tells the harness something changed: a pending request was decided,
// an entry came or went, a writeback failed.
type Event struct {
	Seq       uint64 `json:"seq"`
	Type      string `json:"type"`
	Name      string `json:"name,omitempty"`
	AuthReqID string `json:"auth_req_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Time      int64  `json:"ts"`
}

const eventKeep = 256

// eventLog keeps the last events and wakes long-polling readers.
type eventLog struct {
	mu     sync.Mutex
	seq    uint64
	items  []Event
	notify chan struct{}
}

func newEventLog() *eventLog { return &eventLog{notify: make(chan struct{})} }

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	l.seq++
	e.Seq, e.Time = l.seq, time.Now().Unix()
	l.items = append(l.items, e)
	if len(l.items) > eventKeep {
		l.items = l.items[len(l.items)-eventKeep:]
	}
	close(l.notify)
	l.notify = make(chan struct{})
	l.mu.Unlock()
}

func (l *eventLog) since(after uint64) ([]Event, chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.items {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out, l.notify
}

// wait returns the events after seq, blocking up to d for the first one.
func (l *eventLog) wait(ctx context.Context, after uint64, d time.Duration) []Event {
	out, ch := l.since(after)
	if len(out) > 0 || d <= 0 {
		return out
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
	}
	out, _ = l.since(after)
	return out
}
