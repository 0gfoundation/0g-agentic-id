package main

import (
	"strings"
	"sync"
)

// Runtime status reporting model.
//
// sealed's `/status` reports to attestor used to be a binary running/error
// flag driven by two separate sources: handleDrift posted "error" on
// 5 consecutive upload.Apply failures, and runHeartbeat unconditionally
// re-posted "running" every 5 minutes — so a real error would get
// silently overwritten by the next heartbeat.
//
// This file introduces a 3-level severity model that both sources read
// from / write to as a single source of truth:
//
//	running   all good (default)
//	warning   owner-recoverable condition, agent itself is operational
//	          (e.g., agent wallet has insufficient funds for the
//	          drift-publish transaction — only owner can fix by funding
//	          the address)
//	error     genuine system failure, owner can't act on it directly
//	          (sealed / openclaw / 0G chain / attestor link broken)
//
// Heartbeat now reflects current state instead of hard-coding "running",
// and handleDrift uses the severity classifier to decide whether to
// escalate immediately (warning, first occurrence) or after the
// 5-failure threshold (error, defended against transient blips).

// runtimeStatus is the single source of truth for what the next /status
// report (drift, heartbeat, or recovery) should declare. Zero value is
// {"running", ""} which matches the implicit pre-refactor behaviour.
type runtimeStatus struct {
	mu      sync.Mutex
	level   string // "running" | "warning" | "error"
	message string
	// pinned is an owner-recoverable condition that no runtime event
	// clears for the life of this boot (today: an owner-supplied sealed
	// key that did not apply, so the agent cannot call its model). While
	// the runtime itself is "running", it shows as a "warning" with this
	// message, so a later drift success or heartbeat cannot report the
	// agent healthy. A real warning or error still takes precedence.
	pinned string
}

var currentStatus = &runtimeStatus{level: "running"}

// effective is what a /status report should declare. Caller holds mu.
func (s *runtimeStatus) effective() (string, string) {
	if s.level == "running" && s.pinned != "" {
		return "warning", s.pinned
	}
	return s.level, s.message
}

// Get returns the current effective level + message snapshot.
func (s *runtimeStatus) Get() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effective()
}

// Set replaces the current level + message. Returns the previous
// effective level so callers can decide whether the transition warrants
// pushing a /status report immediately (rather than waiting for the next
// heartbeat); they report Get(), which accounts for a pinned warning.
func (s *runtimeStatus) Set(level, message string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, _ := s.effective()
	s.level = level
	s.message = message
	return prev
}

// Pin sets (or, with "", clears) the pinned warning described on
// runtimeStatus. The message must carry no secret values.
func (s *runtimeStatus) Pin(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned = message
}

// severityOf classifies a runtime error into one of the 3 severity
// levels. Owner-recoverable conditions (insufficient funds, etc.) are
// "warning" so the UI can prompt the owner to act without escalating
// the alarm; everything else is "error" by default (defensive — we'd
// rather false-alarm than silently miss a real failure).
//
// nil error → "running" (caller's success path).
func severityOf(err error) string {
	if err == nil {
		return "running"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "insufficient funds"),
		strings.Contains(s, "insufficient balance"):
		return "warning"
	// A near-empty seal wallet doesn't always fail as "insufficient
	// funds" — eth_estimateGas can cap the gas budget at what the
	// balance affords, and execution then runs out of gas mid-way,
	// surfacing as a bare, reasonless revert. The only caller of
	// severityOf is upload.Apply's drift-publish tx (signed by this
	// agent's own seal wallet), so a data-less revert here is the same
	// owner-recoverable condition as the funds-check above, just a
	// different shape. Confirmed by reproducing byte-for-byte against a
	// 0.0008 OG balance (fails) vs 0.0058 OG (succeeds) with the same
	// 0g-storage-client build and params.
	case strings.Contains(s, "execution reverted; data: 0x"):
		return "warning"
	// Future owner-recoverable patterns slot in here without changing
	// the rest of the pipeline:
	//   strings.Contains(s, "api key") → bad/expired LLM provider key
	//   strings.Contains(s, "rate limit") → provider throttling
	//   strings.Contains(s, "quota") → provider quota exhausted
	default:
		return "error"
	}
}

// summarizeError trims long multi-line error strings (in particular
// 0g-storage CLI output that interleaves INFO / WARN / FATA lines)
// down to the single most informative line. The full error is still
// in the sealed log; this is what we hand to the attestor / UI.
//
// Heuristic: pick the last non-empty line of the error string. The
// 0g-storage CLI prints `FATA[...] Failed to upload file error="..."`
// as the final line on terminal failure, which is exactly what owners
// need to see.
func summarizeError(err error) string {
	if err == nil {
		return ""
	}
	raw := err.Error()
	// Fast path: single-line errors don't need trimming.
	if !strings.Contains(raw, "\n") {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return raw
}
