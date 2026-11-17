package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCommitRetryDelaysDoubleToTheCap(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := delayAfter(i + 1); got != w {
			t.Errorf("after %d failures: %s; want %s", i+1, got, w)
		}
	}
	if got := delayAfter(1000); got != commitRetryMax {
		t.Errorf("after 1000 failures: %s; want the cap %s", got, commitRetryMax)
	}
}

func TestCommitBackoffWaitsOnlyForTheSameContent(t *testing.T) {
	b := &commitBackoff{}
	t0 := time.Unix(1_800_000_000, 0)
	if w, _ := b.Wait(t0, "a"); w != 0 {
		t.Fatalf("no failure yet, wait %s", w)
	}
	if d := b.Failed(t0, "a"); d != 30*time.Second {
		t.Fatalf("first failure: %s", d)
	}
	w, first := b.Wait(t0.Add(10*time.Second), "a")
	if w != 20*time.Second || !first {
		t.Fatalf("10 s after the first failure: wait %s first %v; want 20s true", w, first)
	}
	if _, first := b.Wait(t0.Add(11*time.Second), "a"); first {
		t.Error("the same wait reported as first twice (logged every tick)")
	}
	if w, _ := b.Wait(t0.Add(10*time.Second), "b"); w != 0 {
		t.Errorf("new content waits %s; want 0", w)
	}
	if w, _ := b.Wait(t0.Add(30*time.Second), "a"); w != 0 {
		t.Errorf("at the end of the wait: %s; want 0", w)
	}
	t1 := t0.Add(30 * time.Second)
	if d := b.Failed(t1, "a"); d != time.Minute {
		t.Errorf("second failure of the same content: %s; want 1m", d)
	}
	if _, first := b.Wait(t1.Add(time.Second), "a"); !first {
		t.Error("the wait after a new failure is not reported as first")
	}
	// New content starts the count over.
	if d := b.Failed(t1, "b"); d != 30*time.Second {
		t.Errorf("first failure of new content: %s; want 30s", d)
	}
	b.Succeeded()
	if w, _ := b.Wait(t1.Add(time.Second), "b"); w != 0 {
		t.Errorf("after a success: wait %s", w)
	}
}

func TestDriftKeyIsTheContentOfEveryRole(t *testing.T) {
	a := driftKey(map[string][]byte{"framework": []byte("x"), "memory/": []byte("y")})
	if b := driftKey(map[string][]byte{"memory/": []byte("y"), "framework": []byte("x")}); a != b {
		t.Error("the key depends on map order")
	}
	if b := driftKey(map[string][]byte{"framework": []byte("x"), "memory/": []byte("z")}); a == b {
		t.Error("a content change keeps the key")
	}
	if b := driftKey(map[string][]byte{"framework": []byte("x")}); a == b {
		t.Error("a role's absence keeps the key")
	}
}

// A failing commit never makes the agent an "error" (which the attestor
// shows as offline): it is a warning, at once when the seal wallet cannot
// pay, after failureEscalateAt failures otherwise.
func TestCommitFailureIsAWarningNeverAnError(t *testing.T) {
	funds := errors.New("uploader.Apply: upload framework: 0g-storage upload: insufficient funds for gas * price + value: have 0 want 30733644962")
	level, msg := commitFailureStatus(funds, 1)
	if level != "warning" || !strings.Contains(msg, "insufficient funds") || !strings.HasPrefix(msg, "agent data not committed to chain") {
		t.Errorf("unfunded wallet: %q %q", level, msg)
	}
	other := errors.New("uploader.Apply: upload APPEND_SYSTEM.md: 0g-storage upload: Failed to submit log entry: execution reverted")
	for n := 1; n <= 40; n++ {
		level, msg := commitFailureStatus(other, n)
		if level == "error" {
			t.Fatalf("failure %d graded error: %q", n, msg)
		}
		if n < failureEscalateAt && level != "" {
			t.Errorf("failure %d shown already: %q", n, msg)
		}
		if n >= failureEscalateAt && (level != "warning" || !strings.Contains(msg, "execution reverted")) {
			t.Errorf("failure %d: %q %q", n, level, msg)
		}
	}
}
