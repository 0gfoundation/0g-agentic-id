package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// ── severityOf ─────────────────────────────────────────────────────────────

func TestSeverityOf_NilIsRunning(t *testing.T) {
	if got := severityOf(nil); got != "running" {
		t.Errorf("severityOf(nil) = %q; want running", got)
	}
}

func TestSeverityOf_InsufficientFundsIsWarning(t *testing.T) {
	// The 0g-storage CLI raises "Failed to submit log entry: Failed to send
	// transaction to append log entry: failed to send transaction:
	// insufficient funds for transfer" — the substring "insufficient funds"
	// is the stable signal.
	err := errors.New("upload openclaw.json: upload cmd: exit status 1: " +
		"Failed to submit log entry: insufficient funds for transfer")
	if got := severityOf(err); got != "warning" {
		t.Errorf("severityOf(insufficient funds err) = %q; want warning", got)
	}
}

func TestSeverityOf_InsufficientBalanceIsWarning(t *testing.T) {
	// Some chains say "insufficient balance" instead.
	err := errors.New("rpc error: insufficient balance for transaction fee")
	if got := severityOf(err); got != "warning" {
		t.Errorf("severityOf(insufficient balance err) = %q; want warning", got)
	}
}

func TestSeverityOf_CaseInsensitive(t *testing.T) {
	// Some upstreams shout. Make sure casing doesn't sneak past the matcher.
	err := errors.New("INSUFFICIENT FUNDS FOR TRANSFER")
	if got := severityOf(err); got != "warning" {
		t.Errorf("severityOf(uppercase err) = %q; want warning", got)
	}
}

func TestSeverityOf_GasExhaustedBareRevertIsWarning(t *testing.T) {
	// A near-empty seal wallet can fail as a data-less revert rather than
	// "insufficient funds": eth_estimateGas caps the gas budget at what the
	// balance affords, execution runs out mid-way. Reproduced against a
	// real 0.0008 OG balance.
	err := errors.New("Failed to submit file: Failed to send transaction to append log entry: " +
		"failed to send transaction: execution reverted; data: 0x")
	if got := severityOf(err); got != "warning" {
		t.Errorf("severityOf(gas-exhausted bare revert) = %q; want warning", got)
	}
}

func TestSeverityOf_GenericErrorIsError(t *testing.T) {
	// Unknown / system-level errors stay "error" so the 5-failure escalation
	// still defends against silent system failures.
	for _, msg := range []string{
		"connection refused",
		"chain reverted: nonce too low",
		"openclaw not responding",
		"tee attestation expired",
		"",
	} {
		err := errors.New(msg)
		if got := severityOf(err); got != "error" {
			t.Errorf("severityOf(%q) = %q; want error", msg, got)
		}
	}
}

// ── summarizeError ─────────────────────────────────────────────────────────

func TestSummarizeError_NilIsEmpty(t *testing.T) {
	if got := summarizeError(nil); got != "" {
		t.Errorf("summarizeError(nil) = %q; want \"\"", got)
	}
}

func TestSummarizeError_SingleLinePassthrough(t *testing.T) {
	err := errors.New("connection refused")
	if got := summarizeError(err); got != "connection refused" {
		t.Errorf("summarizeError(single-line) = %q; want passthrough", got)
	}
}

func TestSummarizeError_MultilineKeepsLastNonEmpty(t *testing.T) {
	// Mimics the 0g-storage CLI's multi-line output: many INFO/WARN
	// lines, then the final FATA on terminal failure. We want the FATA.
	raw := "INFO[2026-05-15T02:18:36Z] Selecting nodes ...\n" +
		"INFO[2026-05-15T02:18:38Z] submit with fee fee(neuron)=122934579848\n" +
		"WARN[2026-05-15T02:18:39Z] Upload failed, retrying error=\"...\"\n" +
		"FATA[2026-05-15T02:18:45Z] Failed to upload file error=\"insufficient funds for transfer\"\n"
	err := errors.New(raw)
	got := summarizeError(err)
	if !strings.HasPrefix(got, "FATA") {
		t.Errorf("summarizeError multiline:\n got %q\n want a line starting with FATA", got)
	}
	if !strings.Contains(got, "insufficient funds") {
		t.Errorf("summarizeError dropped the actual cause: %q", got)
	}
}

func TestSummarizeError_TrailingBlanksIgnored(t *testing.T) {
	err := errors.New("real cause\n\n   \n")
	if got := summarizeError(err); got != "real cause" {
		t.Errorf("summarizeError(trailing blanks) = %q; want \"real cause\"", got)
	}
}

// ── runtimeStatus ──────────────────────────────────────────────────────────

func TestRuntimeStatus_DefaultIsRunning(t *testing.T) {
	s := &runtimeStatus{level: "running"}
	level, msg := s.Get()
	if level != "running" || msg != "" {
		t.Errorf("default status = (%q, %q); want (running, \"\")", level, msg)
	}
}

func TestRuntimeStatus_SetReturnsPrevious(t *testing.T) {
	s := &runtimeStatus{level: "running"}
	if prev := s.Set("warning", "needs funds"); prev != "running" {
		t.Errorf("Set returned %q; want running", prev)
	}
	if prev := s.Set("warning", "needs funds"); prev != "warning" {
		t.Errorf("re-Set returned %q; want warning (no transition)", prev)
	}
	if prev := s.Set("running", ""); prev != "warning" {
		t.Errorf("recover Set returned %q; want warning", prev)
	}
}

func TestRuntimeStatus_GetReflectsLatestSet(t *testing.T) {
	s := &runtimeStatus{level: "running"}
	s.Set("error", "openclaw exit")
	level, msg := s.Get()
	if level != "error" || msg != "openclaw exit" {
		t.Errorf("Get = (%q, %q); want (error, openclaw exit)", level, msg)
	}
}

func TestRuntimeStatus_ConcurrentSetGetSafe(t *testing.T) {
	// Race-detector test: Set and Get from many goroutines should not
	// trip the race detector. (Run with `go test -race`.)
	s := &runtimeStatus{level: "running"}
	const N = 200
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				s.Set("warning", "x")
			} else {
				s.Set("running", "")
			}
		}(i)
		go func() {
			defer wg.Done()
			_, _ = s.Get()
		}()
	}
	wg.Wait()
}
