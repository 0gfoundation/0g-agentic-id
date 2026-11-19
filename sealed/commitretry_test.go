package main

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/uploader"
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
	level, msg := commitFailureStatus(funds, 1, "")
	if level != "warning" || !strings.Contains(msg, "insufficient funds") || !strings.HasPrefix(msg, "agent data not committed to chain") {
		t.Errorf("unfunded wallet: %q %q", level, msg)
	}
	other := errors.New("uploader.Apply: upload APPEND_SYSTEM.md: 0g-storage upload: Failed to submit log entry: execution reverted")
	for n := 1; n <= 40; n++ {
		level, msg := commitFailureStatus(other, n, "")
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

// ogWei is n/1000 OG in wei.
func ogWei(milli int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(milli), big.NewInt(1_000_000_000_000_000))
}

var (
	sealWallet = common.HexToAddress("0x29e1Cf672CD426ee02DD83ba4498aBbA7DED2a18")
	reverted   = errors.New("uploader.Apply: upload memory/ entry a.md: 0g-storage upload: Failed to submit log entry: execution reverted")
	// 450k gas at Galileo's 2000 gwei.
	submitAt2000 = new(big.Int).Mul(big.NewInt(uploader.StorageSubmitGas), big.NewInt(2000_000_000_000))
)

func readsWallet(balance *big.Int) func(context.Context, error) (uploader.WalletFunds, error) {
	return func(context.Context, error) (uploader.WalletFunds, error) {
		return uploader.WalletFunds{Address: sealWallet, Balance: balance, Need: submitAt2000}, nil
	}
}

// The dev case (625, 2026-11-17): 0.1041 OG against a submit needing ~0.9 OG
// at 2000 gwei, failing as a bare revert. It warns at the first failure and
// says how much the wallet has and needs.
func TestRevertedCommitWithAShortWalletWarnsAtOnce(t *testing.T) {
	short := fundsShortfall(context.Background(), readsWallet(ogWei(104)), reverted)
	for _, want := range []string{sealWallet.Hex(), "has 0.10 OG", "about 0.90 OG is needed"} {
		if !strings.Contains(short, want) {
			t.Errorf("%q lacks %q", short, want)
		}
	}
	level, msg := commitFailureStatus(reverted, 1, short)
	if level != "warning" || msg != short {
		t.Errorf("first failure: %q %q; want the warning at once", level, msg)
	}
}

// A wallet that holds enough leaves the failure to the count rule.
func TestRevertedCommitWithEnoughFundsKeepsTheCountRule(t *testing.T) {
	short := fundsShortfall(context.Background(), readsWallet(ogWei(9798)), reverted)
	if short != "" {
		t.Fatalf("a funded wallet reported short: %q", short)
	}
	if level, _ := commitFailureStatus(reverted, 1, short); level != "" {
		t.Errorf("first failure shown: %q", level)
	}
	if level, msg := commitFailureStatus(reverted, failureEscalateAt, short); level != "warning" || !strings.Contains(msg, "execution reverted") {
		t.Errorf("failure %d: %q %q", failureEscalateAt, level, msg)
	}
}

// A balance that cannot be read changes nothing: the error's own grading
// stands (the count rule; an insufficient-funds error warns at once with its
// own text).
func TestCommitFundsReadFailureFallsBack(t *testing.T) {
	failing := func(context.Context, error) (uploader.WalletFunds, error) {
		return uploader.WalletFunds{}, errors.New("dial tcp: connection refused")
	}
	if short := fundsShortfall(context.Background(), failing, reverted); short != "" {
		t.Errorf("a failed read reported short: %q", short)
	}
	if level, _ := commitFailureStatus(reverted, 1, ""); level != "" {
		t.Errorf("first failure shown after a failed read: %q", level)
	}
	funds := errors.New("0g-storage upload: insufficient funds for gas * price + value: have 0 want 30733644962")
	if short := fundsShortfall(context.Background(), failing, funds); short != "" {
		t.Errorf("a failed read reported short: %q", short)
	}
	if level, msg := commitFailureStatus(funds, 1, ""); level != "warning" || !strings.Contains(msg, "insufficient funds") {
		t.Errorf("an insufficient-funds failure without a balance read: %q %q", level, msg)
	}
}

// An insufficient-funds error is read for too: the owner sees the wallet and
// what a commit needs, not the storage client's "want <storage fee in wei>".
func TestInsufficientFundsShowsTheWalletAndTheNeed(t *testing.T) {
	funds := errors.New("drift: upload.Apply: upload framework: 0g-storage upload: insufficient funds for gas * price + value: have 0 want 30733644962")
	short := fundsShortfall(context.Background(), readsWallet(big.NewInt(0)), funds)
	for _, want := range []string{sealWallet.Hex(), "has 0.00 OG", "about 0.90 OG is needed"} {
		if !strings.Contains(short, want) {
			t.Errorf("%q lacks %q", short, want)
		}
	}
	level, msg := commitFailureStatus(funds, 1, short)
	if level != "warning" || msg != short || strings.Contains(msg, "30733644962") {
		t.Errorf("first failure: %q %q; want the wallet message at once", level, msg)
	}
}

func TestFormatOG(t *testing.T) {
	for wei, want := range map[string]string{"0": "0.00", "5000000000000000": "0.0050", "104100000000000000": "0.10", "900000000000000000": "0.90", "9798229938528504000": "9.80"} {
		n, _ := new(big.Int).SetString(wei, 10)
		if got := formatOG(n); got != want {
			t.Errorf("formatOG(%s) = %s; want %s", wei, got, want)
		}
	}
}
