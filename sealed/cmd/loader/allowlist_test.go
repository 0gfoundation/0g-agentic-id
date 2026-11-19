package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

func keccakHex(s string) string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func TestSelectorsAndKind(t *testing.T) {
	for want, sig := range map[string]string{
		trustRegistrySelector: "trustRegistry()",
		isListedSelector:      "isListed(bytes32,bytes32)",
		listedSelector:        "listed(bytes32)",
	} {
		if got := keccakHex(sig)[:8]; got != want {
			t.Fatalf("%s selector %s, want %s", sig, got, want)
		}
	}
	if got := keccakHex("sealed"); got != sealedKind {
		t.Fatalf("SEALED kind %s, want %s", got, sealedKind)
	}
}

// The AgenticID and trust registry fakeRPC serves.
const (
	fakeAgenticID = "0x00000000000000000000000000000000000000a9"
	fakeRegistry  = "0x00000000000000000000000000000000000000b0"
)

// fakeRPC answers AgenticID.trustRegistry() with fakeRegistry (a JSON-RPC
// error when order is nil, as an AgenticID before 1.4.0 reverts), the
// registry's listed(SEALED) with order, and its isListed(SEALED, hash) with
// whether order holds hash.
func fakeRPC(t *testing.T, order []string) *httptest.Server {
	t.Helper()
	reverted := `{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &req) != nil || req.Method != "eth_call" || len(req.Params) != 2 {
			http.Error(w, "bad request", 400)
			return
		}
		var call struct{ To, Data string }
		_ = json.Unmarshal(req.Params[0], &call)
		answer := func(result string) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x`+result+`"}`)
		}
		switch {
		case strings.EqualFold(call.To, fakeAgenticID) && call.Data == "0x"+trustRegistrySelector:
			if order == nil {
				_, _ = io.WriteString(w, reverted)
				return
			}
			answer(strings.Repeat("0", 24) + strings.TrimPrefix(fakeRegistry, "0x"))
		case strings.EqualFold(call.To, fakeRegistry) && call.Data == "0x"+listedSelector+sealedKind:
			answer(encodeBytes32Array(order))
		case strings.EqualFold(call.To, fakeRegistry) && strings.HasPrefix(call.Data, "0x"+isListedSelector+sealedKind):
			h := strings.TrimPrefix(call.Data, "0x"+isListedSelector+sealedKind)
			v := "0"
			for _, x := range order {
				if x == h {
					v = "1"
				}
			}
			answer(strings.Repeat("0", 63) + v)
		default:
			_, _ = io.WriteString(w, reverted)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// encodeBytes32Array is the ABI encoding of a bytes32[] return, as hex.
func encodeBytes32Array(hashes []string) string {
	return fmt.Sprintf("%064x%064x%s", 32, len(hashes), strings.Join(hashes, ""))
}

func TestAllowlistAnswers(t *testing.T) {
	a1, a2, other := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32)
	l := newAllowlist(fakeRPC(t, []string{a1, a2}).URL, fakeAgenticID)
	if got, err := l.listed(); err != nil || !reflect.DeepEqual(got, []string{a1, a2}) {
		t.Fatalf("listed: %v %v", got, err)
	}
	if refused, err := l.refuses(a2); refused || err != nil {
		t.Fatalf("listed one: %v %v", refused, err)
	}
	if refused, err := l.refuses(other); !refused || err != nil {
		t.Fatalf("one not listed: %v %v", refused, err)
	}
	if got, err := newAllowlist(fakeRPC(t, []string{}).URL, fakeAgenticID).listed(); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	if newAllowlist("", fakeAgenticID) != nil || newAllowlist(fakeRPC(t, nil).URL, "") != nil {
		t.Fatal("an allowlist without its endpoint or contract")
	}
	// Without its endpoint the list cannot be read: no answer.
	var none *allowlist
	if _, err := none.listed(); err == nil {
		t.Fatal("no allowlist: an answer")
	}
	if refused, err := none.refuses(a1); refused || err == nil {
		t.Fatalf("no allowlist: %v %v", refused, err)
	}
	// An AgenticID before 1.4.0 names no trust registry: no answer either.
	pre := newAllowlist(fakeRPC(t, nil).URL, fakeAgenticID)
	if _, err := pre.listed(); err == nil || !strings.Contains(err.Error(), "1.4.0") {
		t.Fatalf("no trust registry: %v", err)
	}
	if refused, err := pre.refuses(a1); refused || err == nil {
		t.Fatalf("no trust registry: %v %v", refused, err)
	}
}

func TestDecodeBytes32Array(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for name, in := range map[string]string{
		"short":        strings.Repeat("0", 63),
		"bad offset":   fmt.Sprintf("%064x%064x%s", 64, 1, h),
		"bad length":   fmt.Sprintf("%064x%064x%s", 32, 2, h),
		"too many":     fmt.Sprintf("%064x%064x", 32, maxListed+1),
		"not in words": fmt.Sprintf("%064x%064x%s00", 32, 1, h),
	} {
		b, _ := hex.DecodeString(in)
		if _, err := decodeBytes32Array(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	b, _ := hex.DecodeString(encodeBytes32Array([]string{h, h}))
	if got, err := decodeBytes32Array(b); err != nil || !reflect.DeepEqual(got, []string{h, h}) {
		t.Fatalf("%v %v", got, err)
	}
}

// On a chain whose AgenticID names no trust registry nothing runs, and the
// log says what the image needs.
func TestRunWaitsOnAChainWithoutTheTrustRegistry(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	a, ab := f.version(t, "\nA\n")
	f.staged(t, a, ab)
	f.write(t, "current", a)
	f.write(t, "confirmed", a)
	f.s.allow = newAllowlist(fakeRPC(t, nil).URL, fakeAgenticID)
	done := runAsync(f.s)
	for !f.logs.has("1.4.0") {
		time.Sleep(5 * time.Millisecond)
	}
	f.sigs <- syscall.SIGTERM
	if code := waitCode(t, done); code != 128+int(syscall.SIGTERM) {
		t.Fatalf("exit code %d, want %d", code, 128+int(syscall.SIGTERM))
	}
	if got := f.report(); got != nil {
		t.Fatalf("ran %q", got)
	}
}

// Through the chain reads: a version the chain does not list does not run,
// the listed one does.
func TestRunSkipsWhatTheChainDoesNotList(t *testing.T) {
	f := newFixture(t, "report", 5*time.Second)
	x, xb := f.version(t, "\nX\n")
	a, _ := f.version(t, "\nA\n")
	f.staged(t, x, xb)
	f.write(t, "current", x)
	f.write(t, "confirmed", x)
	f.s.allow = newAllowlist(fakeRPC(t, []string{a}).URL, fakeAgenticID)
	if code := f.stopWhenReady(t, runAsync(f.s)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := f.report(); !reflect.DeepEqual(got, []string{a + " 1"}) {
		t.Fatalf("ran %q, want the listed version", got)
	}
}
