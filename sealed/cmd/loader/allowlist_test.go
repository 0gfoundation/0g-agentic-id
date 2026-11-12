package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
// error when listed is nil, as an AgenticID before 1.4.0 reverts) and the
// registry's isListed(SEALED, hash) from listed: true, false, or absent (an
// error).
func fakeRPC(t *testing.T, listed map[string]bool) *httptest.Server {
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
		switch {
		case strings.EqualFold(call.To, fakeAgenticID) && call.Data == "0x"+trustRegistrySelector:
			if listed == nil {
				_, _ = io.WriteString(w, reverted)
				return
			}
			word := strings.Repeat("0", 24) + strings.TrimPrefix(fakeRegistry, "0x")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x`+word+`"}`)
		case strings.EqualFold(call.To, fakeRegistry) && strings.HasPrefix(call.Data, "0x"+isListedSelector+sealedKind):
			v, ok := listed[strings.TrimPrefix(call.Data, "0x"+isListedSelector+sealedKind)]
			if !ok {
				_, _ = io.WriteString(w, reverted)
				return
			}
			word := strings.Repeat("0", 63) + map[bool]string{true: "1", false: "0"}[v]
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x`+word+`"}`)
		default:
			_, _ = io.WriteString(w, reverted)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAllowlistAnswers(t *testing.T) {
	listed, delisted, unknown := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32)
	srv := fakeRPC(t, map[string]bool{listed: true, delisted: false})
	a := newAllowlist(srv.URL, fakeAgenticID)
	if refused, err := a.refuses(listed); refused || err != nil {
		t.Fatalf("listed: %v %v", refused, err)
	}
	if refused, err := a.refuses(delisted); !refused || err != nil {
		t.Fatalf("delisted: %v %v", refused, err)
	}
	if refused, err := a.refuses(unknown); refused || err == nil {
		t.Fatalf("no answer: %v %v", refused, err)
	}
	if newAllowlist("", fakeAgenticID) != nil || newAllowlist(srv.URL, "") != nil {
		t.Fatal("an allowlist without its endpoint or contract")
	}
	var none *allowlist
	if refused, err := none.refuses(listed); refused || err != nil {
		t.Fatalf("no allowlist: %v %v", refused, err)
	}
	// An AgenticID before 1.4.0 names no trust registry: no answer, so the
	// version runs.
	pre := newAllowlist(fakeRPC(t, nil).URL, fakeAgenticID)
	if refused, err := pre.refuses(delisted); refused || err == nil {
		t.Fatalf("no trust registry: %v %v", refused, err)
	}
}

// A version the chain says is not listed does not run: the loader falls
// back to the image's own, and runs nothing when that is not listed either.
func TestRunSkipsWhatTheChainDoesNotList(t *testing.T) {
	s, _, _ := helper(t, "exit7", time.Second, true)
	exe, _ := os.Executable()
	b, _ := os.ReadFile(exe)
	b = append(b, []byte("\nstaged\n")...)
	sum := sha256.Sum256(b)
	staged := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(string(s.state), "sealed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.state.staged(staged), b, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.state.write("current", staged); err != nil {
		t.Fatal(err)
	}
	if err := s.state.write("confirmed", staged); err != nil {
		t.Fatal(err)
	}

	s.allow = newAllowlist(fakeRPC(t, map[string]bool{staged: false, s.builtin.hash: true}).URL, fakeAgenticID)
	if code := waitCode(t, runAsync(s)); code != 7 {
		t.Fatalf("exit code %d, want 7 (the image's own, run in place of the delisted one)", code)
	}
	if got := s.state.hash("current"); got != s.builtin.hash {
		t.Fatalf("current %q, want the image's version", got)
	}

	s.allow = newAllowlist(fakeRPC(t, map[string]bool{s.builtin.hash: false}).URL, fakeAgenticID)
	if code := waitCode(t, runAsync(s)); code != 1 {
		t.Fatalf("exit code %d, want 1 (nothing listed, nothing run)", code)
	}
}
