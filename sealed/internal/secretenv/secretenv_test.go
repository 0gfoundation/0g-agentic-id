package secretenv

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	eciesgo "github.com/ecies/go/v2"
)

// Well-known test key; its address is 0x2c7536E3605D9C16a7a3D7b1898e529396a65c23.
const testSealPrivHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

const testOwner = "0x00000000000000000000000000000000000000aa"

// sdkVector was produced by the TypeScript SDK (sdk/typescript/src/secretEnv.ts,
// sealSecretEnv) for the test key above, owner testOwner and
// env {"API_KEY":"sk-test-166-vector"}. Opening it here proves the SDK's
// ECIES output is what the container decrypts; the SDK suite checks the same
// vector and format from its side.
const sdkVector = "BN0hd+sQUFej8UU6XRLlP91Y+XWSiNWzsM2vZh7YEbwULf1YF15YNBYp6o0sjXvcg8ZAp2VTkAlKMGMw9YLPbzLvr4U5BclE+mBW9Msb+6AWAc5nk80RKcC0XbexMejxcH2tU5Qh1FTd3sdouF0Fa8MYrCrDK5dOlvwZ79qt0K06fjg+i1spmPFIPR6VlYL7GqoWOFnl2ILscQV6cnDwzzrry4/s1LRkqlpfOG8RF+pFvy9V7u1iPUEvxpAJxrwWZF0Psw=="

func testPriv(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(testSealPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seal encrypts an arbitrary plaintext document to the test key.
func seal(t *testing.T, doc any) string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := eciesgo.Encrypt(eciesgo.NewPrivateKeyFromBytes(testPriv(t)).PublicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func TestOpenSDKVector(t *testing.T) {
	got, err := Open(sdkVector, testPriv(t), testOwner)
	if err != nil {
		t.Fatalf("open SDK vector: %v", err)
	}
	if got.Env["API_KEY"] != "sk-test-166-vector" || len(got.Env) != 1 || len(got.Ignored) != 0 {
		t.Fatalf("unexpected result: %d names, %d ignored", len(got.Env), len(got.Ignored))
	}
}

func TestOpenOwnerMatchIsCaseInsensitive(t *testing.T) {
	enc := seal(t, map[string]any{"v": 1, "owner": "0xAbCdEf0000000000000000000000000000000001", "env": map[string]string{"API_KEY": "k"}})
	if _, err := Open(enc, testPriv(t), "0xabcdef0000000000000000000000000000000001"); err != nil {
		t.Fatalf("checksum case must not matter: %v", err)
	}
}

func TestOpenIgnoresUnsupportedNames(t *testing.T) {
	enc := seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": "k", "Z_TOKEN": "z", "PATH": "/evil"}})
	got, err := Open(enc, testPriv(t), testOwner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Env["API_KEY"] != "k" || len(got.Env) != 1 {
		t.Fatalf("only API_KEY may apply, got %v names", len(got.Env))
	}
	if strings.Join(got.Ignored, ",") != "PATH,Z_TOKEN" {
		t.Fatalf("ignored = %v", got.Ignored)
	}
}

// Every rejection path, with the secret checked absent from the error text
// (errors reach the public /log).
func TestOpenRejects(t *testing.T) {
	const secret = "sk-must-never-appear"
	other, _ := eciesgo.GenerateKey()
	otherCT, _ := eciesgo.Encrypt(other.PublicKey, []byte(`{"v":1,"owner":"`+testOwner+`","env":{"API_KEY":"`+secret+`"}}`))

	cases := []struct {
		name       string
		enc        string
		chainOwner string
		want       string
		reason     string
	}{
		{"empty", "  ", testOwner, "empty", ReasonMalformed},
		{"bad base64", "!!!", testOwner, "base64", ReasonMalformed},
		{"sealed to another agent", base64.StdEncoding.EncodeToString(otherCT), testOwner, "ecies decrypt", ReasonNotSealedToAgent},
		{"previous owner's ciphertext", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": secret}}), "0x00000000000000000000000000000000000000bb", "sealed for owner", ReasonOwnerMismatch},
		{"owner unknown on chain", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": secret}}), "", "on-chain owner unknown", ReasonOwnerUnknown},
		{"future version", seal(t, map[string]any{"v": 2, "owner": testOwner, "env": map[string]string{"API_KEY": secret}}), testOwner, "unsupported version", ReasonUnsupportedVersion},
		{"unknown field", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": secret}, "x": 1}), testOwner, "not a v1", ReasonMalformed},
		{"not an owner address", seal(t, map[string]any{"v": 1, "owner": "alice", "env": map[string]string{"API_KEY": secret}}), testOwner, "owner is not an address", ReasonMalformed},
		{"nothing supported", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"OTHER": secret}}), testOwner, "no supported names", ReasonMalformed},
		{"empty value", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": ""}}), testOwner, "empty or invalid", ReasonMalformed},
		{"NUL in value", seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": secret + "\x00"}}), testOwner, "empty or invalid", ReasonMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Open(c.enc, testPriv(t), c.chainOwner)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
			if got := Reason(err); got != c.reason {
				t.Fatalf("Reason = %q, want %q", got, c.reason)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error text leaks the secret")
			}
		})
	}
}

func TestOpenRejectsShortKey(t *testing.T) {
	_, err := Open(sdkVector, []byte{1, 2, 3}, testOwner)
	if err == nil {
		t.Fatal("a non-32-byte key must be rejected")
	}
	if Reason(err) != ReasonInternal {
		t.Fatalf("Reason = %q", Reason(err))
	}
}

// ResolveAPIKey is the only place the sealed key becomes the key the
// adapters use; these pin its precedence and its fail-safe behavior, and
// that no log line carries a key.
func TestResolveAPIKey(t *testing.T) {
	good := seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": "sk-sealed"}})
	const other = "0x00000000000000000000000000000000000000bb"
	cases := []struct {
		name, plain, secret, chainOwner, want, logWant, issue string
	}{
		{"no secret env keeps the plain key", "sk-plain", "", testOwner, "sk-plain", "", ""},
		{"no key at all is not an issue", "", "", testOwner, "", "", ""},
		{"sealed key applies", "", good, testOwner, "sk-sealed", "OK   API_KEY (from SEAL_SECRET_ENV", ""},
		{"sealed key wins over a plain key", "sk-plain", good, testOwner, "sk-sealed", "using the sealed value", ""},
		{"owner mismatch applies nothing", "", good, other, "", "FAIL SEAL_SECRET_ENV not applied", "secret_env_not_applied: owner_mismatch"},
		{"owner mismatch keeps the plain key", "sk-plain", good, other, "sk-plain", "FAIL SEAL_SECRET_ENV not applied", ""},
		{"unknown owner applies nothing", "", good, "", "", "FAIL SEAL_SECRET_ENV not applied", "secret_env_not_applied: owner_unknown"},
		{"garbage applies nothing", "", "not-base64!", testOwner, "", "FAIL SEAL_SECRET_ENV not applied", "secret_env_not_applied: malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var lines []string
			logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
			got, issue := ResolveAPIKey(c.plain, c.secret, testPriv(t), c.chainOwner, logf)
			if got != c.want {
				t.Fatalf("key = %q, want %q", got, c.want)
			}
			if issue != c.issue {
				t.Fatalf("issue = %q, want %q", issue, c.issue)
			}
			all := strings.Join(lines, "\n")
			if c.logWant != "" && !strings.Contains(all, c.logWant) {
				t.Fatalf("log %q does not contain %q", all, c.logWant)
			}
			if c.logWant == "" && len(lines) != 0 {
				t.Fatalf("unexpected log lines: %q", all)
			}
			if strings.Contains(all, "sk-sealed") || strings.Contains(all, "sk-plain") {
				t.Fatal("a log line carries a key")
			}
		})
	}
}

// LiveOwner re-reads an owner the boot-time read missed, so one RPC error
// does not leave the agent keyless; it never re-reads a known owner.
func TestLiveOwner(t *testing.T) {
	noLog := func(string, ...any) {}

	calls := 0
	read := func() (string, error) { calls++; return "0xnew", nil }
	if got := LiveOwner(testOwner, read, 3, 0, noLog); got != testOwner || calls != 0 {
		t.Fatalf("known owner: got %q after %d reads", got, calls)
	}
	if got := LiveOwner("", nil, 3, 0, noLog); got != "" {
		t.Fatalf("no reader: got %q", got)
	}

	calls = 0
	flaky := func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("rpc: connection reset")
		}
		return testOwner, nil
	}
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	if got := LiveOwner("", flaky, 3, 0, logf); got != testOwner || calls != 3 {
		t.Fatalf("flaky read: got %q after %d reads", got, calls)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "owner re-read 1/3 failed") {
		t.Fatalf("log lines: %q", lines)
	}

	calls = 0
	down := func() (string, error) { calls++; return "", errors.New("rpc down") }
	if got := LiveOwner("", down, 3, 0, noLog); got != "" || calls != 3 {
		t.Fatalf("rpc down: got %q after %d reads", got, calls)
	}
	// An owner that stays unknown still fails closed in Open.
	good := seal(t, map[string]any{"v": 1, "owner": testOwner, "env": map[string]string{"API_KEY": "sk-sealed"}})
	if key, issue := ResolveAPIKey("", good, testPriv(t), LiveOwner("", down, 1, 0, noLog), noLog); key != "" || issue == "" {
		t.Fatalf("an unknown owner must not apply a sealed key, and must be reported (issue %q)", issue)
	}
}
