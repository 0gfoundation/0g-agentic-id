package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// testKeyHex is a throwaway secp256k1 key used only by these tests.
const testKeyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

func testKeyAddress(t *testing.T) common.Address {
	t.Helper()
	priv, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	return crypto.PubkeyToAddress(priv.PublicKey)
}

// sealedArgs is the argument list sealed/internal/dataplane.uploadCommand
// passes. Keep the two in sync.
func sealedArgs(file string) []string {
	return []string{
		"--file", file,
		"--indexer", "http://indexer.example:5678",
		"--url", "http://rpc.example:8545",
		"--expected-replica", "1",
		"--skip-tx=true",
		"--fast-mode=true",
		"--full-trusted=true",
		"--method", "random",
	}
}

// ── readKey ────────────────────────────────────────────────────────────────

func TestReadKey_AcceptsSingleLineHex(t *testing.T) {
	want := testKeyAddress(t)
	for name, in := range map[string]string{
		"bare":              testKeyHex,
		"0x prefix":         "0x" + testKeyHex,
		"0X prefix":         "0X" + testKeyHex,
		"newline":           testKeyHex + "\n",
		"crlf":              testKeyHex + "\r\n",
		"0x and newline":    "0x" + testKeyHex + "\n",
		"upper-case digits": strings.ToUpper(testKeyHex) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			priv, err := readKey(strings.NewReader(in))
			if err != nil {
				t.Fatalf("readKey: %v", err)
			}
			if got := crypto.PubkeyToAddress(priv.PublicKey); got != want {
				t.Fatalf("address = %s, want %s", got, want)
			}
		})
	}
}

func TestReadKey_RejectsMalformedInput(t *testing.T) {
	nonHex := "g" + testKeyHex[1:]
	for name, in := range map[string]string{
		"empty":            "",
		"newline only":     "\n",
		"too short":        testKeyHex[:62],
		"too long":         testKeyHex + "00",
		"two lines":        testKeyHex + "\n" + testKeyHex + "\n",
		"trailing garbage": testKeyHex + "\nx",
		"leading space":    " " + testKeyHex,
		"trailing space":   testKeyHex + " \n",
		"non-hex":          nonHex,
		"zero key":         strings.Repeat("0", 64),
		"key above order":  strings.Repeat("f", 64),
	} {
		t.Run(name, func(t *testing.T) {
			priv, err := readKey(strings.NewReader(in))
			if err == nil {
				t.Fatalf("readKey accepted %q (address %s)", in, crypto.PubkeyToAddress(priv.PublicKey))
			}
			// Errors must not quote the input.
			msg := err.Error()
			if trimmed := strings.TrimSpace(in); trimmed != "" && strings.Contains(msg, trimmed) {
				t.Fatalf("error quotes the input: %q", msg)
			}
			if strings.Contains(msg, testKeyHex[1:]) {
				t.Fatalf("error contains key material: %q", msg)
			}
		})
	}
}

func TestReadKey_NonHexErrorDoesNotQuoteTheByte(t *testing.T) {
	_, err := readKey(strings.NewReader("z" + testKeyHex[1:]))
	if err == nil {
		t.Fatal("non-hex key accepted")
	}
	if strings.Contains(err.Error(), "z") || strings.Contains(err.Error(), "U+") {
		t.Fatalf("error quotes the offending input byte: %q", err)
	}
}

// countingReader yields an endless stream of hex digits and counts how
// much was consumed.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n += len(p)
	return len(p), nil
}

func TestReadKey_StopsAtSizeCap(t *testing.T) {
	r := &countingReader{}
	_, err := readKey(r)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want a size-cap error", err)
	}
	if r.n > maxKeyInput+1 {
		t.Fatalf("read %d bytes, want at most %d", r.n, maxKeyInput+1)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReadKey_ReadError(t *testing.T) {
	_, err := readKey(failingReader{})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("err = %v, want the read error", err)
	}
}

// ── parseFlags ─────────────────────────────────────────────────────────────

func TestParseFlags_DefaultsMatchCLI(t *testing.T) {
	o, err := parseFlags([]string{"--file", "f", "--indexer", "i", "--url", "u"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	want := options{
		file: "f", indexer: "i", url: "u",
		// `0g-storage-client upload` defaults (cmd/upload.go).
		expectedReplica: 1, skipTx: true, fastMode: true, fullTrusted: true, method: "min",
	}
	if o != want {
		t.Fatalf("options = %+v, want %+v", o, want)
	}
}

func TestParseFlags_SealedInvocation(t *testing.T) {
	o, err := parseFlags(sealedArgs("/tmp/blob.bin"), io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	want := options{
		file:            "/tmp/blob.bin",
		indexer:         "http://indexer.example:5678",
		url:             "http://rpc.example:8545",
		expectedReplica: 1,
		skipTx:          true,
		fastMode:        true,
		fullTrusted:     true,
		method:          "random",
	}
	if o != want {
		t.Fatalf("options = %+v, want %+v", o, want)
	}
}

func TestParseFlags_BooleanFalse(t *testing.T) {
	args := append(sealedArgs("f"), "--skip-tx=false", "--fast-mode=false", "--full-trusted=false")
	o, err := parseFlags(args, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.skipTx || o.fastMode || o.fullTrusted {
		t.Fatalf("booleans not cleared: %+v", o)
	}
}

func TestParseFlags_RejectsKeyFlag(t *testing.T) {
	for _, args := range [][]string{
		append(sealedArgs("f"), "--key", testKeyHex),
		append(sealedArgs("f"), "--key="+testKeyHex),
		append(sealedArgs("f"), "-key", testKeyHex),
	} {
		var stderr bytes.Buffer
		_, err := parseFlags(args, &stderr)
		if err == nil {
			t.Fatalf("parseFlags accepted %v", args)
		}
		if strings.Contains(err.Error(), testKeyHex) || strings.Contains(stderr.String(), testKeyHex) {
			t.Fatalf("key value echoed: err=%q stderr=%q", err, stderr.String())
		}
	}
}

func TestParseFlags_RejectsPositionalWithoutEchoing(t *testing.T) {
	for _, args := range [][]string{
		// A separate value word after a boolean flag would end flag
		// parsing and drop --method; it must fail instead.
		{"--file", "f", "--indexer", "i", "--url", "u", "--skip-tx", "true", "--method", "random"},
		{"--file", "f", "--indexer", "i", "--url", "u", testKeyHex},
	} {
		_, err := parseFlags(args, io.Discard)
		if err == nil {
			t.Fatalf("parseFlags accepted %v", args)
		}
		if strings.Contains(err.Error(), testKeyHex) || strings.Contains(err.Error(), "true") {
			t.Fatalf("error echoes a positional argument: %q", err)
		}
	}
}

func TestParseFlags_RequiresFileIndexerURL(t *testing.T) {
	_, err := parseFlags([]string{"--file", "f"}, io.Discard)
	if err == nil {
		t.Fatal("missing --indexer/--url accepted")
	}
	for _, f := range []string{"--indexer", "--url"} {
		if !strings.Contains(err.Error(), f) {
			t.Fatalf("error %q does not name %s", err, f)
		}
	}
}

func TestParseFlags_Method(t *testing.T) {
	for _, m := range []string{"min", "max", "random", "1", "3"} {
		if _, err := parseFlags([]string{"--file", "f", "--indexer", "i", "--url", "u", "--method", m}, io.Discard); err != nil {
			t.Errorf("--method %q rejected: %v", m, err)
		}
	}
	for _, m := range []string{"", "0", "-1", "fastest", "1.5"} {
		if _, err := parseFlags([]string{"--file", "f", "--indexer", "i", "--url", "u", "--method", m}, io.Discard); err == nil {
			t.Errorf("--method %q accepted", m)
		}
	}
}

// ── SDK option mapping ─────────────────────────────────────────────────────

func TestUploadOption_MatchesCLIMapping(t *testing.T) {
	o, err := parseFlags(sealedArgs("f"), io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	submitter := testKeyAddress(t)
	got := uploadOption(o, submitter)

	if got.Submitter != submitter {
		t.Errorf("Submitter = %s, want %s", got.Submitter, submitter)
	}
	if got.Fee != nil || got.Nonce != nil || got.MaxGasPrice != nil {
		t.Errorf("Fee/Nonce/MaxGasPrice = %v/%v/%v, want nil (CLI defaults)", got.Fee, got.Nonce, got.MaxGasPrice)
	}
	if got.NRetries != 0 || got.Step != 15 {
		t.Errorf("NRetries/Step = %d/%d, want 0/15", got.NRetries, got.Step)
	}
	if got.Tags == nil || len(got.Tags) != 0 {
		t.Errorf("Tags = %#v, want non-nil empty (CLI's decoded \"0x\")", got.Tags)
	}
	if got.EncryptionKey != nil || got.RecipientPubKey != nil {
		t.Error("encryption set; the CLI invocation never encrypted")
	}
	// The zero value is FileFinalized; the CLI without --finality-required
	// waits only for TransactionPacked.
	if got.FinalityRequired != transfer.TransactionPacked {
		t.Errorf("FinalityRequired = %v, want TransactionPacked", got.FinalityRequired)
	}
	if got.TaskSize != 10 || got.FragmentSize != 4*1024*1024*1024 || got.BatchSize != 10 {
		t.Errorf("TaskSize/FragmentSize/BatchSize = %d/%d/%d, want 10/4GiB/10", got.TaskSize, got.FragmentSize, got.BatchSize)
	}
	if got.ExpectedReplica != 1 || !got.SkipTx || !got.FastMode || !got.FullTrusted || got.Method != "random" {
		t.Errorf("flag-driven fields = replica %d skipTx %v fast %v trusted %v method %q",
			got.ExpectedReplica, got.SkipTx, got.FastMode, got.FullTrusted, got.Method)
	}
}

func TestProviderOption_MatchesCLIDefaults(t *testing.T) {
	p := providerOption()
	if p.RetryCount != 5 || p.RetryInterval.Seconds() != 5 || p.RequestTimeout.Seconds() != 30 {
		t.Fatalf("provider option = %+v, want retry 5 / 5s / timeout 30s", p)
	}
}

// ── output contract ────────────────────────────────────────────────────────

// sealedRootRegexp is sealed/internal/dataplane's rootLineRegexp. Keep the
// two in sync.
var sealedRootRegexp = regexp.MustCompile(`root\s*=\s*(0x[0-9a-fA-F]{64})`)

func TestFormatRoot_ParsesWithSealedRegexp(t *testing.T) {
	root := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	line := formatRoot(root)
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("formatRoot = %q, want exactly one line", line)
	}
	m := sealedRootRegexp.FindStringSubmatch(line)
	if len(m) < 2 || common.HexToHash(m[1]) != root {
		t.Fatalf("sealed regexp parsed %q from %q, want %s", m, line, root.Hex())
	}
}

// ── run ────────────────────────────────────────────────────────────────────

func TestRun_SuccessPrintsOnlyTheRootLine(t *testing.T) {
	root := common.HexToHash("0xabcdef0000000000000000000000000000000000000000000000000000000001")
	wantAddr := testKeyAddress(t)
	var gotOpts options
	var gotAddr common.Address
	stub := func(_ context.Context, o options, priv *ecdsa.PrivateKey) ([]common.Hash, error) {
		gotOpts, gotAddr = o, crypto.PubkeyToAddress(priv.PublicKey)
		return []common.Hash{root}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), sealedArgs("/tmp/x.bin"), strings.NewReader(testKeyHex+"\n"), &stdout, &stderr, stub)
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if stdout.String() != "root = "+root.Hex()+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if gotAddr != wantAddr {
		t.Fatalf("uploader got key for %s, want %s", gotAddr, wantAddr)
	}
	if gotOpts.file != "/tmp/x.bin" || gotOpts.method != "random" {
		t.Fatalf("uploader got options %+v", gotOpts)
	}
}

func TestRun_UploadErrorIsLastStderrLine(t *testing.T) {
	stub := func(context.Context, options, *ecdsa.PrivateKey) ([]common.Hash, error) {
		return nil, errors.New("failed to send transaction:\ninsufficient funds for gas * price + value")
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), sealedArgs("f"), strings.NewReader(testKeyHex), &stdout, &stderr, stub)
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}
	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "zg-upload: upload: ") || !strings.Contains(last, "insufficient funds") {
		t.Fatalf("last stderr line = %q", last)
	}
	if strings.Contains(stderr.String(), testKeyHex) {
		t.Fatal("stderr contains the key")
	}
}

func TestRun_RejectsMultipleRoots(t *testing.T) {
	stub := func(context.Context, options, *ecdsa.PrivateKey) ([]common.Hash, error) {
		return []common.Hash{{1}, {2}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), sealedArgs("f"), strings.NewReader(testKeyHex), &stdout, &stderr, stub); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRun_BadKeyOrFlagsNeverUpload(t *testing.T) {
	called := false
	stub := func(context.Context, options, *ecdsa.PrivateKey) ([]common.Hash, error) {
		called = true
		return []common.Hash{{1}}, nil
	}
	cases := []struct {
		args  []string
		stdin string
	}{
		{sealedArgs("f"), ""},
		{sealedArgs("f"), "not a key"},
		{[]string{"--file", "f"}, testKeyHex},
		{append(sealedArgs("f"), "--key", testKeyHex), testKeyHex},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), c.args, strings.NewReader(c.stdin), &stdout, &stderr, stub); code != exitUsage {
			t.Errorf("args %v: exit %d, want %d", c.args, code, exitUsage)
		}
		if strings.Contains(stderr.String(), testKeyHex) {
			t.Errorf("args %v: stderr contains the key", c.args)
		}
	}
	if called {
		t.Fatal("upload ran despite invalid input")
	}
}
