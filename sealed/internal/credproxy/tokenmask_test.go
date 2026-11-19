package credproxy

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// Test tokens are built at run time so no token-shaped literal sits in the
// source for secret scanners to flag.
func fakeToken(prefix string, n int) string { return prefix + strings.Repeat("a1B2", n/4+1)[:n] }

func TestMaskTokensFormatsAndBoundaries(t *testing.T) {
	gh := fakeToken("ghp"+"_", 36)
	pat := fakeToken("github"+"_pat_", 82)
	slack := "xox" + "b-" + "1234567890-0987654321-" + fakeToken("", 24)
	sk := fakeToken("sk"+"-proj-", 60)
	// GitHub's installation tokens: about 520 bytes with two dots.
	ghs := "ghs" + "_" + "123456_" + fakeToken("", 200) + "." + fakeToken("", 150) + "." + fakeToken("", 160)
	for in, want := range map[string]string{
		`{"token":"` + gh + `"}`:        `{"token":"[[redacted]]"}`,
		"a " + pat + " b":               "a [[redacted]] b",
		"Bearer " + slack:               "Bearer [[redacted]]",
		sk + "\n" + gh:                  "[[redacted]]\n[[redacted]]",
		"task-" + fakeToken("", 40):     "task-" + fakeToken("", 40),     // "sk-" inside a word
		"x" + gh:                        "x" + gh,                        // not at a word boundary
		fakeToken("ghp"+"_", 10) + " .": fakeToken("ghp"+"_", 10) + " .", // too short
		"no tokens here":                "no tokens here",
		"t=" + ghs + ".":                "t=[[redacted]].", // the full stop stays
		"see " + gh + ", then":          "see [[redacted]], then",
		"file." + gh:                    "file.[[redacted]]", // '.' ends a word
	} {
		if got := newProxyRedactor().applyString(in); got != want {
			t.Errorf("%q\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestMaskTokensAcrossReads(t *testing.T) {
	gh := fakeToken("ghs"+"_", 36)
	stream := `data: {"t":"` + gh + `"}` + "\n\n" + "tail " + fakeToken("hf"+"_", 34)
	want := `data: {"t":"[[redacted]]"}` + "\n\n" + "tail [[redacted]]"
	for _, r := range []io.Reader{
		iotest.OneByteReader(strings.NewReader(stream)),
		iotest.HalfReader(strings.NewReader(stream)),
		strings.NewReader(stream),
	} {
		out, err := io.ReadAll(newProxyRedactor().reader(r))
		if err != nil || string(out) != want {
			t.Fatalf("got %q (%v)", out, err)
		}
	}
	// A token that begins right after a token byte of the previous read is
	// not at a word boundary.
	glued := "abc" + fakeToken("ghp"+"_", 36)
	out, _ := io.ReadAll(newProxyRedactor().reader(iotest.OneByteReader(strings.NewReader(glued))))
	if string(out) != glued {
		t.Fatalf("got %q", out)
	}
}

func TestMaskTokensKeepsLengthForWebSocket(t *testing.T) {
	in := "x " + fakeToken("glpat"+"-", 20) + " y"
	out := newMaskRedactor().applyString(in)
	if len(out) != len(in) || strings.Contains(out, "glpat") {
		t.Fatalf("got %q", out)
	}
}

// What sealed itself sends on (the /api/* responses, committed data) is
// scrubbed of the values it holds only, never rewritten by format.
func TestScrubDoesNotMaskTokens(t *testing.T) {
	in := "note: " + fakeToken("ghp"+"_", 36)
	if got := string(newRedactor().apply([]byte(in))); got != in {
		t.Fatalf("got %q", got)
	}
}

// An event that ends at a newline passes at once: nothing is held back.
func TestProxyRedactorDoesNotHoldEvents(t *testing.T) {
	pr, pw := io.Pipe()
	r := newProxyRedactor().reader(pr)
	go func() { _, _ = pw.Write([]byte("data: {\"text\":\"see sk-\"}\n\n")) }()
	buf := make([]byte, 64)
	done := make(chan int, 1)
	go func() { n, _ := r.Read(buf); done <- n }()
	select {
	case n := <-done:
		if string(buf[:n]) != "data: {\"text\":\"see sk-\"}\n\n" {
			t.Fatalf("got %q", buf[:n])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an event was held back")
	}
	pw.Close()
}
