package scrub

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/manifest"
)

// Test values only: shapes of real secrets, no real secret.
const (
	hex64    = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	pemBlock = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDx0t3sKey0nLyF0rTe5tS0000000000000000000000000AAAA\n-----END OPENSSH PRIVATE KEY-----" // privacy-check: allow
	jwt      = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"                                                                                                                   // privacy-check: allow
	// BIP39 test vectors (valid checksums).
	mnemonic12 = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	mnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
)

func TestWordlistIsBIP39English(t *testing.T) {
	words := strings.Fields(bip39English)
	if len(words) != 2048 || words[0] != "abandon" || words[2047] != "zoo" || len(bip39Index) != 2048 {
		t.Fatalf("wordlist: %d words, %q … %q", len(words), words[0], words[len(words)-1])
	}
}

func TestBIP39Checksum(t *testing.T) {
	valid := []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		mnemonic12,
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		mnemonic24,
	}
	for _, m := range valid {
		if !validMnemonic(indexes(t, m)) {
			t.Errorf("valid mnemonic refused: %q", m)
		}
	}
	if validMnemonic(indexes(t, strings.Repeat("abandon ", 12))) {
		t.Error("twelve abandons pass the checksum")
	}
}

func indexes(t *testing.T, m string) []int {
	t.Helper()
	var out []int
	for _, w := range strings.Fields(m) {
		i, ok := bip39Index[w]
		if !ok {
			t.Fatalf("%q is not a wordlist word", w)
		}
		out = append(out, i)
	}
	return out
}

func TestSecretFormatsRedacted(t *testing.T) {
	cases := []struct{ in, want string }{
		{"key:\n" + pemBlock + "\nend", "key:\n[redacted:private-key]\nend"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n(cut here)", "[redacted:private-key]\n(cut here)"}, // privacy-check: allow
		{"OPENAI_API_KEY=sk-proj-Ab3dEf6hIj9kLmN0pQrS2tUvWxYz", "OPENAI_API_KEY=[redacted:api-key]"},                                                                                                                              // privacy-check: allow
		{"key sk-ant-api03-AbCdEf0123456789GhIjKlMnOpQr ok", "key [redacted:api-key] ok"},                                                                                                                                         // privacy-check: allow
		{"GH=ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6", "GH=[redacted:github-token]"},                                                                                                                                             // privacy-check: allow
		{"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF0123", "[redacted:github-token]"},                                                                                                                        // privacy-check: allow
		{"aws AKIAIOSFODNN7EXAMPLE here", "aws [redacted:aws-key] here"},                                                                                                                                                          // privacy-check: allow
		{"maps AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY!", "maps [redacted:google-key]!"},                                                                                                                                          // privacy-check: allow
		{"slack xox" + "b-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "slack [redacted:slack-token]"},                                                                                                                     // privacy-check: allow
		{"token glpat-Ab3dEf6hIj9kLmN0pQrS2t done", "token [redacted:gitlab-token] done"},
		{"STRIPE=sk_" + "live_51Hx0aB3dEf6hIj9kLmN0pQrS", "STRIPE=[redacted:stripe-key]"},
		{"HF_TOKEN=hf_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF", "HF_TOKEN=[redacted:huggingface-token]"},
		{"notion ntn_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3h", "notion [redacted:notion-token]"},
		{"//registry/:_authToken=npm_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6", "//registry/:_authToken=[redacted:npm-token]"}, // privacy-check: allow
		{"Authorization: Bearer " + jwt, "Authorization: Bearer [redacted:jwt]"},
		{"PRIVATE_KEY=0x" + hex64, "PRIVATE_KEY=[redacted:private-key]"},
		{`{"privateKey": "` + hex64 + `"}`, `{"privateKey": "[redacted:private-key]"}`},
		{"wallet seed: " + hex64, "wallet seed: [redacted:private-key]"},
		{"my words are " + mnemonic12 + "; keep them", "my words are [redacted:mnemonic]; keep them"},
		{"backup:\n" + mnemonic24 + "\n", "backup:\n[redacted:mnemonic]\n"},
		{"1. legal 2. winner 3. thank 4. year 5. wave 6. sausage 7. worth 8. useful 9. legal 10. winner 11. thank 12. yellow", "1. [redacted:mnemonic]"},
		// A typo breaks the checksum; the word before it still names it.
		{"Mnemonic: legal winner thank year wave sausage worth useful legal winner thank zoo", "Mnemonic: [redacted:mnemonic]"}, // privacy-check: allow
		{"助记词：legal winner thank year wave sausage worth useful legal winner thank zoo", "助记词：[redacted:mnemonic]"},
	}
	for _, c := range cases {
		got := string(Patterns([]byte(c.in)))
		if got != c.want {
			t.Errorf("Patterns(%q)\n got  %q\n want %q", c.in, got, c.want)
		}
		if again := string(Patterns([]byte(got))); again != got {
			t.Errorf("not idempotent: %q → %q", got, again)
		}
	}
}

func TestNearMissesKept(t *testing.T) {
	plainRun := "ability able about above absent absorb abstract absurd abuse access accident account"
	if validMnemonic(indexes(t, plainRun)) {
		t.Fatal("fixture: the plain run happens to pass the checksum; pick another")
	}
	kept := []string{
		"tx 0x" + hex64 + " confirmed in block 42",
		"sealId: 0x" + hex64,
		"sha256 " + hex64,
		"sk-abc123",
		"use sk-learn-pipeline-example-for-docs here", // privacy-check: allow
		"The owner asked me to review the account, check access, and write an abstract before the audit on Friday.",
		plainRun,
		strings.Repeat("abandon ", 12),
		"key: AKIAIOSFODNN7EXAMPLE1", // 17 after AKIA: not an access key id // privacy-check: allow
		"[[credential:github]] and [redacted:jwt]",
	}
	for _, in := range kept {
		b := []byte(in)
		if got := Patterns(b); !bytes.Equal(got, b) {
			t.Errorf("near miss changed: %q → %q", in, got)
		}
	}
	// Not text: a file with a NUL byte is never rewritten.
	bin := []byte("\x89PNG\x00\x00AKIAIOSFODNN7EXAMPLE\x00")
	if got := Patterns(bin); !bytes.Equal(got, bin) {
		t.Error("binary content was rewritten")
	}
}

func TestRolesScrubbedWithNoValuesHeld(t *testing.T) {
	ctx := context.Background()
	fw := &fakeFW{
		notes:   []byte("aws AKIAIOSFODNN7EXAMPLE\n"), // privacy-check: allow
		entries: map[string][]byte{"token.md": []byte("jwt " + jwt), "plain.md": []byte("nothing")},
	}
	for _, a := range []*IData{Wrap(fw, nil), Wrap(fw, &values{n: 0})} {
		got, err := a.EvolutionFor(ctx, "notes")
		if err != nil || string(got) != "aws [redacted:aws-key]\n" {
			t.Fatalf("leaf: %q %v", got, err)
		}
		out, err := a.EvolutionFor(ctx, "skills")
		if err != nil {
			t.Fatal(err)
		}
		m, _ := manifest.Unmarshal(out)
		tok, _ := a.LoadEntry(ctx, "skills", "token.md")
		if string(tok) != "jwt [redacted:jwt]" || m.EntryByPath("token.md").ContentHash != manifest.HashHex(tok) {
			t.Fatalf("manifest entry %+v does not describe %q", *m.EntryByPath("token.md"), tok)
		}
		// Stable: the next pass reads nothing again and gives the same bytes.
		loads := fw.loads
		again, _ := a.EvolutionFor(ctx, "skills")
		if fw.loads != loads || !bytes.Equal(again, out) {
			t.Fatal("second pass reread or changed")
		}
	}
}

func TestValuesAndPatternsCompose(t *testing.T) {
	fw := &fakeFW{notes: []byte("held " + secret + " and pasted AKIAIOSFODNN7EXAMPLE")} // privacy-check: allow
	got, err := Wrap(fw, &values{n: 1, gen: 1}).EvolutionFor(context.Background(), "notes")
	if err != nil || string(got) != "held [[credential:github]] and pasted [redacted:aws-key]" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestArchiveEntryPatternScrubbed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh"), []byte("export PRIVATE_KEY=0x"+hex64+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tgz, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := Wrap(&fakeFW{entries: map[string][]byte{"tool/": tgz}}, nil)
	first, err := a.LoadEntry(context.Background(), "skills", "tool/")
	if err != nil {
		t.Fatal(err)
	}
	if f := untar(t, first)["deploy.sh"]; f != "export PRIVATE_KEY=[redacted:private-key]\n" {
		t.Fatalf("archive file %q", f)
	}
	second, _ := a.LoadEntry(context.Background(), "skills", "tool/")
	if !bytes.Equal(first, second) {
		t.Fatal("the same archive scrubbed to different bytes")
	}
}
