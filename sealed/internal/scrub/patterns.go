package scrub

// Secret formats: the second pass over committed content, for secrets sealed
// does not hold (a key the owner pasted into the conversation, a token the
// agent was shown). Only shapes that are secrets with high confidence are
// redacted, each to [redacted:<kind>]:
//
//   - PEM private key blocks (RSA, EC, DSA, OPENSSH, PGP, ENCRYPTED);
//   - provider tokens: sk- API keys (sk-proj-, sk-ant-, sk-or-), GitHub
//     (gh?_, github_pat_), GitLab (glpat- …), AWS access key ids (AKIA),
//     Google API keys (AIza), Slack (xox?-, xapp-, xwfp-), Stripe (sk_live_ …),
//     Hugging Face (hf_), Notion (ntn_), npm (npm_) — the formats the
//     credential proxy also masks in responses (credproxy/tokenmask.go);
//   - JWTs (two base64url JSON parts and a signature);
//   - a 64-hex value next to a word that makes it a key (private key,
//     secret, seed, mnemonic …), never a bare hash;
//   - a BIP39 English mnemonic: a run of 12 or more wordlist words whose
//     12/15/18/21/24-word window passes the BIP39 checksum, or that follows a
//     word naming it (mnemonic, seed phrase, recovery phrase …).
//
// The rules follow 0g-harness's privacy check (scripts/privacy-check.mjs) and
// the proxy's token formats.
// Content that is not text (a NUL byte, invalid UTF-8) is left as it is: a
// rewrite would corrupt a binary file. The pass is deterministic and
// idempotent, so a file that keeps a secret scrubs to the same bytes on every
// pass and is committed once.

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"regexp"
	"strings"
	"unicode/utf8"
)

//go:embed bip39_english.txt
var bip39English string

// bip39Index maps a wordlist word to its index.
var bip39Index = func() map[string]int {
	words := strings.Fields(bip39English)
	m := make(map[string]int, len(words))
	for i, w := range words {
		m[w] = i
	}
	return m
}()

type pattern struct {
	kind  string
	re    *regexp.Regexp
	group int               // the submatch that is redacted; 0 = the whole match
	keep  func([]byte) bool // when set, a match it rejects is a near miss and stays
}

const pemKind = `(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?`

var patterns = []pattern{
	{kind: "private-key", re: regexp.MustCompile(`(?s)-----BEGIN ` + pemKind + `-----.*?-----END ` + pemKind + `-----`)},
	// A block whose END line is missing: the header and the lines of key
	// material after it.
	{kind: "private-key", re: regexp.MustCompile(`-----BEGIN ` + pemKind + `-----(?:\r?\n(?:\r?\n)?(?:[A-Za-z0-9+/=]{16,}|Proc-Type:[^\r\n]*|DEK-Info:[^\r\n]*))*`)},
	{kind: "api-key", re: regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`), keep: looksRandom},
	{kind: "github-token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})`)},
	{kind: "gitlab-token", re: regexp.MustCompile(`\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_.-]{20,}`)},
	{kind: "aws-key", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{kind: "google-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{kind: "slack-token", re: regexp.MustCompile(`\b(?:xox[abeprs]|xapp|xwfp)[-.][A-Za-z0-9-]{10,}`), keep: func(b []byte) bool { return count(b, isDigit) >= 4 }},
	{kind: "stripe-key", re: regexp.MustCompile(`\b(?:(?:sk|rk)_(?:live|test)|sk_org)_[A-Za-z0-9]{20,}`)},
	{kind: "huggingface-token", re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`)},
	{kind: "notion-token", re: regexp.MustCompile(`\bntn_[A-Za-z0-9]{30,}`)},
	{kind: "npm-token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`)},
	{kind: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{kind: "private-key", group: 1, re: regexp.MustCompile(`(?i)(?:priv(?:ate)?[_ -]?key|secret|_priv\b|privkey|mnemonic|seed)\W{0,6}(?:[\w"' ]{0,20}[:=]\s*)?["']?((?:0x)?[0-9a-f]{64})\b`)},
}

// mnemonicLead is a word naming a seed phrase right before a run of wordlist
// words ("mnemonic: …", "seed phrase is\n…", "助记词：…"); it makes the run a
// mnemonic even when its checksum fails (a typo).
var mnemonicLead = regexp.MustCompile(`(?i)(?:mnemonic|seed(?: phrase| words)?|recovery phrase|secret phrase|backup phrase|助记词|种子)(?:\s*(?:is|are|was))?[\s:="'“”：]{0,12}$`)

// Patterns returns b with every secret of a known format replaced by
// [redacted:<kind>], or b itself (the same slice) when nothing matched or b
// is not text.
func Patterns(b []byte) []byte {
	if len(b) == 0 || bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return b
	}
	out := b
	for _, p := range patterns {
		out = p.apply(out)
	}
	return redactMnemonics(out)
}

func (p pattern) apply(b []byte) []byte {
	locs := p.re.FindAllSubmatchIndex(b, -1)
	if len(locs) == 0 {
		return b
	}
	var buf bytes.Buffer
	last := 0
	for _, loc := range locs {
		s, e := loc[2*p.group], loc[2*p.group+1]
		if s < 0 || (p.keep != nil && !p.keep(b[s:e])) {
			continue
		}
		buf.Write(b[last:s])
		buf.WriteString("[redacted:" + p.kind + "]")
		last = e
	}
	if last == 0 {
		return b
	}
	buf.Write(b[last:])
	return buf.Bytes()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func count(b []byte, f func(byte) bool) int {
	n := 0
	for _, c := range b {
		if f(c) {
			n++
		}
	}
	return n
}

// looksRandom keeps sk-… matches that read like a generated key (digits and
// capitals), not a hyphenated name (an sk-learn style label).
func looksRandom(b []byte) bool {
	return count(b, isDigit) >= 2 && count(b, isUpper) >= 2
}

type word struct {
	start, end int
	index      int // BIP39 index, -1 when not a wordlist word
}

// redactMnemonics replaces each run of 12 or more wordlist words, joined by
// whitespace or list numbering, that holds a valid BIP39 mnemonic or follows a
// word naming one.
func redactMnemonics(b []byte) []byte {
	var spans [][2]int
	var run []word
	flush := func() {
		if len(run) >= 12 && (hasValidWindow(run) || mnemonicLead.Match(b[max(0, run[0].start-64):run[0].start])) {
			spans = append(spans, [2]int{run[0].start, run[len(run)-1].end})
		}
		run = run[:0]
	}
	prevEnd := -1
	for i := 0; i < len(b); {
		if !isLetter(b[i]) {
			i++
			continue
		}
		s := i
		for i < len(b) && isLetter(b[i]) {
			i++
		}
		idx, ok := bip39Index[strings.ToLower(string(b[s:i]))]
		if !ok || (prevEnd >= 0 && !joins(b[prevEnd:s])) {
			flush()
		}
		if ok {
			run = append(run, word{start: s, end: i, index: idx})
		}
		prevEnd = i
	}
	flush()
	if len(spans) == 0 {
		return b
	}
	var buf bytes.Buffer
	last := 0
	for _, sp := range spans {
		buf.Write(b[last:sp[0]])
		buf.WriteString("[redacted:mnemonic]")
		last = sp[1]
	}
	buf.Write(b[last:])
	return buf.Bytes()
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// joins reports whether the text between two words keeps them in one run:
// whitespace and list numbering ("1. ", "2) ", ", "), at most 8 bytes.
func joins(sep []byte) bool {
	if len(sep) == 0 || len(sep) > 8 {
		return false
	}
	for _, c := range sep {
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		case isDigit(c) || c == '.' || c == ')' || c == ',':
		default:
			return false
		}
	}
	return true
}

// hasValidWindow reports whether the run holds a 12, 15, 18, 21 or 24-word
// window that passes the BIP39 checksum.
func hasValidWindow(run []word) bool {
	for _, n := range []int{24, 21, 18, 15, 12} {
		for s := 0; s+n <= len(run); s++ {
			idx := make([]int, n)
			for i := range idx {
				idx[i] = run[s+i].index
			}
			if validMnemonic(idx) {
				return true
			}
		}
	}
	return false
}

// validMnemonic checks the BIP39 checksum of n word indexes (n a multiple of
// 3, 12..24): the first n*11/33 bits after the entropy are the first bits of
// the entropy's SHA-256.
func validMnemonic(idx []int) bool {
	bits := len(idx) * 11
	csBits := bits / 33
	entBits := bits - csBits
	buf := make([]byte, (bits+7)/8)
	for i, v := range idx {
		for j := 0; j < 11; j++ {
			if v&(1<<(10-j)) != 0 {
				pos := i*11 + j
				buf[pos/8] |= 1 << (7 - pos%8)
			}
		}
	}
	h := sha256.Sum256(buf[:entBits/8])
	for j := 0; j < csBits; j++ {
		pos := entBits + j
		if (buf[pos/8]>>(7-pos%8))&1 != (h[j/8]>>(7-j%8))&1 {
			return false
		}
	}
	return true
}
