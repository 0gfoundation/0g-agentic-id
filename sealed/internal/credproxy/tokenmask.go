package credproxy

import "bytes"

// tokenFormat is a well-known credential format: a fixed prefix followed by
// at least min token bytes ([A-Za-z0-9_.-]; a trailing '.' is left out). The
// proxy masks such tokens in the responses it relays even when sealed does
// not hold them (a token an ordinary API call returns, say). Best effort: a
// format missing here, or a token split by the response's own framing, goes
// through. Prefixes are the providers' documented ones as of 2026-11; lengths
// are lower bounds, since most providers document none.
type tokenFormat struct {
	prefix string
	min    int
}

var tokenFormats = []tokenFormat{
	// GitHub personal (classic, fine-grained), OAuth, app user, installation
	// (now a ~520-byte token with dots) and refresh tokens.
	{"github_pat_", 40}, {"ghp_", 30}, {"gho_", 30}, {"ghu_", 30}, {"ghs_", 30}, {"ghr_", 30},
	// GitLab's token prefixes (gitlab.com; self-managed may change glpat-).
	{"glpat-", 20}, {"gloas-", 20}, {"gldt-", 20}, {"glrt-", 20}, {"glrtr-", 20}, {"glcbt-", 20}, {"glptt-", 20},
	{"glft-", 20}, {"glimt-", 20}, {"glagent-", 20}, {"glwt-", 20}, {"glsoat-", 20}, {"glffct-", 20},
	// Slack bot, user, app-level and workflow tokens, and the rotating ones.
	{"xoxb-", 20}, {"xoxp-", 20}, {"xapp-", 20}, {"xwfp-", 20}, {"xoxe-", 20}, {"xoxe.", 20},
	// Stripe secret, restricted and organization keys.
	{"sk_live_", 20}, {"sk_test_", 20}, {"rk_live_", 20}, {"rk_test_", 20}, {"sk_org_", 20},
	// Anthropic (sk-ant-), OpenRouter (sk-or-), OpenAI and others share "sk-".
	{"sk-", 32},
	{"hf_", 30},  // Hugging Face
	{"AIza", 35}, // Google API keys
	{"npm_", 30}, // npm
	{"ntn_", 30}, // Notion
}

// maxTokenRun bounds how far a match extends, and so how much a stream holds
// back while a token may still be arriving.
const maxTokenRun = 1024

// tokenMask is what a matched token becomes; it is not a placeholder, since
// sealed holds no value for it.
var tokenMask = []byte("[[redacted]]")

// tokenStart marks the first bytes of the prefixes, to skip most positions at once.
var tokenStart = func() (t [256]bool) {
	for _, f := range tokenFormats {
		t[f.prefix[0]] = true
	}
	return t
}()

// wordByte decides word boundaries: a token starts only after a non-word byte.
func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// tokenByte is what a token may contain.
func tokenByte(c byte) bool { return wordByte(c) || c == '.' }

// maskTokens replaces the well-known tokens in b. prevToken says whether the
// byte before b (already sent) is a token byte, in which case b does not
// begin at a word boundary. Unless final, a token (or a prefix) touching the
// end of b may be continued by the next read: it is left as is, and keep is
// the number of trailing bytes the caller holds back for that. With mask the
// replacement is as many '*' as the token has bytes.
func maskTokens(b []byte, prevToken, final, mask bool) (out []byte, keep int) {
	hold := -1
	var w bytes.Buffer
	last := 0
scan:
	for i := 0; i < len(b); i++ {
		if !tokenStart[b[i]] || i == 0 && prevToken || i > 0 && wordByte(b[i-1]) {
			continue // not at a word boundary
		}
		rest := b[i:]
		for _, f := range tokenFormats {
			if len(rest) < len(f.prefix) {
				if !final && bytes.HasPrefix([]byte(f.prefix), rest) {
					hold = i
					break scan
				}
				continue
			}
			if !bytes.HasPrefix(rest, []byte(f.prefix)) {
				continue
			}
			j := len(f.prefix)
			for j < len(rest) && j < maxTokenRun && tokenByte(rest[j]) {
				j++
			}
			if j == len(rest) && j < maxTokenRun && !final {
				hold = i
				break scan
			}
			for j > len(f.prefix) && rest[j-1] == '.' {
				j-- // a sentence's full stop, not the token's
			}
			if j-len(f.prefix) < f.min {
				continue
			}
			w.Write(b[last:i])
			if mask {
				w.Write(bytes.Repeat([]byte("*"), j))
			} else {
				w.Write(tokenMask)
			}
			last = i + j
			i = last - 1
			continue scan
		}
	}
	if hold >= 0 {
		keep = len(b) - hold // the held bytes lie after every replacement
	}
	if last == 0 {
		return b, keep
	}
	w.Write(b[last:])
	return w.Bytes(), keep
}
