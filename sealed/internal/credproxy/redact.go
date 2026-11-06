package credproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

// Values shorter than minRawRedact are not redacted, and encoded forms
// shorter than minEncodedRedact neither (base64 aside, see addValue): a short
// string would match ordinary response bytes. Credentials are far longer in
// practice.
const (
	minRawRedact     = 6
	minEncodedRedact = 8
)

type redactForm struct{ match, repl []byte }

// secret is one value to redact and the entry whose placeholder replaces it.
type secret struct {
	name  string
	value []byte
}

func secretsOf(sets ...map[string][]byte) []secret {
	var out []secret
	for _, m := range sets {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, secret{name: n, value: m[n]})
		}
	}
	return out
}

// redactor replaces every known credential value with its placeholder, in
// the encodings a value is likely to travel in (addValue). A proxy redactor
// also masks tokens of well-known formats (tokenmask.go).
type redactor struct {
	sets   []*formSet
	tokens bool
	mask   bool
}

// newRedactor covers the given values, for what sealed itself sends on.
func newRedactor(secrets ...map[string][]byte) *redactor {
	return &redactor{sets: []*formSet{newFormSet(secretsOf(secrets...))}}
}

// newProxyRedactor also masks well-known tokens, for responses the proxy
// relays to the harness.
func newProxyRedactor(secrets ...map[string][]byte) *redactor {
	return &redactor{sets: []*formSet{newFormSet(secretsOf(secrets...))}, tokens: true}
}

// newMaskRedactor is a proxy redactor that replaces each match with as many
// '*' as it has bytes, for streams whose framing a change in length would
// break (WebSocket).
func newMaskRedactor(secrets ...map[string][]byte) *redactor {
	return &redactor{sets: []*formSet{newFormSet(secretsOf(secrets...))}, tokens: true, mask: true}
}

// proxyRedactor is the redactor for the response to one request: every value
// Scrub covers, and the values filled into that request, which may have left
// the registry while the request was in flight.
func (r *Registry) proxyRedactor(mask bool, filled map[string][]byte) *redactor {
	red := &redactor{sets: []*formSet{r.scrubForms()}, tokens: true, mask: mask}
	if len(filled) > 0 {
		red.sets = append(red.sets, newFormSet(secretsOf(filled)))
	}
	return red
}

// formKeyLen is how many leading bytes index a form; every form is longer.
const formKeyLen = 4

// formSet is the forms of a set of values, indexed by their first bytes so
// a scan costs about the same however many values there are.
type formSet struct {
	forms  []redactForm        // longest first
	index  map[uint32][]int32  // first formKeyLen bytes -> forms, longest first
	heads  map[string]struct{} // every shorter prefix of a form
	maxLen int

	lowerOnce sync.Once
	lower     *formSet // the forms in ASCII lower case, for header names
}

// newFormSet covers every value of list, each replaced by its entry's
// placeholder (a minted token by the placeholder that stood for it). Where
// two values share a form, the first in list names it.
func newFormSet(list []secret) *formSet {
	var forms []redactForm
	seen := map[string]bool{}
	add := func(match string, min int, repl []byte) {
		if len(match) < min || seen[match] {
			return
		}
		seen[match] = true
		forms = append(forms, redactForm{match: []byte(match), repl: repl})
	}
	for _, v := range list {
		addValue(add, v.name, v.value)
	}
	return indexForms(forms)
}

// indexForms builds the set of forms, each at least formKeyLen long.
func indexForms(forms []redactForm) *formSet {
	s := &formSet{forms: forms, index: map[uint32][]int32{}, heads: map[string]struct{}{}}
	// Longest first, so where several forms start at one place the longest
	// is replaced.
	sort.SliceStable(s.forms, func(i, j int) bool { return len(s.forms[i].match) > len(s.forms[j].match) })
	for i, f := range s.forms {
		k := formKey(f.match)
		s.index[k] = append(s.index[k], int32(i))
		for l := 1; l < formKeyLen; l++ {
			s.heads[string(f.match[:l])] = struct{}{}
		}
		s.maxLen = max(s.maxLen, len(f.match))
	}
	return s
}

// lowerForms is s with every form in ASCII lower case, built on first use.
func (s *formSet) lowerForms() *formSet {
	s.lowerOnce.Do(func() {
		seen := map[string]bool{}
		var forms []redactForm
		for _, f := range s.forms {
			m := asciiLower(f.match)
			if !seen[string(m)] {
				seen[string(m)] = true
				forms = append(forms, redactForm{match: m, repl: f.repl})
			}
		}
		s.lower = indexForms(forms)
	})
	return s.lower
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = lowerASCII(c)
	}
	return out
}

// inName reports whether the header name k holds a value's form in any case
// of its ASCII letters.
func (r *redactor) inName(k string) bool {
	lk := asciiLower([]byte(k))
	for _, s := range r.sets {
		lower := s.lowerForms()
		for i := 0; i+formKeyLen <= len(lk); i++ {
			if lower.matchAt(lk[i:]) != nil {
				return true
			}
		}
	}
	return false
}

func formKey(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// matchAt returns the longest form b starts with, or nil.
func (s *formSet) matchAt(b []byte) *redactForm {
	if len(b) < formKeyLen {
		return nil
	}
	for _, i := range s.index[formKey(b)] {
		if f := &s.forms[i]; bytes.HasPrefix(b, f.match) {
			return f
		}
	}
	return nil
}

// isProperPrefix reports whether b is a proper prefix of some form.
func (s *formSet) isProperPrefix(b []byte) bool {
	if len(b) >= s.maxLen {
		return false
	}
	if len(b) < formKeyLen {
		_, ok := s.heads[string(b)]
		return ok
	}
	for _, i := range s.index[formKey(b)] {
		if f := s.forms[i].match; len(f) > len(b) && bytes.HasPrefix(f, b) {
			return true
		}
	}
	return false
}

// addValue registers v in each encoding it may travel in: raw; percent-
// encoded as Go's QueryEscape and PathEscape write it and as Python's
// quote() does (every byte but the unreserved ones, '/' kept or not), each
// with upper- or lower-case hex; JSON-escaped as common encoders write it
// (jsonStrings), each with '/' written plain or as "\/"; and standard or
// URL-safe base64 at each of the three byte alignments a value can take
// inside a longer base64 run. Base64 wrapped across lines and hex are not
// covered.
//
// Base64 is redacted for every value redacted raw, whatever the length of
// the encoded run: a 6-byte value leaves only 7 characters that are its
// alone at two of the three alignments.
func addValue(add func(match string, min int, repl []byte), name string, v []byte) {
	repl := []byte(Placeholder(name))
	s := string(v)
	add(s, minRawRedact, repl)
	for _, p := range []string{url.QueryEscape(s), url.PathEscape(s), awsEscape(s, true), awsEscape(s, false)} {
		add(p, minEncodedRedact, repl)
		add(lowerHex(p), minEncodedRedact, repl)
	}
	for _, j := range jsonStrings(s) {
		add(j, minEncodedRedact, repl)
		add(strings.ReplaceAll(j, "/", `\/`), minEncodedRedact, repl)
	}
	if len(v) < minRawRedact {
		return
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := 0; k < 3; k++ {
			full := enc.EncodeToString(append(make([]byte, k), v...))
			start, end := (8*k+5)/6, (8*(k+len(v)))/6
			add(full[start:end], 0, repl)
		}
	}
}

// jsonStrings is s inside a JSON string (quotes left out), as Go writes it
// with HTML escapes (as Rails does) and without (as JavaScript, Ruby and Rust
// do), and as the encoders of jsonProfiles write it.
func jsonStrings(s string) []string {
	var out []string
	if q, err := json.Marshal(s); err == nil {
		out = append(out, string(q[1:len(q)-1]))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) == nil {
		q := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
		out = append(out, string(q[1:len(q)-1]))
	}
	for _, p := range jsonProfiles {
		out = append(out, p.quote(s))
	}
	return out
}

// jsonProfile is how a family of JSON encoders writes a string: the ASCII
// characters it writes as \u00XX besides the ones JSON requires, the case of
// its hex digits, and whether it writes every non-ASCII character as \uXXXX.
type jsonProfile struct {
	escape   string
	upper    bool
	nonASCII bool
}

var jsonProfiles = []jsonProfile{
	{"", false, true},              // Python's default, PHP
	{"", true, false},              // Jackson (control characters in upper-case hex)
	{"<>&", true, false},           // HTML escapes in upper-case hex (PHP's JSON_HEX_TAG, JSON_HEX_AMP)
	{"<>&='", false, false},        // Gson
	{"<>&'\"", false, false},       // Json.NET with EscapeHtml
	{"<>&'\"+`\x7f", true, true},   // System.Text.Json
	{"<>&'\"+=`\x7f", false, true}, // every one of these, in either case
	{"<>&'\"+=`\x7f", true, true},
}

// quote writes s as p's encoders do inside a JSON string: '"' and '\'
// escaped, \b \f \n \r \t short and other control characters as \u00XX, the
// characters of p.escape as \u00XX, non-ASCII as \uXXXX (UTF-16) when
// p.nonASCII.
func (p jsonProfile) quote(s string) string {
	digits := "0123456789abcdef"
	if p.upper {
		digits = "0123456789ABCDEF"
	}
	var b strings.Builder
	u := func(r rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(digits[r>>shift&0xf])
		}
	}
	for _, r := range s {
		switch {
		case r < 0x80 && strings.ContainsRune(p.escape, r):
			u(r)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			u(r)
		case r >= 0x80 && p.nonASCII:
			if r > 0xffff {
				r1, r2 := utf16.EncodeRune(r)
				u(r1)
				u(r2)
			} else {
				u(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lowerHex writes the hex digits of every %XX escape in s in lower case.
func lowerHex(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1], b[i+2] = lowerASCII(b[i+1]), lowerASCII(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// apply redacts a whole value, such as a header.
func (r *redactor) apply(b []byte) []byte {
	b, _ = r.applyValues(b, true)
	if r.tokens {
		b, _ = maskTokens(b, false, true, r.mask)
	}
	return b
}

func (r *redactor) empty() bool {
	for _, s := range r.sets {
		if len(s.forms) > 0 {
			return false
		}
	}
	return true
}

// applyValues replaces, scanning left to right, the longest form that starts
// at each place. b comes back as it is when nothing matched.
//
// Unless final (more of the stream is to come), the bytes from where a form
// may begin that b ends inside of (pendingTail, measured on b as it came, so
// a value inside another or a prefix of another is held whole) are left as
// they are, and so is everything from the start of a match that would run
// into them; hold is their length, for the caller to hold back until more
// data arrives. What is replaced is then what a scan of the whole stream
// replaces.
func (r *redactor) applyValues(b []byte, final bool) (out []byte, hold int) {
	if r.empty() {
		return b, 0
	}
	end := len(b)
	if !final {
		end -= r.pendingTail(b)
	}
	last := 0
	for i := 0; i < end && i+min(minRawRedact, minEncodedRedact) <= len(b); i++ {
		var f *redactForm
		for _, s := range r.sets {
			if g := s.matchAt(b[i:]); g != nil && (f == nil || len(g.match) > len(f.match)) {
				f = g
			}
		}
		if f == nil {
			continue
		}
		if i+len(f.match) > end {
			end = i
			break
		}
		if out == nil {
			out = make([]byte, 0, len(b))
		}
		out = append(out, b[last:i]...)
		if r.mask {
			out = append(out, bytes.Repeat([]byte("*"), len(f.match))...)
		} else {
			out = append(out, f.repl...)
		}
		last = i + len(f.match)
		i = last - 1
	}
	hold = len(b) - end
	if out == nil {
		return b, hold
	}
	return append(out, b[last:]...), hold
}

// isProperPrefix reports whether b is a proper prefix of a form of any set.
func (r *redactor) isProperPrefix(b []byte) bool {
	for _, s := range r.sets {
		if s.isProperPrefix(b) {
			return true
		}
	}
	return false
}

func (r *redactor) applyString(s string) string { return string(r.apply([]byte(s))) }

// pendingTail is the length of the longest suffix of b that is a proper
// prefix of some form: those bytes may be the start of a value split across
// reads, so they are held back until more data arrives.
func (r *redactor) pendingTail(b []byte) int {
	keep := 0
	for _, s := range r.sets {
		for l := min(s.maxLen-1, len(b)); l > keep; l-- {
			if s.isProperPrefix(b[len(b)-l:]) {
				keep = l
				break
			}
		}
	}
	return keep
}

// reader streams src with values redacted. It holds back only the bytes that
// could begin a value split across reads, so event streams (SSE) keep their
// latency.
func (r *redactor) reader(src io.Reader) io.Reader {
	if r.empty() && !r.tokens {
		return src
	}
	return &redactReader{src: src, red: r}
}

type redactReader struct {
	src  io.Reader
	red  *redactor
	held []byte
	out  []byte
	err  error
	// prevToken: the last byte passed on was a token byte, so what follows
	// does not start a word.
	prevToken bool
}

func (rr *redactReader) Read(p []byte) (int, error) {
	for len(rr.out) == 0 {
		if rr.err != nil {
			if len(rr.held) > 0 {
				rr.out, _ = rr.red.applyValues(rr.held, true)
				rr.held = nil
				if rr.red.tokens {
					rr.out, _ = maskTokens(rr.out, rr.prevToken, true, rr.red.mask)
				}
				break
			}
			return 0, rr.err
		}
		chunk := make([]byte, 32<<10)
		n, err := rr.src.Read(chunk)
		if err != nil {
			rr.err = err
		}
		if n == 0 {
			continue
		}
		final := rr.err != nil
		buf, hold := rr.red.applyValues(append(rr.held, chunk[:n]...), final)
		// The held tail, as it came, is left to the next round whole: token
		// masking sees only what comes before it.
		head := buf[:len(buf)-hold]
		keep := 0
		if rr.red.tokens {
			head, keep = maskTokens(head, rr.prevToken, final, rr.red.mask)
		}
		if hold > 0 {
			buf = append(append(make([]byte, 0, len(head)+hold), head...), buf[len(buf)-hold:]...)
		} else {
			buf = head
		}
		keep += hold
		rr.out = buf[:len(buf)-keep]
		rr.held = append([]byte(nil), buf[len(buf)-keep:]...)
		if len(rr.out) > 0 {
			rr.prevToken = wordByte(rr.out[len(rr.out)-1])
		}
	}
	n := copy(p, rr.out)
	rr.out = rr.out[n:]
	return n, nil
}

// Generation advances whenever the values Scrub covers change, so a caller
// caching scrubbed content knows when to scrub again.
func (r *Registry) Generation() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gen
}

// Len is the number of values Scrub covers: the entries sealed holds, and
// the values it held earlier in this boot (retired, minted).
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries) + len(r.retired) + len(r.retiredDerived) + len(r.minted)
}

// Scrub returns b with every value sealed holds or held during this boot
// replaced by its placeholder, in the encodings the proxy redacts. b comes
// back unchanged (the same slice) when nothing matched.
func (r *Registry) Scrub(b []byte) []byte {
	return (&redactor{sets: []*formSet{r.scrubForms()}}).apply(b)
}

// ScrubReader streams src with every value Scrub covers now replaced by its
// placeholder, holding back only what could begin a value split across
// reads.
func (r *Registry) ScrubReader(src io.Reader) io.Reader {
	return (&redactor{sets: []*formSet{r.scrubForms()}}).reader(src)
}
