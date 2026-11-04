package credproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"sort"
)

// Values shorter than these are not redacted: a short string would match
// ordinary response bytes. Credentials are far longer in practice.
const (
	minRawRedact     = 6
	minEncodedRedact = 8
)

type redactForm struct{ match, repl []byte }

// redactor replaces every known credential value with its placeholder, in
// the encodings a value is likely to travel in: raw, percent-encoded,
// JSON-escaped, and standard or URL-safe base64 at each of the three byte
// alignments a value can take inside a longer base64 run.
type redactor struct{ forms []redactForm }

func newRedactor(secrets map[string][]byte) *redactor { return buildRedactor(secrets, false) }

// newMaskRedactor replaces each match with as many '*' as it has bytes, for
// streams whose framing a change in length would break (WebSocket).
func newMaskRedactor(secrets map[string][]byte) *redactor { return buildRedactor(secrets, true) }

func buildRedactor(secrets map[string][]byte, mask bool) *redactor {
	r := &redactor{}
	seen := map[string]bool{}
	add := func(match string, min int, repl []byte) {
		if len(match) < min || seen[match] {
			return
		}
		seen[match] = true
		if mask {
			repl = bytes.Repeat([]byte("*"), len(match))
		}
		r.forms = append(r.forms, redactForm{match: []byte(match), repl: repl})
	}
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		v := secrets[name]
		repl := []byte(Placeholder(name))
		add(string(v), minRawRedact, repl)
		add(url.QueryEscape(string(v)), minEncodedRedact, repl)
		add(url.PathEscape(string(v)), minEncodedRedact, repl)
		if q, err := json.Marshal(string(v)); err == nil {
			add(string(q[1:len(q)-1]), minEncodedRedact, repl)
		}
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			for k := 0; k < 3; k++ {
				full := enc.EncodeToString(append(make([]byte, k), v...))
				start, end := (8*k+5)/6, (8*(k+len(v)))/6
				if end > start {
					add(full[start:end], minEncodedRedact, repl)
				}
			}
		}
	}
	// Longest first, so a longer encoding is replaced before a shorter one
	// that happens to be its substring.
	sort.SliceStable(r.forms, func(i, j int) bool { return len(r.forms[i].match) > len(r.forms[j].match) })
	return r
}

func (r *redactor) apply(b []byte) []byte {
	for _, f := range r.forms {
		if bytes.Contains(b, f.match) {
			b = bytes.ReplaceAll(b, f.match, f.repl)
		}
	}
	return b
}

func (r *redactor) applyString(s string) string { return string(r.apply([]byte(s))) }

// pendingTail is the length of the longest suffix of b that is a proper
// prefix of some form: those bytes may be the start of a value split across
// reads, so they are held back until more data arrives.
func (r *redactor) pendingTail(b []byte) int {
	keep := 0
	for _, f := range r.forms {
		max := len(f.match) - 1
		if max > len(b) {
			max = len(b)
		}
		for l := max; l > keep; l-- {
			if bytes.HasSuffix(b, f.match[:l]) {
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
	if len(r.forms) == 0 {
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
}

func (rr *redactReader) Read(p []byte) (int, error) {
	for len(rr.out) == 0 {
		if rr.err != nil {
			if len(rr.held) > 0 {
				rr.out, rr.held = rr.red.apply(rr.held), nil
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
		buf := rr.red.apply(append(rr.held, chunk[:n]...))
		keep := 0
		if rr.err == nil {
			keep = rr.red.pendingTail(buf)
		}
		rr.out = buf[:len(buf)-keep]
		rr.held = append([]byte(nil), buf[len(buf)-keep:]...)
	}
	n := copy(p, rr.out)
	rr.out = rr.out[n:]
	return n, nil
}

// Generation advances whenever the entries change, so a caller caching
// scrubbed content knows when to scrub again.
func (r *Registry) Generation() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gen
}

// Len is the number of entries sealed holds.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// Scrub returns b with every value sealed holds replaced by its placeholder,
// in the encodings the proxy redacts. b comes back unchanged (the same
// slice) when nothing matched.
func (r *Registry) Scrub(b []byte) []byte { return newRedactor(r.secrets()).apply(b) }

// ScrubReader streams src with every value sealed holds now replaced by its
// placeholder, holding back only what could begin a value split across
// reads.
func (r *Registry) ScrubReader(src io.Reader) io.Reader { return newRedactor(r.secrets()).reader(src) }
