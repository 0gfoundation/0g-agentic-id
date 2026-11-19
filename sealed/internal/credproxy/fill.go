package credproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// maxBodyBytes caps a request body the proxy will parse to fill a
// placeholder. Larger bodies pass through untouched; a placeholder inside one
// is refused rather than silently sent.
const maxBodyBytes = 64 << 10

// Error is a refusal reported to the harness: an HTTP status, a stable code
// (X-Seal-Credential-Error) and a message that never carries a value.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func refuse(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// filler resolves the placeholders of one request bound for host.
type filler struct {
	reg    *Registry
	host   string
	now    time.Time
	named  []string          // every placeholder name met so far, filled or not
	used   []string          // the entries filled
	filled map[string][]byte // entry name -> the value written in
	minted map[string][]byte // jwt entries: the token this request carries
}

// note keeps names for the audit record, which names a refused request's
// credentials too.
func (f *filler) note(names ...string) {
	for _, n := range names {
		if !slices.Contains(f.named, n) {
			f.named = append(f.named, n)
		}
	}
}

// entry checks that name may be filled into a request for f.host.
func (f *filler) entry(name string) (*Entry, *Error) {
	e := f.reg.Get(name)
	if e == nil {
		return nil, refuse(http.StatusForbidden, "unknown_entry", "no credential named %q", name)
	}
	if !e.ExpiresAt.IsZero() && f.now.After(e.ExpiresAt) {
		return nil, refuse(http.StatusGone, "expired", "credential %q has expired", name)
	}
	switch {
	case e.Use == UseTokenOnly:
		return nil, refuse(http.StatusForbidden, "token_only", "credential %q may only be used in a token request", name)
	case e.Use == UseSign && (e.Signer == nil || e.Signer.Method != SignJWT):
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "credential %q is a signing key and is never written into a request", name)
	}
	allowed := false
	for _, h := range e.Hosts {
		if h == f.host {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, refuse(http.StatusForbidden, "host_not_allowed", "credential %q may not be sent to %s", name, f.host)
	}
	f.used = append(f.used, name)
	if e.Use == UseSign {
		// A jwt entry stands for a token minted from its key, the same one
		// wherever it appears in this request.
		tok, ok := f.minted[name]
		if !ok {
			var err error
			if tok, err = MintJWT(e, f.now); err != nil {
				return nil, refuse(http.StatusInternalServerError, "sign_failed", "credential %q could not mint a token", name)
			}
			if f.minted == nil {
				f.minted = map[string][]byte{}
			}
			f.minted[name] = tok
		}
		cp := *e
		cp.Value = tok
		f.filled[name] = tok
		return &cp, nil
	}
	f.filled[name] = e.Value
	return e, nil
}

// single requires s to hold exactly one placeholder and returns its name.
func (f *filler) single(s, where string) (string, *Error) {
	names := placeholderNames(s)
	f.note(names...)
	if len(names) != 1 || strings.Count(s, "[[credential:") != 1 {
		return "", refuse(http.StatusForbidden, "position_not_allowed", "%s must hold exactly one placeholder", where)
	}
	return names[0], nil
}

// fillRequest rewrites req (bound for host) and body in place of their
// placeholders. It returns the new body, the entry names used and the values
// written in (by entry name; a jwt entry's is the token minted for it).
// Nothing is changed when it returns an error; the names are then the
// placeholder names met so far, for the audit record.
func (r *Registry) fillRequest(req *http.Request, host string, body []byte) ([]byte, []string, map[string][]byte, *Error) {
	f := &filler{reg: r, host: NormalizeHost(host), now: r.now(), filled: map[string][]byte{}}
	out, err := f.fill(req, body)
	if err != nil {
		return nil, f.named, nil, err
	}
	for name, tok := range f.minted {
		r.holdMinted(name, tok, jwtExpiry(tok, f.now))
	}
	return out, f.used, f.filled, nil
}

func (f *filler) fill(req *http.Request, body []byte) ([]byte, *Error) {
	header := req.Header.Clone()
	for k, vs := range header {
		if strings.Contains(k, "[[credential:") {
			f.note(placeholderNames(k)...)
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may not stand in a header name")
		}
		for i, v := range vs {
			nv, err := f.fillHeader(k, v)
			if err != nil {
				return nil, err
			}
			vs[i] = nv
		}
	}

	path, err := f.fillPath(req.URL.EscapedPath())
	if err != nil {
		return nil, err
	}
	query, _, err := f.fillQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	newBody, err := f.fillBody(req.Header.Values("Content-Type"), body)
	if err != nil {
		return nil, err
	}

	req.Header = header
	decoded := req.URL.Path
	if path != req.URL.EscapedPath() {
		if p, perr := url.PathUnescape(path); perr == nil {
			decoded = p
		}
	}
	old := req.URL
	req.URL = &url.URL{
		Scheme: old.Scheme, Opaque: old.Opaque, User: old.User, Host: old.Host,
		Path: decoded, RawPath: path, ForceQuery: old.ForceQuery, RawQuery: query,
		Fragment: old.Fragment, RawFragment: old.RawFragment,
	}
	return newBody, nil
}

func (f *filler) fillHeader(name, v string) (string, *Error) {
	if strings.EqualFold(name, "Authorization") && len(v) > 6 && strings.EqualFold(v[:6], "Basic ") {
		if decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:])); derr == nil && bytes.Contains(decoded, []byte("[[credential:")) {
			return f.fillBasic(string(decoded))
		}
	}
	if !strings.Contains(v, "[[credential:") {
		return v, nil
	}
	f.note(placeholderNames(v)...)
	if forbiddenHeader(name) {
		return "", refuse(http.StatusForbidden, "forbidden_header", "header %s may not carry a credential", name)
	}
	n, err := f.single(v, "header "+name)
	if err != nil {
		return "", err
	}
	e, err := f.entry(n)
	if err != nil {
		return "", err
	}
	ph := Placeholder(n)
	for _, p := range e.Positions {
		if p.Kind != PosHeader || !strings.EqualFold(p.Name, name) {
			continue
		}
		prefix, suffix, _ := strings.Cut(p.Template, "{v}")
		if v == prefix+ph+suffix {
			return prefix + string(e.Value) + suffix, nil
		}
	}
	return "", refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in header %s in this form", n, name)
}

func (f *filler) fillBasic(decoded string) (string, *Error) {
	user, pass, _ := strings.Cut(decoded, ":")
	// `echo user:pass | base64` encodes a trailing newline; it is never part
	// of the password the agent meant.
	pass = strings.TrimRight(pass, "\r\n")
	if strings.Contains(user, "[[credential:") {
		f.note(placeholderNames(user)...)
		return "", refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may only stand in the Basic password")
	}
	n, err := f.single(pass, "the Basic password")
	if err != nil {
		return "", err
	}
	if pass != Placeholder(n) {
		return "", refuse(http.StatusForbidden, "position_not_allowed", "the Basic password must be the placeholder alone")
	}
	e, err := f.entry(n)
	if err != nil {
		return "", err
	}
	for _, p := range e.Positions {
		if p.Kind == PosBasic && p.Username == user {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+string(e.Value))), nil
		}
	}
	return "", refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in Basic auth for user %q", n, user)
}

// fillPath fills a path segment that is a placeholder as written or once
// percent-decoded, whichever of its bytes are escaped.
func (f *filler) fillPath(escaped string) (string, *Error) {
	if !strings.Contains(escaped, "credential") && !strings.Contains(escaped, "%") {
		return escaped, nil
	}
	segs := strings.Split(escaped, "/")
	changed := false
	for i, seg := range segs {
		dec, derr := url.PathUnescape(seg)
		if derr != nil || !strings.Contains(dec, "[[credential:") {
			continue
		}
		n, err := f.single(dec, "a path segment")
		if err != nil {
			return "", err
		}
		if dec != Placeholder(n) {
			return "", refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in the path must be a whole segment")
		}
		e, err := f.entry(n)
		if err != nil {
			return "", err
		}
		if !hasKind(e, PosPath) {
			return "", refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in the path", n)
		}
		segs[i] = url.PathEscape(string(e.Value))
		changed = true
	}
	if !changed {
		return escaped, nil
	}
	return strings.Join(segs, "/"), nil
}

// fillPairs fills a query string or a form body: name=value pairs joined by
// '&', each placeholder standing alone as the value of an allowed name. It
// returns the pairs and how many placeholders it filled.
func (f *filler) fillPairs(raw, where string, allowed func(*Entry, string) bool) (string, int, *Error) {
	if !strings.Contains(raw, "credential") && !strings.Contains(raw, "%") {
		return raw, 0, nil
	}
	parts := strings.Split(raw, "&")
	filled := 0
	for i, part := range parts {
		k, v, _ := strings.Cut(part, "=")
		dk, kerr := url.QueryUnescape(k)
		dv, verr := url.QueryUnescape(v)
		if kerr != nil {
			dk = k
		}
		if verr != nil {
			dv = v
		}
		if strings.Contains(dk, "[[credential:") {
			f.note(placeholderNames(dk)...)
			return "", 0, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may not stand in a %s name", where)
		}
		if !strings.Contains(dv, "[[credential:") {
			continue
		}
		n, err := f.single(dv, where+" "+dk)
		if err != nil {
			return "", 0, err
		}
		if dv != Placeholder(n) {
			return "", 0, refuse(http.StatusForbidden, "position_not_allowed", "%s %s must be the placeholder alone", where, dk)
		}
		e, err := f.entry(n)
		if err != nil {
			return "", 0, err
		}
		if !allowed(e, dk) {
			return "", 0, refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in %s %s", n, where, dk)
		}
		parts[i] = k + "=" + url.QueryEscape(string(e.Value))
		filled++
	}
	if filled == 0 {
		return raw, 0, nil
	}
	return strings.Join(parts, "&"), filled, nil
}

func (f *filler) fillQuery(raw string) (string, int, *Error) {
	return f.fillPairs(raw, "query parameter", func(e *Entry, name string) bool {
		for _, p := range e.Positions {
			if p.Kind == PosQuery && p.Param == name {
				return true
			}
		}
		return false
	})
}

func bodyField(e *Entry, name string) bool {
	for _, p := range e.Positions {
		if p.Kind == PosBody && p.Field == name {
			return true
		}
	}
	return false
}

var literalPlaceholder = []byte("[[credential:")

// mentionsPlaceholder reports whether b names a placeholder as it is, or once
// its percent escapes or its JSON string escapes are decoded.
func mentionsPlaceholder(b []byte) bool {
	return bytes.Contains(b, literalPlaceholder) ||
		bytes.Contains(percentDecode(b), literalPlaceholder) ||
		bytes.Contains(jsonUnescape(b), literalPlaceholder)
}

// mentionedNames lists the entry names b names, in any of those forms.
func mentionedNames(b []byte) []string {
	var out []string
	for _, d := range [][]byte{b, percentDecode(b), jsonUnescape(b)} {
		for _, n := range placeholderNames(string(d)) {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// fillBody fills a JSON or form body. A body that names a placeholder in any
// form must have it filled, or the request is refused: it is never sent on
// with a placeholder the harness believes was filled, and never filled in a
// way the server could read differently from how the proxy read it. A form
// body must be url-encoded throughout once filled; a JSON body goes out with
// its own '&' and ';' escaped (fillJSON).
func (f *filler) fillBody(contentTypes []string, body []byte) ([]byte, *Error) {
	if len(body) == 0 || !mentionsPlaceholder(body) {
		return body, nil
	}
	f.note(mentionedNames(body)...)
	if len(contentTypes) != 1 {
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "a body holding a placeholder needs exactly one Content-Type")
	}
	mt, _, _ := mime.ParseMediaType(contentTypes[0])
	switch mt {
	case "application/x-www-form-urlencoded":
		out, n, err := f.fillPairs(string(body), "form field", bodyField)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a form body must be the whole value of a field")
		}
		// What is sent must be url-encoded throughout; a placeholder written
		// raw as a whole value is gone once filled (fillPairs refuses one
		// anywhere else, and a placeholder name holds no '&', '=', ';' or '+').
		if !wellFormedForm([]byte(out)) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "a form body holding a placeholder must be url-encoded throughout")
		}
		return []byte(out), nil
	case "application/json":
		return f.fillJSON(body)
	}
	return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may only stand in a JSON or form body")
}

// wellFormedForm reports whether b is application/x-www-form-urlencoded as an
// encoder writes it: alphanumerics, "*-._~", '+', '=', '&' and %XX escapes,
// nothing else. A body with JSON's braces, quotes, colons or whitespace, for
// one, would read differently to a server that parses it as JSON, and the
// value filled into a form field would land in some other field there.
func wellFormedForm(b []byte) bool {
	if len(b) > 0 && (b[0] == '{' || b[0] == '[') {
		return false
	}
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("*-._~+=&", c) >= 0:
		case c == '%' && i+2 < len(b) && isHex(b[i+1]) && isHex(b[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

// fillJSON fills placeholders that stand alone as top-level string values,
// written as they are (no escapes). Every placeholder the decoded body names
// must be one of those, so one nested deeper, inside a key or escaped is
// refused.
//
// The body's own '&' and ';' go out as \u0026 and \u003b. In valid JSON
// those bytes stand only inside strings, where the escapes read the same to
// a JSON parser, and a server that parses the body as a form finds no field
// separator of the agent's writing in it. A filled value is written as
// encoding/json writes it ('&' escaped too).
func (f *filler) fillJSON(body []byte) ([]byte, *Error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body needs a top-level object")
	}
	type fill struct{ quoted, value []byte }
	var fills []fill
	for k, raw := range obj {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || !strings.Contains(s, "[[credential:") {
			continue
		}
		n, err := f.single(s, "JSON field "+k)
		if err != nil {
			return nil, err
		}
		if s != Placeholder(n) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "JSON field %s must be the placeholder alone", k)
		}
		quoted := []byte(`"` + Placeholder(n) + `"`)
		if !bytes.Equal(raw, quoted) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "the placeholder in JSON field %s must be written without escapes", k)
		}
		e, err := f.entry(n)
		if err != nil {
			return nil, err
		}
		if !bodyField(e, k) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in JSON field %s", n, k)
		}
		v, _ := json.Marshal(string(e.Value))
		fills = append(fills, fill{quoted: quoted, value: v})
	}
	if len(fills) == 0 || jsonPlaceholderCount(body) != len(fills) {
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body must be a whole top-level string value")
	}
	out := bytes.ReplaceAll(bytes.ReplaceAll(body, []byte("&"), []byte(`\u0026`)), []byte(";"), []byte(`\u003b`))
	for _, fl := range fills {
		if !bytes.Contains(out, fl.quoted) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body could not be filled")
		}
		out = bytes.Replace(out, fl.quoted, fl.value, 1)
	}
	return out, nil
}

// jsonPlaceholderCount counts the placeholders in every decoded string of
// body, keys included, at any depth.
func jsonPlaceholderCount(body []byte) int {
	dec := json.NewDecoder(bytes.NewReader(body))
	n := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return n
		}
		if err != nil {
			return -1
		}
		if s, ok := tok.(string); ok {
			n += strings.Count(s, "[[credential:")
		}
	}
}

// percentDecode decodes every valid %XX escape in b and leaves the rest.
func percentDecode(b []byte) []byte {
	if bytes.IndexByte(b, '%') < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '%' && i+2 < len(b) && isHex(b[i+1]) && isHex(b[i+2]) {
			out = append(out, unhex(b[i+1])<<4|unhex(b[i+2]))
			i += 2
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// jsonUnescape decodes the JSON string escapes in b (\uXXXX, \/, \", \\)
// wherever they stand, and leaves the rest.
func jsonUnescape(b []byte) []byte {
	if bytes.IndexByte(b, '\\') < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			switch c := b[i+1]; c {
			case 'u':
				if i+5 < len(b) && isHex(b[i+2]) && isHex(b[i+3]) && isHex(b[i+4]) && isHex(b[i+5]) {
					r := rune(unhex(b[i+2]))<<12 | rune(unhex(b[i+3]))<<8 | rune(unhex(b[i+4]))<<4 | rune(unhex(b[i+5]))
					out = utf8.AppendRune(out, r)
					i += 5
					continue
				}
			case '/', '"', '\\':
				out = append(out, c)
				i++
				continue
			}
		}
		out = append(out, b[i])
	}
	return out
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func hasKind(e *Entry, kind string) bool {
	for _, p := range e.Positions {
		if p.Kind == kind {
			return true
		}
	}
	return false
}
