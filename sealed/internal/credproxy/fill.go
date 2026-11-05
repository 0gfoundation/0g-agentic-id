package credproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
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
	used   []string
	minted map[string][]byte // jwt entries: the token this request carries
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
		return &cp, nil
	}
	return e, nil
}

// single requires s to hold exactly one placeholder and returns its name.
func single(s, where string) (string, *Error) {
	names := placeholderNames(s)
	if len(names) != 1 || strings.Count(s, "[[credential:") != 1 {
		return "", refuse(http.StatusForbidden, "position_not_allowed", "%s must hold exactly one placeholder", where)
	}
	return names[0], nil
}

// fillRequest rewrites req (bound for host) and body in place of their
// placeholders. It returns the new body, the entry names used and the tokens
// minted for jwt entries (by entry name). Nothing is changed when it returns
// an error.
func (r *Registry) fillRequest(req *http.Request, host string, body []byte) ([]byte, []string, map[string][]byte, *Error) {
	f := &filler{reg: r, host: NormalizeHost(host), now: r.now()}

	header := req.Header.Clone()
	for k, vs := range header {
		if strings.Contains(k, "[[credential:") {
			return nil, nil, nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may not stand in a header name")
		}
		for i, v := range vs {
			nv, err := f.fillHeader(k, v)
			if err != nil {
				return nil, nil, nil, err
			}
			vs[i] = nv
		}
	}

	path, err := f.fillPath(req.URL.EscapedPath())
	if err != nil {
		return nil, nil, nil, err
	}
	query, err := f.fillQuery(req.URL.RawQuery)
	if err != nil {
		return nil, nil, nil, err
	}
	newBody, err := f.fillBody(req.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, nil, nil, err
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
	return newBody, f.used, f.minted, nil
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
	if forbiddenHeader(name) {
		return "", refuse(http.StatusForbidden, "forbidden_header", "header %s may not carry a credential", name)
	}
	n, err := single(v, "header "+name)
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
		return "", refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may only stand in the Basic password")
	}
	n, err := single(pass, "the Basic password")
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

func (f *filler) fillPath(escaped string) (string, *Error) {
	if !strings.Contains(escaped, "credential") {
		return escaped, nil
	}
	segs := strings.Split(escaped, "/")
	changed := false
	for i, seg := range segs {
		dec, derr := url.PathUnescape(seg)
		if derr != nil || !strings.Contains(dec, "[[credential:") {
			continue
		}
		n, err := single(dec, "a path segment")
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
// '&', each placeholder standing alone as the value of an allowed name.
func (f *filler) fillPairs(raw, where string, allowed func(*Entry, string) bool) (string, *Error) {
	if !strings.Contains(raw, "credential") {
		return raw, nil
	}
	parts := strings.Split(raw, "&")
	changed := false
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
			return "", refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may not stand in a %s name", where)
		}
		if !strings.Contains(dv, "[[credential:") {
			continue
		}
		n, err := single(dv, where+" "+dk)
		if err != nil {
			return "", err
		}
		if dv != Placeholder(n) {
			return "", refuse(http.StatusForbidden, "position_not_allowed", "%s %s must be the placeholder alone", where, dk)
		}
		e, err := f.entry(n)
		if err != nil {
			return "", err
		}
		if !allowed(e, dk) {
			return "", refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in %s %s", n, where, dk)
		}
		parts[i] = k + "=" + url.QueryEscape(string(e.Value))
		changed = true
	}
	if !changed {
		return raw, nil
	}
	return strings.Join(parts, "&"), nil
}

func (f *filler) fillQuery(raw string) (string, *Error) {
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

var encodedPlaceholder = []byte("%5B%5Bcredential%3A")

func (f *filler) fillBody(contentType string, body []byte) ([]byte, *Error) {
	if len(body) == 0 || (!bytes.Contains(body, []byte("[[credential:")) && !bytes.Contains(bytes.ToUpper(body), bytes.ToUpper(encodedPlaceholder))) {
		return body, nil
	}
	mt, _, _ := mime.ParseMediaType(contentType)
	switch mt {
	case "application/x-www-form-urlencoded":
		out, err := f.fillPairs(string(body), "form field", bodyField)
		if err != nil {
			return nil, err
		}
		return []byte(out), nil
	case "application/json":
		return f.fillJSON(body)
	}
	return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder may only stand in a JSON or form body")
}

// fillJSON fills placeholders that stand alone as top-level string values.
// Every occurrence in the body must be one of those, so a placeholder nested
// deeper or inside a key is refused.
func (f *filler) fillJSON(body []byte) ([]byte, *Error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body needs a top-level object")
	}
	type fill struct{ quoted, value []byte }
	var fills []fill
	allowedHits := 0
	for k, raw := range obj {
		if !bytes.Contains(raw, []byte("[[credential:")) {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body must be a whole top-level string value")
		}
		n, err := single(s, "JSON field "+k)
		if err != nil {
			return nil, err
		}
		if s != Placeholder(n) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "JSON field %s must be the placeholder alone", k)
		}
		e, err := f.entry(n)
		if err != nil {
			return nil, err
		}
		if !bodyField(e, k) {
			return nil, refuse(http.StatusForbidden, "position_not_allowed", "credential %q is not allowed in JSON field %s", n, k)
		}
		v, _ := json.Marshal(string(e.Value))
		fills = append(fills, fill{quoted: []byte(`"` + Placeholder(n) + `"`), value: v})
		allowedHits++
	}
	if bytes.Count(body, []byte("[[credential:")) != allowedHits {
		return nil, refuse(http.StatusForbidden, "position_not_allowed", "a placeholder in a JSON body must be a whole top-level string value")
	}
	out := body
	for _, fl := range fills {
		out = bytes.Replace(out, fl.quoted, fl.value, 1)
	}
	return out, nil
}

func hasKind(e *Entry, kind string) bool {
	for _, p := range e.Positions {
		if p.Kind == kind {
			return true
		}
	}
	return false
}
