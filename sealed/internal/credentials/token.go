package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

// templateRe matches what a field template fills in: {v}, or {cred:<name>}.
var templateRe = regexp.MustCompile(`\{v\}|\{cred:([a-z0-9][a-z0-9._-]{0,62})\}`)

const maxTokenResponse = 1 << 20

func (s *Store) httpClient() *http.Client {
	if s.env.HTTPClient != nil {
		return s.env.HTTPClient
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{DialContext: credproxy.SafeDial, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Store) lockFor(name string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.tokenMu[name]
	if !ok {
		m = &sync.Mutex{}
		s.tokenMu[name] = m
	}
	return m
}

func tokenErr(status int, code, format string, args ...any) *credproxy.Error {
	return &credproxy.Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Token calls the token endpoint of entry name following its signed
// template, keeps the values the template names as derived entries, and
// returns their descriptions; the harness only ever sees placeholders. One
// request per entry runs at a time, so a rotating refresh token is never
// used twice.
func (s *Store) Token(ctx context.Context, name string, params map[string]string) ([]EntryInfo, *credproxy.Error) {
	if err := s.ensureOwner(ctx); err != nil {
		return nil, err
	}
	// A lock exists only for an entry the owner defined: the harness cannot
	// grow the map with names of its own.
	s.mu.Lock()
	_, defined := s.defs[name]
	s.mu.Unlock()
	if !defined {
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", name)
	}
	lock := s.lockFor(name)
	lock.Lock()
	defer lock.Unlock()
	// Again once it is this request's turn: one ahead of it may have taken
	// a minute.
	if err := s.ensureOwner(ctx); err != nil {
		return nil, err
	}

	// What the request was made under: its result is kept only if that
	// still holds when it returns.
	s.mu.Lock()
	def, value, srcHash, gen := s.defs[name], s.values[name], s.defHashes[name], s.gen
	s.mu.Unlock()
	if def == nil || value == nil {
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", name)
	}
	if s.expired(name) {
		return nil, tokenErr(http.StatusGone, "expired", "credential %q has expired", name)
	}
	tr := def.TokenRequest
	if tr == nil {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q has no token request template", name)
	}
	for k := range params {
		if !contains(tr.Params, k) {
			return nil, tokenErr(http.StatusForbidden, "not_allowed", "parameter %q is not allowed for %q", k, name)
		}
		// A field the owner's template sets is the owner's: a parameter
		// adds a field, never replaces one.
		if _, set := tr.Fields[k]; set {
			return nil, tokenErr(http.StatusForbidden, "not_allowed", "parameter %q is set by the owner's template for %q", k, name)
		}
		// Shown to the owner with a derived token's reveal request.
		if len(params[k]) > maxParam || hasControl(params[k]) {
			return nil, tokenErr(http.StatusBadRequest, "bad_request", "parameter %q is too long or holds control characters", k)
		}
	}
	own, oerr := s.templateValue(name, value)
	if oerr != nil {
		return nil, oerr
	}
	fields := map[string]string{}
	for k, tmpl := range tr.Fields {
		v, err := s.expand(tmpl, own)
		if err != nil {
			return nil, err
		}
		fields[k] = v
	}
	for k, v := range params {
		fields[k] = v
	}
	req, cerr := s.buildTokenRequest(ctx, tr, fields)
	if cerr != nil {
		return nil, cerr
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		s.auditRepeat("token", name, tr.URL, "unreachable")
		return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "token endpoint unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	got := parseTokenResponse(body)
	// Some endpoints refuse with a 200 that carries an error.
	if code, _ := got["error"].(string); resp.StatusCode/100 != 2 || code != "" {
		s.auditRepeat("token", name, tr.URL, fmt.Sprintf("%d %s", resp.StatusCode, sanitizeCode(code)))
		return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "token endpoint answered %d %s", resp.StatusCode, sanitizeCode(code))
	}

	if tr.RotateField != "" {
		if nv, _ := got[tr.RotateField].(string); nv != "" && nv != string(value) {
			s.rotate(ctx, def, gen, []byte(nv))
		}
	}
	var entries []*credproxy.Entry
	now := s.now()
	for _, t := range tr.Take {
		v, _ := got[t.Field].(string)
		if v == "" {
			continue
		}
		dn := t.Name
		if dn == "" {
			dn = "derived:" + name + "." + t.Field
		}
		if !strings.HasPrefix(dn, "derived:") {
			dn = "derived:" + dn
		}
		e := &credproxy.Entry{Name: dn, Hosts: append([]string(nil), t.Hosts...), Positions: t.Positions, Use: credproxy.UseInject, Value: []byte(v)}
		if t.ExpiresInField != "" {
			if secs := expiresIn(got[t.ExpiresInField]); secs > 0 {
				e.ExpiresAt = now.Add(time.Duration(secs) * time.Second)
			}
		}
		// Never past its source: an expired entry obtains nothing that
		// outlives it.
		if def.ExpiresAt > 0 && (e.ExpiresAt.IsZero() || e.ExpiresAt.Unix() > def.ExpiresAt) {
			e.ExpiresAt = time.Unix(def.ExpiresAt, 0)
		}
		if err := e.Validate(); err != nil {
			return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "template produced an invalid entry: %v", err)
		}
		entries = append(entries, e)
	}
	s.mu.Lock()
	if s.gen != gen || s.defHashes[name] != srcHash {
		s.mu.Unlock()
		s.auditRepeat("token", name, tr.URL, "dropped: the entry changed while the request ran")
		return nil, tokenErr(http.StatusConflict, "changed", "credential %q changed while the token request ran; ask again", name)
	}
	var out []EntryInfo
	for _, e := range entries {
		if err := s.reg.Put(e); err != nil {
			s.mu.Unlock()
			return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "template produced an invalid entry: %v", err)
		}
		var exp int64
		if !e.ExpiresAt.IsZero() {
			exp = e.ExpiresAt.Unix()
		}
		s.derived[e.Name] = derived{from: name, srcHash: srcHash, params: params, hosts: e.Hosts, expiresAt: exp}
		out = append(out, EntryInfo{Name: e.Name, Source: "derived", From: name, Use: string(credproxy.UseInject), Hosts: e.Hosts,
			Positions: e.Positions, ExpiresAt: exp, AllowReveal: def.AllowReveal, Placeholder: credproxy.Placeholder(e.Name)})
	}
	s.mu.Unlock()
	s.auditRepeat("token", name, tr.URL, "ok")
	return out, nil
}

// expiresIn reads a lifetime in seconds, as a number or as a string of
// digits (some endpoints send one).
func expiresIn(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func (s *Store) buildTokenRequest(ctx context.Context, tr *TokenRequest, fields map[string]string) (*http.Request, *credproxy.Error) {
	u, err := url.Parse(tr.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "token endpoint must be an https URL")
	}
	var body []byte
	ctype := "application/x-www-form-urlencoded"
	switch tr.Encoding {
	case "", "form":
		vals := url.Values{}
		for k, v := range fields {
			vals.Set(k, v)
		}
		body = []byte(vals.Encode())
	case "json":
		body, _ = json.Marshal(fields)
		ctype = "application/json"
	default:
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "unknown token request encoding %q", tr.Encoding)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tr.URL, bytes.NewReader(body))
	if err != nil {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "token endpoint is not valid")
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json")
	if ba := tr.BasicAuth; ba != nil {
		user, uerr := s.refValue(ba.UsernameEntry)
		pass, perr := s.refValue(ba.PasswordEntry)
		if uerr != nil {
			return nil, uerr
		}
		if perr != nil {
			return nil, perr
		}
		req.SetBasicAuth(user, pass)
	}
	return req, nil
}

// expand fills a field template: {v} is the entry's own value, {cred:<n>}
// another owner entry's value; everything else is sent as written. One
// pass: a value that itself reads like {cred:<n>} is sent as it is.
func (s *Store) expand(tmpl string, own []byte) (string, *credproxy.Error) {
	var ferr *credproxy.Error
	out := templateRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		if m == "{v}" {
			return string(own)
		}
		v, err := s.refValue(templateRe.FindStringSubmatch(m)[1])
		if err != nil {
			ferr = err
			return ""
		}
		return v
	})
	return out, ferr
}

func (s *Store) refValue(name string) (string, *credproxy.Error) {
	s.mu.Lock()
	v, ok := s.values[name]
	v = usableValue(s.defs[name], v)
	s.mu.Unlock()
	if !ok || v == nil {
		return "", tokenErr(http.StatusNotFound, "unknown_entry", "the template refers to %q, which is not loaded", name)
	}
	if s.expired(name) {
		return "", tokenErr(http.StatusGone, "expired", "the template refers to %q, which has expired", name)
	}
	tv, err := s.templateValue(name, v)
	return string(tv), err
}

// templateValue is what an entry stands for in a token request: its value,
// or for a jwt signing entry a token freshly minted from its key. Any other
// signing key is never sent. The owner's definition decides, not what the
// proxy currently serves.
func (s *Store) templateValue(name string, value []byte) ([]byte, *credproxy.Error) {
	s.mu.Lock()
	d := s.defs[name]
	s.mu.Unlock()
	if d == nil {
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", name)
	}
	if useOf(d) != credproxy.UseSign {
		return value, nil
	}
	if d.Signer == nil || d.Signer.Method != credproxy.SignJWT {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q is a signing key and is never sent", name)
	}
	tok, err := credproxy.MintJWT(d.Entry(value), s.now())
	if err != nil {
		return nil, tokenErr(http.StatusInternalServerError, "sign_failed", "credential %q could not mint a token", name)
	}
	return tok, nil
}

// parseTokenResponse reads a JSON object, or the form encoding some token
// endpoints still answer with.
func parseTokenResponse(body []byte) map[string]any {
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		return m
	}
	m = map[string]any{}
	if vals, err := url.ParseQuery(string(body)); err == nil {
		for k := range vals {
			m[k] = vals.Get(k)
		}
	}
	return m
}

// sanitizeCode keeps an OAuth error code (RFC 6749 §5.2 grammar) and drops
// anything else, so no response text reaches the harness.
func sanitizeCode(code string) string {
	for _, r := range code {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	if len(code) > 64 {
		return ""
	}
	return code
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Store) audit(op, name, target, result string) {
	s.addAudit(auditRecord(s.now(), op, name, target, result))
}

// auditRepeat records what the harness can cause as often as it likes: it is
// counted by kind (AuditRecord.repeat).
func (s *Store) auditRepeat(op, name, target, result string) {
	r := auditRecord(s.now(), op, name, target, result)
	r.repeat = true
	s.addAudit(r)
}

func auditRecord(now time.Time, op, name, target, result string) AuditRecord {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	var names []string
	if name != "" {
		names = []string{name}
	}
	return AuditRecord{Time: now, Op: op, Names: names, Host: host, Result: result}
}

// rotate makes value, which sealed obtained for def (a rotated token, a
// login), the entry's value, and writes it back to the attestor, signed by
// agentSeal, so the next boot starts from it. It is dropped if everything
// was cleared since gen, or the owner gave the entry a new value or login
// meanwhile (its binding changed). had says whether the entry had a value
// before. A failed write is retried in the background.
func (s *Store) rotate(ctx context.Context, def *Definition, gen uint64, value []byte) (applied, had bool) {
	// A value the proxy could not serve (over credproxy.MaxValueLen, say)
	// is not taken: the entry keeps the value it has.
	if def.Entry(value).Validate() != nil {
		s.auditRepeat("rotate", def.Name, "", "refused: a value the proxy cannot serve")
		return false, false
	}
	s.mu.Lock()
	cur := s.defs[def.Name]
	if s.gen != gen || cur == nil || cur.Binding() != def.Binding() {
		s.mu.Unlock()
		s.auditRepeat("rotate", def.Name, "", "dropped: the entry changed meanwhile")
		return false, false
	}
	had = s.values[def.Name] != nil
	s.values[def.Name] = value
	s.syncRegistryLocked()
	owner, binding, writeback := s.owner, cur.Binding(), cur.Writeback
	s.mu.Unlock()
	if !writeback || s.env.Writeback == nil {
		s.auditRepeat("rotate", def.Name, "", "kept until restart: no writeback")
		return true, had
	}
	wb, err := s.signWriteback(def.Name, value, binding, owner)
	if err != nil {
		s.env.Logf("credentials: a rotated value could not be sealed for writeback (the owner's audit log names it)")
		s.audit("writeback", def.Name, "", "failed: "+err.Error())
		return true, had
	}
	// The harness hanging up does not stop the writeback: the endpoint has
	// already rotated, and the next boot needs the new value.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if s.postWriteback(ctx, def.Name, wb) == nil {
		s.auditRepeat("writeback", def.Name, "", "ok")
		return true, had
	}
	s.auditRepeat("writeback", def.Name, "", "failed")
	s.events.add(Event{Type: "writeback_failed", Name: def.Name})
	go s.retryWriteback(def.Name, wb, value)
	return true, had
}

// writeBackOnce seals value for owner, signs it for binding and posts it to
// the attestor (three tries), with no retry after.
func (s *Store) writeBackOnce(ctx context.Context, name, binding string, owner common.Address, value []byte) error {
	wb, err := s.signWriteback(name, value, binding, owner)
	if err != nil {
		return err
	}
	return s.postWriteback(ctx, name, wb)
}

// postWriteback posts wb, trying three times.
func (s *Store) postWriteback(ctx context.Context, name string, wb Writeback) (err error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err = s.env.Writeback(ctx, name, wb); err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * s.retryUnit)
	}
	return err
}

// retryWriteback posts wb again with backoff while value is still the
// entry's value. Under the entry's lock, like every other writeback, so a
// later one (a new login, a rotation, a disconnect) is never overwritten.
func (s *Store) retryWriteback(name string, wb Writeback, value []byte) {
	for backoff := 30 * s.retryUnit; backoff <= 1800*s.retryUnit; backoff *= 2 {
		time.Sleep(backoff)
		if s.retryOnce(name, wb, value) {
			return
		}
	}
}

// retryOnce reports whether the retry is over: posted, or superseded.
func (s *Store) retryOnce(name string, wb Writeback, value []byte) bool {
	lock := s.lockFor(name)
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	current := s.values[name]
	s.mu.Unlock()
	if !bytes.Equal(current, value) {
		return true // superseded
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.env.Writeback(ctx, name, wb) != nil {
		return false
	}
	s.auditRepeat("writeback", name, "", "ok after retry")
	return true
}

// signWriteback seals value to agentSeal for owner (the owner the state
// belongs to) and signs it for binding.
func (s *Store) signWriteback(name string, value []byte, binding string, owner common.Address) (Writeback, error) {
	if owner == (common.Address{}) {
		return Writeback{}, errors.New("the owner is not known yet")
	}
	pub := eciesgo.NewPrivateKeyFromBytes(s.env.AgentSealPriv).PublicKey
	ct, err := SealValue(pub, owner, s.env.SealID, s.env.Domain.ChainID, name, value)
	if err != nil {
		return Writeback{}, err
	}
	key, err := crypto.ToECDSA(s.env.AgentSealPriv)
	if err != nil {
		return Writeback{}, err
	}
	sig, err := crypto.Sign(crypto.Keccak256(WritebackMessage(s.env.SealID, name, binding, s.env.BootID, ct)), key)
	if err != nil {
		return Writeback{}, err
	}
	sig[64] += 27
	return Writeback{Ciphertext: base64.StdEncoding.EncodeToString(ct), Binding: binding, BootID: s.env.BootID, Signature: hexutil.Encode(sig)}, nil
}
