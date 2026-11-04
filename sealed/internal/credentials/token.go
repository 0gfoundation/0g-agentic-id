package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

var credRefRe = regexp.MustCompile(`\{cred:([a-z0-9][a-z0-9._-]{0,62})\}`)

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
	lock := s.lockFor(name)
	lock.Lock()
	defer lock.Unlock()

	s.mu.Lock()
	def, value := s.defs[name], s.values[name]
	s.mu.Unlock()
	if def == nil || value == nil {
		return nil, tokenErr(http.StatusNotFound, "unknown_entry", "no credential named %q", name)
	}
	tr := def.TokenRequest
	if tr == nil {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q has no token request template", name)
	}
	for k := range params {
		if !contains(tr.Params, k) {
			return nil, tokenErr(http.StatusForbidden, "not_allowed", "parameter %q is not allowed for %q", k, name)
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
		s.audit("token", name, tr.URL, "unreachable")
		return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "token endpoint unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	got := parseTokenResponse(body)
	if resp.StatusCode/100 != 2 {
		code, _ := got["error"].(string)
		s.audit("token", name, tr.URL, fmt.Sprintf("%d %s", resp.StatusCode, code))
		return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "token endpoint answered %d %s", resp.StatusCode, sanitizeCode(code))
	}

	if tr.RotateField != "" {
		if nv, _ := got[tr.RotateField].(string); nv != "" && nv != string(value) {
			s.rotate(ctx, def, []byte(nv))
		}
	}
	var out []EntryInfo
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
		var exp int64
		if t.ExpiresInField != "" {
			if secs, ok := got[t.ExpiresInField].(float64); ok && secs > 0 {
				e.ExpiresAt = now.Add(time.Duration(secs) * time.Second)
				exp = e.ExpiresAt.Unix()
			}
		}
		if err := s.reg.Put(e); err != nil {
			return nil, tokenErr(http.StatusBadGateway, "token_request_failed", "template produced an invalid entry: %v", err)
		}
		s.mu.Lock()
		s.derived[dn] = derived{from: name, hosts: e.Hosts, expiresAt: exp}
		s.mu.Unlock()
		out = append(out, EntryInfo{Name: dn, Source: "derived", From: name, Use: string(credproxy.UseInject), Hosts: e.Hosts,
			ExpiresAt: exp, AllowReveal: def.AllowReveal, Placeholder: credproxy.Placeholder(dn)})
	}
	s.audit("token", name, tr.URL, "ok")
	return out, nil
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
// another owner entry's value; everything else is sent as written.
func (s *Store) expand(tmpl string, own []byte) (string, *credproxy.Error) {
	out := strings.ReplaceAll(tmpl, "{v}", string(own))
	var ferr *credproxy.Error
	out = credRefRe.ReplaceAllStringFunc(out, func(m string) string {
		v, err := s.refValue(credRefRe.FindStringSubmatch(m)[1])
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
	tv, err := s.templateValue(name, v)
	return string(tv), err
}

// templateValue is what an entry stands for in a token request: its value,
// or for a jwt signing entry a token freshly minted from its key. Any other
// signing key is never sent.
func (s *Store) templateValue(name string, value []byte) ([]byte, *credproxy.Error) {
	e := s.reg.Get(name)
	if e == nil || e.Use != credproxy.UseSign {
		return value, nil
	}
	if e.Signer == nil || e.Signer.Method != credproxy.SignJWT {
		return nil, tokenErr(http.StatusForbidden, "not_allowed", "credential %q is a signing key and is never sent", name)
	}
	tok, err := credproxy.MintJWT(e, s.now())
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
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{name}, Host: host, Result: result})
}

// rotate replaces an entry's value with the one the token endpoint just
// issued and writes it back to the attestor, signed by agentSeal, so the
// next boot starts from it. A failed write is retried in the background.
func (s *Store) rotate(ctx context.Context, def *Definition, value []byte) {
	s.mu.Lock()
	s.values[def.Name] = value
	s.syncRegistryLocked()
	defHash := s.defHashes[def.Name]
	s.mu.Unlock()
	if !def.Writeback || s.env.Writeback == nil {
		s.env.Logf("credentials: %q rotated; no writeback configured, the new value lives until restart", def.Name)
		return
	}
	wb, err := s.signWriteback(ctx, def.Name, value, defHash)
	if err != nil {
		s.env.Logf("credentials: %q rotated but could not be sealed for writeback: %v", def.Name, err)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err = s.env.Writeback(ctx, def.Name, wb); err == nil {
			s.audit("writeback", def.Name, "", "ok")
			return
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	s.audit("writeback", def.Name, "", "failed")
	s.events.add(Event{Type: "writeback_failed", Name: def.Name})
	go s.retryWriteback(def.Name, wb, value)
}

func (s *Store) retryWriteback(name string, wb Writeback, value []byte) {
	for backoff := 30 * time.Second; backoff <= 30*time.Minute; backoff *= 2 {
		time.Sleep(backoff)
		s.mu.Lock()
		current := s.values[name]
		s.mu.Unlock()
		if !bytes.Equal(current, value) {
			return // superseded by a later rotation
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.env.Writeback(ctx, name, wb)
		cancel()
		if err == nil {
			s.audit("writeback", name, "", "ok after retry")
			return
		}
	}
}

func (s *Store) signWriteback(ctx context.Context, name string, value []byte, defHash string) (Writeback, error) {
	owner, err := s.env.LiveOwner(ctx)
	if err != nil {
		return Writeback{}, err
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
	sig, err := crypto.Sign(crypto.Keccak256(WritebackMessage(s.env.SealID, name, defHash, s.env.BootID, ct)), key)
	if err != nil {
		return Writeback{}, err
	}
	sig[64] += 27
	return Writeback{Ciphertext: base64.StdEncoding.EncodeToString(ct), DefHash: defHash, BootID: s.env.BootID, Signature: hexutil.Encode(sig)}, nil
}
