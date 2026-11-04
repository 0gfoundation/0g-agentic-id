package credproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signing methods of an entry whose Use is UseSign.
const (
	SignSigV4  = "sigv4"
	SignHMAC   = "hmac"
	SignJWT    = "jwt"
	SignWallet = "wallet"
)

// SignHeader names the signing entry a request is to be signed with (sigv4,
// hmac). The proxy removes it before the request leaves.
const SignHeader = "X-Seal-Sign"

// Signer is how a signing entry's value, the key, is used. The proxy signs
// sigv4 and hmac requests on the way out, fills a freshly minted JWT where a
// jwt entry's placeholder stands, and a wallet key signs only through the
// credential socket. The key itself is never written into a request.
type Signer struct {
	Method string `json:"method"`

	// sigv4: the value is the AWS secret access key.
	AccessKeyID string `json:"access_key_id,omitempty"`
	Region      string `json:"region,omitempty"`
	Service     string `json:"service,omitempty"`
	// SessionTokenEntry names the entry holding a session token for
	// temporary credentials; it is sent as X-Amz-Security-Token.
	SessionTokenEntry string `json:"session_token_entry,omitempty"`

	// hmac: the value is the shared secret.
	Algorithm string `json:"algorithm,omitempty"` // sha256 (default), sha512, sha1
	// Message is what is signed: {method} {path} {query} {body} {timestamp}
	// and {header:<name>} are replaced, everything else is literal ("\n"
	// escapes allowed in JSON).
	Message         string `json:"message,omitempty"`
	Header          string `json:"header,omitempty"`   // the signature goes in this header,
	Param           string `json:"param,omitempty"`    // or in this query parameter
	Encoding        string `json:"encoding,omitempty"` // hex (default) or base64
	Prefix          string `json:"prefix,omitempty"`   // e.g. "sha256="
	TimestampHeader string `json:"timestamp_header,omitempty"`

	// jwt: the value is a PEM private key (RS256, ES256) or a secret (HS256).
	Alg    string         `json:"alg,omitempty"`
	KeyID  string         `json:"kid,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
	TTL    int64          `json:"ttl,omitempty"` // seconds; default 3600, at most 86400
}

func (e *Entry) validateSigner() error {
	if e.Use != UseSign {
		if e.Signer != nil {
			return fmt.Errorf("credential %q: a signer needs use sign", e.Name)
		}
		return nil
	}
	s := e.Signer
	if s == nil {
		return fmt.Errorf("credential %q: use sign needs a signer", e.Name)
	}
	switch s.Method {
	case SignSigV4:
		if s.AccessKeyID == "" || s.Region == "" || s.Service == "" {
			return fmt.Errorf("credential %q: sigv4 needs access_key_id, region and service", e.Name)
		}
		if len(e.Hosts) == 0 {
			return fmt.Errorf("credential %q: sigv4 needs the hosts it signs for", e.Name)
		}
	case SignHMAC:
		if s.Message == "" || (s.Header == "") == (s.Param == "") {
			return fmt.Errorf("credential %q: hmac needs a message and exactly one of header or param", e.Name)
		}
		if s.Header != "" && forbiddenHeader(s.Header) {
			return fmt.Errorf("credential %q: header %q may not carry a signature", e.Name, s.Header)
		}
		if _, err := hmacHash(s.Algorithm); err != nil {
			return fmt.Errorf("credential %q: %v", e.Name, err)
		}
		if s.Encoding != "" && s.Encoding != "hex" && s.Encoding != "base64" {
			return fmt.Errorf("credential %q: hmac encoding is hex or base64", e.Name)
		}
		if len(e.Hosts) == 0 {
			return fmt.Errorf("credential %q: hmac needs the hosts it signs for", e.Name)
		}
	case SignJWT:
		if _, err := jwtKey(s.Alg, e.Value); err != nil {
			return fmt.Errorf("credential %q: %v", e.Name, err)
		}
		if s.TTL < 0 || s.TTL > 86400 {
			return fmt.Errorf("credential %q: jwt ttl is 1 to 86400 seconds", e.Name)
		}
		if len(e.Hosts) == 0 || len(e.Positions) == 0 {
			return fmt.Errorf("credential %q: jwt needs the hosts and positions its token may go to", e.Name)
		}
	case SignWallet:
		if _, err := WalletKey(e.Value); err != nil {
			return fmt.Errorf("credential %q: %v", e.Name, err)
		}
	default:
		return fmt.Errorf("credential %q: unknown signing method %q", e.Name, s.Method)
	}
	return nil
}

// signRequest signs req on its way to host when it names a signing entry in
// X-Seal-Sign, or when it carries an AWS signature made with a sigv4 entry's
// access key id (an AWS tool given a placeholder for its secret: the proxy
// signs the same request again with the real key). A request that does
// neither leaves untouched. body is the buffered body; streamed means the
// body is too large to have been buffered.
func (r *Registry) signRequest(req *http.Request, host string, body []byte, streamed bool) ([]string, *Error) {
	host = NormalizeHost(host)
	now := r.now()
	name := strings.TrimSpace(req.Header.Get(SignHeader))
	req.Header.Del(SignHeader)
	if name != "" {
		e, err := r.signingEntry(name, host, now)
		if err != nil {
			return nil, err
		}
		switch e.Signer.Method {
		case SignSigV4:
			return []string{name}, r.sigV4(req, e, body, streamed, now, nil)
		case SignHMAC:
			return []string{name}, signHMAC(req, e, body, streamed, now)
		}
		return nil, refuse(http.StatusForbidden, "not_allowed", "credential %q does not sign requests", name)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return nil, nil
	}
	a, ok := parseAWSAuth(auth)
	if !ok {
		return nil, nil
	}
	e := r.sigV4ByKeyID(a.accessKeyID, host)
	if e == nil {
		return nil, nil // signed with a key sealed does not hold
	}
	if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
		return nil, refuse(http.StatusGone, "expired", "credential %q has expired", e.Name)
	}
	return []string{e.Name}, r.sigV4(req, e, body, streamed, now, &a)
}

func (r *Registry) signingEntry(name, host string, now time.Time) (*Entry, *Error) {
	e := r.Get(name)
	if e == nil {
		return nil, refuse(http.StatusForbidden, "unknown_entry", "no credential named %q", name)
	}
	if e.Use != UseSign || e.Signer == nil {
		return nil, refuse(http.StatusForbidden, "not_allowed", "credential %q is not a signing key", name)
	}
	if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
		return nil, refuse(http.StatusGone, "expired", "credential %q has expired", name)
	}
	if !hostAllowed(e, host) {
		return nil, refuse(http.StatusForbidden, "host_not_allowed", "credential %q may not sign for %s", name, host)
	}
	return e, nil
}

func (r *Registry) sigV4ByKeyID(keyID, host string) *Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.Use == UseSign && e.Signer != nil && e.Signer.Method == SignSigV4 && e.Signer.AccessKeyID == keyID && hostAllowed(e, host) {
			return e
		}
	}
	return nil
}

func hostAllowed(e *Entry, host string) bool {
	for _, h := range e.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// ── AWS Signature Version 4 ──────────────────────────────────────────────────

type awsAuth struct {
	accessKeyID, date, region, service string
	signedHeaders                      []string
}

// parseAWSAuth reads "AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/
// <service>/aws4_request, SignedHeaders=<a;b>, Signature=<hex>".
func parseAWSAuth(v string) (awsAuth, bool) {
	var a awsAuth
	for _, part := range strings.Split(strings.TrimPrefix(v, "AWS4-HMAC-SHA256 "), ",") {
		k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			f := strings.Split(val, "/")
			if len(f) != 5 || f[4] != "aws4_request" {
				return a, false
			}
			a.accessKeyID, a.date, a.region, a.service = f[0], f[1], f[2], f[3]
		case "SignedHeaders":
			a.signedHeaders = strings.Split(val, ";")
		}
	}
	return a, a.accessKeyID != "" && len(a.signedHeaders) > 0
}

// sigV4 signs req with entry e. With resign, the request keeps the date,
// scope and signed headers the client chose and is signed again; without,
// the proxy signs it from scratch.
func (r *Registry) sigV4(req *http.Request, e *Entry, body []byte, streamed bool, now time.Time, resign *awsAuth) *Error {
	s := e.Signer
	var amzDate, date, region, service string
	var signed []string
	if resign != nil {
		amzDate = req.Header.Get("X-Amz-Date")
		if len(amzDate) < 8 || amzDate[:8] != resign.date {
			return refuse(http.StatusBadRequest, "sign_failed", "an AWS-signed request must carry X-Amz-Date for its scope")
		}
		date, region, service = resign.date, resign.region, resign.service
		signed = resign.signedHeaders
	} else {
		amzDate = now.UTC().Format("20060102T150405Z")
		date, region, service = amzDate[:8], s.Region, s.Service
		req.Header.Set("X-Amz-Date", amzDate)
		signed = []string{"host", "x-amz-content-sha256", "x-amz-date"}
		if s.SessionTokenEntry != "" {
			tok := r.Get(s.SessionTokenEntry)
			if tok == nil {
				return refuse(http.StatusForbidden, "unknown_entry", "no credential named %q", s.SessionTokenEntry)
			}
			req.Header.Set("X-Amz-Security-Token", string(tok.Value))
			signed = append(signed, "x-amz-security-token")
		}
		switch {
		case !streamed:
			req.Header.Set("X-Amz-Content-Sha256", hexSum(body))
		case service == "s3":
			req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		default:
			return refuse(http.StatusRequestEntityTooLarge, "body_too_large", "a body over %d bytes cannot be signed for %s", maxBodyBytes, service)
		}
		sort.Strings(signed)
	}
	payload := req.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		if streamed {
			return refuse(http.StatusRequestEntityTooLarge, "body_too_large", "a body over %d bytes cannot be signed without X-Amz-Content-Sha256", maxBodyBytes)
		}
		payload = hexSum(body)
	}
	canonical := strings.Join([]string{
		req.Method,
		awsCanonicalURI(req.URL.EscapedPath(), service),
		awsCanonicalQuery(req.URL.RawQuery),
		awsCanonicalHeaders(req, signed),
		strings.Join(signed, ";"),
		payload,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexSum([]byte(canonical))
	key := hmacSum(sha256.New, []byte("AWS4"+string(e.Value)), []byte(date))
	key = hmacSum(sha256.New, key, []byte(region))
	key = hmacSum(sha256.New, key, []byte(service))
	key = hmacSum(sha256.New, key, []byte("aws4_request"))
	sig := hex.EncodeToString(hmacSum(sha256.New, key, []byte(toSign)))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKeyID, scope, strings.Join(signed, ";"), sig))
	return nil
}

// awsEscape is AWS's URI encoding: every byte but A-Z a-z 0-9 - _ . ~ is
// percent-encoded, upper case; '/' is kept when keepSlash.
func awsEscape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// awsCanonicalURI: the path as sent; S3 signs it as it is, every other
// service signs it encoded once more.
func awsCanonicalURI(escaped, service string) string {
	if escaped == "" {
		escaped = "/"
	}
	if service == "s3" {
		return escaped
	}
	return awsEscape(escaped, true)
}

func awsCanonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		pairs = append(pairs, kv{awsEscape(k, false), awsEscape(v, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

func awsCanonicalHeaders(req *http.Request, signed []string) string {
	var b strings.Builder
	for _, name := range signed {
		var v string
		if name == "host" {
			v = req.Host
			if v == "" {
				v = req.URL.Host
			}
		} else {
			v = strings.Join(req.Header.Values(name), ",")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(strings.Fields(v), " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// ── HMAC ─────────────────────────────────────────────────────────────────────

func hmacHash(alg string) (func() hash.Hash, error) {
	switch alg {
	case "", "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "sha1":
		return sha1.New, nil
	}
	return nil, fmt.Errorf("unknown hmac algorithm %q", alg)
}

func signHMAC(req *http.Request, e *Entry, body []byte, streamed bool, now time.Time) *Error {
	s := e.Signer
	if streamed && strings.Contains(s.Message, "{body}") {
		return refuse(http.StatusRequestEntityTooLarge, "body_too_large", "a body over %d bytes cannot be signed", maxBodyBytes)
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	if s.TimestampHeader != "" {
		req.Header.Set(s.TimestampHeader, ts)
	}
	msg := expandSignMessage(s.Message, func(field string) string {
		switch field {
		case "method":
			return req.Method
		case "path":
			return req.URL.EscapedPath()
		case "query":
			return req.URL.RawQuery
		case "timestamp":
			return ts
		case "body":
			return string(body)
		}
		if h, ok := strings.CutPrefix(field, "header:"); ok {
			return req.Header.Get(h)
		}
		return "{" + field + "}"
	})
	h, _ := hmacHash(s.Algorithm)
	sum := hmacSum(h, e.Value, []byte(msg))
	sig := hex.EncodeToString(sum)
	if s.Encoding == "base64" {
		sig = base64.StdEncoding.EncodeToString(sum)
	}
	sig = s.Prefix + sig
	if s.Header != "" {
		req.Header.Set(s.Header, sig)
		return nil
	}
	q := req.URL.RawQuery
	if q != "" {
		q += "&"
	}
	u := *req.URL
	u.RawQuery = q + url.QueryEscape(s.Param) + "=" + url.QueryEscape(sig)
	req.URL = &u
	return nil
}

// expandSignMessage replaces each {field} of tmpl in one pass, so what a
// field expands to is never expanded again.
func expandSignMessage(tmpl string, field func(string) string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		b.WriteString(tmpl[:i])
		b.WriteString(field(tmpl[i+1 : i+j]))
		tmpl = tmpl[i+j+1:]
	}
}

// ── JWT ──────────────────────────────────────────────────────────────────────

func jwtKey(alg string, value []byte) (any, error) {
	switch alg {
	case "HS256":
		if len(value) < 16 {
			return nil, fmt.Errorf("an HS256 secret needs at least 16 bytes")
		}
		return value, nil
	case "RS256", "ES256":
	default:
		return nil, fmt.Errorf("jwt alg is RS256, ES256 or HS256, not %q", alg)
	}
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("the %s key is not PEM", alg)
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("the %s key does not parse", alg)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if alg == "RS256" {
			return k, nil
		}
	case *ecdsa.PrivateKey:
		if alg == "ES256" && k.Curve.Params().BitSize == 256 {
			return k, nil
		}
	}
	return nil, fmt.Errorf("the key is not a %s key", alg)
}

// MintJWT returns a token signed with entry e's key: the definition's
// claims, with iat and exp set (exp only when the claims do not set it).
func MintJWT(e *Entry, now time.Time) ([]byte, error) {
	s := e.Signer
	key, err := jwtKey(s.Alg, e.Value)
	if err != nil {
		return nil, err
	}
	header := map[string]string{"alg": s.Alg, "typ": "JWT"}
	if s.KeyID != "" {
		header["kid"] = s.KeyID
	}
	ttl := s.TTL
	if ttl == 0 {
		ttl = 3600
	}
	claims := map[string]any{}
	for k, v := range s.Claims {
		claims[k] = v
	}
	claims["iat"] = now.Unix()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Unix() + ttl
	}
	hb, _ := json.Marshal(header)
	cb, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	switch k := key.(type) {
	case []byte:
		sig = hmacSum(sha256.New, k, []byte(input))
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		var rr, ss *big.Int
		rr, ss, err = ecdsa.Sign(rand.Reader, k, digest[:])
		if err == nil {
			sig = make([]byte, 64)
			rr.FillBytes(sig[:32])
			ss.FillBytes(sig[32:])
		}
	}
	if err != nil {
		return nil, err
	}
	return []byte(input + "." + enc.EncodeToString(sig)), nil
}

// ── wallet ───────────────────────────────────────────────────────────────────

// WalletKey parses a wallet entry's value: a secp256k1 private key, 32 bytes
// of hex with or without 0x.
func WalletKey(value []byte) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(value)), "0x"))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("a wallet key is 32 bytes of hex")
	}
	return k, nil
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hmacSum(h func() hash.Hash, key, msg []byte) []byte {
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil)
}
