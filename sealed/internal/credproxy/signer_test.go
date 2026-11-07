package credproxy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The AWS example secret from AWS's SigV4 documentation; the vectors were
// produced by aws-sdk-go v1.44.203's own signer, once with this secret
// (want_auth) and once with a placeholder for it (what an AWS tool given
// the placeholder sends).
const awsExampleSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

type sigv4Vector struct {
	Name     string            `json:"name"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Body     string            `json:"body"`
	Service  string            `json:"service"`
	Region   string            `json:"region"`
	Headers  map[string]string `json:"headers"`
	WantAuth string            `json:"want_auth"`
}

func loadSigV4Vectors(t *testing.T) []sigv4Vector {
	t.Helper()
	b, err := os.ReadFile("testdata/sigv4_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []sigv4Vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func awsRegistry(t *testing.T, host, region, service string, at time.Time) *Registry {
	t.Helper()
	reg := NewRegistry()
	reg.now = func() time.Time { return at }
	if err := reg.Replace([]*Entry{{
		Name: "aws", Hosts: []string{host}, Use: UseSign, Value: []byte(awsExampleSecret),
		Signer: &Signer{Method: SignSigV4, AccessKeyID: "AKIDEXAMPLE", Region: region, Service: service},
	}}); err != nil {
		t.Fatal(err)
	}
	return reg
}

// An AWS tool signs with a placeholder for its secret; the proxy signs the
// same request again with the real one and gets what aws-sdk-go gets.
func TestSigV4ResignMatchesAWSSDK(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, v := range loadSigV4Vectors(t) {
		if strings.HasPrefix(v.Name, "fresh-") {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			u, _ := url.Parse(v.URL)
			req, _ := http.NewRequest(v.Method, v.URL, strings.NewReader(v.Body))
			for k, val := range v.Headers {
				req.Header.Set(k, val)
			}
			reg := awsRegistry(t, u.Host, v.Region, v.Service, at)
			names, _, err := reg.signRequest(req, u.Host, []byte(v.Body), false)
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Authorization"); got != v.WantAuth || len(names) != 1 {
				t.Fatalf("\ngot  %s\nwant %s", got, v.WantAuth)
			}
		})
	}
}

// X-Seal-Sign: the proxy signs from scratch, as aws-sdk-go signs the same
// request with only the payload hash header on it.
func TestSigV4SignMatchesAWSSDK(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, v := range loadSigV4Vectors(t) {
		if !strings.HasPrefix(v.Name, "fresh-") {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			u, _ := url.Parse(v.URL)
			req, _ := http.NewRequest(v.Method, v.URL, strings.NewReader(v.Body))
			req.Header.Set(SignHeader, "aws")
			reg := awsRegistry(t, u.Host, v.Region, v.Service, at)
			if _, _, err := reg.signRequest(req, u.Host, []byte(v.Body), false); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Authorization"); got != v.WantAuth {
				t.Fatalf("\ngot  %s\nwant %s", got, v.WantAuth)
			}
			if req.Header.Get(SignHeader) != "" || req.Header.Get("X-Amz-Content-Sha256") != v.Headers["X-Amz-Content-Sha256"] {
				t.Fatalf("headers %v", req.Header)
			}
		})
	}
}

func TestSigV4LeavesOtherKeysAlone(t *testing.T) {
	reg := awsRegistry(t, "sts.amazonaws.com", "us-east-1", "sts", time.Now())
	req, _ := http.NewRequest("GET", "https://sts.amazonaws.com/", nil)
	orig := "AWS4-HMAC-SHA256 Credential=AKIAOTHER/20150830/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=00"
	req.Header.Set("Authorization", orig)
	names, _, err := reg.signRequest(req, "sts.amazonaws.com", nil, false)
	if err != nil || names != nil || req.Header.Get("Authorization") != orig {
		t.Fatalf("a request signed with someone else's key was touched: %v %v", names, err)
	}
	// Our key, another host: not ours to sign there either.
	req.Header.Set("Authorization", strings.Replace(orig, "AKIAOTHER", "AKIDEXAMPLE", 1))
	if names, _, _ := reg.signRequest(req, "evil.example", nil, false); names != nil {
		t.Fatal("re-signed for a host the entry does not name")
	}
}

func TestSignRefusals(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Replace([]*Entry{
		{Name: "plain", Hosts: []string{"api.example"}, Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte("plain-value-123")},
		{Name: "aws", Hosts: []string{"s3.example"}, Use: UseSign, Value: []byte("secret-secret"), Signer: &Signer{Method: SignSigV4, AccessKeyID: "AK", Region: "r", Service: "s3"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, host, code string }{
		{"nope", "s3.example", "unknown_entry"},
		{"plain", "api.example", "not_allowed"},
		{"aws", "elsewhere.example", "host_not_allowed"},
	} {
		req, _ := http.NewRequest("GET", "https://"+c.host+"/", nil)
		req.Header.Set(SignHeader, c.name)
		if _, _, err := reg.signRequest(req, c.host, nil, false); err == nil || err.Code != c.code {
			t.Fatalf("%s: got %v, want %s", c.name, err, c.code)
		}
	}
	// A signing key is never written into a request.
	req, _ := http.NewRequest("GET", "https://s3.example/", nil)
	req.Header.Set("Authorization", "Bearer [[credential:aws]]")
	if _, _, _, err := reg.fillRequest(req, "s3.example", nil); err == nil || err.Code != "position_not_allowed" {
		t.Fatalf("got %v", err)
	}
	// A big body cannot be signed for a service that needs its hash.
	req, _ = http.NewRequest("PUT", "https://s3.example/", nil)
	req.Header.Set(SignHeader, "aws")
	if _, _, err := reg.signRequest(req, "s3.example", nil, true); err != nil || req.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" {
		t.Fatalf("s3 streams unsigned: %v %v", err, req.Header)
	}
}

func TestHMACHeaderAndParam(t *testing.T) {
	at := time.Unix(1700000000, 0)
	reg := NewRegistry()
	reg.now = func() time.Time { return at }
	secret := []byte("whsec_0123456789abcdef")
	if err := reg.Replace([]*Entry{
		{Name: "hook", Hosts: []string{"hooks.example"}, Use: UseSign, Value: secret,
			Signer: &Signer{Method: SignHMAC, Message: "{body}", Header: "X-Hub-Signature-256", Prefix: "sha256="}},
		{Name: "ex", Hosts: []string{"api.example"}, Use: UseSign, Value: secret,
			Signer: &Signer{Method: SignHMAC, Message: "{timestamp}{method}{path}{query}{header:X-Nonce}", Param: "signature", TimestampHeader: "X-Ts", Encoding: "base64"}},
	}); err != nil {
		t.Fatal(err)
	}
	mac := func(msg string) []byte { m := hmac.New(sha256.New, secret); m.Write([]byte(msg)); return m.Sum(nil) }

	body := `{"event":"push"}`
	req, _ := http.NewRequest("POST", "https://hooks.example/hook", strings.NewReader(body))
	req.Header.Set(SignHeader, "hook")
	if _, _, err := reg.signRequest(req, "hooks.example", []byte(body), false); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Hub-Signature-256"); got != "sha256="+hex.EncodeToString(mac(body)) {
		t.Fatalf("got %s", got)
	}

	req, _ = http.NewRequest("GET", "https://api.example/v1/order?a=1", nil)
	req.Header.Set(SignHeader, "ex")
	req.Header.Set("X-Nonce", "{header:X-Nonce}")
	if _, _, err := reg.signRequest(req, "api.example", nil, false); err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(mac("1700000000GET/v1/ordera=1{header:X-Nonce}"))
	if got := req.URL.Query().Get("signature"); got != want || req.Header.Get("X-Ts") != "1700000000" {
		t.Fatalf("got %s (ts %s), want %s", got, req.Header.Get("X-Ts"), want)
	}
}

func pemOf(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func jwtParts(t *testing.T, tok string) (map[string]any, map[string]any, []byte, []byte) {
	t.Helper()
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		t.Fatalf("not a JWT: %s", tok)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var h, c map[string]any
	_ = json.Unmarshal(dec(p[0]), &h)
	_ = json.Unmarshal(dec(p[1]), &c)
	return h, c, []byte(p[0] + "." + p[1]), dec(p[2])
}

func TestJWTMintedAndVerifiable(t *testing.T) {
	at := time.Unix(1700000000, 0)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekDER, _ := x509.MarshalECPrivateKey(ek)
	pk8, _ := x509.MarshalPKCS8PrivateKey(rk)
	claims := map[string]any{"iss": "sa@example.org", "aud": "https://oauth2.example/token", "scope": "read"}
	for _, c := range []struct {
		alg    string
		key    []byte
		verify func(input, sig []byte) bool
	}{
		{"RS256", pemOf(t, "PRIVATE KEY", pk8), func(in, sig []byte) bool {
			d := sha256.Sum256(in)
			return rsa.VerifyPKCS1v15(&rk.PublicKey, crypto.SHA256, d[:], sig) == nil
		}},
		{"ES256", pemOf(t, "EC PRIVATE KEY", ekDER), func(in, sig []byte) bool {
			d := sha256.Sum256(in)
			return len(sig) == 64 && ecdsa.Verify(&ek.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}},
		{"HS256", []byte("hs256-shared-secret-value"), func(in, sig []byte) bool {
			m := hmac.New(sha256.New, []byte("hs256-shared-secret-value"))
			m.Write(in)
			return hmac.Equal(m.Sum(nil), sig)
		}},
	} {
		e := &Entry{Name: "sa", Hosts: []string{"oauth2.example"}, Use: UseSign, Value: c.key,
			Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}},
			Signer:    &Signer{Method: SignJWT, Alg: c.alg, KeyID: "k1", Claims: claims, TTL: 600}}
		if err := e.validate(); err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		tok, err := MintJWT(e, at)
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		h, cl, input, sig := jwtParts(t, string(tok))
		if h["alg"] != c.alg || h["kid"] != "k1" || cl["iss"] != claims["iss"] || cl["iat"] != float64(1700000000) || cl["exp"] != float64(1700000600) {
			t.Fatalf("%s: header %v claims %v", c.alg, h, cl)
		}
		if !c.verify(input, sig) {
			t.Fatalf("%s: signature does not verify", c.alg)
		}
	}
	// A key of the wrong kind is refused when the set loads.
	bad := &Entry{Name: "sa", Hosts: []string{"x.example"}, Use: UseSign, Value: pemOf(t, "PRIVATE KEY", pk8),
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Signer: &Signer{Method: SignJWT, Alg: "ES256"}}
	if bad.validate() == nil {
		t.Fatal("an RSA key was accepted for ES256")
	}
}

// Through the proxy: the placeholder of a jwt entry becomes a fresh token,
// and the token echoed back is redacted like any value.
func TestJWTFilledAndRedacted(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts, &Entry{Name: "sa", Hosts: []string{"example.com"}, Use: UseSign, Value: []byte("hs256-shared-secret-value"),
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}},
		Signer:    &Signer{Method: SignJWT, Alg: "HS256", Claims: map[string]any{"sub": "agent"}}})
	req, _ := http.NewRequest("GET", h.explicitURL("/me"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:sa]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	auth := got.snapshot().header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ey") {
		t.Fatalf("upstream got %q", auth)
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	if strings.Contains(body, tok) || strings.Contains(resp.Header.Get("X-Echo"), tok) || !strings.Contains(body, "[[credential:sa]]") {
		t.Fatalf("minted token came back: %s", body)
	}
}

// Through the proxy: X-Seal-Sign signs the request that leaves, and the
// header itself does not leave.
func TestHMACThroughProxy(t *testing.T) {
	ts, got := upstream(t)
	secret := []byte("whsec_0123456789abcdef")
	h := newHarness(t, ts, &Entry{Name: "hook", Hosts: []string{"example.com"}, Use: UseSign, Value: secret,
		Signer: &Signer{Method: SignHMAC, Message: "{body}", Header: "X-Signature"}})
	req, _ := http.NewRequest("POST", h.explicitURL("/hook"), bytes.NewReader([]byte("payload")))
	req.Header.Set(SignHeader, "hook")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("payload"))
	g := got.snapshot()
	if g.header.Get("X-Signature") != hex.EncodeToString(m.Sum(nil)) || g.header.Get(SignHeader) != "" {
		t.Fatalf("upstream headers %v", g.header)
	}
}

func TestWalletKey(t *testing.T) {
	k := "0x" + strings.Repeat("ab", 32)
	if b, err := WalletKey([]byte(k)); err != nil || len(b) != 32 {
		t.Fatal(err)
	}
	if _, err := WalletKey([]byte("0x1234")); err == nil {
		t.Fatal("a short key was accepted")
	}
}

// Re-signing uses the entry's own region and service, whatever scope the
// client's signature named: the result is what aws-sdk-go gets for the
// entry's scope.
func TestSigV4ResignUsesEntryScope(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, v := range loadSigV4Vectors(t) {
		if v.Name != "iam-get" {
			continue
		}
		u, _ := url.Parse(v.URL)
		req, _ := http.NewRequest(v.Method, v.URL, nil)
		for k, val := range v.Headers {
			req.Header.Set(k, val)
		}
		req.Header.Set("Authorization", strings.Replace(v.Headers["Authorization"], "/us-east-1/iam/", "/eu-west-1/s3/", 1))
		reg := awsRegistry(t, u.Host, v.Region, v.Service, at)
		if _, _, err := reg.signRequest(req, u.Host, nil, false); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Authorization"); got != v.WantAuth {
			t.Fatalf("\ngot  %s\nwant %s", got, v.WantAuth)
		}
		return
	}
	t.Fatal("vector iam-get missing")
}

// A fresh signature covers every x-amz-* header and Content-Type and
// Content-MD5, so none of them can change on the way unnoticed.
func TestSigV4FreshSignsEveryAmzHeader(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	reg := awsRegistry(t, "sqs.example", "us-east-1", "sqs", at)
	body := []byte(`{"QueueUrl":"q"}`)
	req, _ := http.NewRequest("POST", "https://sqs.example/", bytes.NewReader(body))
	req.Header.Set(SignHeader, "aws")
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("Content-Md5", "q1w2e3")
	req.Header.Set("X-Amz-Target", "AmazonSQS.SendMessage")
	req.Header.Set("X-Amz-Meta-Note", "hi")
	req.Header.Set("User-Agent", "not-signed")
	if _, _, err := reg.signRequest(req, "sqs.example", body, false); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	a, ok := parseAWSAuth(auth)
	want := "content-md5;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-note;x-amz-target"
	if !ok || strings.Join(a.signedHeaders, ";") != want {
		t.Fatalf("signed %v, want %s", a.signedHeaders, want)
	}
	// The signature is right for that list: re-signing the request as a
	// client-signed one (checked against aws-sdk-go above) gives the same.
	if _, _, err := reg.signRequest(req, "sqs.example", body, false); err != nil || req.Header.Get("Authorization") != auth {
		t.Fatalf("re-signed differently: %v\n%s\n%s", err, auth, req.Header.Get("Authorization"))
	}
}

// session_token_entry names an entry whose value may go into a request: not
// a signing key, not expired, and loaded.
func TestSigV4SessionTokenEntry(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, c := range []struct{ session, code, token string }{
		{"key", "not_allowed", ""},
		{"old", "expired", ""},
		{"nope", "unknown_entry", ""},
		{"sess", "", "session-token-value"},
	} {
		reg := NewRegistry()
		reg.now = func() time.Time { return at }
		if err := reg.Replace([]*Entry{
			{Name: "aws", Hosts: []string{"sts.example"}, Use: UseSign, Value: []byte(awsExampleSecret),
				Signer: &Signer{Method: SignSigV4, AccessKeyID: "AKIDEXAMPLE", Region: "us-east-1", Service: "sts", SessionTokenEntry: c.session}},
			{Name: "key", Hosts: []string{"hooks.example"}, Use: UseSign, Value: []byte("whsec_signing_key_value"),
				Signer: &Signer{Method: SignHMAC, Message: "{body}", Header: "X-Sig"}},
			{Name: "old", Hosts: []string{"sts.example"}, Value: []byte("expired-session-token"), ExpiresAt: at.Add(-time.Minute)},
			{Name: "sess", Hosts: []string{"sts.example"}, Value: []byte("session-token-value")},
		}); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "https://sts.example/", nil)
		req.Header.Set(SignHeader, "aws")
		_, set, err := reg.signRequest(req, "sts.example", nil, false)
		got := req.Header.Get("X-Amz-Security-Token")
		if c.code != "" {
			if err == nil || err.Code != c.code || got != "" {
				t.Fatalf("%s: got %v, token %q", c.session, err, got)
			}
			continue
		}
		a, _ := parseAWSAuth(req.Header.Get("Authorization"))
		if err != nil || got != c.token || !slices.Contains(a.signedHeaders, "x-amz-security-token") {
			t.Fatalf("%s: got %v, token %q, signed %v", c.session, err, got, a.signedHeaders)
		}
		// The token and the signature are redacted from the response.
		if _, sig, _ := strings.Cut(req.Header.Get("Authorization"), "Signature="); string(set["sess"]) != c.token || string(set["aws"]) != sig {
			t.Fatalf("%s: set %q", c.session, set)
		}
	}
}

// What the proxy itself sets (Accept-Encoding, the final Content-Length, the
// WebSocket upgrade headers) is in place before signing, so the signature
// covers the request as it is sent.
func TestSignatureCoversHeadersAsSent(t *testing.T) {
	secret := []byte("whsec_0123456789abcdef")
	mac := func(msg string) string {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(msg))
		return hex.EncodeToString(m.Sum(nil))
	}
	ts, got := upstream(t)
	h := newHarness(t, ts,
		&Entry{Name: "github", Hosts: []string{"example.com"}, Positions: []Position{{Kind: PosBody, Field: "token"}}, Value: []byte(secretValue)},
		&Entry{Name: "hook", Hosts: []string{"example.com"}, Use: UseSign, Value: secret,
			Signer: &Signer{Method: SignHMAC, Message: "{header:Accept-Encoding}|{header:Content-Length}|{body}", Header: "X-Signature"}})
	req, _ := http.NewRequest("POST", h.explicitURL("/hook"), strings.NewReader(`{"token":"[[credential:github]]"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set(SignHeader, "hook")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	g := got.snapshot()
	want := mac(g.header.Get("Accept-Encoding") + "|" + strconv.Itoa(len(g.body)) + "|" + g.body)
	if resp.StatusCode != 200 || g.header.Get("Accept-Encoding") != "identity" || g.header.Get("X-Signature") != want {
		t.Fatalf("status %d, upstream Accept-Encoding %q, signature %q, want %q", resp.StatusCode, g.header.Get("Accept-Encoding"), g.header.Get("X-Signature"), want)
	}

	ws := wsUpstream(t, switching, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-Signature") != mac(r.Header.Get("Upgrade")+"|"+r.Header.Get("Sec-WebSocket-Extensions")) {
			http.Error(w, "signature does not cover the headers sent", http.StatusUnauthorized)
			return false
		}
		return true
	}, nil)
	hw := newHarness(t, ws, &Entry{Name: "hook", Hosts: []string{"example.com"}, Use: UseSign, Value: secret,
		Signer: &Signer{Method: SignHMAC, Message: "{header:Upgrade}|{header:Sec-WebSocket-Extensions}", Header: "X-Signature"}})
	_, _, wresp := wsDial(t, hw, SignHeader+": hook\r\n")
	if wresp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WebSocket: status %d", wresp.StatusCode)
	}
}

// A minted token stays scrubbed after its own request, under the
// placeholder of the jwt entry, until its exp.
func TestMintedJWTScrubbedLater(t *testing.T) {
	var mu sync.Mutex
	var last string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/later" {
			_, _ = io.WriteString(w, last)
			return
		}
		last = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts, &Entry{Name: "sa", Hosts: []string{"example.com"}, Use: UseSign, Value: []byte("hs256-shared-secret-value"),
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}},
		Signer:    &Signer{Method: SignJWT, Alg: "HS256", TTL: 600}})
	req, _ := http.NewRequest("GET", h.explicitURL("/me"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:sa]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	mu.Lock()
	tok := last
	mu.Unlock()
	if !strings.HasPrefix(tok, "ey") {
		t.Fatalf("upstream got %q", tok)
	}
	resp, err = http.Get(h.explicitURL("/later"))
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); body != "[[credential:sa]]" {
		t.Fatalf("a later response: %q", body)
	}
	if got := string(h.reg().Scrub([]byte(tok))); got != "[[credential:sa]]" {
		t.Fatalf("Scrub: %q", got)
	}

	// Past its exp a token is dropped when the next one is held.
	reg := NewRegistry()
	now := time.Unix(1700000000, 0)
	reg.now = func() time.Time { return now }
	reg.holdMinted("sa", []byte("first-minted-token"), now.Add(time.Minute))
	if got := string(reg.Scrub([]byte("first-minted-token"))); got != "[[credential:sa]]" {
		t.Fatalf("held: %q", got)
	}
	now = now.Add(2 * time.Minute)
	reg.holdMinted("sa", []byte("second-minted-token"), now.Add(time.Minute))
	if reg.Len() != 1 || string(reg.Scrub([]byte("first-minted-token"))) != "first-minted-token" {
		t.Fatalf("an expired token was kept: Len %d", reg.Len())
	}
	for i := 0; i < maxMinted+10; i++ {
		reg.holdMinted("sa", []byte(fmt.Sprintf("minted-token-%06d", i)), now.Add(time.Hour))
	}
	if reg.Len() != maxMinted {
		t.Fatalf("Len %d, want %d", reg.Len(), maxMinted)
	}
}

// Re-signing a client's AWS signature needs an X-Amz-Date within 15 minutes
// of now and host among the signed headers. Neither mode signs a request
// carrying a query-string signature's parameters.
func TestSigV4SignRefusesUnboundRequests(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	reg := awsRegistry(t, "s3.example", "us-east-1", "s3", at)
	for _, c := range []struct {
		name, date, signed, query string
		fresh                     bool
		ok                        bool
	}{
		{"within the window", "20150830T124900Z", "host;x-amz-date", "", false, true},
		{"16 minutes ahead", "20150830T125200Z", "host;x-amz-date", "", false, false},
		{"17 minutes behind", "20150830T121900Z", "host;x-amz-date", "", false, false},
		{"another year", "20301231T000000Z", "host;x-amz-date", "", false, false},
		{"not a date", "20150830T1236", "host;x-amz-date", "", false, false},
		{"host not signed", "20150830T123600Z", "x-amz-date", "", false, false},
		{"query X-Amz-Algorithm", "20150830T123600Z", "host;x-amz-date", "X-Amz-Algorithm=AWS4-HMAC-SHA256", false, false},
		{"query X-Amz-Credential", "20150830T123600Z", "host;x-amz-date", "a=1&x-amz-credential=AKIDEXAMPLE%2F20150830", false, false},
		{"query X-Amz-Signature", "20150830T123600Z", "host;x-amz-date", "X-Amz-Signature=00", false, false},
		{"query X-Amz-Expires alone", "20150830T123600Z", "host;x-amz-date", "X-Amz-Expires=60", false, true},
		{"fresh, query X-Amz-Credential", "", "", "X-Amz-Credential=AKIDEXAMPLE%2F20150830", true, false},
		{"fresh", "", "", "a=1", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://s3.example/b/k?"+c.query, nil)
			if c.fresh {
				req.Header.Set(SignHeader, "aws")
			} else {
				req.Header.Set("X-Amz-Date", c.date)
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"+c.date[:min(8, len(c.date))]+"/us-east-1/s3/aws4_request, SignedHeaders="+c.signed+", Signature=00")
			}
			_, _, err := reg.signRequest(req, "s3.example", nil, false)
			if c.ok != (err == nil) || err != nil && err.Code != "sign_failed" {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A signature the proxy makes is redacted from the response like a value it
// filled: SigV4 (fresh and re-signed) and HMAC, in a header or a query
// parameter.
func TestSignaturesRedacted(t *testing.T) {
	var mu sync.Mutex
	var sent string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.Header.Get("Authorization") + "|" + r.Header.Get("X-Signature") + "|" + r.URL.RawQuery + "|" + r.URL.Query().Get("sig")
		mu.Lock()
		sent = s
		mu.Unlock()
		w.Header().Set("X-Echo", s)
		_, _ = io.WriteString(w, s)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	secret := []byte("whsec_0123456789abcdef")
	h := newHarness(t, ts,
		&Entry{Name: "aws", Hosts: []string{"example.com"}, Use: UseSign, Value: []byte(awsExampleSecret),
			Signer: &Signer{Method: SignSigV4, AccessKeyID: "AKIDEXAMPLE", Region: "us-east-1", Service: "s3"}},
		&Entry{Name: "hook", Hosts: []string{"example.com"}, Use: UseSign, Value: secret,
			Signer: &Signer{Method: SignHMAC, Message: "{method}{path}", Header: "X-Signature"}},
		&Entry{Name: "hookq", Hosts: []string{"example.com"}, Use: UseSign, Value: secret,
			Signer: &Signer{Method: SignHMAC, Message: "{path}{query}", Param: "sig", Encoding: "base64"}})
	sigOf := map[string]func(string) string{
		"aws":   func(s string) string { _, sig, _ := strings.Cut(strings.Split(s, "|")[0], "Signature="); return sig },
		"hook":  func(s string) string { return strings.Split(s, "|")[1] },
		"hookq": func(s string) string { return strings.Split(s, "|")[3] },
	}
	now := time.Now().UTC()
	for _, c := range []struct {
		name, entry string
		set         func(*http.Request)
	}{
		{"sigv4 fresh", "aws", func(r *http.Request) { r.Header.Set(SignHeader, "aws") }},
		{"sigv4 re-signed", "aws", func(r *http.Request) {
			r.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
			r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"+now.Format("20060102")+"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=00")
		}},
		{"hmac header", "hook", func(r *http.Request) { r.Header.Set(SignHeader, "hook") }},
		{"hmac query parameter", "hookq", func(r *http.Request) { r.Header.Set(SignHeader, "hookq") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", h.explicitURL("/b/k?a=1"), nil)
			c.set(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body := readAll(t, resp)
			mu.Lock()
			sig := sigOf[c.entry](sent)
			mu.Unlock()
			if resp.StatusCode != 200 || len(sig) < 20 {
				t.Fatalf("status %d, signature %q", resp.StatusCode, sig)
			}
			echo := resp.Header.Get("X-Echo")
			for _, form := range []string{sig, url.QueryEscape(sig)} {
				if strings.Contains(body, form) || strings.Contains(echo, form) {
					t.Fatalf("signature came back: %s / %s", body, echo)
				}
			}
			if !strings.Contains(body, Placeholder(c.entry)) {
				t.Fatalf("body %s", body)
			}
		})
	}
}
