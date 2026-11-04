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
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
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
			reg := awsRegistry(t, u.Host, "elsewhere", "other", at)
			names, err := reg.signRequest(req, u.Host, []byte(v.Body), false)
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
			if _, err := reg.signRequest(req, u.Host, []byte(v.Body), false); err != nil {
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
	names, err := reg.signRequest(req, "sts.amazonaws.com", nil, false)
	if err != nil || names != nil || req.Header.Get("Authorization") != orig {
		t.Fatalf("a request signed with someone else's key was touched: %v %v", names, err)
	}
	// Our key, another host: not ours to sign there either.
	req.Header.Set("Authorization", strings.Replace(orig, "AKIAOTHER", "AKIDEXAMPLE", 1))
	if names, _ := reg.signRequest(req, "evil.example", nil, false); names != nil {
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
		if _, err := reg.signRequest(req, c.host, nil, false); err == nil || err.Code != c.code {
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
	if _, err := reg.signRequest(req, "s3.example", nil, true); err != nil || req.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" {
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
	if _, err := reg.signRequest(req, "hooks.example", []byte(body), false); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Hub-Signature-256"); got != "sha256="+hex.EncodeToString(mac(body)) {
		t.Fatalf("got %s", got)
	}

	req, _ = http.NewRequest("GET", "https://api.example/v1/order?a=1", nil)
	req.Header.Set(SignHeader, "ex")
	req.Header.Set("X-Nonce", "{header:X-Nonce}")
	if _, err := reg.signRequest(req, "api.example", nil, false); err != nil {
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
