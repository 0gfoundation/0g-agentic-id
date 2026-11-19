package credentials

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/evmsign"
)

// A wallet entry signs through the socket; the key never comes back, and
// the signature recovers to the wallet's address.
func TestWalletSignsThroughTheSocket(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	wallet, _ := crypto.GenerateKey()
	keyHex := hex.EncodeToString(crypto.FromECDSA(wallet))
	doc := f.doc(t, 1, map[string]string{"wallet": keyHex, "github": "ghp_value_0123"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "wallet" {
			d.Use, d.Hosts, d.Positions = credproxy.UseSign, nil, nil
			d.Signer = &credproxy.Signer{Method: credproxy.SignWallet}
		}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	h := s.HarnessHandler()
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/credentials/sign", strings.NewReader(body)))
		return w
	}
	w := post(`{"name":"wallet","personal_sign":{"message":"hello"}}`)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), keyHex) {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var out struct{ Signature, Address, MsgHash string }
	_ = json.Unmarshal(w.Body.Bytes(), &struct {
		Signature *string `json:"signature"`
		Address   *string `json:"address"`
		MsgHash   *string `json:"msg_hash"`
	}{&out.Signature, &out.Address, &out.MsgHash})
	sig, _ := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	sig[64] -= 27
	digest := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", 5)), []byte("hello"))
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != crypto.PubkeyToAddress(wallet.PublicKey) || out.Address != crypto.PubkeyToAddress(wallet.PublicKey).Hex() {
		t.Fatalf("signature does not recover to the wallet: %v %s", err, out.Address)
	}
	for body, want := range map[string]int{
		`{"name":"github","personal_sign":{"message":"x"}}`: http.StatusForbidden,
		`{"name":"nope","personal_sign":{"message":"x"}}`:   http.StatusNotFound,
		`{"name":"wallet"}`: http.StatusBadRequest,
		`{"name":"wallet","personal_sign":{"message":"x"},"typed_data":{"primaryType":"A"}}`: http.StatusBadRequest,
		`{"name":"wallet","transaction":{"chain_id":"0","gas_limit":21000}}`:                 http.StatusBadRequest,
	} {
		if w := post(body); w.Code != want {
			t.Fatalf("%s: HTTP %d, want %d (%s)", body, w.Code, want, w.Body.String())
		}
	}
	// A transaction signs for its chain.
	w = post(`{"name":"wallet","transaction":{"chain_id":"16602","nonce":1,"to":"0x000000000000000000000000000000000000dEaD","value":"1","gas_limit":21000,"max_fee_per_gas":"2","max_priority_fee_per_gas":"1"}}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"raw_tx":"0x02`) {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if _, err := evmsign.PersonalSign(evmsign.PersonalSignRequest{}, nil); evmsign.Status(err) != http.StatusBadRequest {
		t.Fatal("an empty message is the caller's mistake")
	}
}

// The GCP service-account flow: a jwt entry's own token request sends a
// freshly minted assertion; the key never leaves.
func TestJWTAssertionInTokenRequest(t *testing.T) {
	const secret = "hs256-shared-secret-value"
	var assertion string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		assertion = r.PostForm.Get("assertion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.token","expires_in":3600}`))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"gsa": secret})
	f.editDefs(t, &doc, func(d *Definition) {
		d.Use = credproxy.UseSign
		d.Hosts = []string{"oauth2.googleapis.com"}
		d.Signer = &credproxy.Signer{Method: credproxy.SignJWT, Alg: "HS256", Claims: map[string]any{"iss": "sa@example.org", "aud": ts.URL + "/token"}}
		d.TokenRequest = &TokenRequest{URL: ts.URL + "/token",
			Fields: map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": "{v}"},
			Take: []TokenTake{{Field: "access_token", Hosts: []string{"storage.googleapis.com"},
				Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, ExpiresInField: "expires_in"}}}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "gsa", nil); cerr != nil {
		t.Fatal(cerr)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || strings.Contains(assertion, secret) {
		t.Fatalf("assertion %q", assertion)
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(m.Sum(nil)) != parts[2] {
		t.Fatal("assertion is not signed with the entry's key")
	}
	if e := reg.Get("derived:gsa.access_token"); e == nil || string(e.Value) != "ya29.token" {
		t.Fatal("access token not kept")
	}
}

// A signing key other than a jwt is never put into a token request.
func TestSigningKeyNotSentInTemplates(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"aws": "aws-secret-value", "tok": "rt"})
	f.editDefs(t, &doc, func(d *Definition) {
		switch d.Name {
		case "aws":
			d.Use, d.Positions = credproxy.UseSign, nil
			d.Signer = &credproxy.Signer{Method: credproxy.SignSigV4, AccessKeyID: "AK", Region: "us-east-1", Service: "sts"}
		case "tok":
			d.Use, d.Positions = credproxy.UseTokenOnly, nil
			d.TokenRequest = &TokenRequest{URL: "https://token.example/", Fields: map[string]string{"x": "{cred:aws}"}}
		}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, cerr := s.Token(context.Background(), "tok", nil); cerr == nil || cerr.Code != "not_allowed" {
		t.Fatalf("got %v", cerr)
	}
}

// One bad entry is skipped with its reason; the rest of the set loads.
func TestInvalidSignerSkippedNotTheSet(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	doc := f.doc(t, 1, map[string]string{"bad": "not a pem key", "github": "ghp_value_0123"})
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "bad" {
			d.Use = credproxy.UseSign
			d.Signer = &credproxy.Signer{Method: credproxy.SignJWT, Alg: "RS256"}
		}
	})
	o, err := s.Load(context.Background(), doc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, skipped := o.Skipped["bad"]; !skipped || reg.Get("github") == nil || reg.Get("bad") != nil {
		t.Fatalf("skipped %v, registry %v", o.Skipped, reg.Names())
	}
	b, _ := json.Marshal(s.List())
	if !bytes.Contains(b, []byte(`"positions"`)) {
		t.Fatalf("list lacks positions: %s", b)
	}
}
