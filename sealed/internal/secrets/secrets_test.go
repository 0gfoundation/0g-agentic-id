package secrets

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// sealDoc encrypts a v1 secrets document to priv's public key, as the SDK would.
func sealDoc(t *testing.T, priv *eciesgo.PrivateKey, owner string, secrets map[string]secretIn) string {
	t.Helper()
	doc := payload{V: 1, Owner: owner, Secrets: secrets}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := eciesgo.Encrypt(priv.PublicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func testKeyAndOwner(t *testing.T) (*eciesgo.PrivateKey, []byte, string) {
	t.Helper()
	priv, err := eciesgo.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Derive an address to use as the on-chain owner from an unrelated key.
	ownerKey, _ := crypto.GenerateKey()
	owner := crypto.PubkeyToAddress(ownerKey.PublicKey).Hex()
	return priv, priv.Bytes(), owner
}

func TestOpen_valid(t *testing.T) {
	priv, privBytes, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{
		"STRIPE": {Value: "sk_live_abc123", Hosts: []string{"api.stripe.com"}},
	})
	m, err := Open(enc, privBytes, owner)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if m["STRIPE"].Value != "sk_live_abc123" || m["STRIPE"].Hosts[0] != "api.stripe.com" {
		t.Fatalf("bad decode: %+v", m["STRIPE"])
	}
}

func TestOpen_ownerMismatch(t *testing.T) {
	priv, privBytes, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{"X": {Value: "v123456", Hosts: []string{"a.com"}}})
	other := common.HexToAddress("0x000000000000000000000000000000000000dEaD").Hex()
	if _, err := Open(enc, privBytes, other); Reason(err) != ReasonOwnerMismatch {
		t.Fatalf("want owner_mismatch, got %v (%v)", Reason(err), err)
	}
}

func TestOpen_unknownOwnerFailsClosed(t *testing.T) {
	priv, privBytes, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{"X": {Value: "v123456", Hosts: []string{"a.com"}}})
	if _, err := Open(enc, privBytes, ""); Reason(err) != ReasonOwnerUnknown {
		t.Fatalf("want owner_unknown, got %v", Reason(err))
	}
}

func TestOpen_noHostsRejected(t *testing.T) {
	priv, privBytes, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{"X": {Value: "v123456", Hosts: nil}})
	if _, err := Open(enc, privBytes, owner); Reason(err) != ReasonMalformed {
		t.Fatalf("a secret with no hosts must be rejected, got %v", Reason(err))
	}
}

func TestOpen_emptyValueRejected(t *testing.T) {
	priv, privBytes, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{"X": {Value: "", Hosts: []string{"a.com"}}})
	if _, err := Open(enc, privBytes, owner); Reason(err) != ReasonMalformed {
		t.Fatalf("empty value must be rejected, got %v", Reason(err))
	}
}

func TestOpen_empty(t *testing.T) {
	_, privBytes, owner := testKeyAndOwner(t)
	m, err := Open("", privBytes, owner)
	if err != nil || len(m) != 0 {
		t.Fatalf("empty encoded = no secrets, got %v %v", m, err)
	}
}

func TestOpen_wrongKey(t *testing.T) {
	priv, _, owner := testKeyAndOwner(t)
	enc := sealDoc(t, priv, owner, map[string]secretIn{"X": {Value: "v123456", Hosts: []string{"a.com"}}})
	other, _ := eciesgo.GenerateKey()
	if _, err := Open(enc, other.Bytes(), owner); Reason(err) != ReasonNotSealedToAgent {
		t.Fatalf("want not_sealed_to_this_agent, got %v", Reason(err))
	}
}

func TestHostAllowed(t *testing.T) {
	cases := []struct {
		host  string
		allow []string
		want  bool
	}{
		{"api.stripe.com", []string{"api.stripe.com"}, true},
		{"API.Stripe.com", []string{"api.stripe.com"}, true},
		{"api.stripe.com:443", []string{"api.stripe.com"}, true},
		{"evil.com", []string{"api.stripe.com"}, false},
		{"a.stripe.com", []string{"*.stripe.com"}, true},
		{"deep.a.stripe.com", []string{"*.stripe.com"}, true},
		{"stripe.com", []string{"*.stripe.com"}, false}, // apex not matched by wildcard
		{"notstripe.com", []string{"*.stripe.com"}, false},
		{"", []string{"a.com"}, false},
	}
	for _, c := range cases {
		if got := hostAllowed(c.host, c.allow); got != c.want {
			t.Errorf("hostAllowed(%q,%v)=%v want %v", c.host, c.allow, got, c.want)
		}
	}
}

func TestSubstituteForHost(t *testing.T) {
	s := NewStore()
	s.Replace(map[string]Secret{
		"STRIPE": {Value: "sk_live_abc123", Hosts: []string{"api.stripe.com"}},
		"TG":     {Value: "tg_tok_999999", Hosts: []string{"api.telegram.org"}},
	})
	// Allowed host → substituted.
	out, blocked := s.substituteForHost("Bearer {{secret:STRIPE}}", "api.stripe.com")
	if out != "Bearer sk_live_abc123" || len(blocked) != 0 {
		t.Fatalf("allowed sub failed: %q %v", out, blocked)
	}
	// Disallowed host → left as placeholder, reported blocked.
	out, blocked = s.substituteForHost("Bearer {{secret:STRIPE}}", "evil.com")
	if out != "Bearer {{secret:STRIPE}}" || len(blocked) != 1 || blocked[0] != "STRIPE" {
		t.Fatalf("disallowed must not substitute: %q %v", out, blocked)
	}
	// Unknown placeholder → untouched, not blocked (not ours).
	out, _ = s.substituteForHost("{{secret:NOPE}}", "api.stripe.com")
	if out != "{{secret:NOPE}}" {
		t.Fatalf("unknown placeholder changed: %q", out)
	}
}

func TestRedact(t *testing.T) {
	s := NewStore()
	s.Replace(map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{"api.stripe.com"}}})
	if got := s.redact(`{"error":"bad key sk_live_abc123"}`); got != `{"error":"bad key {{secret:STRIPE}}"}` {
		t.Fatalf("redact failed: %q", got)
	}
}
