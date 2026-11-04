package credentials

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

const testSeal = "0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f"

type fixture struct {
	owner     *ecdsa.PrivateKey
	seal      *ecdsa.PrivateKey
	sealECIES *eciesgo.PrivateKey
	domain    Domain
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	owner, _ := crypto.GenerateKey()
	seal, _ := crypto.GenerateKey()
	return &fixture{
		owner: owner, seal: seal,
		sealECIES: eciesgo.NewPrivateKeyFromBytes(crypto.FromECDSA(seal)),
		domain:    Domain{ChainID: 16602, Contract: common.HexToAddress("0x5BB5000000000000000000000000000000000001")},
	}
}

func (f *fixture) check() Check {
	return Check{
		Domain: f.domain, SealID: testSeal,
		Owner: crypto.PubkeyToAddress(f.owner.PublicKey), AgentSeal: crypto.PubkeyToAddress(f.seal.PublicKey),
		AgentSealPriv: crypto.FromECDSA(f.seal),
	}
}

func (f *fixture) sign(t *testing.T, digest common.Hash, key *ecdsa.PrivateKey) string {
	t.Helper()
	sig, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	return hexutil.Encode(sig)
}

// doc builds a signed document holding one entry per name → value.
func (f *fixture) doc(t *testing.T, version uint64, values map[string]string) Document {
	t.Helper()
	d := Document{Defs: map[string]string{}, Values: map[string]string{}}
	d.Set = CredentialSet{SealID: testSeal, OwnerEpoch: 7, Version: version}
	for name, v := range values {
		ct, err := SealValue(f.sealECIES.PublicKey, crypto.PubkeyToAddress(f.owner.PublicKey), testSeal, f.domain.ChainID, name, []byte(v))
		if err != nil {
			t.Fatal(err)
		}
		def := Definition{V: 1, Name: name, Hosts: []string{"api.github.com"}, Use: credproxy.UseInject,
			Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}},
			ValueHash: crypto.Keccak256Hash(ct).Hex()}
		raw, _ := json.Marshal(def)
		d.Defs[name] = base64.StdEncoding.EncodeToString(raw)
		d.Values[name] = base64.StdEncoding.EncodeToString(ct)
		d.Set.Entries = append(d.Set.Entries, SetEntry{Name: name, DefHash: crypto.Keccak256Hash(raw).Hex()})
	}
	digest, err := d.Set.Digest(f.domain)
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = f.sign(t, digest, f.owner)
	return d
}

func TestOpenVerifiesAndDecrypts(t *testing.T) {
	f := newFixture(t)
	o, err := Open(f.doc(t, 3, map[string]string{"github": "ghp_value"}), f.check())
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Values["github"]) != "ghp_value" || o.Defs["github"].Hosts[0] != "api.github.com" || len(o.Skipped) != 0 {
		t.Fatalf("opened %+v", o)
	}
}

func TestOpenRefusals(t *testing.T) {
	f := newFixture(t)
	doc := f.doc(t, 3, map[string]string{"github": "ghp_value"})

	c := f.check()
	other, _ := crypto.GenerateKey()
	c.Owner = crypto.PubkeyToAddress(other.PublicKey)
	if _, err := Open(doc, c); !errors.Is(err, ErrWrongSigner) {
		t.Fatalf("wrong owner: %v", err)
	}
	c = f.check()
	c.MinVersion = 4
	if _, err := Open(doc, c); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	c = f.check()
	c.SealID = "0x" + "11" + testSeal[4:]
	if _, err := Open(doc, c); !errors.Is(err, ErrWrongSeal) {
		t.Fatalf("other seal: %v", err)
	}
	c = f.check()
	c.OwnerEpoch = 8
	if _, err := Open(doc, c); !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("epoch: %v", err)
	}
}

func TestOpenSkipsTamperedEntries(t *testing.T) {
	f := newFixture(t)
	doc := f.doc(t, 3, map[string]string{"github": "ghp_value", "other": "other_value"})
	// Swap github's ciphertext for one sealed by someone else with the same name.
	attacker, _ := crypto.GenerateKey()
	ct, _ := SealValue(f.sealECIES.PublicKey, crypto.PubkeyToAddress(attacker.PublicKey), testSeal, f.domain.ChainID, "github", []byte("attacker"))
	doc.Values["github"] = base64.StdEncoding.EncodeToString(ct)
	o, err := Open(doc, f.check())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Values["github"]; ok || o.Skipped["github"] == "" {
		t.Fatalf("swapped value was accepted: %+v", o.Skipped)
	}
	if string(o.Values["other"]) != "other_value" {
		t.Fatal("an untouched entry was dropped")
	}
}

func TestWritebackPreferredWhenSignedBySeal(t *testing.T) {
	f := newFixture(t)
	doc := f.doc(t, 3, map[string]string{"rt": "old_refresh_token"})
	var def Definition
	raw, _ := base64.StdEncoding.DecodeString(doc.Defs["rt"])
	_ = json.Unmarshal(raw, &def)
	def.Writeback = true
	raw, _ = json.Marshal(def)
	doc.Defs["rt"] = base64.StdEncoding.EncodeToString(raw)
	doc.Set.Entries[0].DefHash = crypto.Keccak256Hash(raw).Hex()
	digest, _ := doc.Set.Digest(f.domain)
	doc.Signature = f.sign(t, digest, f.owner)

	ct, _ := SealValue(f.sealECIES.PublicKey, crypto.PubkeyToAddress(f.owner.PublicKey), testSeal, f.domain.ChainID, "rt", []byte("rotated_refresh_token"))
	msg := WritebackMessage(testSeal, "rt", 3, "boot-1", ct)
	doc.Writebacks = map[string]Writeback{"rt": {Ciphertext: base64.StdEncoding.EncodeToString(ct), SetVersion: 3, BootID: "boot-1",
		Signature: f.sign(t, crypto.Keccak256Hash(msg), f.seal)}}
	o, err := Open(doc, f.check())
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Values["rt"]) != "rotated_refresh_token" {
		t.Fatalf("got %q", o.Values["rt"])
	}
	// A writeback signed by anyone else is ignored.
	doc.Writebacks["rt"] = Writeback{Ciphertext: doc.Writebacks["rt"].Ciphertext, SetVersion: 3, BootID: "boot-1", Signature: f.sign(t, crypto.Keccak256Hash(msg), f.owner)}
	o, _ = Open(doc, f.check())
	if string(o.Values["rt"]) != "old_refresh_token" {
		t.Fatalf("an unsigned writeback won: %q", o.Values["rt"])
	}
}

func TestApprovalDigestStable(t *testing.T) {
	f := newFixture(t)
	a := Approval{SealID: testSeal, BootID: crypto.Keccak256Hash([]byte("boot")).Hex(), AuthReqID: crypto.Keccak256Hash([]byte("req")).Hex(),
		RequestDigest: crypto.Keccak256Hash([]byte("d")).Hex(), ExpiresAt: 1800000000}
	d1, err := a.Digest(f.domain)
	if err != nil {
		t.Fatal(err)
	}
	a.ExpiresAt++
	d2, _ := a.Digest(f.domain)
	if d1 == d2 {
		t.Fatal("expiry is not covered by the approval digest")
	}
}

// TestDigestVectors pins the EIP-712 digests. The attestor (Rust) and the SDK
// (TypeScript) assert the same values; viem's hashTypedData produces them too.
func TestDigestVectors(t *testing.T) {
	d := Domain{ChainID: 16602, Contract: common.HexToAddress("0x5BB5000000000000000000000000000000000001")}
	set := CredentialSet{SealID: testSeal, OwnerEpoch: 7, Version: 3, Entries: []SetEntry{
		{Name: "github", DefHash: crypto.Keccak256Hash([]byte("def-github")).Hex()},
		{Name: "gcp", DefHash: crypto.Keccak256Hash([]byte("def-gcp")).Hex()},
	}}
	if h, _ := set.Digest(d); h.Hex() != "0xb176433ffedb59fd89cececf370cb5d8ba9ce6d526d51b4734fd4e278e6d1c76" {
		t.Fatalf("CredentialSet digest %s", h.Hex())
	}
	a := Approval{SealID: testSeal, BootID: crypto.Keccak256Hash([]byte("boot")).Hex(), AuthReqID: crypto.Keccak256Hash([]byte("req")).Hex(),
		RequestDigest: crypto.Keccak256Hash([]byte("d")).Hex(), ExpiresAt: 1800000000}
	if h, _ := a.Digest(d); h.Hex() != "0x9d253d4f6dee2cc9d68bd5a5a7df81c1ac83910b7f26338eef2dd729ee8d879a" {
		t.Fatalf("Approval digest %s", h.Hex())
	}
}
