package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/logger"
)

// bootFixture is a shared /provision request fixture
// (internal/inference/testdata/boot-v1*.json, also read by the attestor).
type bootFixture struct {
	Key struct {
		PrivateKey string `json:"private_key"`
		Address    string `json:"address"`
		Pubkey     string `json:"pubkey"`
	} `json:"test_only_container_key"`
	Recorded  string          `json:"recorded_container_pubkey"`
	Request   json.RawMessage `json:"request"`
	Canonical string          `json:"canonical"`
}

func loadBootFixture(t *testing.T, name string) bootFixture {
	t.Helper()
	raw, err := os.ReadFile("../inference/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var fixture bootFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// recoverClaim checks a POST body's claim and returns its signer.
func recoverClaim(t *testing.T, request provisionRequest) (common.Address, string) {
	t.Helper()
	id, err := hex.DecodeString(strings.TrimPrefix(request.BootID, "0x"))
	if err != nil || len(id) != 32 {
		t.Fatalf("boot_id %q", request.BootID)
	}
	canonical := bootMessage(strings.TrimPrefix(request.SealID, "0x"), request.BootGeneration, sha256.Sum256([]byte(request.BootTicket)), id, request.BootStartedAt)
	signature, err := hex.DecodeString(strings.TrimPrefix(request.ContainerSignature, "0x"))
	if err != nil || len(signature) != 65 || (signature[64] != 27 && signature[64] != 28) {
		t.Fatalf("container_signature %q", request.ContainerSignature)
	}
	signature[64] -= 27
	pubkey, err := crypto.SigToPub(crypto.Keccak256([]byte(canonical)), signature)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PubkeyToAddress(*pubkey), canonical
}

// The first-provision and later-boot fixtures are what this package sends.
func TestBootRequestFixtures(t *testing.T) {
	vector := loadCertificateVector(t)
	for _, test := range []struct {
		file  string
		first bool
	}{{"boot-v1-first.json", true}, {"boot-v1.json", false}} {
		t.Run(test.file, func(t *testing.T) {
			fixture := loadBootFixture(t, test.file)
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(fixture.Request, &fields); err != nil {
				t.Fatal(err)
			}
			want := []string{"boot_generation", "boot_id", "boot_started_at", "boot_ticket", "container_signature", "seal_id"}
			if test.first {
				want = append(want, "certificate")
			}
			if got := sortedKeys(fields); !reflect.DeepEqual(got, sortedStrings(want)) {
				t.Fatalf("request fields %v, want %v", got, sortedStrings(want))
			}
			var request provisionRequest
			if err := json.Unmarshal(fixture.Request, &request); err != nil {
				t.Fatal(err)
			}
			signer, canonical := recoverClaim(t, request)
			if canonical != fixture.Canonical {
				t.Fatalf("canonical %s", canonical)
			}
			if signer.Hex() != fixture.Key.Address || fixture.Key.Address != vector.ContainerKey.Address {
				t.Fatalf("claim signed by %s", signer.Hex())
			}
			if test.first {
				var compact bytes.Buffer
				if err := json.Compact(&compact, request.Certificate); err != nil || compact.String() != vector.Wire {
					t.Fatal("first-provision certificate is not the vector's wire object")
				}
				if request.SealID != "0x"+vector.certificate(t).SealID {
					t.Fatal("seal_id differs from the certificate's")
				}
			} else if fixture.Recorded != fixture.Key.Pubkey {
				t.Fatal("recorded pubkey is not the signing key")
			}

			// The production encoder reproduces the fixture byte for byte
			// (RFC 6979 signatures are deterministic).
			boot := Boot{SealKey: vector.containerKey(t), Ticket: request.BootTicket, Certificate: vector.certificate(t), CertificateJSON: json.RawMessage(vector.Wire)}
			boot.Certificate.SealID = strings.TrimPrefix(request.SealID, "0x")
			key, _ := crypto.ToECDSA(boot.SealKey)
			c := &claim{boot: boot, key: key, ticketHash: sha256.Sum256([]byte(request.BootTicket)), startedAt: request.BootStartedAt}
			id, _ := hex.DecodeString(strings.TrimPrefix(request.BootID, "0x"))
			copy(c.bootID[:], id)
			built, err := c.request(authorization{Generation: request.BootGeneration, CertificateRequired: test.first})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(built)
			var fixtureCompact bytes.Buffer
			_ = json.Compact(&fixtureCompact, fixture.Request)
			if string(encoded) != fixtureCompact.String() {
				t.Fatalf("encoder output differs from the fixture:\n%s\n%s", encoded, fixtureCompact.String())
			}
		})
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return sortedStrings(keys)
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// ── mock attestor ───────────────────────────────────────────────────────────

type answer struct {
	status int
	body   any
}

// mockAttestor answers GET and POST /provision from scripts; past a script's
// end its last answer repeats. A nil POST body answers with a valid payload.
type mockAttestor struct {
	t       *testing.T
	key     *eciesgo.PrivateKey
	gets    []answer
	posts   []answer
	mu      sync.Mutex
	getN    int
	sent    []provisionRequest
	raw     []map[string]json.RawMessage
	payload map[string]string
}

func newMockAttestor(t *testing.T, containerKey []byte, gets, posts []answer) (*mockAttestor, *httptest.Server) {
	m := &mockAttestor{t: t, key: eciesgo.NewPrivateKeyFromBytes(containerKey), gets: gets, posts: posts}
	m.payload = map[string]string{
		"encrypted_agent_seal_priv": m.encrypt(bytes.Repeat([]byte{9}, 32)),
		"encrypted_settings":        m.encrypt([]byte(`{"model":"m"}`)),
		"encrypted_status_binding":  m.encrypt([]byte(`{"token":"` + strings.Repeat("ab", 32) + `"}`)),
	}
	server := httptest.NewServer(m)
	t.Cleanup(server.Close)
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	return m, server
}

func (m *mockAttestor) encrypt(plaintext []byte) string {
	ct, err := eciesgo.Encrypt(m.key.PublicKey, plaintext)
	if err != nil {
		m.t.Fatal(err)
	}
	return "0x" + hex.EncodeToString(ct)
}

func pick(script []answer, n int) answer {
	if n >= len(script) {
		return script[len(script)-1]
	}
	return script[n]
}

func (m *mockAttestor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.URL.Path != "/provision" {
		m.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(404)
		return
	}
	var a answer
	if r.Method == http.MethodGet {
		a = pick(m.gets, m.getN)
		m.getN++
	} else {
		raw, _ := io.ReadAll(r.Body)
		var request provisionRequest
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &request); err != nil || json.Unmarshal(raw, &fields) != nil {
			m.t.Errorf("POST body: %v", err)
		}
		a = pick(m.posts, len(m.sent))
		m.sent = append(m.sent, request)
		m.raw = append(m.raw, fields)
	}
	if a.body == nil && a.status == http.StatusOK {
		a.body = m.payload
	}
	w.WriteHeader(a.status)
	switch body := a.body.(type) {
	case nil:
	case string:
		_, _ = io.WriteString(w, body)
	default:
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (m *mockAttestor) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getN, len(m.sent)
}

// fakeClock replaces the retry loop's clock: sleeping advances it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func useFakeClock(t *testing.T) *fakeClock {
	f := &fakeClock{now: time.Now()}
	saved := clock
	clock.now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	clock.sleep = func(d time.Duration) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sleeps = append(f.sleeps, d)
		f.now = f.now.Add(d)
	}
	t.Cleanup(func() { clock = saved })
	return f
}

func testBoot(t *testing.T, url string, started time.Time) Boot {
	vector := loadCertificateVector(t)
	return Boot{AttestorURL: url, SealKey: vector.containerKey(t), Certificate: vector.certificate(t),
		CertificateJSON: json.RawMessage(vector.Wire), Ticket: strings.Repeat("22", 32), Started: started}
}

func gen(generation int64, required bool) answer {
	return answer{200, authorization{Generation: generation, CertificateRequired: required}}
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestFirstProvisionForwardsCertificateVerbatim(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{200, nil}})
	result := FromAttestor(testBoot(t, server.URL, f.now))
	if !bytes.Equal(result.AgentSealPriv, bytes.Repeat([]byte{9}, 32)) || string(result.Settings) != `{"model":"m"}` || result.StatusToken != strings.Repeat("ab", 32) {
		t.Fatalf("provision payload mismatch: %+v", result)
	}
	if len(m.sent) != 1 {
		t.Fatalf("POSTs %d", len(m.sent))
	}
	want := sortedStrings([]string{"seal_id", "certificate", "boot_ticket", "boot_generation", "boot_id", "boot_started_at", "container_signature"})
	if got := sortedKeys(m.raw[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("first-provision fields %v", got)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, m.raw[0]["certificate"]); err != nil || compact.String() != vector.Wire {
		t.Fatalf("certificate not forwarded verbatim: %s", m.raw[0]["certificate"])
	}
	request := m.sent[0]
	if request.SealID != "0x"+vector.certificate(t).SealID || request.BootGeneration != 1 || request.BootTicket != strings.Repeat("22", 32) {
		t.Fatalf("claim fields %+v", request)
	}
	if signer, _ := recoverClaim(t, request); signer.Hex() != vector.ContainerKey.Address {
		t.Fatalf("claim signed by %s, want the certificate's key", signer.Hex())
	}
}

func TestLaterBootOmitsCertificate(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(4, false)}, []answer{{200, nil}})
	if result := FromAttestor(testBoot(t, server.URL, f.now)); result.AgentSealPriv == nil {
		t.Fatal("later boot failed")
	}
	want := sortedStrings([]string{"seal_id", "boot_ticket", "boot_generation", "boot_id", "boot_started_at", "container_signature"})
	if got := sortedKeys(m.raw[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("later-boot fields %v", got)
	}
	if m.sent[0].BootGeneration != 4 {
		t.Fatalf("generation %d", m.sent[0].BootGeneration)
	}
}

func TestProvisionRetryClassification(t *testing.T) {
	vector := loadCertificateVector(t)
	for _, test := range []struct {
		name            string
		gets, posts     []answer
		ok              bool
		getsN, postsN   int
		certificateSent []bool
		generations     []int64
		sleeps          int
	}{
		{name: "400 stops", gets: []answer{gen(1, true)}, posts: []answer{{400, `{"error":"bad request"}`}}, getsN: 1, postsN: 1},
		{name: "401 stops", gets: []answer{gen(1, true)}, posts: []answer{{401, `{"error":"image_hash not in validFrameworkHashes"}`}}, getsN: 1, postsN: 1},
		{name: "other 4xx stops", gets: []answer{gen(1, true)}, posts: []answer{{404, ""}}, getsN: 1, postsN: 1},
		{name: "403 without a newer generation stops", gets: []answer{gen(1, true), gen(1, true)}, posts: []answer{{403, `{"error":"stale boot"}`}}, getsN: 2, postsN: 1},
		{name: "403 then a newer generation re-signs", gets: []answer{gen(1, true), gen(2, true)}, posts: []answer{{403, ""}, {200, nil}}, ok: true, getsN: 2, postsN: 2, generations: []int64{1, 2}},
		{name: "403 then a transient discovery failure", gets: []answer{gen(1, true), {503, ""}, gen(1, true)}, posts: []answer{{403, ""}}, getsN: 3, postsN: 1, sleeps: 1},
		{name: "discovery 403 stops", gets: []answer{{403, `{"error":"no authorized boot; reset required"}`}}, getsN: 1},
		{name: "discovery 400 stops", gets: []answer{{400, ""}}, getsN: 1},
		{name: "malformed discovery stops", gets: []answer{gen(0, true)}, getsN: 1},
		{name: "discovery 503 retries", gets: []answer{{503, ""}, gen(1, false)}, posts: []answer{{200, nil}}, ok: true, getsN: 2, postsN: 1, sleeps: 1},
		{name: "409 rediscovers and sends the certificate", gets: []answer{gen(1, false), gen(1, true)}, posts: []answer{{409, `{"error":"certificate_required"}`}, {200, nil}}, ok: true, getsN: 2, postsN: 2, certificateSent: []bool{false, true}, sleeps: 1},
		{name: "409 while the sandbox id is not persisted", gets: []answer{gen(1, true)}, posts: []answer{{409, ""}, {409, ""}, {200, nil}}, ok: true, getsN: 3, postsN: 3, sleeps: 2},
		{name: "5xx retries", gets: []answer{gen(1, true)}, posts: []answer{{503, ""}, {500, ""}, {200, nil}}, ok: true, getsN: 1, postsN: 3, sleeps: 2},
		{name: "429 retries", gets: []answer{gen(1, true)}, posts: []answer{{429, ""}, {200, nil}}, ok: true, getsN: 1, postsN: 2, sleeps: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := useFakeClock(t)
			posts := test.posts
			if posts == nil {
				posts = []answer{{500, "unexpected POST"}}
			}
			m, server := newMockAttestor(t, vector.containerKey(t), test.gets, posts)
			result := FromAttestor(testBoot(t, server.URL, f.now))
			if (result.AgentSealPriv != nil) != test.ok {
				t.Fatalf("ok=%v, want %v", result.AgentSealPriv != nil, test.ok)
			}
			if gets, sent := m.counts(); gets != test.getsN || sent != test.postsN {
				t.Fatalf("GETs %d POSTs %d, want %d and %d", gets, sent, test.getsN, test.postsN)
			}
			if len(f.sleeps) != test.sleeps {
				t.Fatalf("slept %v, want %d sleeps", f.sleeps, test.sleeps)
			}
			for i, request := range m.sent {
				if signer, _ := recoverClaim(t, request); signer.Hex() != vector.ContainerKey.Address {
					t.Fatalf("POST %d not signed by the container key", i)
				}
				if i > 0 {
					if request.BootID != m.sent[0].BootID {
						t.Fatal("boot_id changed within one boot")
					}
					if request.BootStartedAt <= m.sent[i-1].BootStartedAt {
						t.Fatal("boot_started_at did not increase between attempts")
					}
				}
				if test.certificateSent != nil && (len(m.raw[i]["certificate"]) > 0) != test.certificateSent[i] {
					t.Fatalf("POST %d certificate present=%v", i, len(m.raw[i]["certificate"]) > 0)
				}
				if test.generations != nil && request.BootGeneration != test.generations[i] {
					t.Fatalf("POST %d generation %d", i, request.BootGeneration)
				}
			}
		})
	}
}

func TestProvisionRetriesTransportErrors(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{200, nil}})
	dropped := false
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !dropped {
			dropped = true
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		m.ServeHTTP(w, r)
	})
	if result := FromAttestor(testBoot(t, server.URL, f.now)); result.AgentSealPriv == nil {
		t.Fatal("transport error was not retried")
	}
	if !dropped || len(f.sleeps) != 1 || len(m.sent) != 1 {
		t.Fatalf("dropped=%v sleeps=%v accepted POSTs=%d", dropped, f.sleeps, len(m.sent))
	}
}

func TestProvisionBacksOffAndGivesUpTenMinutesAfterBoot(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	// PID-1 started a minute before provisioning began.
	started := f.now.Add(-time.Minute)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{503, "busy"}})
	if result := FromAttestor(testBoot(t, server.URL, started)); result.AgentSealPriv != nil {
		t.Fatal("provisioned against an attestor that never answered")
	}
	// 1+2+4+8+16 = 31 s, then 30 s steps while one more still ends inside
	// the 540 s left of the window: 31 + 16×30 = 511 s, and 541 s would not.
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for range 16 {
		want = append(want, 30*time.Second)
	}
	if !reflect.DeepEqual(f.sleeps, want) {
		t.Fatalf("backoff %v, want %v", f.sleeps, want)
	}
	if elapsed := f.now.Sub(started); elapsed >= retryWindow || elapsed+maxBackoff < retryWindow {
		t.Fatalf("gave up %s after boot", elapsed)
	}
	if _, sent := m.counts(); sent != len(want)+1 {
		t.Fatalf("POSTs %d", sent)
	}
}

func TestProvisionRequiresEncryptedBootReceipt(t *testing.T) {
	vector := loadCertificateVector(t)
	for name, receipt := range map[string]func(m *mockAttestor) string{
		"missing":        func(*mockAttestor) string { return "" },
		"not ciphertext": func(*mockAttestor) string { return "0x1234" },
		"empty token":    func(m *mockAttestor) string { return m.encrypt([]byte(`{"token":""}`)) },
		"opaque token":   func(m *mockAttestor) string { return m.encrypt([]byte(`{"token":"current-boot"}`)) },
		"uppercase hex":  func(m *mockAttestor) string { return m.encrypt([]byte(`{"token":"` + strings.Repeat("AB", 32) + `"}`)) },
		"short hex":      func(m *mockAttestor) string { return m.encrypt([]byte(`{"token":"` + strings.Repeat("ab", 31) + `"}`)) },
	} {
		t.Run(name, func(t *testing.T) {
			f := useFakeClock(t)
			m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{200, nil}})
			m.payload["encrypted_status_binding"] = receipt(m)
			if result := FromAttestor(testBoot(t, server.URL, f.now)); result.AgentSealPriv != nil {
				t.Fatal("accepted a boot without a valid receipt")
			}
			if _, sent := m.counts(); sent != 1 || len(f.sleeps) != 0 {
				t.Fatal("an undecryptable answer was retried")
			}
		})
	}
}

func TestFromAttestorRejectsInvalidInputsBeforeHTTP(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{200, nil}})
	for name, change := range map[string]func(*Boot){
		"v2 certificate":      func(b *Boot) { b.Certificate.Version = 2 },
		"no certificate JSON": func(b *Boot) { b.CertificateJSON = nil },
		"short ticket":        func(b *Boot) { b.Ticket = "22" },
		"uppercase ticket":    func(b *Boot) { b.Ticket = strings.Repeat("AA", 32) },
		"no ticket":           func(b *Boot) { b.Ticket = "" },
		"bad container key":   func(b *Boot) { b.SealKey = make([]byte, 32) },
	} {
		boot := testBoot(t, server.URL, f.now)
		change(&boot)
		if result := FromAttestor(boot); result.AgentSealPriv != nil {
			t.Fatalf("%s: returned a key", name)
		}
	}
	if gets, sent := m.counts(); gets+sent != 0 {
		t.Fatal("an invalid boot reached the attestor")
	}
}

// /log is public: no ticket, key, signature, token or raw env blob may reach
// it, and attestor error bodies are bounded.
func TestProvisionLogsNoSecrets(t *testing.T) {
	vector := loadCertificateVector(t)
	f := useFakeClock(t)
	long := strings.Repeat("e", 300) + "\nFAIL forged line\r\x1b[2J" + strings.Repeat("界", 100)
	m, server := newMockAttestor(t, vector.containerKey(t), []answer{gen(1, true)}, []answer{{503, long}, {200, nil}})
	before := len(logger.Lines())
	boot := testBoot(t, server.URL, f.now)
	if result := FromAttestor(boot); result.AgentSealPriv == nil {
		t.Fatal("provision failed")
	}
	lines := logger.Lines()[before:]
	secrets := map[string]string{
		"ticket":              boot.Ticket,
		"container key":       strings.TrimPrefix(vector.ContainerKey.PrivateKey, "0x"),
		"agent key":           hex.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		"status token":        strings.Repeat("ab", 32),
		"certificate blob":    vector.Wire,
		"provider signature":  strings.TrimPrefix(vector.Signature, "0x"),
		"container signature": strings.TrimPrefix(m.sent[0].ContainerSignature, "0x"),
	}
	var bounded bool
	for _, line := range lines {
		for name, secret := range secrets {
			if strings.Contains(strings.ToLower(line), strings.ToLower(secret)) {
				t.Errorf("%s reached /log: %s", name, line)
			}
		}
		if strings.Contains(line, "HTTP 503") {
			bounded = true
			// The body past its first 256 bytes never reaches the log.
			if strings.Contains(line, "\n") || strings.Contains(line, "FAIL forged") || len(line) > 320 {
				t.Errorf("unbounded attestor body in /log (%d bytes): %q", len(line), line)
			}
		}
	}
	if !bounded {
		t.Fatal("the 503 answer was not logged")
	}
}
