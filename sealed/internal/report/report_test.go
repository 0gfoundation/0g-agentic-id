package report

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// This fixture is also verified by Rust's status signature tests.
func TestBoundStatusCrossLanguage(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	raw, err := os.ReadFile("../inference/testdata/status-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Settings   string         `json:"settings"`
		PrivateKey string         `json:"private_key"`
		Canonical  string         `json:"canonical"`
		Report     map[string]any `json:"report"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	token := fixture.Report["status_binding"].(string)
	binding := NewBinding(token)
	// A receipt alone cannot claim the settings were applied.
	if _, digest := binding.snapshot(); digest != "" {
		t.Fatal("settings adopted too early")
	}
	binding.AdoptSettings([]byte(fixture.Settings))
	_, digest := binding.snapshot()
	seal := strings.TrimPrefix(fixture.Report["seal_id"].(string), "0x")
	if got := statusMessage(seal, "running", "", token, digest); got != fixture.Canonical {
		t.Fatalf("canonical mismatch: %s", got)
	}
	seen := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var packet map[string]any
		if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
			t.Error(err)
		}
		seen <- packet
		w.WriteHeader(200)
	}))
	defer srv.Close()
	key, _ := hex.DecodeString(strings.TrimPrefix(fixture.PrivateKey, "0x"))
	Status(srv.URL, key, seal, "running", "", binding)
	var packet map[string]any
	select {
	case packet = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("status report did not reach the mock attestor")
	}
	for _, field := range []string{"seal_id", "status", "error_detail", "status_binding", "settings_digest", "agent_seal_signature"} {
		if packet[field] != fixture.Report[field] {
			t.Errorf("%s differs: got %v want %v", field, packet[field], fixture.Report[field])
		}
	}
	binding.AdoptSettings(nil)
	if _, digest := binding.snapshot(); digest != "" {
		t.Fatal("clearing adoption retained digest")
	}
}

// Every report carries this boot's receipt; there is no unbound form.
func TestStatusWithoutReceiptSendsNothing(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	key := make([]byte, 32)
	key[31] = 1
	for _, binding := range []*Binding{nil, NewBinding("")} {
		Status(srv.URL, key, strings.Repeat("aa", 32), "running", "", binding)
	}
	if calls != 0 {
		t.Fatalf("%d unbound status reports sent", calls)
	}
}
