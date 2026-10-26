package provision

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	eciesgo "github.com/ecies/go/v2"
)

func TestFromAttestorForwardsV2SignedScopeAndDecrypts(t *testing.T) {
	vector := loadAttestationVector(t)
	containerKey, err := hex.DecodeString(strings.TrimPrefix(vector.ContainerKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	// Public test bytes stand in for the response payload only. The production
	// container key and agentSeal ECIES path are exercised without alteration.
	agentKey := []byte(strings.Repeat("k", 32))
	settings := []byte(`{"version":1,"others":{}}`)
	container := eciesgo.NewPrivateKeyFromBytes(containerKey)
	encryptedKey, err := eciesgo.Encrypt(container.PublicKey, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedSettings, err := eciesgo.Encrypt(container.PublicKey, settings)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/provision" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if !reflect.DeepEqual(got, vector.ProvisionRequest) {
			t.Errorf("forwarded request differs from signed v2 fixture: %#v", got)
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"encrypted_agent_seal_priv": "0x" + hex.EncodeToString(encryptedKey), "encrypted_settings": "0x" + hex.EncodeToString(encryptedSettings)})
	}))
	defer server.Close()
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	result := FromAttestor(server.URL, containerKey, vector.Envelope)
	if requests.Load() != 1 || !reflect.DeepEqual(result.AgentSealPriv, agentKey) || !reflect.DeepEqual(result.Settings, settings) {
		t.Fatal("v2 request/decryption did not preserve the original payloads")
	}
}

func TestFromAttestorRejectsUnsupportedBeforeHTTP(t *testing.T) {
	vector := loadAttestationVector(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	for _, version := range []uint64{0, 1, 3} {
		a := vector.Envelope
		a.Version = version
		if result := FromAttestor(server.URL, nil, a); result.AgentSealPriv != nil {
			t.Fatalf("version %d returned a key", version)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("unsupported envelope reached the attestor")
	}
}
