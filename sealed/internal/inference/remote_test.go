package inference

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPinnedRegistrySurvivesPublicationAndProcessRestart(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	fixture := registryFixture(t)
	old := fixture["snapshot"].(map[string]any)
	config := fixture["config"].(map[string]any)
	oldDigest := config["provider_registry_digest"].(string)
	var doc map[string]any
	_ = json.Unmarshal([]byte(old["document"].(string)), &doc)
	doc["base_version"] = 1
	doc["providers"].([]any)[3].(map[string]any)["endpoints"].(map[string]any)["openai"] = "https://new-partner.example/v1"
	encoded, _ := json.Marshal(doc)
	newSnapshot := map[string]any{"version": 2, "providers": doc["providers"], "document": string(encoded), "signature": "accepted-new-signature"}
	documentHash := sha256.Sum256(encoded)
	digest := sha256.Sum256([]byte(fmt.Sprintf("AgentDNA.ProviderRegistryAccepted.v1:%x:%s", documentHash, newSnapshot["signature"])))
	newDigest := fmt.Sprintf("0x%x", digest)
	config["provider_registry_version"], config["provider_registry_digest"] = 2, newDigest
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/config" {
			_ = json.NewEncoder(w).Encode(config)
			return
		}
		requested = append(requested, req.URL.RawQuery)
		if req.URL.Query().Get("version") == "1" {
			_ = json.NewEncoder(w).Encode(old)
			return
		}
		_ = json.NewEncoder(w).Encode(newSnapshot)
	}))
	defer server.Close()
	credential := ProviderCredential{Provider: "partner", RouteHash: fixture["route_hash"].(string), Registry: &RegistryPin{Version: 1, Digest: oldDigest}}
	for boot := 0; boot < 2; boot++ {
		registry, err := LoadPinnedRegistry(context.Background(), server.URL, uint64(fixture["chain_id"].(float64)), fixture["agentic_id_addr"].(string), credential)
		if err != nil {
			t.Fatal(err)
		}
		if got := registry.providers["partner"].Endpoints[WireOpenAI]; got != "https://partner.example/v1" {
			t.Fatalf("boot %d redirected to %s", boot, got)
		}
	}
	// A reset signs the new version and route; no process-global cache carries the old route over.
	registry, _ := NewRegistry(mustJSON(t, doc["providers"]))
	newHash, _ := registry.RouteHash("partner")
	credential.Registry = &RegistryPin{Version: 2, Digest: newDigest}
	credential.RouteHash = newHash
	registry, err := LoadPinnedRegistry(context.Background(), server.URL, uint64(fixture["chain_id"].(float64)), fixture["agentic_id_addr"].(string), credential)
	if err != nil || registry.providers["partner"].Endpoints[WireOpenAI] != "https://new-partner.example/v1" {
		t.Fatalf("reset route: %v", err)
	}
	if strings.Join(requested, ",") != "version=1,version=1,version=2" {
		t.Fatalf("requested: %v", requested)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPinnedRegistryNeverFallsBackToLatest(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	for _, cause := range []string{"missing", "wrong-version", "tampered", "route", "rollback"} {
		t.Run(cause, func(t *testing.T) {
			fixture := registryFixture(t)
			config := fixture["config"].(map[string]any)
			snapshot := fixture["snapshot"].(map[string]any)
			credential := ProviderCredential{Provider: "partner", RouteHash: fixture["route_hash"].(string), Registry: &RegistryPin{Version: 1, Digest: config["provider_registry_digest"].(string)}}
			switch cause {
			case "wrong-version":
				snapshot["version"] = 2
			case "tampered":
				snapshot["document"] = snapshot["document"].(string) + " "
			case "route":
				credential.RouteHash = "0xwrong"
			case "rollback":
				config["provider_registry_version"] = 0
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/config" {
					_ = json.NewEncoder(w).Encode(config)
					return
				}
				if req.URL.Query().Get("version") != "1" {
					t.Error("fell back to the latest registry")
				}
				if cause == "missing" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(snapshot)
			}))
			defer server.Close()
			if _, err := LoadPinnedRegistry(context.Background(), server.URL, uint64(fixture["chain_id"].(float64)), fixture["agentic_id_addr"].(string), credential); err == nil {
				t.Fatal("invalid pinned registry accepted")
			}
		})
	}
}

func TestBuiltinRegistryPinSurvivesFirstPublication(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	fixture := registryFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/config" {
			_ = json.NewEncoder(w).Encode(fixture["config"])
			return
		}
		if req.URL.Query().Get("version") != "0" {
			t.Error("built-in credential requested the latest registry")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 0, "providers": json.RawMessage(providerDefinitions)})
	}))
	defer server.Close()
	hash, _ := DefaultRegistry.RouteHash(ZGComputeProvider)
	credential := ProviderCredential{Provider: ZGComputeProvider, RouteHash: hash, Registry: &RegistryPin{Version: 0}}
	r, err := LoadPinnedRegistry(context.Background(), server.URL, uint64(fixture["chain_id"].(float64)), fixture["agentic_id_addr"].(string), credential)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.RouteHash(ZGComputeProvider); got != hash {
		t.Fatal("built-in route changed")
	}
}

func registryFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/registry-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSignedRemoteRegistryMatchesSDKRouteHash(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	fixture := registryFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "" {
			t.Error("public registry received an inference key")
		}
		switch req.URL.Path {
		case "/config":
			_ = json.NewEncoder(w).Encode(fixture["config"])
		case "/inference/providers":
			_ = json.NewEncoder(w).Encode(fixture["snapshot"])
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	registry, err := LoadRemoteRegistry(context.Background(), server.URL, uint64(fixture["chain_id"].(float64)), fixture["agentic_id_addr"].(string))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := registry.RouteHash("partner")
	if err != nil || hash != fixture["route_hash"] {
		t.Fatalf("route hash = %s (%v), want %s", hash, err, fixture["route_hash"])
	}
	facts, endpoint, err := registry.Resolve(context.Background(), "partner", "private-model")
	if err != nil || endpoint.BaseURL != "https://partner.example/v1" || facts.MaxTokens != 12000 {
		t.Fatalf("route = %+v %+v %v", facts, endpoint, err)
	}
	if _, _, err := DefaultRegistry.Resolve(context.Background(), "partner", "private-model"); err == nil {
		t.Fatal("remote loading mutated the global built-in registry")
	}
}

func TestRemoteRegistryRefusesUntrustedTamperedAndWrongEnvironment(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	for _, cause := range []string{"bad-receipt", "tampered", "environment", "unavailable", "unsigned"} {
		t.Run(cause, func(t *testing.T) {
			fixture := registryFixture(t)
			config := fixture["config"].(map[string]any)
			snapshot := fixture["snapshot"].(map[string]any)
			switch cause {
			case "bad-receipt":
				config["provider_registry_digest"] = "0xwrong"
			case "tampered":
				snapshot["document"] = snapshot["document"].(string) + " "
			case "unsigned":
				snapshot["version"] = 0
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if cause == "unavailable" {
					w.WriteHeader(503)
					return
				}
				if req.URL.Path == "/config" {
					_ = json.NewEncoder(w).Encode(config)
				} else {
					_ = json.NewEncoder(w).Encode(snapshot)
				}
			}))
			defer server.Close()
			chain := uint64(fixture["chain_id"].(float64))
			if cause == "environment" {
				chain++
			}
			if _, err := LoadRemoteRegistry(context.Background(), server.URL, chain, fixture["agentic_id_addr"].(string)); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}

func TestRemoteRegistryRequiresAuthenticatedAttestor(t *testing.T) {
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "false")
	t.Setenv("ATTESTOR_TLS_DESCRIPTOR", "")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	if _, err := LoadRemoteRegistry(context.Background(), server.URL, 16602, "0x"+strings.Repeat("11", 20)); err == nil {
		t.Fatal("accepted registry without an authenticated attestor")
	}
	if calls != 0 {
		t.Fatal("contacted unauthenticated registry")
	}
}
