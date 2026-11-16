package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"seal-verify/internal/framework"
)

type servicePolicyAdapter struct {
	framework.Framework
	name string
}

func (a servicePolicyAdapter) Name() string { return a.name }

func TestLegacyServiceRegistrationSurvivesManagedHosting(t *testing.T) {
	for _, name := range []string{"0g-harness", "dsh", "openclaw", "hermes", "prime-agent"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(200)
			}))
			defer backend.Close()
			s, _ := armedProxy(t, backend.URL, testValidator)
			s.SetAdapter(servicePolicyAdapter{name: name})
			managed := name == "0g-harness" || name == "dsh"
			entries := []ServiceEntry{
				{Path: "/api/x", Method: "POST", Backend: backend.URL},
				{Path: "/api/mcp", Method: "POST", Backend: backend.URL, Transport: "mcp"},
				{Path: "/api/mcp-other", Method: "POST", Backend: backend.URL},
			}
			body, _ := json.Marshal(map[string]any{"services": entries})
			out := httptest.NewRecorder()
			s.handleServices(out, httptest.NewRequest("POST", "/services", strings.NewReader(string(body))))
			if out.Code != 200 {
				t.Fatalf("legacy registration: %d %s", out.Code, out.Body.String())
			}
			for _, e := range entries {
				out = httptest.NewRecorder()
				s.handleProxy(out, httptest.NewRequest("POST", e.Path, nil))
				if out.Code != 200 || out.Header().Get("X-Agent-Proof") == "" {
					t.Fatalf("legacy route %s lost forwarding/proof: %d", e.Path, out.Code)
				}
			}
			if calls != len(entries) {
				t.Fatal("legacy backend was not reached")
			}
			out = httptest.NewRecorder()
			s.handleServices(out, httptest.NewRequest("GET", "/services", nil))
			var registry struct {
				Services []ServiceEntry `json:"services"`
			}
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &registry) != nil || len(registry.Services) != len(entries) {
				t.Fatalf("legacy discovery changed: %s", out.Body.String())
			}

			body, _ = json.Marshal(map[string]any{"services": []ServiceEntry{{Path: "/api/mcp/old", Method: "POST", Backend: backend.URL}}})
			out = httptest.NewRecorder()
			s.handleServices(out, httptest.NewRequest("POST", "/services", strings.NewReader(string(body))))
			if managed {
				if out.Code != 400 || !strings.Contains(out.Body.String(), "seal_service_publish") || len(s.getServices()) != len(entries) {
					t.Fatalf("managed namespace registration was not rejected atomically: %d %s", out.Code, out.Body.String())
				}
				s.fwRoutes = []framework.Route{{Prefix: "/api/", Kind: "service"}}
				out = httptest.NewRecorder()
				s.handleProxy(out, httptest.NewRequest("POST", "/api/mcp/old", nil))
				if out.Code != 503 || calls != len(entries) {
					t.Fatal("missing host reopened the reserved namespace")
				}
			} else {
				if out.Code != 200 {
					t.Fatalf("another adapter lost its existing namespace: %d", out.Code)
				}
				out = httptest.NewRecorder()
				s.handleProxy(out, httptest.NewRequest("POST", "/api/mcp/old", nil))
				if out.Code != 200 || calls != len(entries)+1 {
					t.Fatal("another adapter's service was intercepted")
				}
			}
		})
	}
}

func TestSelectedHostingAdapterHidesOnlyReservedLegacyEntries(t *testing.T) {
	s := &Server{services: []ServiceEntry{
		{Path: "/api/x", Method: "POST", Backend: "http://localhost:9000"},
		{Path: "/api/mcp/old", Method: "POST", Backend: "http://localhost:9000"},
	}}
	s.SetAdapter(servicePolicyAdapter{name: "0g-harness"})
	if got := s.getServices(); len(got) != 1 || got[0].Path != "/api/x" {
		t.Fatalf("incorrect discovery filtering: %+v", got)
	}
	if _, ok := s.matchService("/api/mcp/old"); ok {
		t.Fatal("a stale legacy entry bypassed managed hosting")
	}
	s.SetAdapter(servicePolicyAdapter{name: "openclaw"})
	if len(s.getServices()) != 2 {
		t.Fatal("non-hosting adapter lost its legacy service discovery")
	}
	if _, ok := s.matchService("/api/mcp/old"); !ok {
		t.Fatal("non-hosting adapter lost its legacy service route")
	}
}
