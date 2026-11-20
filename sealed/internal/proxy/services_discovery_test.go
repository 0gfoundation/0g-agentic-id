package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/servicehost"
)

// Tests discovery through the actual HTTP handlers after an explicit stop.
// A disabled service may remain discoverable for auditing, but callers must
// be able to distinguish it from an endpoint accepting work.
func TestStoppedHostedServiceAdvertisesState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("hosted services require Linux root")
	}
	host, err := servicehost.NewWithOptions(filepath.Join(t.TempDir(), "services"), "qa-owner:qa-identity", servicehost.Options{SkipResourceLimitsForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	_, err = host.Publish(servicehost.Manifest{ID: "qa-stopped", Description: "QA stopped service", Command: "python3", Args: []string{"main.py"}, Files: []servicehost.File{{Path: "main.py", Data: base64.StdEncoding.EncodeToString([]byte("print('QA')"))}}})
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := host.Stop("qa-stopped")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("management status after stop: %+v", stopped)
	s, _ := armedProxy(t, "http://localhost", testValidator)
	s.SetAdapter(servicePolicyAdapter{name: "0g-harness"})
	s.SetServiceHost(host)
	hello := httptest.NewRecorder()
	s.handleHello(hello, httptest.NewRequest("GET", "/hello", nil))
	if hello.Code != 200 {
		t.Fatalf("hello: %d %s", hello.Code, hello.Body.String())
	}
	t.Logf("public discovery: %s", hello.Body.String())
	invocation := httptest.NewRecorder()
	s.handleProxy(invocation, httptest.NewRequest("POST", "/api/mcp/qa-stopped", strings.NewReader(`{}`)))
	t.Logf("invocation after stop: HTTP %d %s", invocation.Code, invocation.Body.String())
	if invocation.Code != 503 {
		t.Fatalf("stopped service accepted work or returned an unexpected status: %d", invocation.Code)
	}
	var body struct {
		Services []map[string]any `json:"services"`
	}
	if err := json.Unmarshal(hello.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, service := range body.Services {
		if service["path"] == "/api/mcp/qa-stopped" && service["state"] != "stopped" && service["status"] != "stopped" && service["available"] != false {
			t.Errorf("stopped service is advertised without its stopped/unavailable state: %v", service)
		}
	}
}
