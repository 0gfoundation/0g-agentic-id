package servicehost

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishedReleaseReturnsNormalizedVerifiableSnapshot(t *testing.T) {
	root(t)
	m, err := newTestManager(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	man := manifest("audit", "print('public source')")
	man.Env = map[string]string{"PUBLIC_MODE": "example"}
	status, err := m.Publish(man)
	if err != nil {
		t.Fatal(err)
	}
	release, err := m.Release("audit")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(release.CanonicalManifest)
	if hex.EncodeToString(hash[:]) != status.Version || release.Version != status.Version || release.Manifest.MemoryMB == 0 || release.Manifest.ResidentMemoryMB == 0 {
		t.Fatal("release does not expose its normalized version preimage")
	}
	var canonical Manifest
	if json.Unmarshal(release.CanonicalManifest, &canonical) != nil || canonical.ID != "audit" {
		t.Fatal("invalid canonical manifest")
	}
	release.Manifest.Env["PUBLIC_MODE"] = "changed"
	release.Manifest.Files[0].Data = "changed"
	again, err := m.Release("audit")
	if err != nil || again.Manifest.Env["PUBLIC_MODE"] != "example" || again.Manifest.Files[0].Data != base64.StdEncoding.EncodeToString([]byte("print('public source')")) {
		t.Fatal("release caller mutated the stored immutable release")
	}
}

func TestPrivateInputRequiresAuditedVersionBeforeAnyProgram(t *testing.T) {
	for _, coordinator := range []bool{false, true} {
		man := Manifest{}
		if coordinator {
			man.Worker = &Program{Command: "python3"}
		}
		version := strings.Repeat("a", 64)
		m := &Manager{entries: map[string]*entry{"audit": {Manifest: man, Status: Status{ID: "audit", Version: version, Desired: true, State: "running"}}}}
		for _, tc := range []struct {
			versions []string
			code     int
		}{
			{nil, 400}, {[]string{"invalid"}, 400}, {[]string{strings.Repeat("b", 64)}, 409}, {[]string{version, version}, 400},
		} {
			req := httptest.NewRequest("POST", "http://localhost/mcp", nil)
			req.Header.Set(RuntimeInputHeader, base64.StdEncoding.EncodeToString([]byte(`{"token":"private-fixture"}`)))
			for _, v := range tc.versions {
				req.Header.Add(ServiceVersionHeader, v)
			}
			resp, err := (&taskTransport{manager: m, id: "audit"}).RoundTrip(req)
			if err != nil || resp.StatusCode != tc.code {
				t.Fatalf("coordinator=%v versions=%v: %+v %v", coordinator, tc.versions, resp, err)
			}
			resp.Body.Close()
		}
		req := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", nil)
		req.Header.Set(RuntimeInputHeader, "e30=")
		req.Header.Set(ServiceVersionHeader, version)
		if code, _ := checkPrivateInputVersion(req, version); code != 0 {
			t.Fatal("matching audited release rejected")
		}
		req.Header.Del(RuntimeInputHeader)
		req.Header.Set(ServiceVersionHeader, strings.Repeat("b", 64))
		if code, _ := checkPrivateInputVersion(req, version); code != 409 {
			t.Fatal("provided public-call version pin was ignored")
		}
	}
}

func TestPrivateHandoffCannotRetargetAfterReleaseChange(t *testing.T) {
	version := strings.Repeat("a", 64)
	m := &Manager{entries: map[string]*entry{"audit": {Manifest: Manifest{Worker: &Program{Command: "python3"}}, Status: Status{ID: "audit", Version: version, Desired: true, State: "running"}}}, pendingInputs: map[string]pendingInput{}}
	handle, cleanup, err := m.handoffForVersion("audit", version, []byte(`{"token":"private-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	m.entries["audit"].Version = strings.Repeat("b", 64)
	if _, _, err := m.handoffForVersion("audit", version, []byte(`{}`)); err == nil {
		t.Fatal("stale release created a new handoff")
	}
	if _, err := m.spawnWithHandoff("audit", executionTestKey(987), []byte(`{}`), handle); err == nil {
		t.Fatal("private handoff reached replacement code")
	}
	if len(m.executions) != 0 || len(m.workers) != 0 {
		t.Fatal("release conflict reserved an execution or identity")
	}
}
