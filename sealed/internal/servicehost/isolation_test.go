package servicehost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/serviceidentity"
)

func TestServiceIdentityFitsProviderUIDMap(t *testing.T) {
	if MaxServices != serviceidentity.CoordinatorCount || MaxWorkers != serviceidentity.WorkerCount {
		t.Fatal("service capacity differs from the launcher's reserved identities")
	}
	// Sysbox remaps the runner and its children into this 65536-ID range.
	// The host offset does not alter the IDs available inside the sandbox.
	mapping := []byte("         0     100000      65536\n")
	for _, span := range [][2]uint64{{coordinatorUIDBase, serviceidentity.CoordinatorCount}, {workerUIDBase, serviceidentity.WorkerCount}} {
		if !mappedIdentity(mapping, span[0], span[1]) {
			t.Fatalf("service identities do not fit provider uid_map: %v", span)
		}
	}
	for _, span := range [][2]uint64{{200000, 16}, {210000, 32}, {65535, 2}, {0, 0}, {^uint64(0), 2}} {
		if mappedIdentity(mapping, span[0], span[1]) {
			t.Fatalf("unmapped identities accepted: %v", span)
		}
	}
	if mappedIdentity([]byte("not a uid map"), coordinatorUIDBase, 1) {
		t.Fatal("accepted invalid uid_map")
	}
}

func TestServiceAdmissionReportsUnsupportedProvider(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_ISOLATION_EXPECT") != "unsupported" {
		t.Skip("requires the explicit stock provider seccomp profile")
	}
	m, err := New(filepath.Join(t.TempDir(), "services"), "owner:identity")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, id := range []string{"request", "coordinator"} {
		man := manifest(id, requestFixture)
		if id == "coordinator" {
			man.Worker = &Program{Command: "python3", Args: []string{"/app/server.py"}}
		}
		if _, err := m.Publish(man); err != nil {
			t.Fatal(err)
		}
		status, err := m.Start(id)
		if !errors.Is(err, ErrIsolationUnavailable) || status.State != "unsupported" || !status.Desired || !strings.Contains(status.Error, "provider") {
			t.Fatalf("missing actionable unsupported admission: %+v %v", status, err)
		}
	}
	m.Resume()
	for _, status := range m.List() {
		if status.State != "unsupported" || !strings.Contains(status.Error, "provider") {
			t.Fatalf("resume hid unsupported provider: %+v", status)
		}
	}
}

func TestProviderNamespacePolicy(t *testing.T) {
	root(t)
	switch os.Getenv("SEALED_ISOLATION_EXPECT") {
	case "supported":
		if err := ProbeIsolation(context.Background()); err != nil {
			t.Fatal(err)
		}
	case "unsupported":
		if err := ProbeIsolation(context.Background()); !errors.Is(err, ErrIsolationUnavailable) {
			t.Fatalf("missing fail-closed provider policy denial: %v", err)
		}
	default:
		t.Skip("set SEALED_ISOLATION_EXPECT for a real provider-profile probe")
	}
}
