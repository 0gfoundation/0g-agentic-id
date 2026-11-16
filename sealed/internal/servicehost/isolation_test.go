package servicehost

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/serviceidentity"
)

func TestServiceIdentityFitsProviderUIDMap(t *testing.T) {
	// Sysbox remaps the runner and its children into this 65536-ID range.
	// The host offset does not alter the IDs available inside the sandbox.
	mapping := []byte("         0     100000      65536\n")
	if !mappedIdentity(mapping, serviceidentity.Base, serviceidentity.Count) {
		t.Fatal("service identities do not fit the provider uid_map")
	}
	for _, span := range [][2]uint64{{200000, 16}, {60000, 6000}, {65535, 2}, {0, 0}, {^uint64(0), 2}} {
		if mappedIdentity(mapping, span[0], span[1]) {
			t.Fatalf("unmapped identities accepted: %v", span)
		}
	}
	if mappedIdentity([]byte("not a uid map"), serviceidentity.Base, 1) {
		t.Fatal("accepted invalid uid_map")
	}
	for _, uid := range []int{0, 1000, serviceidentity.Base - 1, serviceidentity.Base + serviceidentity.Count, 65534} {
		if serviceidentity.Valid(uid) {
			t.Fatalf("identity %d must not be a service identity", uid)
		}
	}
}

func TestIdentitiesAreDrawnAtRandomAndNeverShared(t *testing.T) {
	m := &Manager{workers: map[uint32]*worker{}, entries: map[string]*entry{}}
	seen := map[uint32]bool{}
	for range MaxWorkers {
		uid, err := m.allocateIdentityLocked()
		if err != nil || !serviceidentity.Valid(int(uid)) || seen[uid] {
			t.Fatalf("identity %d: %v (seen %v)", uid, err, seen[uid])
		}
		seen[uid] = true
		m.workers[uid] = &worker{}
	}
	for range 256 {
		uid, err := m.allocateIdentityLocked()
		if err != nil || seen[uid] || uid == serviceidentity.Probe {
			t.Fatalf("reused an identity in use or the probe's: %d %v", uid, err)
		}
	}
	// Fixed slots (51000.. in every sandbox) would share RLIMIT_NPROC across
	// sandboxes; consecutive draws must not be a counter.
	a, _ := m.allocateIdentityLocked()
	b, _ := m.allocateIdentityLocked()
	c, _ := m.allocateIdentityLocked()
	if b == a+1 && c == b+1 {
		t.Fatal("identities look sequential")
	}
}

// Scripted draws: a coordinator's, a worker's and a quarantined identity
// come up first and are each skipped for the free one after them.
func TestIdentityAllocationSkipsIdentitiesInUse(t *testing.T) {
	controller, busy, held, free := uint32(serviceidentity.Base+11), uint32(serviceidentity.Base+12), uint32(serviceidentity.Base+13), uint32(serviceidentity.Base+14)
	m := &Manager{workers: map[uint32]*worker{busy: {}}, entries: map[string]*entry{"svc": {ControllerUID: controller}}, quarantined: map[uint32]string{held: "fixture"}}
	draws := []uint32{controller, busy, held, free}
	old := drawRandom
	drawRandom = func(b []byte) error {
		binary.BigEndian.PutUint32(b, draws[0]-serviceidentity.Base-1) // Draw maps r to Base+1+r
		draws = draws[1:]
		return nil
	}
	defer func() { drawRandom = old }()
	uid, err := m.allocateIdentityLocked()
	if err != nil || uid != free {
		t.Fatalf("allocated %d (%v), want the free identity %d", uid, err, free)
	}
}

func TestServiceAdmissionReportsUnsupportedProvider(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_ISOLATION_EXPECT") != "unsupported" {
		t.Skip("set SEALED_ISOLATION_EXPECT=unsupported on a kernel or container without Landlock ABI 6")
	}
	m, err := NewWithOptions(filepath.Join(t.TempDir(), "services"), "owner:identity", Options{AcquireRuntime: func(context.Context) (RuntimeLease, error) {
		return RuntimeLease{}, errors.New("unused")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, id := range []string{"request", "coordinator"} {
		man := manifest(id, requestFixture)
		if id == "coordinator" {
			man.Worker = &Program{Command: "python3", Args: []string{"server.py"}}
		}
		if _, err := m.Publish(man); err != nil {
			t.Fatal(err)
		}
		status, err := m.Start(id)
		if !errors.Is(err, ErrIsolationUnavailable) || status.State != "unsupported" || !status.Desired || !strings.Contains(status.Error, "Landlock") {
			t.Fatalf("missing actionable unsupported admission: %+v %v", status, err)
		}
	}
	m.Resume()
	for _, status := range m.List() {
		if status.State != "unsupported" || !strings.Contains(status.Error, "Landlock") {
			t.Fatalf("resume hid unsupported provider: %+v", status)
		}
	}
}

func TestProviderConfinementProbe(t *testing.T) {
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
		t.Skip("set SEALED_ISOLATION_EXPECT for a real confinement probe")
	}
}

// Node's bundled OpenSSL exits at startup when /etc/ssl/openssl.cnf exists
// but cannot be read, so a service process may read it wherever it exists.
func TestImageSystemReadsOpenSSLConfig(t *testing.T) {
	real, err := filepath.EvalSymlinks("/etc/ssl/openssl.cnf")
	if err != nil {
		t.Skip("no OpenSSL configuration on this host")
	}
	for _, p := range imageSystem().readOnly {
		if p == real {
			return
		}
	}
	t.Fatalf("%s missing from the read-only allowlist %v", real, imageSystem().readOnly)
}
