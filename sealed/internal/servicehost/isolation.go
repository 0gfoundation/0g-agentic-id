package servicehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/privsep"
	"seal-verify/internal/serviceidentity"
	"seal-verify/internal/servicesandbox"
)

// Work and temporary files of one request or execution, enforced by the
// resource monitor (a service cannot mount a size-limited filesystem).
const temporaryFilesystemBytes = 64 << 20

// coordinatorStateBytes bounds a coordinator's durable work directory (its
// business state, such as a paid service's task store).
const coordinatorStateBytes = 512 << 20

var ErrIsolationUnavailable = errors.New("isolation unavailable")

// mappedIdentity checks the namespace's inside IDs, not its host UID offset.
// An unmapped ID makes setuid/chown fail even when sealed has SETUID/CHOWN.
func mappedIdentity(mapping []byte, first, count uint64) bool {
	end := first + count
	if count == 0 || end < first {
		return false
	}
	for _, line := range strings.Split(string(mapping), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		inside, e1 := strconv.ParseUint(f[0], 10, 64)
		_, e2 := strconv.ParseUint(f[1], 10, 64)
		n, e3 := strconv.ParseUint(f[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && n > 0 && inside+n >= inside && first >= inside && end <= inside+n {
			return true
		}
	}
	return false
}

func checkServiceIdentityMaps() error {
	for _, name := range []string{"uid_map", "gid_map"} {
		mapping, err := os.ReadFile("/proc/self/" + name)
		if err != nil || !mappedIdentity(mapping, serviceidentity.Base, serviceidentity.Count) {
			return fmt.Errorf("%w: provider %s must map service IDs %d..%d", ErrIsolationUnavailable, name, serviceidentity.Base, serviceidentity.Base+serviceidentity.Count-1)
		}
	}
	return nil
}

// systemPaths is what every service process may use from the image: system
// code read-only, a few /etc entries, and harmless device nodes. Links are
// resolved here so each Landlock rule names the real directory.
type systemPaths struct {
	readExec, readOnly, devices []string
}

var (
	systemOnce sync.Once
	system     systemPaths
)

func imageSystem() systemPaths {
	systemOnce.Do(func() {
		seen := map[string]bool{}
		covered := func(p string) bool {
			for d := range seen {
				if p == d || strings.HasPrefix(p, d+"/") {
					return true
				}
			}
			return false
		}
		for _, p := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
			if real, err := filepath.EvalSymlinks(p); err == nil && !covered(real) {
				if fi, err := os.Stat(real); err == nil && fi.IsDir() {
					seen[real] = true
					system.readExec = append(system.readExec, real)
				}
			}
		}
		for _, p := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs"} {
			if real, err := filepath.EvalSymlinks(p); err == nil && !covered(real) {
				system.readOnly = append(system.readOnly, real)
			}
		}
		for _, p := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"} {
			var st unix.Stat_t
			if unix.Lstat(p, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR {
				system.devices = append(system.devices, p)
			}
		}
	})
	return system
}

func withinAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// ProbeIsolation runs the trusted launcher's probe: it confines itself at a
// service identity and checks that Landlock and the seccomp filter refuse
// what they must. It never relaxes capabilities or the provider's policy.
func ProbeIsolation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkServiceIdentityMaps(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, err := privsep.RootCommand(ctx, "sealed-service-launcher", "probe")
	if err != nil {
		return fmt.Errorf("%w: trusted service launcher is required: %v", ErrIsolationUnavailable, err)
	}
	// Probe diagnostics are bounded by this fixed trusted command and contain
	// no owner state or task input. Keep the concrete denial actionable.
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("isolation probe: %w", ctx.Err())
		}
		detail := strings.TrimSpace(string(out))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return fmt.Errorf("%w: the kernel must provide Landlock ABI %d or later and the container must allow it and seccomp filters: %s: %v", ErrIsolationUnavailable, servicesandbox.MinABI, detail, err)
	}
	return nil
}

// admission caches the probe: the kernel and the container's policy do not
// change while sealed runs. A failure is retried after a minute. The probe
// runs on its own context, so a caller that went away is never cached as the
// kernel's answer for every service.
func (m *Manager) admission() error {
	if m.skipResourceLimitsForTests {
		return nil
	}
	if m.runtime == nil {
		return fmt.Errorf("%w: a verified listed Harness runtime callback is required", ErrIsolationUnavailable)
	}
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	ttl := 10 * time.Minute
	if m.probeErr != nil {
		ttl = time.Minute
	}
	if m.probeAt.IsZero() || time.Since(m.probeAt) > ttl {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m.probeErr, m.probeAt = ProbeIsolation(ctx), time.Now()
		cancel()
	}
	return m.probeErr
}

// ErrDiskLow refuses a new service process while the filesystem of the task
// directories has less than diskReserveBytes free.
var ErrDiskLow = errors.New("sandbox disk space is low; service processes are refused until space is freed")

// prepareLaunch does the slow part of starting a service process (probe, free
// space, runtime listing and pin) without the manager lock.
func (m *Manager) prepareLaunch(ctx context.Context) (RuntimeLease, error) {
	if err := m.admission(); err != nil {
		return RuntimeLease{}, err
	}
	if diskLowCheck(m.programs) {
		return RuntimeLease{}, ErrDiskLow
	}
	return m.acquireRuntime(ctx)
}
