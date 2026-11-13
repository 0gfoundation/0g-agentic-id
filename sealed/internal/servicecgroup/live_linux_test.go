//go:build linux

package servicecgroup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests need the actual provider-shaped writable delegation. Unit tests
// with ordinary files do not establish kernel memory/PID enforcement.
func livePool(t *testing.T) *Pool {
	t.Helper()
	if os.Getenv("SEALED_CGROUP_TESTS") != "1" {
		t.Skip("set SEALED_CGROUP_TESTS=1 in a provider-shaped delegated cgroup-v2 layout")
	}
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}
func liveLease(t *testing.T, p *Pool, key string, memory int64, pids int) *Lease {
	t.Helper()
	lease, err := p.Acquire(key, memory, pids)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := lease.KillAndRemove(ctx); err != nil {
			t.Error(err)
		}
	})
	return lease
}
func helper(lease *Lease, action string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCgroupProcessHelper$")
	cmd.Env = append(os.Environ(), "SEALED_CGROUP_HELPER="+action)
	if lease != nil {
		cmd.ExtraFiles = []*os.File{lease.ProcsFile()}
	}
	return cmd
}

func TestLiveAggregateMemoryKillsTheWholeDescendantGroup(t *testing.T) {
	p := livePool(t)
	lease := liveLease(t, p, "live-memory", 128<<20, 64)
	cmd := helper(lease, "memory-parent")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("two 80MiB descendants escaped a 128MiB aggregate memory.max: %s", out)
	}
	events, readErr := readControl(lease.fd, "memory.events", p.kernel)
	if readErr != nil {
		t.Fatal(readErr)
	}
	found := false
	for _, line := range strings.Split(events, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "oom_kill" && fields[1] != "0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("failure was not a cgroup OOM kill: %v; events=%s; output=%s", err, events, out)
	}
}

func TestLivePIDsLimitCountsAllDescendants(t *testing.T) {
	p := livePool(t)
	lease := liveLease(t, p, "live-pids", 128<<20, 32)
	cmd := helper(lease, "pids")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "pids-limit-reached") {
		t.Fatalf("descendant creation was not bounded: %s", out)
	}
	events, err := readControl(lease.fd, "pids.events", p.kernel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(events) == "max 0" {
		t.Fatalf("kernel did not count a PID-controller rejection: %s", events)
	}
}

func TestLiveKillRemovesDescendantsOutsideTheProcessGroup(t *testing.T) {
	p := livePool(t)
	lease := liveLease(t, p, "live-kill", 128<<20, 32)
	cmd := helper(lease, "escaped-session")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v: %s", err, out)
	}
	events, err := readControl(lease.fd, "cgroup.events", p.kernel)
	if err != nil {
		t.Fatal(err)
	}
	alive, err := populated(events)
	if err != nil || !alive {
		t.Fatalf("fixture has no surviving descendant: %v: %s", err, events)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = lease.KillAndRemove(ctx); err != nil {
		t.Fatal(err)
	}
	if !lease.removed {
		t.Fatal("cleanup returned before kernel-empty acknowledgement and removal")
	}
}

func TestCgroupProcessHelper(t *testing.T) {
	action := os.Getenv("SEALED_CGROUP_HELPER")
	if action == "" {
		return
	}
	if action != "memory-leaf" {
		f := os.NewFile(3, "cgroup.procs")
		if _, err := f.WriteString("0"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(31)
		}
		f.Close()
	}
	switch action {
	case "memory-parent":
		for i := 0; i < 2; i++ {
			cmd := helper(nil, "memory-leaf")
			if err := cmd.Start(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(32)
			}
		}
		time.Sleep(15 * time.Second)
		os.Exit(33)
	case "memory-leaf":
		buf := make([]byte, 80<<20)
		for i := 0; i < len(buf); i += 4096 {
			buf[i] = 1
		}
		for {
			time.Sleep(time.Second)
			runtime.KeepAlive(buf)
		}
	case "pids":
		for i := 0; i < 128; i++ {
			cmd := exec.Command("/bin/sleep", "30")
			if err := cmd.Start(); err != nil {
				fmt.Printf("pids-limit-reached after %d descendants: %v\n", i, err)
				os.Exit(0)
			}
		}
		os.Exit(34)
	case "escaped-session":
		cmd := exec.Command("/usr/bin/setsid", "/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(35)
		}
		os.Exit(0)
	default:
		os.Exit(36)
	}
}
