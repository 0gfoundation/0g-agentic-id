//go:build linux

package servicesandbox

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/serviceidentity"
)

// Usage is what one service identity holds in this container's PID namespace.
type Usage struct {
	Processes int   // live (non-zombie) processes
	Tasks     int   // threads, which RLIMIT_NPROC also counts
	RSSBytes  int64 // resident memory, summed over processes
}

// procRoot is a variable so tests can point the scanner at a fixture tree.
var procRoot = "/proc"

// Scan reads every process's status once and sums usage for the given
// identities. A service cannot change its identity (no_new_privs, no
// capabilities), so its descendants stay counted after setsid or reparenting.
func Scan(uids map[uint32]bool) map[uint32]Usage {
	out := map[uint32]Usage{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "status"))
		if err != nil {
			continue // exited between ReadDir and ReadFile
		}
		uid, u, ok := parseStatus(b)
		if !ok || !uids[uid] {
			continue
		}
		total := out[uid]
		total.Processes += u.Processes
		total.Tasks += u.Tasks
		total.RSSBytes += u.RSSBytes
		out[uid] = total
	}
	return out
}

func parseStatus(b []byte) (uint32, Usage, bool) {
	var uid uint32
	var u Usage
	haveUID, zombie := false, false
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := s.Bytes()
		key, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		fields := bytes.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch string(key) {
		case "State":
			zombie = fields[0][0] == 'Z' || fields[0][0] == 'X'
		case "Uid":
			n, err := strconv.ParseUint(string(fields[0]), 10, 32)
			if err != nil {
				return 0, Usage{}, false
			}
			uid, haveUID = uint32(n), true
		case "Threads":
			u.Tasks, _ = strconv.Atoi(string(fields[0]))
		case "VmRSS":
			kb, _ := strconv.ParseInt(string(fields[0]), 10, 64)
			u.RSSBytes = kb << 10
		}
	}
	if !haveUID || zombie {
		return 0, Usage{}, false
	}
	u.Processes = 1
	return uid, u, true
}

// Reap runs as root, becomes uid and sends SIGKILL to every process it may
// signal: in this PID namespace, exactly the processes of that identity,
// however they re-parented or regrouped. It returns once none is left.
func Reap(uid uint32, timeout time.Duration) error {
	if !serviceidentity.Valid(int(uid)) {
		return fmt.Errorf("invalid service identity")
	}
	runtime.LockOSThread()
	if err := dropTo(uid); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		_ = unix.Kill(-1, unix.SIGKILL)
		left := Scan(map[uint32]bool{uid: true})[uid].Processes
		if left == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d processes of identity %d remain", left, uid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
