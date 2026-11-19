//go:build linux

package servicesandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseStatus(t *testing.T) {
	status := []byte("Name:\tpython3\nState:\tS (sleeping)\nUid:\t20042\t20042\t20042\t20042\nThreads:\t3\nVmRSS:\t  2048 kB\n")
	uid, u, zombie, ok := parseStatus(status)
	if !ok || zombie || uid != 20042 || u.Processes != 1 || u.Tasks != 3 || u.RSSBytes != 2048<<10 {
		t.Fatalf("parse: %d %+v %v %v", uid, u, zombie, ok)
	}
	if _, u, zombie, ok := parseStatus([]byte("State:\tZ (zombie)\nUid:\t20042\t20042\t20042\t20042\n")); !ok || !zombie || u.Processes != 0 {
		t.Fatalf("zombie: %+v %v %v", u, zombie, ok)
	}
	if _, _, _, ok := parseStatus([]byte("Name:\tx\n")); ok {
		t.Fatal("accepted a status without Uid")
	}
}

// procFixture writes /proc-like status files below a temporary root and points
// the scanner at it.
func procFixture(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name, "status")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
}

func TestScanSumsOneIdentity(t *testing.T) {
	procFixture(t, map[string]string{
		"10":   "State:\tS\nUid:\t20001\t20001\t20001\t20001\nThreads:\t2\nVmRSS:\t100 kB\n",
		"11":   "State:\tR\nUid:\t20001\t20001\t20001\t20001\nThreads:\t1\nVmRSS:\t50 kB\n",
		"12":   "State:\tZ\nUid:\t20001\t20001\t20001\t20001\nThreads:\t1\n",
		"13":   "State:\tS\nUid:\t20002\t20002\t20002\t20002\nThreads:\t1\nVmRSS:\t999 kB\n",
		"self": "State:\tS\nUid:\t20001\n",
	})
	u := Scan(map[uint32]bool{20001: true})[20001]
	if u.Processes != 2 || u.Tasks != 3 || u.RSSBytes != 150<<10 {
		t.Fatalf("scan: %+v", u)
	}
}

// A leader that exited while its threads run is a zombie in /proc/<pid>, but
// the process lives on: it must count, with its threads' memory.
func TestScanCountsThreadsOfAnExitedLeader(t *testing.T) {
	procFixture(t, map[string]string{
		"20":         "State:\tZ (zombie)\nUid:\t20003\t20003\t20003\t20003\nThreads:\t3\n",
		"20/task/20": "State:\tZ (zombie)\nUid:\t20003\t20003\t20003\t20003\nThreads:\t3\n",
		"20/task/21": "State:\tR (running)\nUid:\t20003\t20003\t20003\t20003\nThreads:\t3\nVmRSS:\t4096 kB\n",
		"30":         "State:\tS\nUid:\t1000\t1000\t1000\t1000\nThreads:\t1\nVmRSS:\t1 kB\n",
		"31":         "State:\tS\nUid:\t64999\t64999\t64999\t64999\nThreads:\t1\nVmRSS:\t1 kB\n",
		"31/task/31": "State:\tS\nUid:\t64999\t64999\t64999\t64999\nThreads:\t1\nVmRSS:\t1 kB\n",
	})
	u := Scan(map[uint32]bool{20003: true})[20003]
	if u.Processes != 1 || u.Tasks != 3 || u.RSSBytes != 4096<<10 {
		t.Fatalf("scan: %+v", u)
	}
	got := map[uint32]bool{}
	for _, uid := range Identities() {
		got[uid] = true
	}
	if !reflect.DeepEqual(got, map[uint32]bool{20003: true, 64999: true}) {
		t.Fatalf("identities: %v", got)
	}
}
