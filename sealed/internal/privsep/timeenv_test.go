//go:build linux

package privsep

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// utcZone is a minimal TZif (version 1) zone: one type, UTC.
func utcZone(t *testing.T) []byte {
	t.Helper()
	b := append([]byte("TZif"), make([]byte, 16)...)
	for _, n := range []uint32{0, 0, 0, 0, 1, 4} { // isut, isstd, leap, time, type, char counts
		b = binary.BigEndian.AppendUint32(b, n)
	}
	b = append(b, 0, 0, 0, 0, 0, 0) // utoff 0, isdst 0, designation 0
	b = append(b, 'U', 'T', 'C', 0)
	if _, err := time.LoadLocationFromTZData("UTC", b); err != nil {
		t.Fatalf("test zone does not load: %v", err)
	}
	return b
}

// sealed's own time zone comes from a root-only zone file or is UTC: a TZ
// (or, with TZ unset, an /etc/localtime) naming anything else — a file
// another uid can write, a FIFO, a name that climbs out of the zoneinfo
// directories, a file that is not a zone — is replaced by UTC, which Go
// resolves without reading a file, and the check itself never opens what
// it refuses.
func TestScrubTimeEnv(t *testing.T) {
	base := rootOnlyBase(t)
	zone := utcZone(t)
	zoneinfo := filepath.Join(base, "zoneinfo")
	if err := os.MkdirAll(filepath.Join(zoneinfo, "Etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(zoneinfo, "Etc", "UTC")
	if err := os.WriteFile(good, zone, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "localtime")
	mustSymlink(t, good, link)
	notZone := filepath.Join(base, "not-a-zone")
	mustWrite(t, notZone, "hello")
	if err := os.Chmod(notZone, 0o644); err != nil {
		t.Fatal(err)
	}
	agentDir := t.TempDir() // under /tmp: not root-only
	agentZone := filepath.Join(agentDir, "zone")
	if err := os.WriteFile(agentZone, zone, 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(agentDir, "tz")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	escape, err := filepath.Rel(zoneinfo, agentZone)
	if err != nil {
		t.Fatal(err)
	}

	prevSources, prevLocal := zoneSources, localtimePath
	t.Cleanup(func() { zoneSources, localtimePath = prevSources, prevLocal })
	zoneSources = []string{filepath.Join(base, "missing") + "/", zoneinfo + "/"}

	const unset = "\x00unset"
	cases := []struct {
		name, tz, localtime string
		want                string // unset = left unset
	}{
		{"UTC", "UTC", link, "UTC"},
		{":UTC", ":UTC", link, ":UTC"},
		{"empty", "", link, ""},
		{"unset, root-only localtime", unset, link, unset},
		{"unset, agent-writable localtime", unset, agentZone, "UTC"},
		{"unset, missing localtime", unset, filepath.Join(base, "none"), "UTC"},
		{"absolute root-only zone, through a link", link, link, good},
		{"colon and absolute root-only zone", ":" + link, link, good},
		{"absolute agent-writable zone", agentZone, link, "UTC"},
		{"absolute FIFO", fifo, link, "UTC"},
		{"colon and absolute FIFO", ":" + fifo, link, "UTC"},
		{"root-only file that is not a zone", notZone, link, "UTC"},
		{"zone name", "Etc/UTC", link, good},
		{"zone name climbing out", escape, link, "UTC"},
		{"missing zone name", "Mars/Olympus", link, "UTC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			localtimePath = tc.localtime
			if tc.tz == unset {
				t.Setenv("TZ", "")
				os.Unsetenv("TZ")
			} else {
				t.Setenv("TZ", tc.tz)
			}
			done := make(chan []string, 1)
			go func() { done <- ScrubTimeEnv() }()
			var lines []string
			select {
			case lines = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ScrubTimeEnv did not return")
			}
			got, ok := os.LookupEnv("TZ")
			switch {
			case tc.want == unset && ok:
				t.Errorf("TZ = %q, want it left unset", got)
			case tc.want != unset && (!ok || got != tc.want):
				t.Errorf("TZ = %q (set %v), want %q", got, ok, tc.want)
			}
			if changed := tc.want != tc.tz; changed != (len(lines) > 0) {
				t.Errorf("lines %q for a TZ that changed=%v", lines, changed)
			}
			if tc.want == "UTC" && tc.tz != unset && tc.tz != "UTC" && !strings.Contains(strings.Join(lines, "\n"), tc.tz) {
				t.Errorf("lines %q do not name the refused TZ %q", lines, tc.tz)
			}
		})
	}
}

// Harden settles the time zone before anything it runs logs: its first log
// line is what makes Go read the zone.
func TestHardenScrubsTheTimeZoneFirst(t *testing.T) {
	var order []string
	harden(func() []string { order = append(order, "scrub"); return nil },
		func() bool { order = append(order, "active"); return false },
		func() { order = append(order, "self") },
		nil, nil, nil, nil)
	if len(order) == 0 || order[0] != "scrub" {
		t.Fatalf("harden ran %v; the environment checks must come first", order)
	}
	// Harden's own scrub step covers the time zone.
	t.Setenv("TZ", "/nonexistent/zone")
	scrubOwnEnv()
	if got := os.Getenv("TZ"); got != "UTC" {
		t.Fatalf("Harden's scrub step left TZ=%q", got)
	}
}
