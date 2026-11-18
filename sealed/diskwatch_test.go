package main

import (
	"errors"
	"testing"

	"seal-verify/internal/servicehost"
)

// The disk warning rises below servicehost's reserve, holds until free space
// is back a margin above it, and reports only when it rises or clears.
func TestDiskWatch_WarnsBelowTheReserveAndClearsAboveTheMargin(t *testing.T) {
	const mib = 1 << 20
	status := &runtimeStatus{level: "running"}
	reading := servicehost.FreeSpace{Inodes: -1}
	var readErr error
	reports := 0
	d := &diskWatch{
		path:   "/home/agent",
		read:   func(string) (servicehost.FreeSpace, error) { return reading, readErr },
		status: status,
		report: func() { reports++ },
	}
	step := func(name string, bytes int64, wantLevel, wantMsg string, wantReports int) {
		t.Helper()
		reading.Bytes = bytes
		d.check()
		if level, msg := status.Get(); level != wantLevel || msg != wantMsg {
			t.Fatalf("%s: (%q, %q), want (%q, %q)", name, level, msg, wantLevel, wantMsg)
		}
		if reports != wantReports {
			t.Fatalf("%s: %d reports, want %d", name, reports, wantReports)
		}
	}

	step("room", 5<<30, "running", "", 0)
	step("at the reserve", servicehost.DiskReserveBytes, "running", "", 0)
	step("below the reserve", 412*mib, "warning",
		"sandbox disk nearly full: 412 MiB free; ask the agent to delete files it no longer needs, or reset it", 1)
	step("still low", 300*mib, "warning",
		"sandbox disk nearly full: 300 MiB free; ask the agent to delete files it no longer needs, or reset it", 1)
	step("back above the reserve, under the margin", servicehost.DiskReserveBytes+100*mib, "warning",
		"sandbox disk nearly full: 1124 MiB free; ask the agent to delete files it no longer needs, or reset it", 1)
	step("above the margin", servicehost.DiskReserveBytes+diskClearMarginBytes, "running", "", 2)
	step("between the lines again", servicehost.DiskReserveBytes+100*mib, "running", "", 2)

	// An unreadable filesystem changes nothing.
	step("low again", 10*mib, "warning",
		"sandbox disk nearly full: 10 MiB free; ask the agent to delete files it no longer needs, or reset it", 3)
	readErr = errors.New("statfs: permission denied")
	step("unreadable", 5<<30, "warning",
		"sandbox disk nearly full: 10 MiB free; ask the agent to delete files it no longer needs, or reset it", 3)
	readErr = nil
	step("recovered", 5<<30, "running", "", 4)
}

// A filesystem that counts inodes is low when they run out, whatever bytes
// it has left; one that does not count them (-1) never is for that reason.
func TestDiskWatch_Inodes(t *testing.T) {
	status := &runtimeStatus{level: "running"}
	d := &diskWatch{status: status, report: func() {}}
	for _, c := range []struct {
		inodes int64
		want   string
	}{
		{-1, ""},
		{servicehost.DiskReserveInodes, ""},
		{1000, "sandbox disk nearly full: room for 1000 more files; ask the agent to delete files it no longer needs, or reset it"},
		{servicehost.DiskReserveInodes + 100, "sandbox disk nearly full: room for 65636 more files; ask the agent to delete files it no longer needs, or reset it"},
		{servicehost.DiskReserveInodes + diskClearMarginInodes, ""},
	} {
		free := servicehost.FreeSpace{Bytes: 5 << 30, Inodes: c.inodes}
		d.read = func(string) (servicehost.FreeSpace, error) { return free, nil }
		d.check()
		if _, msg := status.Get(); msg != c.want {
			t.Fatalf("%d inodes: %q, want %q", c.inodes, msg, c.want)
		}
	}
}

// The disk warning shows like the settings warning: after it, and behind a
// commit warning or an error, until those clear.
func TestRuntimeStatus_DiskIssueOrder(t *testing.T) {
	s := &runtimeStatus{level: "running"}
	s.DiskIssue("sandbox disk nearly full")
	if level, msg := s.Get(); level != "warning" || msg != "sandbox disk nearly full" {
		t.Fatalf("disk issue Get = (%q, %q)", level, msg)
	}
	s.SettingsIssue("owner settings unusable")
	if _, msg := s.Get(); msg != "owner settings unusable" {
		t.Fatalf("the settings issue comes first, got %q", msg)
	}
	s.SettingsIssue("")
	s.Set("warning", "agent data not committed to chain")
	if _, msg := s.Get(); msg != "agent data not committed to chain" {
		t.Fatalf("a commit warning comes first, got %q", msg)
	}
	if prev := s.Set("running", ""); prev != "warning" {
		t.Fatalf("recover Set returned %q", prev)
	}
	if _, msg := s.Get(); msg != "sandbox disk nearly full" {
		t.Fatalf("after the commit recovers the disk shows again, got %q", msg)
	}
	s.DiskIssue("")
	if level, msg := s.Get(); level != "running" || msg != "" {
		t.Fatalf("cleared: (%q, %q)", level, msg)
	}
}
