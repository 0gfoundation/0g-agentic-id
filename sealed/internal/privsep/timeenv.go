//go:build linux

package privsep

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// sealed's own time zone.
//
// Go's time package resolves the local time zone once, the first time it is
// used — sealed's first log line, inside Harden — from TZ: an absolute path
// (or ":" and one) is read as a zone file; any other name but "UTC" is read
// relative to the image's zoneinfo directories, with no check against "..";
// with TZ unset, /etc/localtime is read; and a zone none of these yields is
// looked for in $GOROOT/lib/time/zoneinfo.zip. Each read is a blocking,
// link-following open. sealed's environment is the container's, which the
// deploy request sets, so TZ (or GOROOT) could name a file inside an agent
// tree: root would read an agent-written file at every boot, and a FIFO
// there would hang PID 1 before it serves anything. ScrubTimeEnv lets the
// zone come only from a root-only zone file that parses — so Go's own read
// succeeds and never reaches the $GOROOT fallback — and otherwise sets
// TZ=UTC, which Go resolves without reading any file. (ZONEINFO is read only
// by time.LoadLocation, which sealed does not call.)

// zoneSources are the directories Go's time package reads a zone name from,
// in its order (platformZoneSources in time/zoneinfo_unix.go). A var so
// tests can redirect it; production code never reassigns it.
var zoneSources = []string{"/usr/share/zoneinfo/", "/usr/share/lib/zoneinfo/", "/usr/lib/locale/TZ/", "/etc/zoneinfo"}

// localtimePath is the zone file Go reads when TZ is unset. A var so tests
// can redirect it; production code never reassigns it.
var localtimePath = "/etc/localtime"

// zoneFileLimit bounds the read of a zone file (they are a few KiB).
const zoneFileLimit = 1 << 20

// ScrubTimeEnv makes sealed's own time zone come from a root-only zone file,
// and returns one line per change for the boot log. It must run before
// anything uses the local time zone (logger.Logf does); Harden runs it
// before its first log line.
//
// TZ "UTC", ":UTC" or "" (UTC, no file read) is left alone. An absolute TZ
// is kept only when it resolves to a root-only regular file holding a zone
// Go can load, and is then replaced by that resolved path; a zone name is
// looked up in the image's zoneinfo directories in Go's order, and replaced
// by the first such file it names. With TZ unset, /etc/localtime must be
// such a file. Anything else sets TZ=UTC.
func ScrubTimeEnv() []string {
	tz, set := os.LookupEnv("TZ")
	name := strings.TrimPrefix(tz, ":")
	if set && (name == "" || name == "UTC") {
		return nil
	}
	var file string
	var err error
	switch {
	case !set:
		file, err = zoneFile(localtimePath)
	case strings.HasPrefix(name, "/"):
		file, err = zoneFile(name)
	default:
		file, err = namedZoneFile(name)
	}
	if err != nil {
		os.Setenv("TZ", "UTC")
		if !set {
			return []string{fmt.Sprintf("TZ is unset and %s is not a root-only zone file (%v); TZ=UTC set, so no zone file is read", localtimePath, err)}
		}
		return []string{fmt.Sprintf("TZ=%q replaced by UTC in sealed's environment (a time zone must come from a root-only zone file: %v)", tz, err)}
	}
	if set && file != tz {
		os.Setenv("TZ", file)
		return []string{fmt.Sprintf("TZ=%q used as %q", tz, file)}
	}
	return nil
}

// namedZoneFile finds the zone file Go would read for a zone name: the
// first of zoneSources that holds it. A name that climbs out with ".." is
// refused.
func namedZoneFile(name string) (string, error) {
	for _, c := range strings.Split(name, "/") {
		if c == ".." {
			return "", fmt.Errorf("%q leaves the zoneinfo directories", name)
		}
	}
	var firstErr error
	for _, src := range zoneSources {
		p := filepath.Join(src, name)
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			continue
		}
		f, err := zoneFile(p)
		if err == nil {
			return f, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no zone %q in %v", name, zoneSources)
	}
	return "", firstErr
}

// zoneFile resolves p and checks that it is a root-only regular file
// holding a zone Go can load.
func zoneFile(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if err := rootOnly(real, unix.S_IFREG); err != nil {
		return "", err
	}
	b, err := ReadFile(real, zoneFileLimit)
	if err != nil {
		return "", err
	}
	if _, err := time.LoadLocationFromTZData(real, b); err != nil {
		return "", fmt.Errorf("%s: %w", real, err)
	}
	return real, nil
}
