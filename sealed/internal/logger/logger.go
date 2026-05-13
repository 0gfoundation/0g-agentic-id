// Package logger is the cross-cutting in-memory log used by the bootstrap
// pipeline. /log HTTP endpoint reads from here, every other module writes here.
package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// tsLayout is the timestamp prefix attached to every Logf message. Kept
// short (HH:MM:SS.mmm) -- absolute date is rarely needed since /log is
// always read in-session, and the millisecond resolution helps line up
// closely-spaced events (e.g. manager reload + watcher tick).
const tsLayout = "15:04:05.000"

const LogPath = "/tmp/seal-bootstrap.log"

var (
	mu    sync.RWMutex
	lines []string
)

// Logf appends a formatted line to the in-memory log AND prints it to stdout.
// Each line gets a [HH:MM:SS.mmm] prefix so callers don't have to remember
// to include one; renderers can parse + restyle it consistently.
func Logf(format string, a ...any) {
	msg := "[" + time.Now().Format(tsLayout) + "] " + fmt.Sprintf(format, a...)
	fmt.Println(msg)
	mu.Lock()
	lines = append(lines, msg)
	mu.Unlock()
}

// Fail logs the message with a "FAIL: " prefix to stderr, flushes to disk,
// and exits the process. Reserved for unrecoverable startup errors.
func Fail(format string, a ...any) {
	msg := "[" + time.Now().Format(tsLayout) + "] FAIL: " + fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	mu.Lock()
	lines = append(lines, msg)
	mu.Unlock()
	Flush()
	os.Exit(1)
}

// Flush persists the current in-memory log to LogPath. Best-effort; errors
// are intentionally swallowed (we're often called from Fail).
func Flush() {
	mu.RLock()
	body := strings.Join(lines, "\n") + "\n"
	mu.RUnlock()
	_ = os.WriteFile(LogPath, []byte(body), 0644)
}

// Snapshot returns the current log as a single newline-joined string.
// Used by the /log HTTP endpoint.
func Snapshot() string {
	mu.RLock()
	defer mu.RUnlock()
	return strings.Join(lines, "\n") + "\n"
}

// Lines returns a copy of the log line slice for callers that want to
// iterate per-line (e.g. /log.html for prefix-based colorization).
func Lines() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, len(lines))
	copy(out, lines)
	return out
}
