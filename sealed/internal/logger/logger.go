// Package logger is the cross-cutting in-memory log used by the bootstrap
// pipeline. /log HTTP endpoint reads from here, every other module writes here.
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// tsLayout is the timestamp prefix attached to every Logf message. Kept
// short (HH:MM:SS.mmm) -- absolute date is rarely needed since /log is
// always read in-session, and the millisecond resolution helps line up
// closely-spaced events (e.g. manager reload + watcher tick).
const tsLayout = "15:04:05.000"

// LogPath is where Flush persists the log: inside sealed's root-only state
// directory (privsep.StateDir, which this package cannot import), not the
// shared /tmp.
const LogPath = "/var/lib/sealed/seal-bootstrap.log"

var (
	mu    sync.RWMutex
	lines []string
)

// Logf appends a formatted line to the in-memory log AND prints it to stdout.
// Each line gets a [HH:MM:SS.mmm] prefix so callers don't have to remember
// to include one; renderers can parse + restyle it consistently.
//
// The message is passed through neutralize first: callers log file names
// and command output the agent controls, and /log is served without
// authentication, so no message may start a line that looks like one of
// sealed's own.
func Logf(format string, a ...any) {
	msg := "[" + time.Now().Format(tsLayout) + "] " + neutralize(fmt.Sprintf(format, a...))
	fmt.Println(msg)
	mu.Lock()
	lines = append(lines, msg)
	mu.Unlock()
}

// continuation is what neutralize puts after each newline in a message.
// Every line Logf starts begins with "[" and a timestamp; a continuation
// line begins with this instead, so text after a newline in a message
// (multi-line command output, or a file name with a newline in it) reads
// as part of the entry it belongs to and can never pass for an entry of
// its own.
const continuation = "    | "

// neutralize makes a message safe to append to the log: each newline is
// followed by the continuation marker, and every other control character
// (a carriage return, which a terminal uses to overwrite the start of a
// line, escape sequences, C1 controls) and the Unicode line and paragraph
// separators are escaped as \xNN or \uNNNN. Tabs stay.
func neutralize(s string) string {
	clean := true
	for _, r := range s {
		if r == '\n' || (r != '\t' && unicode.IsControl(r)) || r == '\u2028' || r == '\u2029' || r == utf8.RuneError {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i, w := 0, 0; i < len(s); i += w {
		r, n := utf8.DecodeRuneInString(s[i:])
		w = n
		switch {
		case r == '\n':
			b.WriteString("\n" + continuation)
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, "\\x%02x", s[i])
		case r == '\t':
			b.WriteRune(r)
		case r < 0x100 && unicode.IsControl(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// maxOnceKeys caps how many distinct keys Once remembers per namespace
// (the part of a key before its first ":"). Past it, Once stays silent for
// new keys in that namespace: its callers report conditions an agent
// process can create in unbounded numbers (one per file name, say), and the
// in-memory log never shrinks. The cap is per namespace so that a flood of
// one kind cannot silence the others.
const maxOnceKeys = 4096

var (
	onceMu    sync.Mutex
	onceSeen  = map[string]bool{}
	onceCount = map[string]int{}
)

// Once is Logf for a condition that can repeat on every pass of a periodic
// walk: it logs the first time key is seen in this process and is silent
// afterwards. Keys are "<namespace>:<detail>". It reports whether it
// logged.
func Once(key, format string, a ...any) bool {
	ns, _, _ := strings.Cut(key, ":")
	onceMu.Lock()
	first := !onceSeen[key] && onceCount[ns] < maxOnceKeys
	if first {
		onceSeen[key] = true
		onceCount[ns]++
	}
	onceMu.Unlock()
	if first {
		Logf(format, a...)
	}
	return first
}

// Fail logs the message with a "FAIL: " prefix to stderr, flushes to disk,
// and exits the process. Reserved for unrecoverable startup errors.
func Fail(format string, a ...any) {
	msg := "[" + time.Now().Format(tsLayout) + "] FAIL: " + neutralize(fmt.Sprintf(format, a...))
	fmt.Fprintln(os.Stderr, msg)
	mu.Lock()
	lines = append(lines, msg)
	mu.Unlock()
	Flush()
	os.Exit(1)
}

// Flush persists the current in-memory log to LogPath. Best-effort; errors
// are intentionally swallowed (we're often called from Fail). The file is
// opened without following a link at its name.
func Flush() {
	mu.RLock()
	body := strings.Join(lines, "\n") + "\n"
	mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(LogPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(LogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(body)
	_ = f.Close()
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
