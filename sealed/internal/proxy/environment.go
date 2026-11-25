package proxy

// GET /environment on the sign socket: what the 0G sandbox runner publishes
// about this sandbox (its CPU, memory, task and disk limits and use, and the
// provider's notices), read from the file the runner keeps in a read-only
// directory of the container, and answered with how old it is.
//
// The agent does not read that file itself: its doctrine refuses any file
// under /run (platform.buildSovereignty, refusal 4). This route, and the
// tool seal_environment over it (signtools.go), is how it learns these
// facts. It signs nothing and changes nothing: sealed reads one file
// through privsep, bounded in size, and passes the object on unchanged.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"net/http"
	"time"

	"seal-verify/internal/privsep"
)

// environmentFile is the file the runner writes, replaced by rename every
// 30 s and whenever the provider sends a notice. It is missing on older
// runners, in the first seconds after boot and outside 0G sandboxes. A
// variable so that tests can point it elsewhere.
var environmentFile = "/run/0g/environment.json"

const (
	// maxEnvironmentFile bounds the read. The runner's largest file (16
	// notices of 2000 bytes, each <, > or & escaped to 6 bytes) is about
	// 195 KB.
	maxEnvironmentFile = 256 << 10
	// environmentStaleAfter is the age past which the figures are reported
	// stale: the runner has missed several of its 30 s rewrites.
	environmentStaleAfter = 120 * time.Second
)

// environmentAnswer is the /environment response. Environment is the
// runner's object as it wrote it, unknown fields included; the other fields
// are sealed's. A computed field is left out when what it needs is missing.
type environmentAnswer struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// AgeSeconds is now - updated_at, in whole seconds (0 for a time ahead
	// of sealed's clock).
	AgeSeconds *int64 `json:"age_seconds,omitempty"`
	// Stale is AgeSeconds past environmentStaleAfter. It covers the file's
	// rewrite only; the disk figures have their own age, DiskAgeSeconds.
	Stale *bool `json:"stale,omitempty"`
	// DiskAgeSeconds is now - disk.measured_at, in whole seconds (0 for a
	// time ahead of sealed's clock): the runner measures disk use less often
	// than it rewrites the file.
	DiskAgeSeconds *int64 `json:"disk_age_seconds,omitempty"`
	// DiskUsedPct is disk.used_bytes / disk.limit_bytes in percent, to one
	// decimal; above 100 when the sandbox is over its disk size.
	DiskUsedPct *float64        `json:"disk_used_pct,omitempty"`
	Environment json.RawMessage `json:"environment,omitempty"`
}

func (s *Server) handleEnvironment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeSignError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, http.StatusOK, readEnvironment(environmentFile, time.Now()))
}

// readEnvironment is the answer for the file at path, as of now. A file
// that is missing, unreadable, too large or not one JSON object is
// {available: false, reason}; the reason names no path.
func readEnvironment(path string, now time.Time) environmentAnswer {
	unavailable := func(reason string) environmentAnswer {
		return environmentAnswer{Reason: reason}
	}
	raw, err := privsep.ReadFile(path, maxEnvironmentFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return unavailable("this sandbox publishes no environment data: its runner does not provide it, the sandbox started less than a minute ago, or this is not a 0G sandbox")
	case errors.Is(err, privsep.ErrTooLarge):
		return unavailable("the sandbox's environment data is larger than 256 KiB and was not read")
	case err != nil:
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return unavailable("the sandbox's environment data could not be read: " + err.Error())
	}
	env, err := decodeEnvironment(raw)
	if err != nil {
		return unavailable("the sandbox's environment data is not a valid JSON object")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return unavailable("the sandbox's environment data is not a valid JSON object")
	}
	out := environmentAnswer{Available: true, Environment: compact.Bytes()}
	if age, ok := environmentAge(env["updated_at"], now); ok {
		secs, stale := int64(age/time.Second), age > environmentStaleAfter
		out.AgeSeconds, out.Stale = &secs, &stale
	}
	if disk, ok := env["disk"].(map[string]any); ok {
		used, usedOK := environmentNumber(disk["used_bytes"])
		limit, limitOK := environmentNumber(disk["limit_bytes"])
		if usedOK && limitOK && limit > 0 {
			// A finite quotient only: +Inf would fail the JSON encoding
			// after the status line is out.
			if pct := math.Round(used/limit*1000) / 10; !math.IsInf(pct, 0) {
				out.DiskUsedPct = &pct
			}
		}
		if age, ok := environmentAge(disk["measured_at"], now); ok {
			secs := int64(age / time.Second)
			out.DiskAgeSeconds = &secs
		}
	}
	return out
}

// environmentAge is now - v for v an RFC 3339 time, 0 for a time ahead of
// now.
func environmentAge(v any, now time.Time) (time.Duration, bool) {
	at, ok := v.(string)
	if !ok {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return 0, false
	}
	return max(now.Sub(t), 0), true
}

// decodeEnvironment parses raw as exactly one JSON object, numbers kept as
// json.Number.
func decodeEnvironment(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var env map[string]any
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}
	if env == nil {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return env, nil
}

// environmentNumber is v as a finite, non-negative number.
func environmentNumber(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
		return 0, false
	}
	return f, true
}
