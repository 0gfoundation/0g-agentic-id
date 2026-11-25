package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A file as the 0G sandbox runner writes it, with a field and a notice
// field this runtime does not know.
const testEnvironment = `{
  "version": 1,
  "sandbox_id": "sb-1",
  "updated_at": "2026-11-24T08:00:00Z",
  "cpu":    { "limit_cores": 1, "used_seconds_total": 12.5, "throttled_seconds_total": 3 },
  "memory": { "limit_bytes": 1073741824, "used_bytes": 209715200, "oom_kills_total": 0 },
  "tasks":  { "current": 37, "limit": 4096 },
  "disk":   { "limit_bytes": 3221225472, "used_bytes": 2411724977, "measured_at": "2026-11-24T07:58:59Z" },
  "notices": [
    { "kind": "disk_over_size", "severity": "critical", "message": "Free disk space.", "deadline": "2026-11-24T15:30:00Z", "action": "stop", "ticket": "T-7" }
  ],
  "gpu": { "count": 0 }
}`

var testEnvironmentTime = time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)

// writeEnvironment writes content as the environment file in a fresh
// directory and returns its path.
func writeEnvironment(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "environment.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// environmentJSON is the answer as the socket sends it, decoded.
func environmentJSON(t *testing.T, a environmentAnswer) map[string]any {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A file that is missing, not JSON, not one object, over 256 KiB or a
// symlink is reported unavailable, with a reason that names no path.
func TestEnvironment_Unavailable(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(writeEnvironment(t, testEnvironment), link); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		want string
	}{
		"missing":            {filepath.Join(dir, "environment.json"), "publishes no environment data"},
		"missing directory":  {filepath.Join(dir, "0g", "environment.json"), "publishes no environment data"},
		"invalid JSON":       {writeEnvironment(t, `{"version": 1,`), "not a valid JSON object"},
		"an array":           {writeEnvironment(t, `[{"version": 1}]`), "not a valid JSON object"},
		"null":               {writeEnvironment(t, `null`), "not a valid JSON object"},
		"two objects":        {writeEnvironment(t, `{"version": 1} {"version": 2}`), "not a valid JSON object"},
		"over 256 KiB":       {writeEnvironment(t, `{"pad":"`+strings.Repeat("x", 256<<10)+`"}`), "larger than 256 KiB"},
		"a symlink":          {link, "could not be read"},
		"a directory":        {dir, "could not be read"},
		"empty":              {writeEnvironment(t, ``), "not a valid JSON object"},
		"whitespace only":    {writeEnvironment(t, " \n"), "not a valid JSON object"},
		"a string, not JSON": {writeEnvironment(t, `"text"`), "not a valid JSON object"},
	} {
		out := environmentJSON(t, readEnvironment(tc.path, testEnvironmentTime))
		reason, _ := out["reason"].(string)
		if out["available"] != false || !strings.Contains(reason, tc.want) {
			t.Errorf("%s: %v", name, out)
		}
		if strings.Contains(reason, dir) || strings.Contains(reason, "/") {
			t.Errorf("%s: the reason names a path: %q", name, reason)
		}
		if len(out) != 2 {
			t.Errorf("%s: an unavailable answer carries only available and reason: %v", name, out)
		}
	}
}

// A valid file is passed on whole, unknown fields and notices included,
// with its age, whether it is stale and the disk use in percent.
func TestEnvironment_Valid(t *testing.T) {
	path := writeEnvironment(t, testEnvironment)
	out := environmentJSON(t, readEnvironment(path, testEnvironmentTime.Add(42*time.Second+900*time.Millisecond)))
	if out["available"] != true || out["reason"] != nil {
		t.Fatalf("answer: %v", out)
	}
	if out["age_seconds"] != 42.0 || out["stale"] != false {
		t.Errorf("age %v, stale %v; want 42, false", out["age_seconds"], out["stale"])
	}
	// 2411724977 / 3221225472 = 74.87 %.
	if out["disk_used_pct"] != 74.9 {
		t.Errorf("disk_used_pct %v, want 74.9", out["disk_used_pct"])
	}
	// Disk measured at 07:58:59, read at 08:00:42.9.
	if out["disk_age_seconds"] != 103.0 {
		t.Errorf("disk_age_seconds %v, want 103", out["disk_age_seconds"])
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(testEnvironment), &want); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(out["environment"])
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Errorf("environment changed on the way:\n got %s\nwant %s", got, wantJSON)
	}
	env := out["environment"].(map[string]any)
	notice := env["notices"].([]any)[0].(map[string]any)
	if notice["deadline"] != "2026-11-24T15:30:00Z" || notice["action"] != "stop" || notice["ticket"] != "T-7" {
		t.Errorf("notice: %v", notice)
	}
	if env["gpu"] == nil {
		t.Error("an unknown top-level field was dropped")
	}

	// The numbers go out as the runner wrote them.
	raw, _ := json.Marshal(readEnvironment(path, testEnvironmentTime))
	for _, lit := range []string{`"used_seconds_total":12.5`, `"limit_bytes":3221225472`, `"used_bytes":2411724977`} {
		if !strings.Contains(string(raw), lit) {
			t.Errorf("answer lacks %s: %s", lit, raw)
		}
	}
}

// Past two minutes the figures are stale; a time ahead of sealed's clock
// is age 0.
func TestEnvironment_Stale(t *testing.T) {
	path := writeEnvironment(t, testEnvironment)
	for name, tc := range map[string]struct {
		now   time.Time
		age   float64
		stale bool
	}{
		"two minutes":         {testEnvironmentTime.Add(120 * time.Second), 120, false},
		"just past":           {testEnvironmentTime.Add(121 * time.Second), 121, true},
		"an hour":             {testEnvironmentTime.Add(time.Hour), 3600, true},
		"ahead of the clock":  {testEnvironmentTime.Add(-5 * time.Second), 0, false},
		"exactly at the time": {testEnvironmentTime, 0, false},
	} {
		out := environmentJSON(t, readEnvironment(path, tc.now))
		if out["age_seconds"] != tc.age || out["stale"] != tc.stale {
			t.Errorf("%s: age %v, stale %v; want %v, %v", name, out["age_seconds"], out["stale"], tc.age, tc.stale)
		}
	}
}

// A figure a computed field needs that is missing or malformed leaves that
// field out; the file is still available.
func TestEnvironment_PartialFile(t *testing.T) {
	for name, tc := range map[string]struct {
		file    string
		age     bool
		diskPct bool
		diskAge bool
	}{
		"version only":           {`{"version": 1}`, false, false, false},
		"disk not measured yet":  {`{"updated_at": "2026-11-24T08:00:00Z", "disk": {"limit_bytes": 3221225472}}`, true, false, false},
		"no disk limit":          {`{"updated_at": "2026-11-24T08:00:00Z", "disk": {"used_bytes": 1}}`, true, false, false},
		"zero disk limit":        {`{"disk": {"limit_bytes": 0, "used_bytes": 1}}`, false, false, false},
		"disk figures as text":   {`{"disk": {"limit_bytes": "10", "used_bytes": "1"}}`, false, false, false},
		"disk not an object":     {`{"disk": 5}`, false, false, false},
		"updated_at not a time":  {`{"updated_at": "yesterday", "disk": {"limit_bytes": 4, "used_bytes": 1}}`, false, true, false},
		"updated_at as a number": {`{"updated_at": 1764000000}`, false, false, false},
		"notices absent":         {`{"updated_at": "2026-11-24T08:00:00Z"}`, true, false, false},
		"an infinite quotient":   {`{"disk": {"limit_bytes": 1, "used_bytes": 1.7e308}}`, false, false, false},
		"a subnormal limit":      {`{"disk": {"limit_bytes": 1e-320, "used_bytes": 1}}`, false, false, false},
		"disk measured":          {`{"disk": {"measured_at": "2026-11-24T07:59:00Z"}}`, false, false, true},
		"measured_at not a time": {`{"disk": {"measured_at": "soon"}}`, false, false, false},
	} {
		out := environmentJSON(t, readEnvironment(writeEnvironment(t, tc.file), testEnvironmentTime))
		if out["available"] != true || out["environment"] == nil {
			t.Errorf("%s: %v", name, out)
			continue
		}
		_, hasAge := out["age_seconds"]
		_, hasStale := out["stale"]
		_, hasPct := out["disk_used_pct"]
		_, hasDiskAge := out["disk_age_seconds"]
		if hasAge != tc.age || hasStale != tc.age || hasPct != tc.diskPct || hasDiskAge != tc.diskAge {
			t.Errorf("%s: age %v stale %v disk %v disk age %v; want age/stale %v, disk %v, disk age %v", name, hasAge, hasStale, hasPct, hasDiskAge, tc.age, tc.diskPct, tc.diskAge)
		}
		// Every answer encodes: the socket writes its status line first.
		if _, err := json.Marshal(readEnvironment(writeEnvironment(t, tc.file), testEnvironmentTime)); err != nil {
			t.Errorf("%s: the answer does not encode: %v", name, err)
		}
	}
	// Over the disk size: above 100 %.
	out := environmentJSON(t, readEnvironment(writeEnvironment(t, `{"disk": {"limit_bytes": 1000, "used_bytes": 1234}}`), testEnvironmentTime))
	if out["disk_used_pct"] != 123.4 {
		t.Errorf("over the disk size: %v", out["disk_used_pct"])
	}
}

// GET /environment is a route of the sign socket and the tool
// seal_environment; it takes GET only.
func TestEnvironment_RouteAndTool(t *testing.T) {
	saved := environmentFile
	t.Cleanup(func() { environmentFile = saved })
	environmentFile = writeEnvironment(t, testEnvironment)

	s, _ := rulesServer(t)
	mux, _ := s.signSocketMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/environment", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET /environment: %d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["available"] != true || out["disk_used_pct"] != 74.9 {
		t.Fatalf("GET /environment: %v %s", err, rec.Body)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/environment", strings.NewReader(`{}`)))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST /environment: %d %q", rec.Code, rec.Header().Get("Allow"))
	}

	text, isErr := signTool(t, s, "seal_environment", `{}`)
	if isErr || !strings.Contains(text, `"available":true`) || !strings.Contains(text, `"disk_over_size"`) {
		t.Fatalf("seal_environment: %v %s", isErr, text)
	}

	// Without the file the tool still answers, as unavailable.
	environmentFile = filepath.Join(t.TempDir(), "environment.json")
	text, isErr = signTool(t, s, "seal_environment", `{}`)
	if isErr || !strings.Contains(text, `"available":false`) {
		t.Fatalf("seal_environment without the file: %v %s", isErr, text)
	}
}
