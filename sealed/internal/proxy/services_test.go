package proxy

import "testing"

func svc(path, method, backend string) ServiceEntry {
	return ServiceEntry{Path: path, Method: method, Backend: backend}
}

func TestValidateServices_valid(t *testing.T) {
	out, err := validateServices([]ServiceEntry{
		{Path: "/api/fortune", Method: "post", Backend: "http://127.0.0.1:9090", InputExample: `{"sign":"leo"}`},
		{Path: "/api/summary", Method: "GET", Backend: "http://localhost:8181"},
	})
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 entries, got %d", len(out))
	}
	if out[0].Method != "POST" {
		t.Errorf("method not upper-cased: %q", out[0].Method)
	}
}

func TestValidateServices_rejects(t *testing.T) {
	cases := []struct {
		name  string
		entry ServiceEntry
	}{
		{"path not under /api/", svc("/fortune", "POST", "http://127.0.0.1:9090")},
		{"bare /api/", svc("/api/", "POST", "http://127.0.0.1:9090")},
		{"reserved /hello", svc("/hello", "GET", "http://127.0.0.1:9090")},
		{"reserved via prefix", svc("/_seal/x", "GET", "http://127.0.0.1:9090")},
		{"bad method", svc("/api/x", "FETCH", "http://127.0.0.1:9090")},
		{"off-box backend", svc("/api/x", "POST", "http://evil.example.com:80")},
		{"non-http backend", svc("/api/x", "POST", "https://127.0.0.1:9090")},
		{"backend no port", svc("/api/x", "POST", "http://127.0.0.1")},
		{"empty backend", svc("/api/x", "POST", "")},
	}
	for _, c := range cases {
		if _, err := validateServices([]ServiceEntry{c.entry}); err == nil {
			t.Errorf("%s: expected rejection, got nil", c.name)
		}
	}
}

func TestValidateServices_rejectsBadInputExample(t *testing.T) {
	e := svc("/api/x", "POST", "http://127.0.0.1:9090")
	e.InputExample = "{not json"
	if _, err := validateServices([]ServiceEntry{e}); err == nil {
		t.Error("expected rejection for invalid input_example JSON")
	}
}

func TestValidateServices_rejectsDuplicatePath(t *testing.T) {
	_, err := validateServices([]ServiceEntry{
		svc("/api/x", "POST", "http://127.0.0.1:9090"),
		svc("/api/x", "GET", "http://127.0.0.1:9091"),
	})
	if err == nil {
		t.Error("expected rejection for duplicate path")
	}
}

// All-or-nothing: one bad entry rejects the whole batch (no partial landing).
func TestValidateServices_allOrNothing(t *testing.T) {
	_, err := validateServices([]ServiceEntry{
		svc("/api/good", "POST", "http://127.0.0.1:9090"),
		svc("/nope", "POST", "http://127.0.0.1:9091"),
	})
	if err == nil {
		t.Error("expected the whole batch rejected when one entry is invalid")
	}
}

func TestMatchService(t *testing.T) {
	s := &Server{services: []ServiceEntry{
		{Path: "/api/fortune", Method: "POST", Backend: "http://127.0.0.1:9090"},
	}}
	if e, ok := s.matchService("/api/fortune"); !ok || e.Backend != "http://127.0.0.1:9090" {
		t.Errorf("expected match, got ok=%v entry=%+v", ok, e)
	}
	if _, ok := s.matchService("/api/unknown"); ok {
		t.Error("unregistered path should not match")
	}
	if _, ok := s.matchService("/hello"); ok {
		t.Error("reserved path should not match an agent service")
	}
}
