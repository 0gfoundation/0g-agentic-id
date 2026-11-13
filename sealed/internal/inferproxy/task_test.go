package inferproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTaskInferencePinsKeyModelAndOutputAndChargesFailedAttempts(t *testing.T) {
	var requests []map[string]any
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer held-only-by-sealed" {
			t.Error("provider key not pinned")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid body")
		}
		requests = append(requests, body)
		w.WriteHeader(503)
	}))
	defer up.Close()
	h, err := NewTaskHandler(Route{Upstream: up.URL, Model: "pinned-model", Headers: map[string]string{"Authorization": "Bearer held-only-by-sealed"}}, TaskLimits{Calls: 2, InputBytes: 2048, OutputTokens: 128}, up.Client())
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range []string{`{"model":"arbitrary","n":99,"max_tokens":9999,"max_output_tokens":9999}`, `{"model":"other","max_completion_tokens":32}`} {
		r := httptest.NewRequest("POST", "/model/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer caller-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatalf("attempt%d: %d", i, w.Code)
		}
	}
	if requests[0]["model"] != "pinned-model" || requests[0]["n"] != float64(1) || requests[0]["max_tokens"] != float64(128) || requests[0]["max_output_tokens"] != nil || requests[1]["max_completion_tokens"] != float64(32) {
		t.Fatalf("request ceilings: %v", requests)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/model/chat/completions", strings.NewReader(`{}`)))
	if w.Code != 429 || len(requests) != 2 {
		t.Fatal("failed upstream requests escaped call budget")
	}
}

func TestTaskInferenceBudgetIsAtomicAndRoutesAreClosed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	h, err := NewTaskHandler(Route{Upstream: up.URL, Model: "model"}, TaskLimits{Calls: 1, InputBytes: 1024, OutputTokens: 32}, up.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/model/models", "/model/v1/threads/x/messages", "/model/chat/completions?destination=other", "/chat/completions"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 404 {
			t.Fatalf("route %s escaped: %d", path, w.Code)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/model/messages", strings.NewReader(`{}`)))
			if w.Code == 200 {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("concurrent admitted %d", admitted)
	}
}
