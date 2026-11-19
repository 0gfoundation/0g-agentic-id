package inferproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// TaskLimits bounds requests, input bytes and the requested output ceiling.
// It is not a monetary balance or a measure of the provider's actual billing.
type TaskLimits struct {
	Calls        int   `json:"calls"`
	InputBytes   int64 `json:"input_bytes"`
	OutputTokens int   `json:"output_tokens"`
}

func (l TaskLimits) Validate() error {
	if l.Calls < 1 || l.Calls > 64 || l.InputBytes < 1024 || l.InputBytes > 16<<20 || l.OutputTokens < 1 || l.OutputTokens > 8192 {
		return fmt.Errorf("inference budget out of range")
	}
	return nil
}

// NewTaskHandler pins a route for one worker. Failed upstream attempts consume
// budget too. The caller supplies a no-redirect, public-only client and binds
// this handler only to that worker's private Unix socket.
func NewTaskHandler(route Route, limits TaskLimits, client *http.Client) (http.Handler, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if route.Model == "" || route.Upstream == "" || client == nil {
		return nil, fmt.Errorf("task inference route required")
	}
	boundClient := *client
	boundClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &Server{token: "model", route: &route, client: &boundClient}
	var mu sync.Mutex
	calls, input := 0, int64(0)
	concurrent := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := lenPrefix(r.URL.Path, "/model")
		kind := endpoint(r.Method, r.URL.Path[prefix:])
		if prefix == 0 || r.URL.RawQuery != "" || (kind != "chat" && kind != "messages" && kind != "responses") {
			http.Error(w, "only budgeted model POSTs are allowed", http.StatusNotFound)
			return
		}
		select {
		case concurrent <- struct{}{}:
			defer func() { <-concurrent }()
		default:
			http.Error(w, "task inference concurrency exhausted", http.StatusTooManyRequests)
			return
		}
		mu.Lock()
		if calls >= limits.Calls {
			mu.Unlock()
			http.Error(w, "task inference budget exhausted", http.StatusTooManyRequests)
			return
		}
		calls++
		mu.Unlock()
		raw, err := io.ReadAll(io.LimitReader(r.Body, (512<<10)+1))
		if err != nil || len(raw) > 512<<10 {
			http.Error(w, "model input too large", http.StatusRequestEntityTooLarge)
			return
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(raw, &body) != nil || body == nil {
			http.Error(w, "invalid model input", http.StatusBadRequest)
			return
		}
		// Preserve a caller's lower ceiling; no alias or multiplicity may
		// defeat the pinned maximum.
		ceiling := limits.OutputTokens
		chatField := "max_tokens"
		if _, ok := body["max_completion_tokens"]; ok {
			chatField = "max_completion_tokens"
		}
		for _, field := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
			if raw, ok := body[field]; ok {
				var n int
				if json.Unmarshal(raw, &n) != nil || n < 1 {
					http.Error(w, "invalid output ceiling", http.StatusBadRequest)
					return
				}
				if n < ceiling {
					ceiling = n
				}
			}
		}
		for _, field := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens", "n", "best_of"} {
			delete(body, field)
		}
		switch kind {
		case "chat":
			body[chatField] = mustJSON(ceiling)
			body["n"] = mustJSON(1)
		case "messages":
			body["max_tokens"] = mustJSON(ceiling)
		case "responses":
			body["max_output_tokens"] = mustJSON(ceiling)
		}
		rewritten, _ := json.Marshal(body)
		mu.Lock()
		if input+int64(len(raw)) > limits.InputBytes {
			mu.Unlock()
			http.Error(w, "task inference budget exhausted", http.StatusTooManyRequests)
			return
		}
		input += int64(len(raw))
		mu.Unlock()
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(rewritten))
		r.ContentLength = int64(len(rewritten))
		// Bound even a malicious or broken provider's response stream.
		s.ServeHTTP(&taskResponse{ResponseWriter: w, remaining: 8 << 20}, r)
	}), nil
}

func lenPrefix(path, prefix string) int {
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix && (len(path) == len(prefix) || path[len(prefix)] == '/') {
		return len(prefix)
	}
	return 0
}

type taskResponse struct {
	http.ResponseWriter
	remaining int
}

func (w *taskResponse) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, io.ErrShortWrite
	}
	w.remaining -= len(p)
	return w.ResponseWriter.Write(p)
}
func (w *taskResponse) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
