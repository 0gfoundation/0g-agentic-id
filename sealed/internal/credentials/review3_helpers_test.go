package credentials

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func httptestTLS(t *testing.T, hook func(n int), mu *sync.Mutex, hits *int) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits++
		n := *hits
		mu.Unlock()
		hook(n)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "expires_in": 3600})
	}))
	t.Cleanup(ts.Close)
	return ts
}
