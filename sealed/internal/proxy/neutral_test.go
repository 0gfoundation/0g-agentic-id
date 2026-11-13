package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"seal-verify/internal/framework"
)

// bearerAdapter keeps the framework's token in sealed: the owner holds
// "owner", the framework checks "framework" (framework.BearerTranslator).
type bearerAdapter struct{ framework.Framework }

func (bearerAdapter) TranslateBearer(token string) (string, bool) {
	if token == "owner" {
		return "framework", true
	}
	return "", false
}

// echoAuthBackend answers with the Authorization header it received.
func echoAuthBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A route that lists its endpoints forwards those only; with a bearer
// translator, only the owner's token goes in, and the framework's comes out.
func TestHandleProxy_ListedEndpointsAndOwnerToken(t *testing.T) {
	backend := echoAuthBackend(t)
	s, _ := armedProxy(t, backend.URL, "")
	s.fwRoutes = []framework.Route{{Prefix: "/v1/", Kind: "chat", Auth: "bearer", Endpoints: []framework.Endpoint{
		{Method: http.MethodPost, Path: "/v1/chat/completions"},
		{Method: http.MethodGet, Path: "/v1/tasks/{id}"},
	}}}
	s.adapter = bearerAdapter{}

	do := func(method, path, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		s.handleProxy(rec, req)
		return rec
	}

	if rec := do(http.MethodPost, "/v1/chat/completions", "Bearer owner"); rec.Code != http.StatusOK || rec.Body.String() != "POST /v1/chat/completions Bearer framework" {
		t.Fatalf("owner's request: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/v1/tasks/bash-1", "Bearer owner"); rec.Code != http.StatusOK {
		t.Fatalf("a listed {id} path: %d %q", rec.Code, rec.Body.String())
	}
	for _, auth := range []string{"", "Bearer framework", "Bearer other", "owner"} {
		if rec := do(http.MethodPost, "/v1/chat/completions", auth); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: %d, want 401", auth, rec.Code)
		}
	}
	if rec := do(http.MethodGet, "/v1/models", "Bearer owner"); rec.Code != http.StatusNotFound {
		t.Errorf("an unlisted path: %d, want 404", rec.Code)
	}
	if rec := do(http.MethodGet, "/v1/chat/completions", "Bearer owner"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("a listed path, unlisted method: %d, want 405", rec.Code)
	}
	if rec := do(http.MethodOptions, "/v1/chat/completions", ""); rec.Code != http.StatusOK {
		t.Errorf("a preflight on a listed path: %d, want it forwarded", rec.Code)
	}
}

// An adapter without a translator, on a route without endpoints, is
// forwarded as before: everything under the prefix, the header as sent.
func TestHandleProxy_RoutesWithoutTheNewDeclarationsUnchanged(t *testing.T) {
	backend := echoAuthBackend(t)
	s, _ := armedProxy(t, backend.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	rec := httptest.NewRecorder()
	s.handleProxy(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "GET /v1/models Bearer whatever" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}
