package credentials

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"seal-verify/internal/credproxy"
)

// A token endpoint answering a new error code on every call fills only the
// token requests' "refused" budget: other operations' records stay named.
func TestTokenErrorCodesStayInTheirBudget(t *testing.T) {
	var n atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_request_%d"}`, n.Add(1))
	}))
	defer ts.Close()
	f := newFixture(t)
	s, _, _ := f.store(t, nil, ts.Client())
	doc := f.doc(t, 1, map[string]string{"g": "secret", "github": "ghp_x"})
	tmpl := tokenTemplate(ts.URL+"/token", false, false)
	f.editDefs(t, &doc, func(d *Definition) {
		if d.Name == "g" {
			tmpl(d)
		}
	})
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCountKeys+10; i++ {
		_, _ = s.Token(context.Background(), "g", nil)
	}
	s.auditMu.Lock()
	tokKeys := 0
	for _, c := range s.auditCounts {
		if c.Op == "token" {
			tokKeys++
		}
	}
	s.auditMu.Unlock()
	if tokKeys > maxResultKeys+8 {
		t.Fatalf("token failures took %d counted kinds", tokKeys)
	}

	// Now: an owner entry used toward a host it does not allow, and a use of
	// sealed's own inference key: both first of their result.
	s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "elsewhere.example", Method: "GET", Code: "host_not_allowed"})
	s.Record(credproxy.Record{Time: time.Now(), Names: []string{"sealed:inference"}, Host: "router.example", Method: "POST"})
	// Proxy uses push the listed refusal out of its ring (folded into a count).
	for i := 0; i < auditKeep; i++ {
		s.Record(credproxy.Record{Time: time.Now(), Names: []string{"github"}, Host: "api.github.com", Method: "GET"})
	}
	var named, blurred []string
	for _, r := range s.AuditSince(0) {
		if r.Op != "inject" || r.Count == 0 {
			continue
		}
		if (r.Result == "host_not_allowed" && r.Host == "elsewhere.example") || (r.Result == "sent" && r.Host == "router.example") {
			named = append(named, fmt.Sprintf("%v %s %s", r.Names, r.Host, r.Result))
		}
		if r.Result == "more kinds" {
			blurred = append(blurred, fmt.Sprintf("%v %q count=%d", r.Names, r.Result, r.Count))
		}
	}
	if len(named) < 2 {
		t.Fatalf("after token-endpoint codes filled the backstop, the first host_not_allowed and the first sealed: use lost their entry, host and result: named=%v blurred=%v", named, blurred)
	}
}

// Spaces other than the plain one become plain spaces in a reason and are
// refused in a parameter.
func TestNonPlainSpaces(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	reason := "理由　テスト; accès : lecture !"
	p, e := s.Request("add", "notion", map[string]string{"preset": "notion"}, reason)
	if e != nil {
		t.Fatalf("reason with Zs refused: %+v", e)
	}
	if p.Reason != "理由 テスト; accès : lecture !" {
		t.Fatalf("reason stored as %q", p.Reason)
	}
	if _, e = s.Request("add", "notion2", map[string]string{"preset": "no\u00a0tion"}, ""); e == nil {
		t.Fatal("a parameter with a no-break space was taken")
	}
}
