package settings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"seal-verify/internal/inference"
)

// An empty blob is a fresh agent, not a corrupt one.
func TestParseEmptyBlobIsEmptyDoc(t *testing.T) {
	for _, blob := range [][]byte{nil, {}, []byte("  \n")} {
		d, err := Parse(blob)
		if err != nil {
			t.Fatalf("Parse(%q): %v", blob, err)
		}
		if d.Model != "" || d.Thinking != "" {
			t.Fatalf("Parse(%q) = %+v, want zero", blob, d)
		}
	}
}

// The framework section survives byte-for-byte: the platform must not
// reformat a document it does not understand.
func TestOthersSectionIsPassedThrough(t *testing.T) {
	in := []byte(`{"model":"glm-5.3","others":{"maxParallelToolCalls":3,"nested":{"a":[1,2]}}}`)
	d, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(d.Others, &got); err != nil {
		t.Fatalf("others section not preserved as JSON: %v", err)
	}
	if got["maxParallelToolCalls"] != float64(3) {
		t.Fatalf("others section lost content: %v", got)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		doc     Doc
		wantErr bool
	}{
		{"model required", Doc{Thinking: "low"}, true},
		{"level off the vocabulary", Doc{Model: "m", Thinking: "ultra"}, true},
		{"level is case-insensitive", Doc{Model: "m", Thinking: "HIGH"}, false},
		{"no level is fine", Doc{Model: "m"}, false},
		{"malformed framework section", Doc{Model: "m", Others: json.RawMessage(`{`)}, true},
		// A framework built-in is legitimately absent from the router
		// catalog; refusing it would lock owners onto 0g-compute.
		{"native provider model", Doc{Provider: "anthropic", Model: "claude-sonnet-5"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.doc.Validate(); (err != nil) != c.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

// catalogServer serves a one-model router catalog.
func catalogServer(t *testing.T, entry map[string]any) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{entry}})
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

// The whole point of the ModelFacts/Endpoint split: a native provider still
// gets the reasoning bound, it just supplies its own endpoint. Before the
// split both hung off one `provider == "0g-compute"` check, so choosing a
// native provider silently dropped the bound (hermes, dsh).
func TestNativeProviderStillGetsBoundedReasoning(t *testing.T) {
	catalogServer(t, map[string]any{
		"id":                    "glm-5.3",
		"supported_formats":     []string{"openai"},
		"max_completion_tokens": 32768,
		"supported_parameters":  []string{"reasoning_effort"},
	})

	routed := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"}, "")
	native := Resolve(context.Background(), Doc{Provider: "openai", Model: "glm-5.3", Thinking: "high"}, "")

	rl, rd := routed.Effort()
	nl, nd := native.Effort()
	if rl != "high" || !rd || nl != "high" || !nd {
		t.Fatalf("effort: routed=(%q,%v) native=(%q,%v) — both must be bounded", rl, rd, nl, nd)
	}
	if routed.Endpoint == nil {
		t.Fatal("platform-routed provider must get an endpoint")
	}
	if native.Endpoint != nil {
		t.Fatalf("native provider must supply its own endpoint, got %+v", native.Endpoint)
	}
}

// A thinking-capable model with no owner preference must still be bounded:
// absent the parameter it reasons forever and never replies.
func TestUnsetThinkingStillBounded(t *testing.T) {
	catalogServer(t, map[string]any{
		"id": "glm-5.3", "supported_formats": []string{"openai"},
		"max_completion_tokens": 32768, "supported_parameters": []string{"reasoning_effort"},
	})
	r := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "")
	lvl, decided := r.Effort()
	if lvl != "low" || !decided {
		t.Fatalf("Effort() = (%q,%v), want the low floor", lvl, decided)
	}
}

// Sending reasoning_effort to a model that rejects it is a hard 400, so a
// non-reasoning model must yield no level at all — not a default.
func TestNonReasoningModelGetsNoEffort(t *testing.T) {
	catalogServer(t, map[string]any{
		"id": "plain-1", "supported_formats": []string{"openai"},
		"max_completion_tokens": 4096, "supported_parameters": []string{},
	})
	r := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "plain-1", Thinking: "high"}, "")
	lvl, decided := r.Effort()
	if lvl != "" || !decided {
		t.Fatalf("Effort() = (%q,%v), want a decided clear for a model that takes no bound", lvl, decided)
	}
}

// During a catalog outage the heuristic's guess must never be persisted:
// written to disk it looks hand-set forever and starves the reply budget.
func TestHeuristicBudgetIsNotPersistable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	defer srv.Close()
	restore := inference.SetCatalogURLForTest(srv.URL)
	defer restore()

	r := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "")
	if r.Facts.MaxTokens == 0 {
		t.Fatal("heuristic should still supply a runtime budget")
	}
	if got := r.PersistableMaxTokens(); got != 0 {
		t.Fatalf("PersistableMaxTokens() = %d, want 0 — only catalog-sourced budgets may be written", got)
	}
}

// The regression an adversarial review caught in the first cut: collapsing
// "catalog unreachable" into "this model takes no bound" made an outage
// strip the bound from an always-thinking model, which then reasons forever
// and never replies. An outage must leave the existing level alone.
func TestCatalogOutageDoesNotDecide(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	defer srv.Close()
	defer inference.SetCatalogURLForTest(srv.URL)()

	silent := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "")
	if lvl, decided := silent.Effort(); decided {
		t.Fatalf("Effort() = (%q,true) during an outage — must not decide, or the bound gets stripped", lvl)
	}

	// A deliberate owner choice still wins over an outage: it lands in the
	// framework's own knob, which gates its own wire behaviour.
	chosen := Resolve(context.Background(), Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"}, "")
	if lvl, decided := chosen.Effort(); lvl != "high" || !decided {
		t.Fatalf("Effort() = (%q,%v), want the owner's level honoured despite the outage", lvl, decided)
	}
}
