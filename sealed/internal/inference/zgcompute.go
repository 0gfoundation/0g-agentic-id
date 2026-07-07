// Package inference holds framework-agnostic knowledge about inference
// providers — today that means 0g-compute's router: its endpoints, which
// wire format each model speaks, and which env var carries the key.
//
// This knowledge used to live inside individual framework adapters and
// drifted between them (the openclaw adapter kept routing every 0g model
// through the OpenAI endpoint after the router started serving Claude
// models on the Anthropic-format endpoint only — deploys went green and
// first inference 400'd). The split is the same one internal/platform
// makes for context injection:
//
//   - WHAT the provider offers (endpoints, formats, model metadata) is
//     platform knowledge → this package, once.
//   - HOW a framework is configured to speak to an endpoint (openclaw's
//     models.providers dialect, claude code's env block) is the
//     adapter's job — that part is irreducibly per-framework.
package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"seal-verify/internal/logger"
)

// WireFormat is the API protocol a model endpoint speaks.
type WireFormat string

const (
	WireOpenAI    WireFormat = "openai"
	WireAnthropic WireFormat = "anthropic"
)

// 0g-compute router endpoints, one per wire format. Anthropic clients
// append /v1/messages themselves, so that base carries no /v1.
const (
	ZGOpenAIBaseURL    = "https://router-api.0g.ai/v1"
	ZGAnthropicBaseURL = "https://router-api.0g.ai"
)

// zgModelsURL is the router's PUBLIC model catalog (no auth). Var so
// tests can point it at a httptest server.
var zgModelsURL = "https://router-api.0g.ai/v1/models"

// Route is a resolved routing decision for one model on 0g-compute.
type Route struct {
	Format  WireFormat
	BaseURL string
	// EnvKey is the environment variable the framework's client reads
	// for this wire format (ANTHROPIC_API_KEY / OPENAI_API_KEY). The 0g
	// key itself is format-agnostic; only the variable name differs.
	EnvKey        string
	ContextWindow int
	MaxTokens     int
}

// ResolveZG returns the routing decision for a model on 0g-compute.
//
// It consults the router's live catalog (supported_formats +
// context/output limits per model), so newly listed models route
// correctly with zero sealed changes. Preference order when a model
// speaks both formats: OpenAI — it's the broadly compatible path and
// the one adapters have the most compat coverage for. Catalog
// unreachable or model unlisted → name heuristic (claude* is
// Anthropic-native) with conservative limits, and the router's own 400
// remains the final arbiter.
func ResolveZG(ctx context.Context, model string) Route {
	if entry, ok := fetchZGCatalogEntry(ctx, model); ok {
		r := routeForFormats(entry.SupportedFormats, model)
		if entry.ContextLength > 0 {
			r.ContextWindow = entry.ContextLength
		}
		if entry.MaxCompletionTokens > 0 {
			r.MaxTokens = entry.MaxCompletionTokens
		}
		return r
	}
	// Fallback heuristic — keep boot working through a catalog outage.
	if strings.HasPrefix(strings.ToLower(model), "claude") {
		logger.Logf("inference: 0g catalog unavailable for %q; falling back to anthropic-format heuristic", model)
		return anthropicRoute(200000, 64000)
	}
	logger.Logf("inference: 0g catalog unavailable for %q; falling back to openai-format heuristic", model)
	return openAIRoute(128000, 8192)
}

func routeForFormats(formats []string, model string) Route {
	hasOpenAI, hasAnthropic := false, false
	for _, f := range formats {
		switch WireFormat(f) {
		case WireOpenAI:
			hasOpenAI = true
		case WireAnthropic:
			hasAnthropic = true
		}
	}
	switch {
	case hasOpenAI:
		return openAIRoute(128000, 8192)
	case hasAnthropic:
		return anthropicRoute(200000, 64000)
	default:
		// Catalog lists the model but with no format we speak; heuristic
		// + router 400 will surface the real story.
		logger.Logf("inference: 0g model %q lists no known wire format %v; defaulting to openai", model, formats)
		return openAIRoute(128000, 8192)
	}
}

func openAIRoute(cw, mt int) Route {
	return Route{Format: WireOpenAI, BaseURL: ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY", ContextWindow: cw, MaxTokens: mt}
}

func anthropicRoute(cw, mt int) Route {
	return Route{Format: WireAnthropic, BaseURL: ZGAnthropicBaseURL, EnvKey: "ANTHROPIC_API_KEY", ContextWindow: cw, MaxTokens: mt}
}

type zgCatalogEntry struct {
	ID                  string   `json:"id"`
	SupportedFormats    []string `json:"supported_formats"`
	ContextLength       int      `json:"context_length"`
	MaxCompletionTokens int      `json:"max_completion_tokens"`
}

func fetchZGCatalogEntry(ctx context.Context, model string) (zgCatalogEntry, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, zgModelsURL, nil)
	if err != nil {
		return zgCatalogEntry{}, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return zgCatalogEntry{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zgCatalogEntry{}, false
	}
	var payload struct {
		Data []zgCatalogEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return zgCatalogEntry{}, false
	}
	for _, e := range payload.Data {
		if e.ID == model {
			return e, true
		}
	}
	return zgCatalogEntry{}, false
}
