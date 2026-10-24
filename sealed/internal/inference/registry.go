package inference

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

//go:embed providers.json
var providerDefinitions []byte

// Provider is trusted image configuration, never part of the owner's settings.
// A provider may use a public catalog in the existing 0G/OpenAI data shape, or
// list models statically. Native providers leave endpoint wiring to the framework.
type Provider struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Native        bool                  `json:"native,omitempty"`
	Formats       []WireFormat          `json:"formats"`
	DefaultFormat WireFormat            `json:"defaultFormat,omitempty"`
	Endpoints     map[WireFormat]string `json:"endpoints,omitempty"`
	ModelCatalog  string                `json:"modelCatalog,omitempty"`
	Models        []zgCatalogEntry      `json:"models,omitempty"`
	Compatibility map[string]any        `json:"compatibility,omitempty"`
}

type Registry struct {
	providers map[string]Provider
	client    *http.Client
}

// Legacy plaintext/v1 keys are compute-only; v2 ciphertext binds a provider.
type Credential struct {
	Provider  string
	APIKey    string
	RouteHash string
	Registry  *RegistryPin
	Bound     bool
	Invalid   bool
}

// RegistryPin survives stop/start inside the owner's encrypted credential.
// Version zero is the image's built-in registry and has no acceptance digest.
type RegistryPin struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

var providerID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func NewRegistry(definitions []byte) (*Registry, error) {
	var entries []Provider
	if err := json.Unmarshal(definitions, &entries); err != nil {
		return nil, fmt.Errorf("provider registry: %w", err)
	}
	r := &Registry{providers: make(map[string]Provider), client: http.DefaultClient}
	for _, p := range entries {
		if !providerID.MatchString(p.ID) || len(p.ID) > 64 || len(p.Formats) == 0 {
			return nil, fmt.Errorf("provider registry: invalid provider %q", p.ID)
		}
		if _, exists := r.providers[p.ID]; exists {
			return nil, fmt.Errorf("provider registry: duplicate provider %q", p.ID)
		}
		if p.Native && (len(p.Endpoints) != 0 || p.ModelCatalog != "" || p.DefaultFormat != "" || (p.ID != "openai" && p.ID != "anthropic") || len(p.Formats) != 1 || string(p.Formats[0]) != p.ID) {
			return nil, fmt.Errorf("provider registry: native provider %q must use framework wiring", p.ID)
		}
		for _, format := range p.Formats {
			if format != WireOpenAI && format != WireAnthropic {
				return nil, fmt.Errorf("provider registry: unsupported format %q", format)
			}
			if !p.Native && !trustedHTTPS(p.Endpoints[format]) {
				return nil, fmt.Errorf("provider registry: %q requires an HTTPS endpoint for %s", p.ID, format)
			}
		}
		if !p.Native && !containsFormat(p.Formats, p.DefaultFormat) {
			return nil, fmt.Errorf("provider registry: %q has no valid default format", p.ID)
		}
		if p.ModelCatalog != "" && !trustedHTTPS(p.ModelCatalog) {
			return nil, fmt.Errorf("provider registry: %q requires an HTTPS catalog", p.ID)
		}
		r.providers[p.ID] = p
	}
	return r, nil
}

func trustedHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func containsFormat(formats []WireFormat, want WireFormat) bool {
	for _, f := range formats {
		if f == want {
			return true
		}
	}
	return false
}

var DefaultRegistry = func() *Registry {
	r, err := NewRegistry(providerDefinitions)
	if err != nil {
		panic(err)
	}
	return r
}()

// Resolve never substitutes another provider's route or credential on failure.
func (r *Registry) Resolve(ctx context.Context, provider, model string) (ModelFacts, *Endpoint, error) {
	p, ok := r.providers[provider]
	if !ok {
		return ModelFacts{}, nil, fmt.Errorf("UNSUPPORTED_INFERENCE_PROVIDER: %q", provider)
	}
	if p.Native {
		// Preserve existing native-provider reasoning metadata until its framework
		// supplies a catalog of its own; endpoint wiring remains entirely native.
		return ResolveZG(ctx, model).ModelFacts, nil, nil
	}
	var facts ModelFacts
	format := p.DefaultFormat
	if p.ID == ZGComputeProvider && (r == DefaultRegistry || p.ModelCatalog == DefaultRegistry.providers[ZGComputeProvider].ModelCatalog) {
		route := ResolveZG(ctx, model)
		facts, format = route.ModelFacts, route.Format
	} else if entry, found := r.catalogEntry(ctx, p, model); found {
		for _, candidate := range []WireFormat{WireOpenAI, WireAnthropic} {
			for _, f := range entry.SupportedFormats {
				if WireFormat(f) == candidate && containsFormat(p.Formats, candidate) {
					format = candidate
					goto selected
				}
			}
		}
	selected:
		// An OpenAI /models response may contain IDs only. Absence of capability
		// metadata means unknown, not an instruction to clear a reasoning bound.
		facts = ModelFacts{ContextWindow: entry.ContextLength, MaxTokens: entry.MaxCompletionTokens, CatalogSourced: entry.SupportedParameters != nil}
		for _, parameter := range entry.SupportedParameters {
			if parameter == "reasoning_effort" {
				facts.SupportsReasoningEffort = true
			}
		}
	}
	base := p.Endpoints[format]
	if base == "" {
		return ModelFacts{}, nil, fmt.Errorf("PROVIDER_PROTOCOL_UNSUPPORTED: %s/%s", provider, format)
	}
	envKey := "OPENAI_API_KEY"
	if format == WireAnthropic {
		envKey = "ANTHROPIC_API_KEY"
	}
	return facts, &Endpoint{ProviderID: provider, Format: format, BaseURL: base, EnvKey: envKey, Compatibility: cloneCompatibility(p.Compatibility)}, nil
}

func (r *Registry) catalogEntry(ctx context.Context, p Provider, model string) (zgCatalogEntry, bool) {
	entries := p.Models
	if p.ModelCatalog != "" {
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ModelCatalog, nil)
		if err != nil {
			return zgCatalogEntry{}, false
		}
		resp, err := r.client.Do(req)
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
		if json.NewDecoder(resp.Body).Decode(&payload) != nil {
			return zgCatalogEntry{}, false
		}
		entries = payload.Data
	}
	for _, entry := range entries {
		if entry.ID == model {
			return entry, true
		}
	}
	return zgCatalogEntry{}, false
}

func cloneCompatibility(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func EndpointCompatibility(ep *Endpoint, provider string) map[string]any {
	if ep != nil && ep.Compatibility != nil {
		return cloneCompatibility(ep.Compatibility)
	}
	if provider == ZGComputeProvider {
		return cloneCompatibility(DefaultRegistry.providers[provider].Compatibility)
	}
	return make(map[string]any)
}

func IsManagedURL(raw string) bool {
	for _, p := range DefaultRegistry.providers {
		for _, endpoint := range p.Endpoints {
			if strings.TrimRight(raw, "/") == strings.TrimRight(endpoint, "/") {
				return true
			}
		}
	}
	return false
}
