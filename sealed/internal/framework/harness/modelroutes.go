package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/inference"
	"seal-verify/internal/inferproxy"
	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// Model routes and web search: what the owner's others.subagentModels and
// others.webSearch offer, and how each reaches its key. One rule for both
// (keySource.reach):
//
//   - the main model's provider and no credential named: the model key, held
//     by the credential proxy for the main endpoint's host (the agent sees a
//     placeholder);
//   - an owner credential named: a request through the credential proxy with
//     that credential's placeholder, which the proxy fills only where the
//     owner allowed it (its hosts and positions), so the value never leaves
//     sealed and the owner's policy for it holds;
//   - neither: not offered, and the log says why (names only, no values).

// keySource is how a route or search can be paid: the main model's provider
// and key, and the credential proxy's explicit prefix.
type keySource struct {
	mainProvider string
	// key is the model key or, when held, its placeholder.
	key string
	// held: the credential proxy holds the key for the main endpoint's host,
	// so a request carrying it goes through the proxy's explicit form.
	held bool
	// proxy is the credential proxy's explicit prefix, "" when it is off.
	proxy string
	// mainHost is the host the held key is filled in on.
	mainHost string
}

// hostOf is the host of an https base URL, "" when it has none.
func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Host
}

// reach is base (an https URL) as a request should address it, and the
// value its credential header carries; why is set when it cannot be paid.
func (k keySource) reach(provider, credential, base string) (upstream, value, why string) {
	switch {
	case credential != "":
		if k.proxy == "" {
			return "", "", "the credential proxy is off, so no owner credential can be used"
		}
		u, err := credproxy.ExplicitURL(k.proxy, base)
		if err != nil {
			return "", "", err.Error()
		}
		return u, credproxy.Placeholder(credential), ""
	case provider == k.mainProvider:
		if !k.held {
			return base, k.key, ""
		}
		if hostOf(base) != k.mainHost {
			return "", "", fmt.Sprintf("the model key is filled in only on %s, so this endpoint needs a credential", k.mainHost)
		}
		u, err := credproxy.ExplicitURL(k.proxy, base)
		if err != nil {
			return "", "", err.Error()
		}
		return u, k.key, ""
	default:
		return "", "", fmt.Sprintf("the model key is for %s, so %s needs a credential (name it with \"credential\")", k.mainProvider, provider)
	}
}

// v1Path is path (starting /) under base: an OpenAI-wire base ends in /v1, an
// Anthropic-wire one does not.
func v1Path(base, path string) string {
	b := strings.TrimRight(base, "/")
	if strings.HasSuffix(b, "/v1") {
		return b + path
	}
	return b + "/v1" + path
}

// searchEndpoint is the service's search URL under base (inferproxy calls it).
func searchEndpoint(service, base string) string {
	switch service {
	case inference.SearchOpenAI:
		return v1Path(base, "/responses")
	case inference.SearchAnthropic:
		return v1Path(base, "/messages")
	}
	return inferproxy.WebSearchURL(base)
}

// searchHeaders carries value the way the service takes a key.
func searchHeaders(service, value string) map[string]string {
	if service == inference.SearchAnthropic {
		return map[string]string{"x-api-key": value}
	}
	return map[string]string{"Authorization": "Bearer " + value}
}

// planWebSearch is the main route's web search for the owner's knobs, or nil
// with the reason it is off. mainEp is the main model's endpoint, mainBase
// the main route's upstream (the endpoint reached as keys.reach would).
func planWebSearch(k harnessKnobs, keys keySource, mainEp *inference.Endpoint, mainBase, mainModel string) (*inferproxy.WebSearch, string) {
	ws := k.WebSearch
	if !k.WebTools {
		return nil, "the webTools setting is off"
	}
	if ws.Service == searchOff || ws.Service == "" {
		return nil, "the webSearch setting is off"
	}
	var url, value string
	if ws.Credential == "" && mainEp != nil && mainEp.WebSearch == ws.Service {
		url, value = searchEndpoint(ws.Service, mainBase), keys.key
	} else if ws.Credential == "" {
		return nil, fmt.Sprintf("the %s search needs the model on %s or a credential (webSearch.credential)", ws.Service, ws.Service)
	} else {
		base, val, why := keys.reach("", ws.Credential, inference.SearchBaseURL(ws.Service))
		if why != "" {
			return nil, why
		}
		url, value = searchEndpoint(ws.Service, base), val
	}
	model := ""
	if ws.Service == inference.SearchOpenAI || ws.Service == inference.SearchAnthropic {
		model = ws.Model
		if model == "" && mainEp != nil && mainEp.WebSearch == ws.Service {
			model = mainModel
		}
		if model == "" {
			return nil, fmt.Sprintf("the %s search needs a model (webSearch.model)", ws.Service)
		}
	}
	return &inferproxy.WebSearch{Service: ws.Service, URL: url, Headers: searchHeaders(ws.Service, value), Model: model}, ""
}

// offeredModel is one subagent model the harness registers: the pi-ai
// provider id it goes under (the main provider's id when it rides the main
// route), where that provider's requests go, and what is known of the model.
type offeredModel struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	BaseURL   string `json:"baseURL"`
	API       string `json:"api"`
	MaxTokens int    `json:"maxTokens,omitempty"`
	Effort    string `json:"effort,omitempty"`
	Images    *bool  `json:"images,omitempty"`
	// owner's provider id (before the route id), for subagentDefault.
	source string
}

// routePlan is what Start sets on the inference route for subagents: models
// the main route also takes, named routes, and what the harness registers.
type routePlan struct {
	mainModels []string
	named      map[string]inferproxy.Route
	offered    []offeredModel
	// defaultRoute is the subagent default as the harness names it, nil for
	// the main model.
	defaultRoute *routeRef
}

// resolveModel is the platform's view of one more model: its endpoint and
// facts, resolved as the main model's are, with the main model's reasoning
// preference.
var resolveModel = func(ctx context.Context, provider, model, thinking string) (settings.Resolved, *inference.Endpoint) {
	r := settings.Resolve(ctx, settings.Doc{Provider: provider, Model: model, Thinking: thinking}, "")
	ep := r.Endpoint
	if ep == nil {
		ep, _ = inference.NativeEndpoint(provider)
	}
	return r, ep
}

// planRoutes turns others.subagentModels into routes. mainRouteBase is the
// main route's address on the proxy, namedBase gives a named route's.
func planRoutes(ctx context.Context, k harnessKnobs, keys keySource, main settings.Resolved, mainEp *inference.Endpoint, doc, mainRouteBase string, namedBase func(id string) string) routePlan {
	plan := routePlan{named: map[string]inferproxy.Route{}}
	if !k.Subagents || len(k.SubagentModels) == 0 {
		if len(k.SubagentModels) > 0 {
			logger.Logf("harness: subagentModels: the subagents setting is off, so no model is offered")
		}
		return plan
	}
	ids := map[string]string{} // route id → the endpoint it was opened for
	for _, m := range k.SubagentModels {
		if m.Provider == main.Provider && m.Model == main.Model && m.Credential == "" {
			continue // the main model is always offered
		}
		res, ep := resolveModel(ctx, m.Provider, m.Model, main.Thinking)
		if ep == nil {
			logger.Logf("harness: subagentModels: %s/%s not offered: sealed knows no endpoint for provider %s", m.Provider, m.Model, m.Provider)
			continue
		}
		om := offeredModel{Model: m.Model, API: wireAPI(ep.Format), MaxTokens: res.RequestMaxTokens(), source: m.Provider}
		if level, decided := res.Effort(); decided && level != "" {
			om.Effort = level
		}
		if takes, known := res.Facts.TakesImages(); known {
			om.Images = &takes
		}
		if m.Credential == "" && mainEp != nil && m.Provider == main.Provider && ep.Format == mainEp.Format && ep.BaseURL == mainEp.BaseURL {
			// Same provider, endpoint and key: the main route takes it too.
			plan.mainModels = append(plan.mainModels, m.Model)
			om.Provider, om.BaseURL = main.Provider, mainRouteBase
			plan.offered = append(plan.offered, om)
			continue
		}
		upstream, value, why := keys.reach(m.Provider, m.Credential, ep.BaseURL)
		if why != "" {
			logger.Logf("harness: subagentModels: %s/%s not offered: %s", m.Provider, m.Model, why)
			continue
		}
		// The route's id is the provider id the harness registers it under:
		// never the main provider's own, and one per endpoint.
		id := m.Provider
		if m.Credential != "" {
			id += "+" + m.Credential
		}
		if id == main.Provider {
			id += "@" + string(ep.Format)
		}
		if at, used := ids[id]; used && at != string(ep.Format)+" "+ep.BaseURL && !strings.HasSuffix(id, "@"+string(ep.Format)) {
			id += "@" + string(ep.Format)
		}
		if at, used := ids[id]; used && at != string(ep.Format)+" "+ep.BaseURL {
			logger.Logf("harness: subagentModels: %s/%s not offered: another entry already uses route %s for a different endpoint", m.Provider, m.Model, id)
			continue
		}
		ids[id] = string(ep.Format) + " " + ep.BaseURL
		r, ok := plan.named[id]
		if !ok {
			r = inferproxy.Route{Upstream: upstream, Headers: inferenceHeaders(ep.Format, value), Model: m.Model, System: doc}
		} else {
			r.Models = append(r.Models, m.Model)
		}
		plan.named[id] = r
		om.Provider, om.BaseURL = id, namedBase(id)
		plan.offered = append(plan.offered, om)
	}
	if d := k.SubagentDefault; d != nil && !(d.Provider == main.Provider && d.Model == main.Model) {
		for _, om := range plan.offered {
			if om.source == d.Provider && om.Model == d.Model {
				plan.defaultRoute = &routeRef{Provider: om.Provider, Model: om.Model}
				break
			}
		}
		if plan.defaultRoute == nil {
			logger.Logf("harness: subagentDefault %s/%s is not offered; subagents default to the main model", d.Provider, d.Model)
		}
	}
	return plan
}

// routesEnv is the harness's view of the plan: SEAL_HARNESS_MODEL_ROUTES (the
// offered models, no keys) and SEAL_HARNESS_SUBAGENT_DEFAULT.
func (p routePlan) env() []string {
	if len(p.offered) == 0 {
		return nil
	}
	routes, _ := json.Marshal(p.offered)
	env := []string{"SEAL_HARNESS_MODEL_ROUTES=" + string(routes)}
	if p.defaultRoute != nil {
		d, _ := json.Marshal(p.defaultRoute)
		env = append(env, "SEAL_HARNESS_SUBAGENT_DEFAULT="+string(d))
	}
	return env
}
