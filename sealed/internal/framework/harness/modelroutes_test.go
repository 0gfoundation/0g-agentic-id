package harness

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// The owner's webSearch, subagentModels and subagentDefault knobs: valid
// values apply, anything else costs that knob only and keeps the default.
func TestParseRouteKnobs(t *testing.T) {
	for _, c := range []struct {
		others  string
		service string
		cred    string
		model   string
	}{
		{`{}`, "0g-router", "", ""},
		{`{"webSearch":{"service":"off"}}`, "off", "", ""},
		{`{"webSearch":{"service":"openai","credential":"my-openai","model":"gpt-x"}}`, "openai", "my-openai", "gpt-x"},
		{`{"webSearch":{"service":"anthropic"}}`, "anthropic", "", ""},
		{`{"webSearch":{"service":"bing"}}`, "0g-router", "", ""},
		{`{"webSearch":{"service":"openai","credential":"Bad Name"}}`, "0g-router", "", ""},
		{`{"webSearch":{"service":"0g-router","model":"x"}}`, "0g-router", "", ""},
		{`{"webSearch":{"service":"openai","extra":1}}`, "0g-router", "", ""},
		{`{"webSearch":"openai"}`, "0g-router", "", ""},
	} {
		ws := parseKnobs(json.RawMessage(c.others)).WebSearch
		if ws.Service != c.service || ws.Credential != c.cred || ws.Model != c.model {
			t.Errorf("%s → %+v", c.others, ws)
		}
	}

	nine := `[` + strings.Repeat(`{"provider":"openai","model":"m"},`, 8) + `{"provider":"openai","model":"z"}]`
	for _, c := range []struct {
		others string
		n      int
	}{
		{`{"subagentModels":[{"provider":"0g-compute","model":"deepseek-v3"},{"provider":"openai","model":"gpt-x","credential":"k"}]}`, 2},
		{`{"subagentModels":` + nine + `}`, 0},
		{`{"subagentModels":[{"provider":"Open AI","model":"m"}]}`, 0},
		{`{"subagentModels":[{"provider":"openai","model":"m"},{"provider":"openai","model":"m"}]}`, 0},
		{`{"subagentModels":[{"provider":"openai","model":"m","key":"sk"}]}`, 0},
		{`{"subagentModels":{"provider":"openai"}}`, 0},
	} {
		if got := len(parseKnobs(json.RawMessage(c.others)).SubagentModels); got != c.n {
			t.Errorf("%s → %d models, want %d", c.others, got, c.n)
		}
	}
	if d := parseKnobs(json.RawMessage(`{"subagentDefault":{"provider":"openai","model":"gpt-x"}}`)).SubagentDefault; d == nil || d.Provider != "openai" || d.Model != "gpt-x" {
		t.Errorf("subagentDefault %+v", d)
	}
	if d := parseKnobs(json.RawMessage(`{"subagentDefault":{"provider":"openai"}}`)).SubagentDefault; d != nil {
		t.Errorf("a default with no model was kept: %+v", d)
	}
}

// RenderSettings keeps a subagentDefault only when it is the main model or
// one of subagentModels.
func TestRenderSettings_SubagentDefaultMustBeOffered(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	for _, c := range []struct {
		others string
		kept   bool
	}{
		{`{"subagentModels":[{"provider":"0g-compute","model":"deepseek-v3"}],"subagentDefault":{"provider":"0g-compute","model":"deepseek-v3"}}`, true},
		{`{"subagentDefault":{"provider":"0g-compute","model":"glm-5.3"}}`, true},
		{`{"subagentDefault":{"provider":"openai","model":"gpt-x"}}`, false},
	} {
		a := New()
		render(t, a, settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: json.RawMessage(c.others)})
		if got := a.rendered.knobs.SubagentDefault != nil; got != c.kept {
			t.Errorf("%s: kept %v, want %v", c.others, got, c.kept)
		}
	}
}

func knobs(t *testing.T, others string) harnessKnobs {
	t.Helper()
	return parseKnobs(json.RawMessage(others))
}

// The key-resolution matrix for web search: the model key when the model's
// provider pays the chosen service, an owner credential through the
// credential proxy, otherwise none.
func TestPlanWebSearch(t *testing.T) {
	routerEp := &inference.Endpoint{ProviderID: inference.ZGComputeProvider, Format: inference.WireOpenAI, BaseURL: "https://router-api.0g.ai/v1", WebSearch: inference.SearchZGRouter}
	openaiEp, _ := inference.NativeEndpoint("openai")
	held := keySource{mainProvider: inference.ZGComputeProvider, key: "[[credential:sealed:inference]]", held: true, proxy: "http://127.0.0.1:9/tok", mainHost: "router-api.0g.ai"}
	unheld := keySource{mainProvider: "openai", key: "sk-raw"}
	routerBase := "http://127.0.0.1:9/tok/https/router-api.0g.ai/v1"

	ws, why := planWebSearch(knobs(t, `{}`), held, routerEp, routerBase, "glm-5.3")
	if ws == nil || ws.Service != "0g-router" || ws.URL != routerBase+"/web/search" || ws.Headers["Authorization"] != "Bearer [[credential:sealed:inference]]" || ws.Model != "" {
		t.Fatalf("router default: %+v %s", ws, why)
	}
	for others, wantWhy := range map[string]string{
		`{"webTools":false}`:                 "webTools",
		`{"webSearch":{"service":"off"}}`:    "webSearch",
		`{"webSearch":{"service":"openai"}}`: "credential",
	} {
		if ws, why := planWebSearch(knobs(t, others), held, routerEp, routerBase, "glm-5.3"); ws != nil || !strings.Contains(why, wantWhy) {
			t.Errorf("%s: %+v %q", others, ws, why)
		}
	}
	// The model's own provider pays its own search, with the main model.
	ws, _ = planWebSearch(knobs(t, `{"webSearch":{"service":"openai"}}`), unheld, openaiEp, "https://api.openai.com/v1", "gpt-main")
	if ws == nil || ws.URL != "https://api.openai.com/v1/responses" || ws.Headers["Authorization"] != "Bearer sk-raw" || ws.Model != "gpt-main" {
		t.Fatalf("openai on its own key: %+v", ws)
	}
	// A credential pays another provider's search through the proxy; a
	// model-run search then needs a model.
	if ws, why := planWebSearch(knobs(t, `{"webSearch":{"service":"anthropic","credential":"my-claude"}}`), held, routerEp, routerBase, "glm-5.3"); ws != nil || !strings.Contains(why, "webSearch.model") {
		t.Fatalf("anthropic with no model: %+v %q", ws, why)
	}
	ws, _ = planWebSearch(knobs(t, `{"webSearch":{"service":"anthropic","credential":"my-claude","model":"claude-haiku-5-5"}}`), held, routerEp, routerBase, "glm-5.3")
	if ws == nil || ws.URL != "http://127.0.0.1:9/tok/https/api.anthropic.com/v1/messages" || ws.Headers["x-api-key"] != "[[credential:my-claude]]" || ws.Model != "claude-haiku-5-5" {
		t.Fatalf("anthropic on a credential: %+v", ws)
	}
	ws, _ = planWebSearch(knobs(t, `{"webSearch":{"service":"0g-router","credential":"router-key"}}`), unheld, openaiEp, "https://api.openai.com/v1", "gpt-main")
	if ws != nil {
		t.Fatalf("a credential with the proxy off: %+v", ws)
	}
	unheld.proxy = "http://127.0.0.1:9/tok"
	ws, _ = planWebSearch(knobs(t, `{"webSearch":{"service":"0g-router","credential":"router-key"}}`), unheld, openaiEp, "https://api.openai.com/v1", "gpt-main")
	if ws == nil || ws.URL != "http://127.0.0.1:9/tok/https/router-api.0g.ai/v1/web/search" || ws.Headers["Authorization"] != "Bearer [[credential:router-key]]" {
		t.Fatalf("router search on a credential: %+v", ws)
	}
}

// stubResolve makes resolveModel answer from a table: provider/model →
// endpoint (nil: unknown provider).
func stubResolve(t *testing.T, eps map[string]*inference.Endpoint) {
	t.Helper()
	prev := resolveModel
	resolveModel = func(_ context.Context, provider, model, thinking string) (settings.Resolved, *inference.Endpoint) {
		return settings.Resolved{Doc: settings.Doc{Provider: provider, Model: model, Thinking: thinking}}, eps[provider+"/"+model]
	}
	t.Cleanup(func() { resolveModel = prev })
}

// The key-resolution matrix for subagent routes, and how routes are named.
func TestPlanRoutes(t *testing.T) {
	routerOpenAI := &inference.Endpoint{ProviderID: "0g-compute", Format: inference.WireOpenAI, BaseURL: "https://router-api.0g.ai/v1", WebSearch: "0g-router"}
	routerAnthropic := &inference.Endpoint{ProviderID: "0g-compute", Format: inference.WireAnthropic, BaseURL: "https://router-api.0g.ai", WebSearch: "0g-router"}
	openaiEp, _ := inference.NativeEndpoint("openai")
	stubResolve(t, map[string]*inference.Endpoint{
		"0g-compute/deepseek-v3": routerOpenAI,
		"0g-compute/claude-like": routerAnthropic,
		"openai/gpt-x":           openaiEp,
		"openai/gpt-y":           openaiEp,
	})
	main := settings.Resolved{Doc: settings.Doc{Provider: "0g-compute", Model: "glm-5.3"}}
	keys := keySource{mainProvider: "0g-compute", key: "[[credential:sealed:inference]]", held: true, proxy: "http://127.0.0.1:9/tok", mainHost: "router-api.0g.ai"}
	named := func(id string) string { return "http://127.0.0.1:7/r/p/" + id }
	k := knobs(t, `{"subagents":true,"subagentModels":[
		{"provider":"0g-compute","model":"glm-5.3"},
		{"provider":"0g-compute","model":"deepseek-v3"},
		{"provider":"0g-compute","model":"claude-like"},
		{"provider":"openai","model":"gpt-x"},
		{"provider":"openai","model":"gpt-x","credential":"my-openai"},
		{"provider":"openai","model":"gpt-y","credential":"my-openai"},
		{"provider":"mystery","model":"m","credential":"c"}],
		"subagentDefault":{"provider":"openai","model":"gpt-y"}}`)
	plan := planRoutes(context.Background(), k, keys, main, routerOpenAI, "DOC", "http://127.0.0.1:7/r", named)

	// Same provider, endpoint and key: the main route takes it.
	if len(plan.mainModels) != 1 || plan.mainModels[0] != "deepseek-v3" {
		t.Fatalf("main route models %v", plan.mainModels)
	}
	// Same provider on another endpoint: a named route on the model key.
	r, ok := plan.named["0g-compute@anthropic"]
	if !ok || r.Upstream != "http://127.0.0.1:9/tok/https/router-api.0g.ai" || r.Headers["x-api-key"] != "[[credential:sealed:inference]]" || r.Model != "claude-like" || r.System != "DOC" {
		t.Fatalf("router anthropic route %+v (%v)", r, ok)
	}
	// Another provider on an owner credential: one named route, both models.
	r, ok = plan.named["openai+my-openai"]
	if !ok || r.Upstream != "http://127.0.0.1:9/tok/https/api.openai.com/v1" || r.Headers["Authorization"] != "Bearer [[credential:my-openai]]" ||
		r.Model != "gpt-x" || len(r.Models) != 1 || r.Models[0] != "gpt-y" {
		t.Fatalf("openai credential route %+v (%v)", r, ok)
	}
	// Another provider with no credential, or one sealed knows no endpoint
	// of: not offered. The main model is always there and not repeated.
	if len(plan.named) != 2 || len(plan.offered) != 4 {
		t.Fatalf("named %v offered %+v", plan.named, plan.offered)
	}
	got := map[string]string{}
	for _, om := range plan.offered {
		got[om.Provider+"/"+om.Model] = om.BaseURL
	}
	for route, base := range map[string]string{
		"0g-compute/deepseek-v3":           "http://127.0.0.1:7/r",
		"0g-compute@anthropic/claude-like": named("0g-compute@anthropic"),
		"openai+my-openai/gpt-x":           named("openai+my-openai"),
		"openai+my-openai/gpt-y":           named("openai+my-openai"),
	} {
		if got[route] != base {
			t.Errorf("%s at %q, want %q", route, got[route], base)
		}
	}
	// The default is named the way the harness registers it.
	if plan.defaultRoute == nil || plan.defaultRoute.Provider != "openai+my-openai" || plan.defaultRoute.Model != "gpt-y" {
		t.Fatalf("default %+v", plan.defaultRoute)
	}
	env := strings.Join(plan.env(), "\n")
	if !strings.Contains(env, `SEAL_HARNESS_SUBAGENT_DEFAULT={"provider":"openai+my-openai","model":"gpt-y"}`) || strings.Contains(env, "sk-") || !strings.Contains(env, `"api":"anthropic-messages"`) {
		t.Fatalf("env %s", env)
	}

	// With subagents off nothing is offered.
	if p := planRoutes(context.Background(), knobs(t, `{"subagentModels":[{"provider":"0g-compute","model":"deepseek-v3"}]}`), keys, main, routerOpenAI, "DOC", "b", named); len(p.offered) != 0 || p.env() != nil {
		t.Fatalf("subagents off: %+v", p)
	}
}

// Start serves the owner's search service on the main route: a malformed
// search is refused as such (400) wherever one is configured, and the path
// does not exist (404) where none can be paid. No request leaves the box.
func TestStart_WebSearchFollowsTheSetting(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	for _, c := range []struct {
		name     string
		doc      settings.Doc
		wantCode int
	}{
		{"0g router, default search", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, http.StatusBadRequest},
		{"0g router, web tools off", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: json.RawMessage(`{"webTools":false}`)}, http.StatusNotFound},
		{"0g router, search off", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: json.RawMessage(`{"webSearch":{"service":"off"}}`)}, http.StatusNotFound},
		{"openai model, default router search: no key for it", settings.Doc{Provider: "openai", Model: "gpt-x"}, http.StatusNotFound},
		{"openai model, its own search", settings.Doc{Provider: "openai", Model: "gpt-x", Others: json.RawMessage(`{"webSearch":{"service":"openai"}}`)}, http.StatusBadRequest},
		{"0g router, anthropic search, no credential", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: json.RawMessage(`{"webSearch":{"service":"anthropic"}}`)}, http.StatusNotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New()
			dshHome = t.TempDir()
			if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(), c.doc, "")); err != nil {
				t.Fatalf("RenderSettings: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = a.Start(ctx, framework.RuntimeContext{APIKey: "k"})
			defer func() { _ = a.Stop(context.Background(), 0) }()
			route, err := a.inferenceRoute()
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Post(route.BaseURL()+"/v1/web/search", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.wantCode {
				t.Fatalf("web/search: %d, want %d", resp.StatusCode, c.wantCode)
			}
		})
	}
}

// The further models reach the harness as JSON with no key, and only when
// Start planned some.
func TestBridgeEnvModelRoutes(t *testing.T) {
	plan := routePlan{offered: []offeredModel{{Provider: "0g-compute", Model: "deepseek-v3", BaseURL: "http://127.0.0.1:1/t", API: "openai-completions"}}}
	env := bridgeEnv{token: "tok", routesEnv: plan.env()}.environ()
	var routes string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "SEAL_HARNESS_MODEL_ROUTES="); ok {
			routes = v
		}
		if strings.HasPrefix(kv, "SEAL_HARNESS_SUBAGENT_DEFAULT=") {
			t.Fatalf("a default with none planned: %s", kv)
		}
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(routes), &got); err != nil || len(got) != 1 || got[0]["model"] != "deepseek-v3" || got[0]["baseURL"] != "http://127.0.0.1:1/t" {
		t.Fatalf("routes %q", routes)
	}
	for _, kv := range (bridgeEnv{token: "tok"}).environ() {
		if strings.HasPrefix(kv, "SEAL_HARNESS_MODEL_ROUTES=") {
			t.Fatal("routes set with none planned")
		}
	}
}
