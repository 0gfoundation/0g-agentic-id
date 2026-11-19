package main

import (
	"context"
	"fmt"
	"net/url"

	"seal-verify/internal/inference"
	"seal-verify/internal/inferproxy"
	"seal-verify/internal/servicehost"
	"seal-verify/internal/settings"
)

// Resolve only the owner's pinned model route. A service cannot supply a
// destination, credential name or provider key to this callback.
func serviceModelRoute(ctx context.Context, keys *modelKeys, doc settings.Doc) (servicehost.ModelRoute, error) {
	choice := keys.choose(doc)
	resolved, err := keys.resolve(ctx, choice)
	if err != nil {
		return servicehost.ModelRoute{}, err
	}
	if resolved.Endpoint == nil || resolved.APIKey == "" {
		return servicehost.ModelRoute{}, fmt.Errorf("a platform-routed owner model is required")
	}
	u, err := url.Parse(resolved.Endpoint.BaseURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return servicehost.ModelRoute{}, fmt.Errorf("task inference requires the pinned HTTPS provider route")
	}
	api := "openai-completions"
	headers := map[string]string{"Authorization": "Bearer " + resolved.APIKey}
	if resolved.Endpoint.Format == inference.WireAnthropic {
		api = "anthropic-messages"
		headers = map[string]string{"x-api-key": resolved.APIKey}
	}
	return servicehost.ModelRoute{API: api, Route: inferproxy.Route{Upstream: resolved.Endpoint.BaseURL, Headers: headers, Model: resolved.Model}}, nil
}
