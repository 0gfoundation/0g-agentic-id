package harness

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"seal-verify/internal/framework"
	"seal-verify/internal/privsep"
)

var _ framework.RuntimePackageValidator = (*Adapter)(nil)

// NewZGH selects the zgh implementation on the dedicated image. New already
// registers the 0g-harness and dsh identifiers, so mint-time and evolved iData
// take the same restore path before any uploader can retire legacy roles.
func NewZGH() *Adapter {
	a := New()
	a.zgh = true
	a.binding.PackageVersion = a.preferredVersion()
	return a
}

func (a *Adapter) preferredVersion() string {
	if a.zgh {
		return "0.3.0"
	}
	return whitelistMax()
}

// A DSH official package can remain in the old deployment's selection. It
// must not run under zgh's advertised native-resource protocol. Let the
// existing layered runtime reject it and use this image's pinned base.
func (a *Adapter) checkZGHRuntime() error {
	a.mu.RLock()
	dir := a.pkgDir
	a.mu.RUnlock()
	return a.ValidateRuntimePackage(dir)
}

func (a *Adapter) ValidateRuntimePackage(dir string) error {
	if !a.zgh {
		return nil
	}
	if dir == "" {
		return fmt.Errorf("zgh requires a pinned runtime package")
	}
	raw, err := privsep.ReadFile(filepath.Join(dir, "runtime.json"), 4096)
	if err != nil {
		return fmt.Errorf("zgh runtime metadata: %w", err)
	}
	var meta struct {
		Backend string `json:"backend"`
		Version string `json:"integration_version"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Backend != "zgh" || meta.Version != a.preferredVersion() {
		return fmt.Errorf("package is not a compatible zgh sealed runtime")
	}
	return nil
}

func (a *Adapter) zghRoutes() []framework.Route {
	backend := fmt.Sprintf("http://127.0.0.1:%d", bridgePort)
	get := func(p string) framework.Endpoint { return framework.Endpoint{Method: http.MethodGet, Path: p} }
	post := func(p string) framework.Endpoint { return framework.Endpoint{Method: http.MethodPost, Path: p} }
	route := func(prefix, kind, description string, endpoints ...framework.Endpoint) framework.Route {
		return framework.Route{Prefix: prefix, Kind: kind, Auth: "bearer", Backend: backend, Description: description, Endpoints: endpoints}
	}
	return []framework.Route{
		route("/v1/", "chat", "Stateful owner conversation (zgh). Only the last user message is consumed; use native sessions to manage separate conversations.", get("/v1/harness"), post("/v1/chat/completions"), post("/v1/interrupt"), post("/v1/compact")),
		route("/v1/sessions", "zgh-sessions-v1", "Native zgh session resources, protocol 1; JSON schemas and SSE events are zgh's, distinct from Responses and turn records.", get("/v1/sessions"), post("/v1/sessions"), get("/v1/sessions/{id}"), post("/v1/sessions/{id}/prompt"), post("/v1/sessions/{id}/cancel"), get("/v1/sessions/{id}/events")),
		route("/v1/tasks", "zgh-tasks-v1", "Native zgh tasks, protocol 1: workspace, inputs, needs-input and archive state. Not the legacy turn/job task schema.", get("/v1/tasks"), post("/v1/tasks"), get("/v1/tasks/{id}"), framework.Endpoint{Method: http.MethodPatch, Path: "/v1/tasks/{id}"}, post("/v1/tasks/{id}/start"), post("/v1/tasks/{id}/input"), post("/v1/tasks/{id}/answer"), post("/v1/tasks/{id}/cancel"), post("/v1/tasks/{id}/archive"), get("/v1/tasks/{id}/events")),
	}
}
