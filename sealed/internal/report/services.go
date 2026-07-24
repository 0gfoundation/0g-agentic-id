package report

// Service is one externally-reachable HTTP entry the agent has declared,
// as surfaced in the signed /hello self-introduction. Carries enough
// metadata for the deploy console to render a discoverable endpoint
// listing and for callers to draft `curl` requests.
//
// Schema matches attestor_shared::types::AgentService — identical field
// names so it round-trips byte-for-byte. Adding a field here requires
// adding it on the attestor side too.
//
// Declarations no longer come from a per-framework file (the old
// `~/.openclaw/services.json` + LoadServices). Agents register services
// with sealed over `POST $SEAL_SIGN_SOCK/services`; proxy builds /hello
// from that registry (see proxy/services.go). This is the public wire
// shape those registry entries map to.
type Service struct {
	Path         string `json:"path"`
	Method       string `json:"method"`
	Description  string `json:"description,omitempty"`
	InputExample string `json:"input_example,omitempty"`
	Skill        string `json:"skill,omitempty"`
}

// Route is one framework-declared path prefix, as surfaced in the `routes`
// array of the signed /hello self-introduction. Distinct from Service: a
// Service is an agent-registered (untrusted) exact path under /api/, whereas
// a Route is declared by the audited framework adapter and may claim a prefix
// (e.g. a dashboard owning "/"). Clients use `kind`/`auth` to pick how to
// interact and present the /_seal/auth token; `signed` says whether responses
// on the route carry an X-Agent-Proof.
type Route struct {
	Prefix      string `json:"prefix"`
	Kind        string `json:"kind,omitempty"`
	Auth        string `json:"auth,omitempty"`
	Signed      bool   `json:"signed"`
	Description string `json:"description,omitempty"`
}
