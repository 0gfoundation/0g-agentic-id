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
