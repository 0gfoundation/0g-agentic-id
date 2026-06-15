package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Service is one externally-reachable HTTP entry the agent has declared
// in `~/.openclaw/services.json` (or whichever path the framework adapter
// designates). Carries enough metadata for the deploy console to render
// a discoverable endpoint listing and for callers to draft `curl` requests.
//
// Schema matches attestor_shared::types::AgentService — identical field
// names so the heartbeat payload round-trips byte-for-byte. Adding a
// field here requires adding it on the attestor side too.
type Service struct {
	Path         string `json:"path"`
	Method       string `json:"method"`
	Description  string `json:"description,omitempty"`
	InputExample string `json:"input_example,omitempty"`
	Skill        string `json:"skill,omitempty"`
}

// servicesFile is the on-disk shape sealed expects at the agent's
// declaration path. Mirrors the schema documented in TOOLS.md so an
// agent following the doctrine produces exactly this layout.
type servicesFile struct {
	Services  []Service `json:"services"`
	UpdatedAt int64     `json:"updated_at,omitempty"`
}

// LoadServices reads the agent's published services from `path`. The
// contract is permissive on purpose — published_services is runtime
// metadata, not a security boundary, so any failure mode collapses
// to "no services declared":
//
//   - file missing → empty slice, nil error
//   - read / parse error → empty slice, error returned (caller logs;
//     the heartbeat itself still goes through with empty services)
//
// nil-slice return is preferred over empty slice for downstream
// json.Marshal-with-omitempty behaviour: "agent hasn't declared
// anything" omits the field entirely instead of sending `[]`.
func LoadServices(path string) ([]Service, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var f servicesFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(f.Services) == 0 {
		return nil, nil
	}
	return f.Services, nil
}
