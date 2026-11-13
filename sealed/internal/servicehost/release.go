package servicehost

import (
	"encoding/json"
	"fmt"
)

// The manifest includes bounded, public source files and non-secret manifest
// configuration only. It contains no runtime input or credential-store values.
// CanonicalManifest is the exact normalized JSON whose SHA256 is Version; JSON
// encodes these bytes as base64 so clients need not reproduce Go's key order.
type PublishedRelease struct {
	Version           string   `json:"version"`
	Manifest          Manifest `json:"manifest"`
	CanonicalManifest []byte   `json:"canonical_manifest"`
}

// MaxReleaseBytes includes the displayed manifest and its canonical byte copy.
const MaxReleaseBytes = 64 << 20

// Release snapshots only one immutable published service. It works while the
// service is stopped and does not execute its code or acquire a model/runtime.
func (m *Manager) Release(id string) (PublishedRelease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[id]
	if m.closed || e == nil {
		return PublishedRelease{}, fmt.Errorf("service release unavailable")
	}
	canonical, err := json.Marshal(e.Manifest)
	if err != nil || len(canonical) > 24<<20 {
		return PublishedRelease{}, fmt.Errorf("published manifest exceeds release limits")
	}
	// Detach every slice/map before returning and validate the normalized
	// snapshot against the version sealed assigned at publication.
	var man Manifest
	if err := json.Unmarshal(canonical, &man); err != nil {
		return PublishedRelease{}, fmt.Errorf("invalid published manifest")
	}
	version, err := man.normalize()
	if err != nil || version != e.Version {
		return PublishedRelease{}, fmt.Errorf("published manifest version mismatch")
	}
	canonical, err = json.Marshal(man)
	if err != nil {
		return PublishedRelease{}, err
	}
	return PublishedRelease{Version: version, Manifest: man, CanonicalManifest: canonical}, nil
}
