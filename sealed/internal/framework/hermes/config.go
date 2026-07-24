// Internal config types for the hermes adapter. All private to this
// package — protocol-level code (state, manager, proxy, main) does NOT
// reference any hermes-specific shape.
//
// Path-driven design (§16): each role's plaintext is interpreted directly
// against disk artifacts. The in-memory composed state retained here is
// limited to the framework binding (versioning info needed across Start
// calls and at evolution-time live probe).
package hermes

// config is the in-memory state the adapter retains across Restore /
// Start. Only the framework binding is stored — every other role's
// content lives on disk and is read back via EvolutionFor when needed.
type config struct {
	framework frameworkBinding
}

// frameworkBinding is the plaintext of role="framework". Same 3-field
// shape as every adapter (attestor mints it framework-agnostically);
// PackageVersion here is a hermes git release tag (e.g. "v0.19.0") —
// hermes has no npm/pip distribution, releases are git tags.
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}
