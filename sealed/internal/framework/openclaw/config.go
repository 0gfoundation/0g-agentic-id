// Internal config types for the openclaw adapter. All private to this
// package — protocol-level code (state, manager, proxy, main) does NOT
// reference any openclaw-specific shape.
//
// Path-driven design (§16): each role's plaintext is interpreted directly
// against disk artifacts. The in-memory composed state retained here is
// limited to the framework binding (versioning info needed across Start
// calls and at evolution-time live probe).
package openclaw

// config is the in-memory state the adapter retains across Restore /
// Start. Only the framework binding is stored — every other role's
// content lives on disk and is read back via EvolutionFor when needed.
type config struct {
	framework frameworkBinding
}

// frameworkBinding is the plaintext of role="framework". Captures which
// framework + which runtime version + which protocol schema this agent
// expects. SchemaVersion gates reader compatibility (§16); incompatible
// values cause Restore to fail loud.
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}
