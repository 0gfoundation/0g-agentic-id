package harness

// supportedVersions is the closed set of 0g-harness versions (the version in
// its package.json) sealed has been validated against. Every harness package —
// the image's base and each one built for the artifacts release — comes from
// the harness-package stage of images/harness/Dockerfile, which fails unless
// the package's version is the LAST entry here; bump it before building a
// package of a newer version. sealed picks packages by their hash on the trust
// registry's harness list (internal/layers) and does not read their version.
// The DSH packages the harness runs on are locked by its own
// npm-shrinkwrap.json, so a harness version names one exact dependency tree.
//
// Stored as a slice (not a map) so the order encodes "preferred order": the
// LAST entry is whitelistMax, the version a `framework` role drift
// reconciles against.
var supportedVersions = []string{
	"0.1.0", // Existing bindings remain accepted; 0.2.0 stays preferred.
	"0.2.0", // DSH 0.2.2-rc.1, native MCP and handle-based persistence
}

// whitelistMax returns the version sealed targets: always the last element.
func whitelistMax() string {
	if len(supportedVersions) == 0 {
		return ""
	}
	return supportedVersions[len(supportedVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions.
func isWhitelisted(v string) bool {
	for _, s := range supportedVersions {
		if s == v {
			return true
		}
	}
	return false
}

// coerceWhitelisted maps any pinned version onto one sealed has validated. An
// empty pin (attestor mints version-less bindings — FRAMEWORK_ADAPTER.md §3.1)
// and any unvalidated pin both resolve to whitelistMax — same conservative
// choice as prime-agent's coercion: the pin does not choose the package that
// runs (packages are chosen by hash), so there is nothing to gain from a
// "nearest lower" search. A binding from before 0g-harness pins a DSH version,
// which resolves the same way.
func coerceWhitelisted(v string) string {
	if v == "" || !isWhitelisted(v) {
		return whitelistMax()
	}
	return v
}
