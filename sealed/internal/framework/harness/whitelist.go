package harness

// supportedVersions is the closed set of 0g-harness versions (the version in
// its package.json) sealed has been validated against. Bump together with the
// image: the harness is installed at image build time, and the build
// (images/harness/Dockerfile) fails unless the installed version is the LAST
// entry here. The DSH packages the harness runs on are locked by its own
// npm-shrinkwrap.json, so a harness version names one exact dependency tree.
//
// Stored as a slice (not a map) so the order encodes "preferred order": the
// LAST entry is whitelistMax, the version a `framework` role drift
// reconciles against.
var supportedVersions = []string{
	"0.1.0", // pre-1.0: expect this list to move often (see package doc)
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
// choice as prime-agent's coercion, for the same reason: the image carries
// exactly one installed version, so there is nothing to gain from a "nearest
// lower" search. A binding from before 0g-harness pins a DSH version, which
// resolves the same way.
func coerceWhitelisted(v string) string {
	if v == "" || !isWhitelisted(v) {
		return whitelistMax()
	}
	return v
}
