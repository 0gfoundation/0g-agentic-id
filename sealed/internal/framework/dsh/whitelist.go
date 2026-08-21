package dsh

// supportedDSHVersions is the closed set of DSH (@deepseek-ai/dsh) versions
// sealed has been validated against. Bump together with the image: the
// framework is installed at image build time (see images/dsh/Dockerfile), so
// a version listed here that the image does not carry cannot be honoured.
//
// Unlike prime-agent, DSH's release series and its npm package version are
// the SAME series (npm dist-tag `latest` at the time this adapter was written
// was 0.1.0-rc.6, matching the checked-out repo's own package.json), so this
// list speaks npm versions directly — no tarball/release-channel split.
//
// Stored as a slice (not a map) so the order encodes "preferred order": the
// LAST entry is whitelistMax, the version a `framework` role drift
// reconciles against.
var supportedDSHVersions = []string{
	"0.1.0-rc.6", // pre-1.0: expect this list to move often (see package doc)
}

// whitelistMax returns the version sealed targets: always the last element.
func whitelistMax() string {
	if len(supportedDSHVersions) == 0 {
		return ""
	}
	return supportedDSHVersions[len(supportedDSHVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions.
func isWhitelisted(v string) bool {
	for _, s := range supportedDSHVersions {
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
// lower" search.
func coerceWhitelisted(v string) string {
	if v == "" || !isWhitelisted(v) {
		return whitelistMax()
	}
	return v
}
