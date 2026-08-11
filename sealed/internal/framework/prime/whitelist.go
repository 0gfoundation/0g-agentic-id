package prime

// supportedPrimeVersions is the closed set of @earendil-works/pi-coding-agent
// npm releases sealed has been validated against. Bump as part of the sealed
// image release flow — adding a version here without rebuilding the sealed
// image leaves us claiming compat we haven't tested.
//
// Prime Agent's public installer (`curl … | sh` from app.primeintellect.ai)
// fetches a versioned release tarball; the same code is published to npm as
// workspace packages, and the npm version is what this adapter pins and
// probes. That is the only pinnable identifier the project offers: the git
// tags track the desktop/release packaging, not the harness itself.
//
// Stored as a slice (not a map) so the order encodes "preferred order":
// the LAST entry is whitelistMax, the version sealed reconciles to on any
// framework dim drift.
var supportedPrimeVersions = []string{
	"0.84.1",
}

// whitelistMax returns the version sealed targets when reconciling framework
// dim drift. Always the last element of the supported list.
func whitelistMax() string {
	if len(supportedPrimeVersions) == 0 {
		return ""
	}
	return supportedPrimeVersions[len(supportedPrimeVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions.
func isWhitelisted(v string) bool {
	for _, s := range supportedPrimeVersions {
		if s == v {
			return true
		}
	}
	return false
}

// coerceWhitelisted maps any pinned version onto one sealed has validated.
// An empty pin (attestor mints version-less bindings — FRAMEWORK_ADAPTER.md
// §3.1) and any unvalidated pin both resolve to whitelistMax.
//
// Unlike the hermes adapter there is no "nearest lower version" behaviour:
// that needs a total order over the whitelist, and with npm semver we would
// have to reimplement semver comparison to get it right. Coercing straight to
// max is the conservative choice — sealed only ever installs something it has
// tested — and the drift commit records what actually got pinned.
func coerceWhitelisted(v string) string {
	if v == "" || !isWhitelisted(v) {
		return whitelistMax()
	}
	return v
}
