package prime

// supportedPrimeVersions is the closed set of Prime Agent RELEASE versions
// sealed has been validated against. Bump together with the image: the
// framework is installed at image build time (see images/prime/Dockerfile), so
// a version listed here that the image does not carry cannot be honoured.
//
// Which artifact this pins, and why it is not npm: Prime Agent ships two
// halves. The npm package `@earendil-works/pi-coding-agent` is the TypeScript
// one — it contains zero `.py` files and has no postinstall. The Python half
// (the RLM runtime, whose `rlm/harness.py` writes the harness state this
// adapter anchors on chain) is distributed ONLY in the release tarball at
// `<base>/releases/v<version>/prime-agent-<version>.tgz`, whose postinstall
// provisions uv, Python and the IPython kernel. An npm-only install yields a
// container where the tracked harness-state file is never created at all.
//
// The two version spaces are unrelated — release 0.7.2 corresponds to npm
// 0.84.1 — so this list speaks release versions and nothing else.
//
// Stored as a slice (not a map) so the order encodes "preferred order": the
// LAST entry is whitelistMax, the version a `framework` role drift reconciles
// against.
var supportedPrimeVersions = []string{
	"0.7.2", // stable channel as of 2026-08-12
}

// whitelistMax returns the version sealed targets: always the last element.
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
// that needs a total order over the whitelist, which would mean reimplementing
// semver comparison to get right. Coercing straight to max is the conservative
// choice — and since the image carries exactly one installed version, the
// coercion result is checked against it at Start rather than installed on
// demand.
func coerceWhitelisted(v string) string {
	if v == "" || !isWhitelisted(v) {
		return whitelistMax()
	}
	return v
}
