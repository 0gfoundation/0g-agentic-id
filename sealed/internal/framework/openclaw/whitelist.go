package openclaw

// supportedOpenclawVersions is the closed set of openclaw npm releases
// sealed has been validated against. Bump as part of the sealed image
// release flow — adding a version here without rebuilding the sealed
// image leaves us claiming compat we haven't tested.
//
// Stored as a slice (not a map) so the order encodes "preferred order":
// the LAST entry is whitelistMax, the version sealed reconciles to on
// any framework dim drift.
var supportedOpenclawVersions = []string{
	"2026.5.6",
	"2026.5.7",
}

// whitelistMax returns the version sealed targets when reconciling
// framework dim drift. Always the last element of the supported list.
func whitelistMax() string {
	if len(supportedOpenclawVersions) == 0 {
		return ""
	}
	return supportedOpenclawVersions[len(supportedOpenclawVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions. Not
// currently load-bearing in the reconcile path (we always reconcile to
// whitelistMax) but exposed for diagnostics + future "fail on unknown
// pinned version" checks.
func isWhitelisted(v string) bool {
	for _, s := range supportedOpenclawVersions {
		if s == v {
			return true
		}
	}
	return false
}
