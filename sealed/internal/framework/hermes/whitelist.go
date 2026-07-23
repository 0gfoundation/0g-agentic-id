package hermes

import (
	"strconv"
	"strings"
)

// supportedHermesVersions is the closed set of hermes-agent git release
// tags sealed has been validated against. Bump as part of the sealed
// image release flow — adding a tag here without rebuilding the sealed
// image leaves us claiming compat we haven't tested.
//
// Naming: hermes double-names its releases — a semantic marketing name
// ("v0.19.0") and the actual CalVer git tag ("v2026.7.20"). Only the
// CalVer form exists as a tag (verified via ls-remote), so THAT is what
// this list, the binding's package_version, and probeHermesVersion all
// speak; the semantic name appears nowhere in the protocol.
//
// Stored as a slice (not a map) so the order encodes "preferred order":
// the LAST entry is whitelistMax, the version sealed reconciles to on
// any framework dim drift. Hermes releases ~bi-weekly minors; expect this
// list to move faster than openclaw's.
var supportedHermesVersions = []string{
	"v2026.7.20", // semantic name v0.19.0
}

// whitelistMax returns the version sealed targets when reconciling
// framework dim drift. Always the last element of the supported list.
func whitelistMax() string {
	if len(supportedHermesVersions) == 0 {
		return ""
	}
	return supportedHermesVersions[len(supportedHermesVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions.
// Load-bearing at install: restoreFramework runs every non-empty pinned
// version through this and coerces misses to nearestWhitelisted, so
// sealed never checks out a tag it hasn't been validated against.
func isWhitelisted(v string) bool {
	for _, s := range supportedHermesVersions {
		if s == v {
			return true
		}
	}
	return false
}

// nearestWhitelisted returns the validated version closest to v in
// version order: the highest whitelisted version that sorts ≤ v, or the
// lowest whitelisted version when v sorts below all of them. Never
// returns "" while the whitelist is non-empty.
func nearestWhitelisted(v string) string {
	floor, lowest := "", ""
	for _, s := range supportedHermesVersions {
		if compareVersions(s, v) <= 0 && (floor == "" || compareVersions(s, floor) > 0) {
			floor = s
		}
		if lowest == "" || compareVersions(s, lowest) < 0 {
			lowest = s
		}
	}
	if floor != "" {
		return floor
	}
	return lowest
}

// compareVersions orders dotted version strings segment-wise: numeric
// segments compare as integers, non-numeric segments fall back to string
// comparison, missing segments count as zero. Hermes tags carry a "v"
// prefix in their first segment ("v0"), which string-compares equal
// across tags, so the remaining segments decide — same behaviour as the
// openclaw twin on its bare CalVer strings.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var sa, sb string
		if i < len(as) {
			sa = as[i]
		}
		if i < len(bs) {
			sb = bs[i]
		}
		na, errA := strconv.Atoi(sa)
		nb, errB := strconv.Atoi(sb)
		switch {
		case errA == nil && errB == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case errA == nil && sb == "":
			if na != 0 {
				return 1
			}
		case errB == nil && sa == "":
			if nb != 0 {
				return -1
			}
		default:
			if sa != sb {
				if sa < sb {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}
