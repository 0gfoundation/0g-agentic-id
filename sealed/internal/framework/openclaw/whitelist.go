package openclaw

import (
	"strconv"
	"strings"
)

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
	"2026.7.1",
}

// whitelistMax returns the version sealed targets when reconciling
// framework dim drift. Always the last element of the supported list.
func whitelistMax() string {
	if len(supportedOpenclawVersions) == 0 {
		return ""
	}
	return supportedOpenclawVersions[len(supportedOpenclawVersions)-1]
}

// isWhitelisted reports whether v is one of the validated versions.
// Load-bearing at install: restoreFramework runs every non-empty pinned
// version through this and coerces misses to nearestWhitelisted, so
// sealed never npm-installs a version it hasn't been validated against.
// (The reconcile path doesn't need it — it always targets whitelistMax.)
func isWhitelisted(v string) bool {
	for _, s := range supportedOpenclawVersions {
		if s == v {
			return true
		}
	}
	return false
}

// nearestWhitelisted returns the validated version closest to v in
// version order: the highest whitelisted version that sorts ≤ v, or the
// lowest whitelisted version when v sorts below all of them. So a pin
// above whitelistMax lands on whitelistMax, a pin between two validated
// releases lands on the older of the two, and a pin below everything
// lands on the oldest validated release. Never returns "" while the
// whitelist is non-empty.
func nearestWhitelisted(v string) string {
	floor, lowest := "", ""
	for _, s := range supportedOpenclawVersions {
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
// segments compare as integers ("2026.5.10" > "2026.5.7"), non-numeric
// segments fall back to string comparison, and missing segments count
// as zero ("2026.5" == "2026.5.0").
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
