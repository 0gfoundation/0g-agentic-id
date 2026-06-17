package openclaw

// SOUL.md sealed-managed injection.
//
// This file is the openclaw adapter's delivery layer: it takes a
// pre-built platform.Sovereignty section string and writes it to
// SOUL.md using the marker-injection mechanism. Content generation
// lives in internal/platform/context.go.
//
// The adapter's only job here is to wrap the platform content in
// marker comments and handle the file I/O.

// upsertSoulMD writes (or replaces) the sealed-managed section in
// SOUL.md with the platform sovereignty content. Empty section strips
// the existing injection.
func upsertSoulMD(path, sovereigntySection string) error {
	return upsertMarkedSection(path, sovereigntySection)
}
