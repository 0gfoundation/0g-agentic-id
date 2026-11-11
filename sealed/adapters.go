//go:build !harnessonly

package main

import (
	"seal-verify/internal/framework/harness"
	"seal-verify/internal/framework/hermes"
	"seal-verify/internal/framework/openclaw"
	"seal-verify/internal/framework/prime"
)

// registerAdapters registers every bundled adapter (side-effect of New()).
// Which one this deployment actually uses is resolved AFTER the chain
// bootstrap, from the on-chain framework binding (see resolveAdapter);
// registration is cheap and touches no disk.
//
// This is the build the openclaw, hermes and prime-agent images ship. The
// 0g-harness image builds with the harnessonly tag and registers its own
// adapter alone (adapters_harnessonly.go).
//
// The adapter interface + platform seam are framework-agnostic (see
// FRAMEWORK_ADAPTER.md); a claude-code adapter was prototyped to validate
// the seam and retired — a per-request CLI couldn't host owner-built public
// services, the shape this platform is for. That port's lessons live on as a
// case study in the doc.
//
// prime-agent needs a node+python image (its runtime is TypeScript over a
// Python IPython kernel); registration is harmless on an image without them,
// since selection is per-agent and an unusable adapter simply never gets
// picked.
func registerAdapters() {
	openclaw.New()
	hermes.New()
	prime.New()
	harness.New()
}
