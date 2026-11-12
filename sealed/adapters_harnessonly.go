//go:build harnessonly && !zghonly

package main

import "seal-verify/internal/framework/harness"

// registerAdapters registers the 0g-harness adapter alone: the 0g-harness
// image builds sealed with the harnessonly tag, so the other frameworks'
// adapters are not in its binary at all. An agent bound to another
// framework does not boot on this image (resolveAdapter fails loud).
func registerAdapters() {
	harness.New()
}
