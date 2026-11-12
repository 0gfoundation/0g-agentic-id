//go:build zghonly

package main

import "seal-verify/internal/framework/harness"

// The zgh image preserves the existing AgenticID framework binding and data
// roles; only the runtime implementation and advertised capabilities change.
func registerAdapters() { harness.NewZGH() }
