//go:build !linux

// sealed runs only on Linux: this package keeps root's side of the
// privilege split with Linux-only system calls (O_PATH descriptors,
// AT_EMPTY_PATH, renameat2, /proc/self/fd), and it has no fallback that
// would keep those guarantees elsewhere. Build and test sealed on Linux,
// for example in the golang container AGENTS.md gives.
package privsep

var _ = sealedBuildsAndTestsOnlyOnLinux_RunGoTestInTheContainerFromAGENTSmd
