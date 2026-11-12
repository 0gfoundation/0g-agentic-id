// Package layers holds sealed's side of the layered runtime
// (sealed/LAYERS.md), used only in the 0g-harness image and only once the
// attestor declares the layered flow at GET /provision:
//
//   - artifacts downloaded by hash from the public release (FetchArtifact)
//     and kept only when they hash to what was asked for;
//   - harness official version packages: unpacked into a directory the agent
//     user can read but not write, one per package hash, and the record of
//     which one runs (harness.go);
//   - the hand-over to the loader: a sealed version staged for it, the
//     request to switch, the confirmation that a new version came up
//     (sealed.go).
//
// The loader (cmd/loader) links only the standard library, so the names it
// shares with this package (the environment variables, the files under
// LoaderDir, the trial exit code) are written out on both sides. Keep the
// two in step.
package layers

import (
	"encoding/hex"
	"strings"
)

// ParseHash turns a "0x"-prefixed or bare 32-byte hex hash, in either case,
// into 64 lowercase hex. ok is false for anything else.
func ParseHash(s string) (string, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", false
	}
	return hex.EncodeToString(b), true
}

// Bytes32 is h (64 hex, as ParseHash returns it) as the contract's bytes32.
func Bytes32(h string) [32]byte {
	var out [32]byte
	b, _ := hex.DecodeString(h)
	copy(out[:], b)
	return out
}
