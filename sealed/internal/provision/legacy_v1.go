package provision

// LEGACY(v1): the boot claim of an image without the loader
// (sealed/LAYERS.md §8): openclaw, hermes and prime-agent, and 0g-harness
// images from before the loader. Their claim names no sealed hash: the image
// hash covers their sealed. A sealed the loader started never sends it.
//
// Delete this file, and every branch marked LEGACY(v1)
// (`git grep -n 'LEGACY(v1)'`), once every running image has the loader —
// openclaw, hermes and prime-agent retired or moved onto the loader, the
// older 0g-harness images reset. The attestor's v1 claim
// (attestor/crates/shared/src/legacy.rs) goes at the same time.

import "fmt"

// bootMessage is the v1 claim: ProvisionBoot.v2's fields without the sealed
// hash.
func bootMessage(seal string, generation int64, ticketHash [32]byte, bootID []byte, startedAt int64) string {
	return fmt.Sprintf("ProvisionBoot.v1:0x%s:%d:%x:%x:%d", seal, generation, ticketHash, bootID, startedAt)
}
