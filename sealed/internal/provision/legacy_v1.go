package provision

// LEGACY(v1): the boot claim of a boot outside the layered flow
// (sealed/LAYERS.md §8): images without the loader (openclaw, hermes and
// prime-agent, and 0g-harness images from before the loader), and a loader
// image whose attestor does not declare the flow (a chain whose AgenticID
// names no trust registry). Their claim names no sealed hash: the image hash
// covers their sealed.
//
// Delete this file, and every branch marked LEGACY(v1)
// (`git grep -n 'LEGACY(v1)'`), once every running image has the loader and
// every attestor declares the layered flow — openclaw, hermes and
// prime-agent retired or moved onto the loader, the older 0g-harness images
// reset, every environment on AgenticID 1.4.0. The attestor's v1 claim
// (attestor/crates/shared/src/legacy.rs) goes at the same time.

import "fmt"

// bootMessage is the v1 claim: ProvisionBoot.v2's fields without the sealed
// hash.
func bootMessage(seal string, generation int64, ticketHash [32]byte, bootID []byte, startedAt int64) string {
	return fmt.Sprintf("ProvisionBoot.v1:0x%s:%d:%x:%x:%d", seal, generation, ticketHash, bootID, startedAt)
}
