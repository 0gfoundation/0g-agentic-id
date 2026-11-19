//! LEGACY(v1): the old-image flow. Containers whose image has no loader report
//! no sealed hash and claim their boot with ProvisionBoot.v1 (sealed/LAYERS.md
//! §8, "Compatibility with existing 0g-harness images"). The flow is picked by
//! the data — a claim with a sealed hash takes the layered flow — never by a
//! switch. Once those images are gone, delete this module and every
//! `LEGACY(v1)` mark (`git grep -n 'LEGACY(v1)'`): the compiler lists every
//! branch that called it, and a claim then names its sealed program
//! (`ProvisionRequest::sealed_hash` a plain hash).

use alloy::primitives::B256;

/// The claim a boot without a sealed hash signs:
/// `ProvisionBoot.v1:0x<seal>:<generation>:<sha256(ticket)>:<boot id>:<started at>`.
pub fn boot_signing_message_v1(
    seal: B256,
    generation: i64,
    ticket_hash: &[u8; 32],
    boot_id: B256,
    started_at: i64,
) -> String {
    format!(
        "ProvisionBoot.v1:0x{}:{}:{}:{}:{}",
        hex::encode(seal),
        generation,
        hex::encode(ticket_hash),
        hex::encode(boot_id),
        started_at
    )
}

/// The provision policy for a claim without a sealed hash: nothing beyond the
/// image check. The image hash covers the sealed program an image without the
/// loader runs, so there is no separate list to consult.
pub fn sealed_covered_by_image() {}
