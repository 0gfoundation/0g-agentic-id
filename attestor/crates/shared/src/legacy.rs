//! The old-image flow: containers whose image has no loader report no sealed
//! hash and claim their boot with ProvisionBoot.v1 (sealed/LAYERS.md §8,
//! "Compatibility with existing 0g-harness images"). The flow is picked by the
//! data — a claim with a sealed hash takes the layered flow — never by a
//! switch. Once those images are gone, delete this module; the compiler then
//! lists every branch that called it.

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
