//! Deploy-edge preflight: the two owner prerequisites (trust-roots ack +
//! prepaid sandbox balance) checked SYNCHRONOUSLY at request accept.
//!
//! Without this, a request that will inevitably fail is accepted, burns a
//! worker slot, and the real error (a sandbox 402) surfaces minutes later
//! with no request context — the owner sees an agent stuck in a phase and
//! has to go digging. Checking here turns both into an immediate,
//! actionable 402 with a stable error code the console/SDK can route to
//! the matching fix-up flow (ack modal / top-up modal).
//!
//! Each check self-disables when its chain surface isn't configured
//! (zero/absent addresses or app ids) so dev/mock environments keep
//! working unchanged. Chain read errors fail OPEN with a warn log: the
//! gate exists to improve errors, not to add an availability dependency —
//! the worker-side failure still backstops whatever slips through.

use crate::error::ApiError;
use crate::state::AppState;
use alloy::primitives::{Address, U256};
use attestor_shared::traits::ChainClient;

/// 0.1 OG — the same floor the console's top-up gate uses.
const MIN_SANDBOX_BALANCE_WEI: U256 = U256::from_limbs([100_000_000_000_000_000u64, 0, 0, 0]);

/// Check trust-roots ack + sandbox balance for `owner`. `Ok(())` when both
/// pass or are unconfigured; `Err(402 …)` with code `trust_roots_not_acked`
/// or `insufficient_sandbox_balance` otherwise.
pub async fn check_owner_ready(state: &AppState, owner: Address) -> Result<(), ApiError> {
    check_inner(
        state.chain.as_ref(),
        owner,
        state.cfg.tapp_registry_addr,
        &[
            ("attestor", state.cfg.app_id.as_deref()),
            ("kms", state.cfg.kms_app_id.as_deref()),
            ("sandbox", state.cfg.sandbox_app_id.as_deref()),
        ],
        state.cfg.sandbox_serving_addr,
        state.cfg.sandbox_provider_addr,
    )
    .await
}

async fn check_inner(
    chain: &dyn ChainClient,
    owner: Address,
    registry: Address,
    slots: &[(&str, Option<&str>)],
    serving: Option<Address>,
    provider: Option<Address>,
) -> Result<(), ApiError> {
    // ── Trust roots ─────────────────────────────────────────────────
    if registry != Address::ZERO {
        let mut missing: Vec<String> = Vec::new();
        for (label, id) in slots {
            let Some(app_id) = id.filter(|s| !s.is_empty()) else {
                continue; // slot unconfigured — dev setups leave these blank
            };
            match chain.is_acknowledged(registry, owner, app_id).await {
                Ok(true) => {}
                Ok(false) => missing.push(format!("{app_id} ({label})")),
                Err(e) => {
                    tracing::warn!(%owner, app_id, "preflight ack read failed (failing open): {e:#}");
                }
            }
        }
        if !missing.is_empty() {
            return Err(ApiError::precondition(
                "trust_roots_not_acked",
                format!(
                    "trust roots not acknowledged for this wallet: {} — call TappRegistry.acknowledgeApps (console: the ack dialog; SDK: ack()) and retry",
                    missing.join(", ")
                ),
            ));
        }
    }

    // ── Prepaid sandbox balance ─────────────────────────────────────
    if let (Some(serving), Some(provider)) = (
        serving.filter(|a| *a != Address::ZERO),
        provider.filter(|a| *a != Address::ZERO),
    ) {
        match chain.sandbox_balance(serving, owner, provider).await {
            Ok(bal) if bal < MIN_SANDBOX_BALANCE_WEI => {
                return Err(ApiError::precondition(
                    "insufficient_sandbox_balance",
                    format!(
                        "prepaid sandbox balance is {bal} wei, below the 0.1 OG minimum — deposit via SandboxServing (console: top-up dialog; SDK: deposit()) and retry"
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(%owner, "preflight balance read failed (failing open): {e:#}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestor_shared::mocks::ConfigurableChain;

    fn addr(n: u8) -> Address {
        Address::repeat_byte(n)
    }
    const SLOTS: &[(&str, Option<&str>)] = &[
        ("attestor", Some("0g-attestor-dev")),
        ("kms", Some("0g-kms-dev")),
        ("sandbox", Some("0g-sandbox-provider-dev")),
    ];

    #[tokio::test]
    async fn passes_when_acked_and_funded() {
        let chain = ConfigurableChain::new(); // permissive defaults
        let r = check_inner(&chain, addr(9), addr(1), SLOTS, Some(addr(2)), Some(addr(3))).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn rejects_unacked_with_stable_code() {
        let chain = ConfigurableChain::new();
        chain.set_acked(false);
        let e = check_inner(&chain, addr(9), addr(1), SLOTS, Some(addr(2)), Some(addr(3)))
            .await
            .unwrap_err();
        assert_eq!(e.code, "trust_roots_not_acked");
        assert!(e.message.contains("0g-kms-dev"), "names every missing slot: {}", e.message);
    }

    #[tokio::test]
    async fn rejects_low_balance_with_stable_code() {
        let chain = ConfigurableChain::new();
        chain.set_sandbox_balance(U256::from(1u64)); // 1 wei < 0.1 OG
        let e = check_inner(&chain, addr(9), addr(1), SLOTS, Some(addr(2)), Some(addr(3)))
            .await
            .unwrap_err();
        assert_eq!(e.code, "insufficient_sandbox_balance");
    }

    #[tokio::test]
    async fn boundary_exactly_min_balance_passes() {
        let chain = ConfigurableChain::new();
        chain.set_sandbox_balance(MIN_SANDBOX_BALANCE_WEI);
        let r = check_inner(&chain, addr(9), addr(1), SLOTS, Some(addr(2)), Some(addr(3))).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn unconfigured_surfaces_self_disable() {
        // Hostile knobs but nothing configured: zero registry disables the
        // ack check, absent serving/provider disables the balance check.
        let chain = ConfigurableChain::new();
        chain.set_acked(false);
        chain.set_sandbox_balance(U256::ZERO);
        let r = check_inner(&chain, addr(9), Address::ZERO, SLOTS, None, None).await;
        assert!(r.is_ok());
    }
}
