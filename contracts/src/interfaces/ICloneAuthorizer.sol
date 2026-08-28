// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ICloneAuthorizer
/// @notice Policy contract that decides whether a `cloneFrom` mint may proceed.
///
///         The source agent's owner configures ONE authorizer per token via
///         `AgenticID.setCloneAuthorizer` (issue #133: marketplace-style fork
///         flows — "publisher issues once, users fork") and the trusted
///         attestor submits every policy-mode clone through
///         `AgenticID.cloneFrom`, which consults the configured authorizer
///         atomically with the mint.
///
///         Division of labor:
///           - identity authorization (ERC-721 approve / operator) answers
///             "WHO may act" — usable only by on-chain callers, because the
///             check is `msg.sender == approved`.
///           - THIS policy authorization answers "UNDER WHAT CONDITIONS may a
///             clone happen" — usable by the off-chain attestor, because the
///             verdict is readable on chain. The attestor's clone execution
///             (TEE re-seal) lives off-chain and can never be `msg.sender`,
///             so identity authorization cannot reach it (issue #133).
///
///         Power scope: an authorizer can ONLY answer true/false. It is called
///         via STATICCALL from `cloneFrom`, gains no on-chain privilege, and
///         cannot transfer, mutate or pause anything. ERC-721 operator
///         approval would be strictly broader (transfer authority) — hence a
///         separate, clone-only primitive.
///
/// @dev Implementations MUST be pure `view` and MUST NOT revert to signal
///      "deny" — return `false` instead. A reverting authorizer still fails
///      the clone closed, but its revert data BUBBLES from `cloneFrom`
///      unchanged (there is no try/catch around the consult) — clients see
///      the authorizer's own error, not `AgenticIDCloneDenied` (which is
///      reserved for an unconfigured/zero authorizer and a clean `false`).
///      Bubbling is deliberate: it preserves the authorizer's diagnostic
///      reason for the tx submitter. Returning `false` remains the
///      recommended deny path.
///
///      One-time semantics are NOT the authorizer's job: replay protection
///      lives in the attestor's idempotency key plus the marketplace's own
///      purchase records (a purchase = an entitlement = a clone). A market
///      that wants explicit on-chain consumption may watch `ClonedFrom`
///      events from its indexer. This split is sound under today's trust
///      model — the attestor is trusted to mint via `registerWithSeal`
///      anyway, so a `view` (non-consuming) policy adds no marginal trust;
///      if the attestor ever becomes less trusted (e.g. a multi-node
///      roadmap), a consuming (state-writing) authorizer variant becomes
///      the on-chain enforcement point and this interface should be
///      revisited.
///
///      Cross-chain and cross-deployment separation come from the call
///      environment: the authorizer is read from THIS AgenticID deployment's
///      storage on THIS chain, and `cloneFrom` only ever consults the
///      authorizer configured for the source it is cloning.
interface ICloneAuthorizer {
    /// @notice Decide whether the clone may be minted.
    /// @param sourceAgentId  the agent being forked (must equal the token the
    ///                       authorizer was configured on — enforced by the caller)
    /// @param targetOwner    wallet the clone will be minted to
    /// @param caller         wallet that initiated the off-chain `/clone` request
    ///                       (typically == targetOwner; kept separate for
    ///                       delegated-purchase flows)
    /// @param data           opaque bytes for the authorizer to interpret
    ///                       (e.g. abi-encoded purchase id, listing terms)
    /// @return allowed       whether the clone may proceed
    function canClone(
        uint256 sourceAgentId,
        address targetOwner,
        address caller,
        bytes calldata data
    ) external view returns (bool allowed);
}
