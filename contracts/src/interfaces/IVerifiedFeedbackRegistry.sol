// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ServeProof} from "./IAgenticIDReputationRegistry.sol";

/// @title Verified Feedback Registry
/// @notice TEE-verification layer over the **official** ERC-8004 Reputation
///         Registry. Feedback itself lives in the canonical registry (clients
///         call its `giveFeedback` directly, so per-client attribution is
///         native and every ERC-8004 reader sees it); this contract only
///         records which of those canonical entries were backed by a real
///         service interaction — a TEE-signed ServeProof.
///
///         Flow (two calls by the same client, SDK-bundled):
///           1. client → canonicalReputation.giveFeedback(agentId, …)
///           2. client → attestFeedback(agentId, lastIndex, proof)
///
///         Readers that care about authenticity intersect the canonical
///         entries with this contract's verified set (events, `isVerified`,
///         or the `getVerifiedSummary` eth_call helper). Entries without a
///         verification mark are unauthenticated noise — the canonical
///         registry is permissionless and accepts feedback from anyone.
interface IVerifiedFeedbackRegistry {

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice A canonical feedback entry passed ServeProof verification.
    /// @dev (agentId, clientAddress, feedbackIndex) identifies the entry in the
    ///      canonical ERC-8004 Reputation Registry. dataHashes/frameworkHash
    ///      are the audit data carried by the proof (signed by agentSeal).
    event FeedbackVerified(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  indexed feedbackIndex,
        bytes32[]       dataHashes,
        bytes32         frameworkHash
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Mark the caller's canonical feedback entry `feedbackIndex` for
    ///         `agentId` as backed by a TEE-signed ServeProof.
    /// @dev Verifies (in order): agentId matches proof.agentId; the ServeProof
    ///      signature against the agentSeal registered in the identity registry
    ///      (digest bound to this chain + identity registry + submitter);
    ///      proof.submitter == msg.sender; the caller is not the agent owner or
    ///      an approved operator; the canonical entry exists for msg.sender;
    ///      the entry is not already verified. Consumes the proof's nonce —
    ///      one proof attests at most one entry.
    function attestFeedback(uint256 agentId, uint64 feedbackIndex, ServeProof calldata proof) external;

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice True if the canonical entry (agentId, clientAddress, feedbackIndex)
    ///         has been attested with a valid ServeProof.
    function isVerified(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bool);

    /// @notice Serve-proof audit data stored for a verified entry.
    /// @dev Buyer due-diligence: compare dataHashes against
    ///      intelligentDatasOf(agentId) to see whether the agent's data changed
    ///      since this reputation was earned. Reverts if the entry is unverified.
    function getServeData(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash);

    /// @notice All verified canonical feedback indexes of `clientAddress` for `agentId`.
    function getVerifiedIndexes(uint256 agentId, address clientAddress)
        external view returns (uint64[] memory);

    /// @notice All clients with at least one verified entry for `agentId`.
    function getVerifiedClients(uint256 agentId) external view returns (address[] memory);

    /// @notice Aggregate the given clients' VERIFIED canonical feedback,
    ///         reading values live from the canonical registry (revoked entries
    ///         skipped, empty tag = wildcard). `clientAddresses` must be
    ///         non-empty — the caller picks whom to trust, mirroring ERC-8004
    ///         getSummary (verification proves a service call happened, not
    ///         that the client is unrelated to the owner).
    /// @dev O(verified entries × canonical reads) — off-chain eth_call only.
    function getVerifiedSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals);

    /// @notice The AgenticID identity registry proofs are verified against.
    function getIdentityRegistry() external view returns (address);

    /// @notice The official ERC-8004 Reputation Registry entries are anchored to.
    function getCanonicalReputation() external view returns (address);
}
