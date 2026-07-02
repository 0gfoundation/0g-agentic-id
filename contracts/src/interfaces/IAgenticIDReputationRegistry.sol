// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC8004ReputationRegistry} from "./IERC8004ReputationRegistry.sol";

/// @notice Proof of a real service interaction, signed by agentSeal inside the TEE.
/// @dev agentSeal private key never leaves TEE memory, so the owner cannot forge
///      this proof. dataHashes and frameworkHash are recorded as audit data —
///      they are part of the signed message and therefore trusted, but are NOT
///      re-verified against on-chain state at submission time.
///      Signed payload: keccak256(abi.encode(agentId, timestamp, deadline,
///          taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash)).
///      Replay protection: nonce key is keccak256("SERVEPROOF" ‖ agentId ‖ signature)
///      — the signature is unique per sealed payload so it doubles as the nonce.
///
///      No `client` binding: attribution is via msg.sender at submission time
///      (feedback is stored under the submitting address). The proof is a
///      bearer attestation that the agent served *a* task; whoever holds it
///      submits one feedback (single-use via the signature nonce).
struct ServeProof {
    uint256   agentId;
    uint256   timestamp;
    /// @dev Unix timestamp after which the proof is rejected at submission.
    uint256   deadline;
    bytes32   taskHash;
    /// @dev The data hashes the TEE was running when it performed this service.
    ///      Stored for buyer auditability: compare against intelligentDatasOf(agentId)
    ///      to see whether the agent's data has changed since this reputation was earned.
    ///      NOT verified against current on-chain state at submission time.
    bytes32[] dataHashes;
    /// @dev Hash of the AgenticID Framework code running in the TEE.
    ///      This is NOT the agent's orchestration framework (LangChain, AutoGen, etc.)
    ///      — that lives in the agent's config data.
    ///      Stored for auditability; not validated against any whitelist.
    bytes32   frameworkHash;
    /// @dev ECDSA signature over the fields above, signed by agentSeal.
    bytes     signature;
}

/// @notice Raised when giveFeedback is called without a ServeProof.
error AgenticIDProofRequired();

/// @title AgenticID Reputation Registry
/// @notice Extends ERC-8004 Reputation Registry to require a TEE-signed ServeProof
///         on every feedback submission, providing two guarantees:
///
///         1. Anti-Sybil: no real service call → no TEE-signed proof → no feedback accepted.
///
///         2. Data transparency: each reputation record stores dataHashes and
///            frameworkHash on-chain so buyers can compare them against the
///            agent's current intelligentDatasOf() result to determine whether
///            the agent's data has changed since that reputation was earned.
///
///         The base giveFeedback() without proof is DISABLED and always reverts.
interface IAgenticIDReputationRegistry is IERC8004ReputationRegistry {

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted alongside NewFeedback when feedback is submitted with a proof.
    /// @dev Carries the on-chain serve proof data needed for buyer verification.
    ///      feedbackIndex links this event to the corresponding NewFeedback entry.
    event FeedbackWithProof(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  indexed feedbackIndex,
        bytes32[]       dataHashes,
        bytes32         frameworkHash
    );

    // ── Disabled base function ────────────────────────────────────────────────

    /// @notice DISABLED — use giveFeedback(... ServeProof) instead.
    /// @dev Always reverts with AgenticIDProofRequired.
    function giveFeedback(
        uint256 agentId,
        int128  value,
        uint8   valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external override;

    // ── Extended functions ────────────────────────────────────────────────────

    /// @notice Submit feedback backed by a TEE-signed serve proof.
    /// @dev The contract verifies:
    ///      1. proof.signature is valid against the agentSeal registered for agentId.
    ///      2. proof.client == msg.sender.
    ///      The agentSeal signature alone proves TEE origin and binds the proof to the
    ///      specific data and framework that performed the service; dataHashes and
    ///      frameworkHash are stored as-is for auditability.
    ///      On success emits both NewFeedback (for ERC-8004 compatibility) and
    ///      FeedbackWithProof (carrying the on-chain serve data).
    function giveFeedback(
        uint256 agentId,
        int128  value,
        uint8   valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash,
        ServeProof calldata proof
    ) external;

    /// @notice Returns the serve proof data stored for a specific feedback entry.
    /// @dev Primary use: buyer due-diligence before purchasing an agent.
    ///      Compare returned dataHashes against intelligentDatasOf(agentId) to
    ///      determine whether the agent's data has changed since this reputation was earned.
    function getServeData(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash);
}
