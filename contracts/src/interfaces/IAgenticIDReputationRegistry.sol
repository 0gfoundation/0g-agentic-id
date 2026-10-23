// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC8004ReputationRegistry} from "./IERC8004ReputationRegistry.sol";

/// @notice Proof of a real service interaction, signed by agentSeal inside the TEE.
/// @dev The agentSeal private key never leaves TEE memory — but key custody
///      alone does NOT make this proof unforgeable: the agent process inside
///      the TEE can have the sealed sign socket sign messages with agentSeal,
///      so the verifier's signed digest must be a preimage the socket never
///      produces. dataHashes and frameworkHash are recorded as audit data —
///      they are part of the signed message and therefore trusted, but are NOT
///      re-verified against on-chain state at submission time.
///      Inner hash: proofHash = keccak256(abi.encode(block.chainid,
///          identityRegistry, submitter, agentId, timestamp, deadline, taskHash,
///          keccak256(abi.encodePacked(dataHashes)), frameworkHash)).
///      Signed digest (signed raw) depends on the verifier:
///        - VerifiedFeedbackRegistry >= 1.2.0: keccak256(0x19 ‖ 0x00 ‖
///          registry proxy ‖ proofHash) — EIP-191 version 0x00, bound to that
///          one registry. The sign socket only signs 0x19 0x45 (personal_sign),
///          0x19 0x01 (typed_data) or socket-built transaction preimages, so
///          the agent cannot forge it offline.
///        - the DEPRECATED AgenticIDReputationRegistry: the legacy
///          toEthSignedMessageHash(proofHash) personal_sign wrap — exactly what
///          the socket's /sign/personal_sign returns for a 32-byte message, so
///          the agent process CAN forge proofs this fork accepts (audit
///          FIND-01). Live fork instances must be paused.
///      Replay protection: nonce key is keccak256("SERVEPROOF" ‖ agentId ‖ signature)
///      — the signature is unique per sealed payload so it doubles as the nonce.
///
///      Domain + submitter binding: the digest fixes the proof to one
///      chain (block.chainid), one protocol deployment (the identity registry
///      the reputation contract is bound to), and one redeemer (`submitter`).
///      A copied proof is worthless to anyone else — a different chain /
///      identity registry makes the recovered signer mismatch, and a different
///      caller fails `submitter == msg.sender`. `submitter` is the address the
///      client declared to the TEE at signing time (echoed from the request);
///      it is NOT identity-verified and does not need to be — the on-chain
///      `submitter == msg.sender` check is itself proof of control, so only the
///      declared address can ever redeem. Attribution (which address the entry
///      is stored under) remains msg.sender at submission.
struct ServeProof {
    uint256   agentId;
    /// @dev The only address permitted to redeem this proof — the client that
    ///      declared it to the TEE. Bound into the signature and enforced as
    ///      `== msg.sender` at giveFeedback; closes front-running / proof theft.
    address   submitter;
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
    /// @dev ECDSA signature by agentSeal over the verifier's signed digest of
    ///      the fields above (see the struct natspec — differs per verifier).
    bytes     signature;
}

/// @notice Raised when giveFeedback is called without a ServeProof.
error AgenticIDProofRequired();

/// @title AgenticID Reputation Registry
/// @notice DEPRECATED — superseded by VerifiedFeedbackRegistry. It still
///         verifies the legacy personal_sign ServeProof digest, which the agent
///         process can obtain for any proofHash from its own sign socket (audit
///         FIND-01), so guarantee 1 below does NOT hold: live instances must be
///         paused by their pauser no later than the VerifiedFeedbackRegistry
///         1.2.0 cut. Original design:
///
///         Extends ERC-8004 Reputation Registry to require a TEE-signed ServeProof
///         on every feedback submission, providing two guarantees:
///
///         1. Anti-Sybil (as designed): no real service call → no TEE-signed proof → no feedback accepted.
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
    ///      1. proof.signature is valid against the agentSeal registered for agentId,
    ///         over a digest bound to this chain + identity registry (legacy
    ///         personal_sign wrap — see the ServeProof natspec).
    ///      2. proof.submitter == msg.sender (only the declared client may redeem).
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
