// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ServeProof} from "./IAgenticIDReputationRegistry.sol";

/// @notice Opening of a ServeProof's `taskHash` commitment — the "receipt"
///         materials of the exact interaction that earned the proof. The
///         sealed proxy computes taskHash = keccak256(method ‖ requestURI ‖
///         keccak256(requestBody) ‖ keccak256(responseBody) ‖ decimal status),
///         so revealing these five values (bodies stay private — only their
///         hashes appear) lets the contract verify WHICH endpoint the
///         interaction hit, upgrading the client-declared endpoint/tag to a
///         TEE-verified fact. A malformed reveal (see the field docs) reverts
///         VerifiedFeedbackInvalidTaskReveal before the recompute.
struct TaskReveal {
    /// @dev HTTP method — must be one of the known set (GET/POST/PUT/PATCH/
    ///      DELETE/HEAD/OPTIONS). The whitelist closes the concatenation
    ///      ambiguity at the method‖uri boundary.
    string  method;
    /// @dev Request URI (path + query) — must start with '/'.
    string  uri;
    bytes32 reqBodyHash;
    bytes32 respBodyHash;
    /// @dev HTTP status — must be in 100..999 (exactly three decimal digits;
    ///      the range Go's net/http emits). The fixed width closes the
    ///      concatenation ambiguity at the respBodyHash‖status tail: a 1–2
    ///      digit status would let a reveal shift body-hash bytes into `uri`.
    uint16  statusCode;
}

/// @notice A ServeProof that carries its version. A v1 proof has no version
///         and goes through {ServeProof} and the v1 entry points; from v2 on
///         every proof names its version, and {attestVersionedFeedback} picks
///         the signed digest by it.
///
///         Version 2 (the 0g-harness layered runtime) keeps every v1 field and
///         adds what ran when the proof was signed: the sealed program and
///         the official harness (each a hash on the TrustRegistry's lists),
///         and where sealed's inference proxy forwarded and with which model
///         name. Like v1's dataHashes and frameworkHash, all four are CLAIMED
///         by the runtime and signed by agentSeal, not checked on chain.
struct VersionedServeProof {
    uint16    version;
    uint256   agentId;
    /// @dev The only address permitted to redeem this proof (== msg.sender).
    address   submitter;
    uint256   timestamp;
    uint256   deadline;
    bytes32   taskHash;
    bytes32[] dataHashes;
    /// @dev The image hash, i.e. base; same meaning as in v1.
    bytes32   frameworkHash;
    /// @dev sha256 of the sealed program the loader verified and ran.
    bytes32   sealedHash;
    /// @dev sha256 of the official harness package sealed started.
    bytes32   harnessHash;
    /// @dev The inference address sealed's proxy forwarded to ("" when the
    ///      framework wires its own provider).
    string    inferenceURL;
    /// @dev The model name the proxy forwarded with.
    string    model;
    bytes     signature;
}

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
    ///      are the audit data carried by the proof: CLAIMED by the agent's
    ///      runtime and signed by agentSeal, not checked on chain against the
    ///      agent's iData or the framework allowlist (see {getServeData});
    ///      taskHash is the TEE-signed interaction receipt (see {TaskReveal}).
    ///      `uri` is non-empty only when the receipt was opened and verified
    ///      on-chain (attestFeedbackWithTask) — the TEE-verified endpoint.
    event FeedbackVerified(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  indexed feedbackIndex,
        bytes32[]       dataHashes,
        bytes32         frameworkHash,
        bytes32         taskHash,
        string          uri
    );

    /// @notice A canonical entry was attested with a versioned proof. Emitted
    ///         right after {FeedbackVerified} for the same entry, so readers
    ///         that only know v1 still see every mark; this event adds the
    ///         fields v1 lacks.
    event VersionedFeedbackVerified(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  indexed feedbackIndex,
        uint16          version,
        bytes32         sealedHash,
        bytes32         harnessHash,
        string          inferenceURL,
        string          model
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Mark the caller's canonical feedback entry `feedbackIndex` for
    ///         `agentId` as backed by a TEE-signed ServeProof.
    /// @dev Verifies (in order): agentId matches proof.agentId;
    ///      proof.submitter == msg.sender (before signature recovery, so a
    ///      mismatched caller reverts cheaply); 0 < proof.timestamp ≤
    ///      proof.deadline; the ServeProof signature
    ///      against the agentSeal registered in the identity registry (inner
    ///      hash bound to this chain + identity registry + submitter, signed
    ///      as EIP-191 version 0x00 with THIS registry as the intended
    ///      validator — keccak256(0x19 ‖ 0x00 ‖ registry ‖ proofHash); legacy
    ///      personal_sign-wrapped proofs are rejected); the proof's nonce
    ///      (consumed — one proof attests at most one entry); the caller is
    ///      not the agent owner, an approved operator, the agent's payment
    ///      wallet, or the agent's agentSeal; the canonical entry exists for
    ///      msg.sender and its value is in range (|value| ≤ 1e9, ≤ 18
    ///      decimals); the entry is not already verified.
    ///      LEGACY(v1): for images that sign ServeProof v1 (a proof without a
    ///      version: the openclaw, hermes and prime-agent images, and 0g-harness
    ///      outside the layered flow). Once every running image signs v2, this
    ///      and attestFeedbackWithTask leave the ABI with
    ///      FeedbackBatcher.giveFeedbackAndAttest — a minor bump, no storage
    ///      change; v1 marks stay readable.
    function attestFeedback(uint256 agentId, uint64 feedbackIndex, ServeProof calldata proof) external;

    /// @notice Like {attestFeedback}, additionally opening the proof's
    ///         taskHash commitment: the contract recomputes the hash from the
    ///         revealed receipt materials and, on match, records `task.uri`
    ///         as the TEE-verified endpoint of this entry — enabling
    ///         trustless per-endpoint aggregation (getVerifiedSummaryForEndpoint).
    /// @dev Reverts VerifiedFeedbackInvalidTaskReveal when the method is
    ///      outside the known set, the uri lacks a leading '/', or statusCode
    ///      is outside 100..999; VerifiedFeedbackTaskMismatch when the
    ///      recomputed hash differs from proof.taskHash.
    ///      LEGACY(v1): see {attestFeedback}.
    function attestFeedbackWithTask(
        uint256 agentId,
        uint64 feedbackIndex,
        ServeProof calldata proof,
        TaskReveal calldata task
    ) external;

    /// @notice {attestFeedback} / {attestFeedbackWithTask} for a proof that
    ///         carries its version. Version 2 is the only one accepted.
    /// @dev Same checks, in the same order, as the v1 entry points, after a
    ///      VerifiedFeedbackUnsupportedVersion revert for any other version.
    ///      The signed digest is the version's (see the registry's
    ///      _serveProofHashV2), wrapped as v1's: EIP-191 version 0x00 with this
    ///      registry as the intended validator. An empty `task.method` skips
    ///      the receipt opening; otherwise the receipt is opened exactly as in
    ///      {attestFeedbackWithTask} and `task.uri` becomes the entry's
    ///      TEE-verified endpoint.
    function attestVersionedFeedback(
        uint256 agentId,
        uint64 feedbackIndex,
        VersionedServeProof calldata proof,
        TaskReveal calldata task
    ) external;

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice True if the canonical entry (agentId, clientAddress, feedbackIndex)
    ///         has been attested with a valid ServeProof.
    function isVerified(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bool);

    /// @notice Serve-proof audit data stored for a verified entry.
    /// @dev Both fields are as CLAIMED in the seal-signed ServeProof — the
    ///      registry checks the signature, not the content: dataHashes is not
    ///      compared with the agent's on-chain iData and frameworkHash is not
    ///      checked against AgenticID's framework allowlist (audit FIND-15).
    ///      Their weight is that only the agent's TEE runtime holds agentSeal.
    ///      Buyer due-diligence: compare dataHashes against
    ///      intelligentDatasOf(agentId) to see whether the agent's data changed
    ///      since this reputation was earned. Reverts if the entry is unverified.
    function getServeData(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash);

    /// @notice The sealed and harness hashes a versioned proof recorded for a
    ///         verified entry — both zero for an entry attested with a v1
    ///         proof. CLAIMED, like getServeData's fields: check them against
    ///         the TrustRegistry's lists off chain. Reverts if the entry is
    ///         unverified.
    /// @dev Zero hashes do not tell a v1 mark from a v2 one: a v2 proof may
    ///      claim zero hashes too, and the registry does not refuse them.
    ///      {VersionedFeedbackVerified}, emitted only for a versioned proof,
    ///      tells the versions apart.
    function getServeLayers(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bytes32 sealedHash, bytes32 harnessHash);

    /// @notice All verified canonical feedback indexes of `clientAddress` for `agentId`.
    function getVerifiedIndexes(uint256 agentId, address clientAddress)
        external view returns (uint64[] memory);

    /// @notice All clients with at least one verified entry for `agentId`.
    function getVerifiedClients(uint256 agentId) external view returns (address[] memory);

    /// @notice The TEE-verified endpoint of a verified entry — empty string
    ///         when the entry was attested without opening its task receipt.
    function getVerifiedEndpoint(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (string memory);

    /// @notice Aggregate the given clients' verified entries whose TEE-verified
    ///         endpoint equals `uri` (values read live from the canonical
    ///         registry; revoked and out-of-range entries skipped; sum +
    ///         count, 18 decimals). `clientAddresses` and `uri` must be
    ///         non-empty — same trust stance as getVerifiedSummary. Off-chain
    ///         eth_call only.
    function getVerifiedSummaryForEndpoint(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata uri
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals);

    /// @notice Aggregate the given clients' VERIFIED canonical feedback,
    ///         reading values live from the canonical registry (revoked entries
    ///         and entries outside |value| ≤ 1e9 / ≤ 18 decimals skipped — the
    ///         latter can only be marks from before 1.2.0; empty tag = wildcard). `clientAddresses` must be
    ///         non-empty — the caller picks whom to trust, mirroring ERC-8004
    ///         getSummary (verification proves a service call happened, not
    ///         that the client is unrelated to the owner).
    /// @dev O(verified entries × canonical reads) — off-chain eth_call only.
    ///      A client listed twice in `clientAddresses` is aggregated twice —
    ///      dedup is the caller's responsibility (matches the fork registry).
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
