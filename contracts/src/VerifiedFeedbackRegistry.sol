// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IVerifiedFeedbackRegistry, TaskReveal} from "./interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "./interfaces/IAgenticIDReputationRegistry.sol";
import {ICanonicalReputationRegistry} from "./interfaces/ICanonicalReputationRegistry.sol";
import {IAgenticID} from "./interfaces/IAgenticID.sol";
import {NonceRegistryUpgradeable} from "./utils/NonceRegistryUpgradeable.sol";

error VerifiedFeedbackNoAgentSeal();
/// @dev The signature does not recover to the agent's agentSeal over the
/// registry-bound digest (EIP-191 version 0x00, see `_serveProofDigest`). A
/// proof signed under the pre-1.2.0 personal_sign wrap (an old sealed image)
/// lands here too — there is no legacy fallback.
error VerifiedFeedbackInvalidProofSignature();
error VerifiedFeedbackNotPauser();
/// @dev The outer `agentId` does not match the agent the ServeProof attests to
/// (`proof.agentId`, whose seal signs it).
error VerifiedFeedbackProofAgentMismatch(uint256 agentId, uint256 proofAgentId);
/// @dev The proof was signed for a different redeemer — `proof.submitter` must
/// equal the attestFeedback caller. Closes front-running / proof theft.
error VerifiedFeedbackProofSubmitterMismatch(address submitter, address sender);
/// @dev ERC-8004: the agent owner, an approved operator, or the agent's own
/// agentSeal must not attest feedback on their own agent. Conformance guard,
/// not sybil resistance (a determined owner can still self-rate from an
/// unrelated second wallet — including a fresh wallet the seal funds).
error VerifiedFeedbackSelfFeedback(uint256 agentId, address submitter);
/// @dev No canonical feedback entry exists at (agentId, msg.sender, feedbackIndex)
/// — index 0, or beyond the client's last canonical index.
error VerifiedFeedbackNoSuchEntry(uint256 agentId, address clientAddress, uint64 feedbackIndex, uint64 lastIndex);
/// @dev The canonical entry already carries a verification mark.
error VerifiedFeedbackAlreadyVerified(uint256 agentId, address clientAddress, uint64 feedbackIndex);
/// @dev The queried entry has no verification mark.
error VerifiedFeedbackNotVerified(uint256 agentId, address clientAddress, uint64 feedbackIndex);
/// @dev getVerifiedSummary requires an explicit, non-empty clientAddresses set.
error VerifiedFeedbackClientsRequired();
/// @dev The revealed receipt materials don't hash to the proof's taskHash.
error VerifiedFeedbackTaskMismatch(bytes32 expected, bytes32 actual);
/// @dev Malformed task reveal: method outside the known HTTP set, a URI not
/// starting with '/', or a statusCode outside 100..999. The first two close
/// the concatenation ambiguity at the method‖uri boundary of the taskHash
/// preimage; the fixed 3-digit status closes it at the respBodyHash‖status
/// tail.
error VerifiedFeedbackInvalidTaskReveal();
/// @dev A summary summation exceeded int128 — unreachable given canonical's
/// bounded writes (|value| ≤ 1e38 is still bounded after 18-decimal
/// normalization only for ≤ 18-decimal values; the guard keeps a would-be
/// silent truncation a clean revert).
error VerifiedFeedbackSummaryOverflow();

/// @title Verified Feedback Registry
/// @notice TEE-verification layer over the official ERC-8004 Reputation
///         Registry — see {IVerifiedFeedbackRegistry} for the architecture.
///         Feedback storage and per-client attribution live in the canonical
///         registry; this contract records which canonical entries were backed
///         by a TEE-signed ServeProof, plus the proof's audit data
///         (dataHashes, frameworkHash).
///
/// @dev Since 1.2.0 the signed ServeProof digest is BOUND TO THIS REGISTRY:
///      agentSeal signs keccak256(0x19 ‖ 0x00 ‖ address(this) ‖ proofHash)
///      raw — EIP-191 version 0x00, "data with intended validator"
///      (address(this) is the proxy under the beacon delegatecall). The inner
///      proofHash is unchanged, still bound to (chainId, identityRegistry,
///      submitter). Two consequences:
///        - The sealed sign socket only produces personal_sign (0x19 0x45 …),
///          typed_data (0x19 0x01 …) and socket-built transaction preimages,
///          so the agent process cannot forge a ServeProof offline by asking
///          its own socket to sign a chosen proofHash (audit FIND-01). This
///          rests on a sealed-side invariant: the socket must never offer
///          raw-hash or version-0x00 signing.
///        - A proof redeems on exactly one registry. Neither the deprecated
///          AgenticIDReputationRegistry (still on the legacy personal_sign
///          wrap — it must be paused) nor a second VerifiedFeedbackRegistry
///          instance anchored to the same pair recovers the seal from it
///          (FIND-16). Readers still pin ONE registry address per deployment
///          (DEPLOYMENT.md §6) — marks live per instance.
///      Residual, not closed here: the agent can still obtain GENUINE proofs
///      by calling its own proxy with a client address it controls — the
///      documented sybil class (see the self-feedback guard).
contract VerifiedFeedbackRegistry is
    IVerifiedFeedbackRegistry,
    OwnableUpgradeable,
    PausableUpgradeable,
    NonceRegistryUpgradeable
{
    using ECDSA for bytes32;

    /// @notice Current implementation version. See contracts/UPGRADING.md for
    ///         the bump rules.
    /// @dev 1.2.0 — ServeProof hardening (beacon upgrade; storage and ABI
    ///      unchanged, but consensus-critical — ships with new sealed images +
    ///      SDK in one window): the signed digest becomes EIP-191 version 0x00
    ///      bound to this registry (toDataWithIntendedValidatorHash(address(this),
    ///      proofHash)); legacy personal_sign-wrapped proofs are rejected, no
    ///      fallback (audit FIND-01 / FIND-16). attestFeedbackWithTask requires
    ///      statusCode in 100..999 (FIND-02). The agent's own agentSeal may not
    ///      attest (VerifiedFeedbackSelfFeedback). Marks attested before an
    ///      environment's 1.2.0 upgrade block carry no FIND-01 / FIND-02
    ///      guarantee: their recorded audit data and verified endpoint are not
    ///      assured to be authentic. That block is recorded per environment in
    ///      contracts/DEPLOYMENT.md §6; readers and indexers should drop
    ///      FeedbackVerified logs below it.
    ///      1.1.0 — task-receipt opening (beacon upgrade): attestFeedbackWithTask
    ///      recomputes the proof's taskHash from revealed receipt materials and
    ///      records the URI as the entry's TEE-verified endpoint; new views
    ///      getVerifiedEndpoint / getVerifiedSummaryForEndpoint; FeedbackVerified
    ///      gains taskHash + uri fields (ABI change); ServeData gains a trailing
    ///      `uri` field (mapping-stored struct — append-safe, old entries read "").
    ///      1.0.0 — initial: attest-only companion to the canonical ERC-8004
    ///      Reputation Registry, replacing the AgenticIDReputationRegistry fork.
    string public constant VERSION = "1.2.0";

    /// @dev Nonce-key tag — same keccak256(tag, agentId, signature) derivation
    ///      as the fork registry (each registry keeps its own nonce store). The
    ///      signed DIGEST is no longer shared with the fork since 1.2.0 (see
    ///      `_serveProofDigest`).
    bytes32 private constant _SERVEPROOF_TAG = keccak256("SERVEPROOF");

    event PauserUpdated(address indexed previousPauser, address indexed newPauser);

    // ── Storage ───────────────────────────────────────────────────────────────

    struct ServeData {
        bool      exists;
        bytes32   frameworkHash;
        bytes32[] dataHashes;
        /// @dev TEE-verified endpoint (task receipt opened on-chain); "" when
        ///      the entry was attested without a reveal. Appended in 1.1.0 —
        ///      mapping-stored struct, so old entries read the zero value.
        string    uri;
    }

    /// @custom:storage-location erc7201:0g.storage.VerifiedFeedbackRegistry
    struct VerifiedFeedbackStorage {
        address identityRegistry;      // AgenticID — seal lookup + owner checks
        address canonicalReputation;   // official ERC-8004 Reputation Registry

        // agentId → client → canonical feedbackIndex → proof audit data
        mapping(uint256 => mapping(address => mapping(uint64 => ServeData))) verified;
        // agentId → client → list of verified canonical indexes (for enumeration)
        mapping(uint256 => mapping(address => uint64[])) verifiedIndexes;
        // agentId → clients with at least one verified entry
        mapping(uint256 => address[]) verifiedClients;
        mapping(uint256 => mapping(address => bool)) isVerifiedClient;

        address pauser;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.VerifiedFeedbackRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VerifiedFeedbackStorageLocation =
        0xa91e4c2ef61514299267811101bdc16c30719384e3b85c6fa8328f091e37e100;

    function _getVerifiedFeedbackStorage() private pure returns (VerifiedFeedbackStorage storage $) {
        assembly {
            $.slot := VerifiedFeedbackStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function initialize(
        address identityRegistry_,
        address canonicalReputation_,
        address owner_,
        address pauser_,
        uint256 maxProofAge_
    ) external initializer {
        require(identityRegistry_ != address(0), "identityRegistry=0");
        require(canonicalReputation_ != address(0), "canonicalReputation=0");
        __Ownable_init(owner_);
        __Pausable_init();
        __NonceRegistry_init_unchained(maxProofAge_);
        VerifiedFeedbackStorage storage $ = _getVerifiedFeedbackStorage();
        $.identityRegistry = identityRegistry_;
        $.canonicalReputation = canonicalReputation_;
        $.pauser = pauser_;
        emit PauserUpdated(address(0), pauser_);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setMaxProofAge(uint256 maxProofAge_) external onlyOwner {
        _setNonceMaxAge(maxProofAge_);
    }

    function cleanExpiredNonces(bytes32[] calldata keys) external {
        _cleanExpiredNonces(keys);
    }

    // ── Pauser ────────────────────────────────────────────────────────────────

    function pauser() external view returns (address) {
        return _getVerifiedFeedbackStorage().pauser;
    }

    function setPauser(address newPauser) external onlyOwner {
        VerifiedFeedbackStorage storage $ = _getVerifiedFeedbackStorage();
        emit PauserUpdated($.pauser, newPauser);
        $.pauser = newPauser;
    }

    function pause() external {
        if (msg.sender != _getVerifiedFeedbackStorage().pauser) revert VerifiedFeedbackNotPauser();
        _pause();
    }

    function unpause() external {
        if (msg.sender != _getVerifiedFeedbackStorage().pauser) revert VerifiedFeedbackNotPauser();
        _unpause();
    }

    // ── IVerifiedFeedbackRegistry — write ─────────────────────────────────────

    function attestFeedback(uint256 agentId, uint64 feedbackIndex, ServeProof calldata proof)
        external whenNotPaused
    {
        _attest(agentId, feedbackIndex, proof, "");
    }

    function attestFeedbackWithTask(
        uint256 agentId,
        uint64 feedbackIndex,
        ServeProof calldata proof,
        TaskReveal calldata task
    ) external whenNotPaused {
        // Open the taskHash commitment: recompute it from the revealed receipt
        // materials exactly as the sealed proxy built it — keccak256(method ‖
        // uri ‖ reqBodyHash ‖ respBodyHash ‖ decimal statusCode). The hash is
        // inside the seal-signed digest, so a match proves the interaction hit
        // `task.uri`. encodePacked is ambiguous at both variable-width ends:
        // method whitelist + leading '/' pin the method‖uri boundary, and a
        // fixed 3-digit status pins the tail — a 1–2 digit status would let a
        // reveal shift body-hash bytes into `uri` (FIND-02). 100..999 is what
        // Go's net/http emits, so no genuine receipt is orphaned.
        if (!_isKnownMethod(task.method)) revert VerifiedFeedbackInvalidTaskReveal();
        bytes memory uriBytes = bytes(task.uri);
        if (uriBytes.length == 0 || uriBytes[0] != "/") revert VerifiedFeedbackInvalidTaskReveal();
        if (task.statusCode < 100 || task.statusCode > 999) revert VerifiedFeedbackInvalidTaskReveal();
        bytes32 recomputed = keccak256(abi.encodePacked(
            bytes(task.method),
            uriBytes,
            task.reqBodyHash,
            task.respBodyHash,
            bytes(Strings.toString(uint256(task.statusCode)))
        ));
        if (recomputed != proof.taskHash) revert VerifiedFeedbackTaskMismatch(proof.taskHash, recomputed);

        _attest(agentId, feedbackIndex, proof, task.uri);
    }

    /// @dev Shared attest routine. `verifiedUri` is "" for the plain path and
    ///      the receipt-opened endpoint for attestFeedbackWithTask.
    function _attest(
        uint256 agentId,
        uint64 feedbackIndex,
        ServeProof calldata proof,
        string memory verifiedUri
    ) internal {
        // The verification mark is stored under the outer `agentId`, but the
        // proof is verified against `proof.agentId` (the agent whose seal signs
        // it). Require them to match — otherwise a valid proof for agent A
        // could mark entries on any other agent B.
        if (agentId != proof.agentId) revert VerifiedFeedbackProofAgentMismatch(agentId, proof.agentId);
        address agentSeal = _verifyServeProof(proof);

        // ERC-8004 conformance: the attester must not be the agent owner, an
        // approved operator, or the agent's own agentSeal. Conformance guard,
        // NOT sybil resistance — the serve proof is obtainable from the
        // unauthenticated /hello, so a determined owner can still self-rate
        // from an unrelated second wallet (and the agent from a fresh wallet
        // its seal funds). msg.sender == proof.submitter here (enforced
        // above), so this checks the real redeemer.
        if (msg.sender == agentSeal || _isOwnerOrApproved(agentId, msg.sender))
            revert VerifiedFeedbackSelfFeedback(agentId, msg.sender);

        VerifiedFeedbackStorage storage $ = _getVerifiedFeedbackStorage();

        // The canonical entry must exist AND belong to the caller — canonical
        // attribution is msg.sender there too, so (agentId, msg.sender,
        // feedbackIndex) names exactly the entry the caller submitted.
        uint64 lastIndex = ICanonicalReputationRegistry($.canonicalReputation).getLastIndex(agentId, msg.sender);
        if (feedbackIndex == 0 || feedbackIndex > lastIndex) {
            revert VerifiedFeedbackNoSuchEntry(agentId, msg.sender, feedbackIndex, lastIndex);
        }

        // One mark per entry. Distinct from the nonce (which is per proof):
        // two different proofs must not stack marks on one entry either.
        ServeData storage slot_ = $.verified[agentId][msg.sender][feedbackIndex];
        if (slot_.exists) revert VerifiedFeedbackAlreadyVerified(agentId, msg.sender, feedbackIndex);

        slot_.exists = true;
        slot_.frameworkHash = proof.frameworkHash;
        slot_.dataHashes = proof.dataHashes;
        slot_.uri = verifiedUri;
        $.verifiedIndexes[agentId][msg.sender].push(feedbackIndex);

        if (!$.isVerifiedClient[agentId][msg.sender]) {
            $.isVerifiedClient[agentId][msg.sender] = true;
            $.verifiedClients[agentId].push(msg.sender);
        }

        emit FeedbackVerified(
            agentId, msg.sender, feedbackIndex,
            proof.dataHashes, proof.frameworkHash, proof.taskHash, verifiedUri
        );
    }

    /// @dev The known HTTP methods a task reveal may claim — closes the
    ///      method‖uri concatenation ambiguity (a shifted split would need a
    ///      "method" outside this set or a URI without a leading '/').
    function _isKnownMethod(string calldata method) private pure returns (bool) {
        bytes32 h = keccak256(bytes(method));
        return h == keccak256("GET") || h == keccak256("POST") || h == keccak256("PUT")
            || h == keccak256("PATCH") || h == keccak256("DELETE") || h == keccak256("HEAD")
            || h == keccak256("OPTIONS");
    }

    // ── IVerifiedFeedbackRegistry — read ──────────────────────────────────────

    function isVerified(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bool)
    {
        return _getVerifiedFeedbackStorage().verified[agentId][clientAddress][feedbackIndex].exists;
    }

    function getServeData(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash)
    {
        ServeData storage d = _getVerifiedFeedbackStorage().verified[agentId][clientAddress][feedbackIndex];
        if (!d.exists) revert VerifiedFeedbackNotVerified(agentId, clientAddress, feedbackIndex);
        return (d.dataHashes, d.frameworkHash);
    }

    function getVerifiedIndexes(uint256 agentId, address clientAddress)
        external view returns (uint64[] memory)
    {
        return _getVerifiedFeedbackStorage().verifiedIndexes[agentId][clientAddress];
    }

    function getVerifiedClients(uint256 agentId) external view returns (address[] memory) {
        return _getVerifiedFeedbackStorage().verifiedClients[agentId];
    }

    function getVerifiedEndpoint(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external view returns (string memory)
    {
        ServeData storage d = _getVerifiedFeedbackStorage().verified[agentId][clientAddress][feedbackIndex];
        if (!d.exists) revert VerifiedFeedbackNotVerified(agentId, clientAddress, feedbackIndex);
        return d.uri;
    }

    /// @dev Same shape and caveats as getVerifiedSummary, additionally
    ///      filtering to entries whose TEE-verified endpoint equals `uri`
    ///      (entries attested without a task reveal never match — their
    ///      endpoint is unproven). Off-chain eth_call only.
    function getVerifiedSummaryForEndpoint(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata uri
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {
        if (clientAddresses.length == 0) revert VerifiedFeedbackClientsRequired();
        VerifiedFeedbackStorage storage $ = _getVerifiedFeedbackStorage();
        ICanonicalReputationRegistry canonical_ = ICanonicalReputationRegistry($.canonicalReputation);
        bytes32 uriHash = keccak256(bytes(uri));

        summaryValueDecimals = 18;
        int256 acc;
        for (uint256 i = 0; i < clientAddresses.length; i++) {
            address client = clientAddresses[i];
            uint64[] storage indexes = $.verifiedIndexes[agentId][client];
            for (uint256 j = 0; j < indexes.length; j++) {
                if (keccak256(bytes($.verified[agentId][client][indexes[j]].uri)) != uriHash) continue;
                (int128 value, uint8 valueDecimals, , , bool revoked) =
                    canonical_.readFeedback(agentId, client, indexes[j]);
                if (revoked) continue;
                count++;
                acc += _normalizeTo18(value, valueDecimals);
            }
        }
        if (acc < type(int128).min || acc > type(int128).max) revert VerifiedFeedbackSummaryOverflow();
        summaryValue = int128(acc);
    }

    /// @dev O(verified entries × external canonical reads), unbounded and
    ///      unpaginated — intended for off-chain / indexer reads (eth_call),
    ///      not on-chain consumption.
    function getVerifiedSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {
        // Mirrors ERC-8004 getSummary: the caller picks whom to trust. A
        // verification mark proves a service call happened, not that the
        // client is unrelated to the owner, so an all-clients aggregate would
        // still fold in owner-driven self-ratings from secondary wallets.
        if (clientAddresses.length == 0) revert VerifiedFeedbackClientsRequired();
        VerifiedFeedbackStorage storage $ = _getVerifiedFeedbackStorage();
        ICanonicalReputationRegistry canonical_ = ICanonicalReputationRegistry($.canonicalReputation);

        summaryValueDecimals = 18;
        int256 acc;
        for (uint256 i = 0; i < clientAddresses.length; i++) {
            address client = clientAddresses[i];
            uint64[] storage indexes = $.verifiedIndexes[agentId][client];
            for (uint256 j = 0; j < indexes.length; j++) {
                (int128 value, uint8 valueDecimals, string memory t1, string memory t2, bool revoked) =
                    canonical_.readFeedback(agentId, client, indexes[j]);
                if (revoked) continue;
                if (!_tagMatches(t1, tag1)) continue;
                if (!_tagMatches(t2, tag2)) continue;
                count++;
                acc += _normalizeTo18(value, valueDecimals);
            }
        }
        if (acc < type(int128).min || acc > type(int128).max) revert VerifiedFeedbackSummaryOverflow();
        summaryValue = int128(acc);
    }

    function getIdentityRegistry() external view returns (address) {
        return _getVerifiedFeedbackStorage().identityRegistry;
    }

    function getCanonicalReputation() external view returns (address) {
        return _getVerifiedFeedbackStorage().canonicalReputation;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// @dev Verifies the ServeProof signature against the agent's agentSeal AND
    ///      consumes the nonce (derived from signature bytes) via NonceRegistry;
    ///      returns the agentSeal. State-mutating despite the "verify" name —
    ///      this is the single entrypoint that guarantees each ServeProof is
    ///      redeemed at most once here. The nonce-key derivation matches the
    ///      fork registry's; the signed digest does not since 1.2.0 (bound to
    ///      this registry — `_serveProofDigest`).
    function _verifyServeProof(ServeProof calldata proof) internal returns (address agentSeal) {
        // Only the address the proof was signed for may redeem it — the
        // front-running / theft guard. Checked before signature recovery so a
        // mismatched caller reverts cheaply.
        if (proof.submitter != msg.sender)
            revert VerifiedFeedbackProofSubmitterMismatch(proof.submitter, msg.sender);

        address identityRegistry = _getVerifiedFeedbackStorage().identityRegistry;
        agentSeal = IAgenticID(identityRegistry).getAgentSeal(proof.agentId);
        if (agentSeal == address(0)) revert VerifiedFeedbackNoAgentSeal();

        // Registry binding: the validator is this proxy, so the digest is one
        // the sign socket never produces and no other registry accepts.
        bytes32 digest = _serveProofDigest(
            address(this), _serveProofHash(block.chainid, identityRegistry, proof)
        );
        if (digest.recover(proof.signature) != agentSeal)
            revert VerifiedFeedbackInvalidProofSignature();

        // Replay protection: signature is unique per sealed payload.
        bytes32 nonceKey = keccak256(abi.encode(_SERVEPROOF_TAG, proof.agentId, proof.signature));
        _checkAndMarkNonce(nonceKey, proof.deadline);
    }

    /// @dev The ServeProof's inner hash (unchanged by 1.2.0). Domain +
    ///      submitter separation: chainId and the identity registry make the
    ///      proof non-portable across chains and protocol deployments;
    ///      `submitter` makes it non-transferable. Fixed-width words only, so
    ///      abi.encode has no encoding ambiguity. Consensus-critical — the
    ///      sealed proxy and the SDK compute it independently (cross-impl
    ///      known-answer vector in test/VerifiedFeedback.t.sol).
    function _serveProofHash(uint256 chainId, address identityRegistry, ServeProof calldata proof)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(
            chainId,
            identityRegistry,
            proof.submitter,
            proof.agentId,
            proof.timestamp,
            proof.deadline,
            proof.taskHash,
            keccak256(abi.encodePacked(proof.dataHashes)),
            proof.frameworkHash
        ));
    }

    /// @dev The digest agentSeal signs — RAW, with no further EIP-191 wrap:
    ///      EIP-191 version 0x00 ("data with intended validator"),
    ///      keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash), validator = the
    ///      registry proxy. The 0x00 version byte separates it from every
    ///      preimage the sealed sign socket signs (personal_sign 0x19 0x45,
    ///      typed_data 0x19 0x01, socket-built transactions), so a
    ///      personal_sign over the same proofHash does not verify (FIND-01).
    function _serveProofDigest(address validator, bytes32 proofHash) internal pure returns (bytes32) {
        return MessageHashUtils.toDataWithIntendedValidatorHash(validator, abi.encodePacked(proofHash));
    }

    /// @dev True if `addr` is the agent owner or an ERC-721 approved operator.
    ///      Checked against the LOCAL AgenticID owner — the canonical registry
    ///      cannot enforce this itself (it sees the AgenticID contract as the
    ///      owner of every custody-bound token). The agent is known to exist
    ///      here (its seal signed a verified proof), so ownerOf does not revert.
    function _isOwnerOrApproved(uint256 agentId, address addr) private view returns (bool) {
        IAgenticID id = IAgenticID(_getVerifiedFeedbackStorage().identityRegistry);
        address owner = id.ownerOf(agentId);
        return addr == owner
            || id.getApproved(agentId) == addr
            || id.isApprovedForAll(owner, addr);
    }

    /// @dev Empty filter = wildcard (matches any stored value).
    function _tagMatches(string memory stored, string calldata filter) private pure returns (bool) {
        if (bytes(filter).length == 0) return true;
        return keccak256(bytes(stored)) == keccak256(bytes(filter));
    }

    /// @dev Normalize a feedback value to 18 decimals, returning int256 so no
    ///      single entry can overflow. decimals above 18+77 round to zero
    ///      rather than overflowing 10**().
    function _normalizeTo18(int128 value, uint8 decimals) private pure returns (int256) {
        if (decimals == 18) return value;
        if (decimals < 18) return int256(value) * int256(10 ** (18 - decimals));
        uint256 shift = uint256(decimals) - 18;
        if (shift > 77) return 0; // 10**78 exceeds uint256 max; the value underflows to 0 anyway
        return int256(value) / int256(10 ** shift);
    }
}
