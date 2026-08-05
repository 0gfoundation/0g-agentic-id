// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IAgenticIDReputationRegistry, ServeProof, AgenticIDProofRequired} from "./interfaces/IAgenticIDReputationRegistry.sol";
import {IAgenticID} from "./interfaces/IAgenticID.sol";
import {NonceRegistryUpgradeable} from "./utils/NonceRegistryUpgradeable.sol";

error ReputationNoAgentSeal();
error ReputationInvalidProofSignature();
error ReputationInvalidIndex(uint256 index, uint256 length);
error ReputationAlreadyRevoked();
error ReputationNotAgentOwner();
error ReputationAlreadyResponded();
error ReputationNotPauser();
/// @dev The outer `agentId` (where feedback is stored) does not match the
/// agent the ServeProof attests to (`proof.agentId`, whose seal signs it).
error ReputationProofAgentMismatch(uint256 agentId, uint256 proofAgentId);
/// @dev Feedback `value` outside [-MAX_ABS_VALUE, MAX_ABS_VALUE].
error ReputationValueOutOfRange(int128 value);
/// @dev `valueDecimals` above 18 — outside the 18-decimal normalization window.
error ReputationValueDecimalsTooLarge(uint8 valueDecimals);
/// @dev A tag/client summation exceeded int128 — unreachable given bounded writes.
error ReputationSummaryOverflow();
/// @dev getSummary requires an explicit, non-empty clientAddresses set per ERC-8004.
error ReputationClientsRequired();
/// @dev The proof was signed for a different redeemer — `proof.submitter` must
/// equal the giveFeedback caller. Closes front-running / proof theft.
error ReputationProofSubmitterMismatch(address submitter, address sender);

/// @title AgenticID Reputation Registry
/// @notice Stores feedback for AgenticID agents, requiring a TEE-signed ServeProof
///         on every submission to prevent sybil attacks.
contract AgenticIDReputationRegistry is
    IAgenticIDReputationRegistry,
    OwnableUpgradeable,
    PausableUpgradeable,
    NonceRegistryUpgradeable
{
    using ECDSA for bytes32;

    /// @notice Current implementation version. See contracts/UPGRADING.md for the
    ///         bump rules (major = storage-incompatible/redeploy; minor = ABI/behavior
    ///         change via a beacon upgrade; patch = compatible fix).
    /// @dev 1.2.0 — audit security fixes (beacon upgrade): giveFeedback requires
    ///      `agentId == proof.agentId`, bounds `value`/`valueDecimals` so one entry
    ///      can't brick getSummary, rejects (via NonceRegistry) a proof whose
    ///      deadline outlives the nonce retention, aligns the read surface to
    ///      ERC-8004 — feedbackIndex is now 1-based and getSummary requires a
    ///      non-empty clientAddresses — and binds every ServeProof to (chainId,
    ///      identity registry, submitter) so a copied proof can't be front-run or
    ///      replayed across chains/deployments. ServeProof gains a `submitter`
    ///      field (ABI change); storage layout unchanged. Migration: old-envelope
    ///      proofs stop verifying at the upgrade — blast radius is the proofs
    ///      issued within serveProofDeadlineWindow (~1h) before rollout.
    ///      1.1.0 — ABI/behavior change (beacon upgrade): `ServeProof` drops `client`,
    ///      attribution is now `msg.sender` at giveFeedback (signed digest + giveFeedback
    ///      ABI changed).
    ///      1.0.0 — initial (client-bound ServeProof).
    string public constant VERSION = "1.2.0";

    bytes32 private constant _SERVEPROOF_TAG = keccak256("SERVEPROOF");

    /// @notice Max absolute feedback `value` (raw, pre-decimals). Bounds a single
    ///         entry so its 18-decimal normalization can't overflow int128 and
    ///         summaries stay finite — an int128 sum would take ~1.7e11 max
    ///         entries. Generous for any real rating scale.
    int128 private constant MAX_ABS_VALUE = 1e9;

    event PauserUpdated(address indexed previousPauser, address indexed newPauser);

    // ── Storage structs ───────────────────────────────────────────────────────

    struct FeedbackEntry {
        int128    value;
        uint8     valueDecimals;
        string    tag1;
        string    tag2;
        bool      isRevoked;
        // ServeProof audit data — trusted because they're part of the signed message.
        bytes32[] dataHashes;
        bytes32   frameworkHash;
    }

    /// @custom:storage-location erc7857:0g.storage.AgenticIDReputationRegistry
    struct ReputationStorage {
        address identityRegistry;

        // agentId → client → feedback entries (index = feedbackIndex)
        mapping(uint256 => mapping(address => FeedbackEntry[])) feedbacks;

        // agentId → list of clients that have submitted at least one feedback
        mapping(uint256 => address[]) clients;
        mapping(uint256 => mapping(address => bool)) isClient;

        // agentId → client → feedbackIndex → list of responders
        mapping(uint256 => mapping(address => mapping(uint64 => address[]))) responseAuthors;
        // prevent duplicate responses per (agentId, client, feedbackIndex, responder)
        mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => bool)))) hasResponse;

        address pauser;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.AgenticIDReputationRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ReputationStorageLocation =
        0x006e35ac9067c2fcc8a4631e7a010043a67a2342b0b0036bfa95c5fb0d9ec700;

    function _getReputationStorage() private pure returns (ReputationStorage storage $) {
        assembly {
            $.slot := ReputationStorageLocation
        }
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function initialize(
        address identityRegistry_,
        address owner_,
        address pauser_,
        uint256 maxProofAge_
    ) external initializer {
        __Ownable_init(owner_);
        __Pausable_init();
        __NonceRegistry_init_unchained(maxProofAge_);
        ReputationStorage storage $ = _getReputationStorage();
        $.identityRegistry = identityRegistry_;
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
        return _getReputationStorage().pauser;
    }

    function setPauser(address newPauser) external onlyOwner {
        ReputationStorage storage $ = _getReputationStorage();
        emit PauserUpdated($.pauser, newPauser);
        $.pauser = newPauser;
    }

    function pause() external {
        if (msg.sender != _getReputationStorage().pauser) revert ReputationNotPauser();
        _pause();
    }

    function unpause() external {
        if (msg.sender != _getReputationStorage().pauser) revert ReputationNotPauser();
        _unpause();
    }

    // ── IAgenticIDReputationRegistry — disabled base function ─────────────────

    function giveFeedback(
        uint256, int128, uint8,
        string calldata, string calldata, string calldata, string calldata, bytes32
    ) external pure override {
        revert AgenticIDProofRequired();
    }

    // ── IAgenticIDReputationRegistry — feedback with proof ───────────────────

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
    ) external whenNotPaused {
        // Feedback is stored under the outer `agentId`, but the proof is verified
        // against `proof.agentId` (the agent whose seal signs it). Require them to
        // match — otherwise a valid proof for agent A could write feedback on any
        // other agent B, including unminted IDs. A nonexistent target is rejected
        // as a side effect: `_verifyServeProof` reverts when the seal is unset.
        if (agentId != proof.agentId) revert ReputationProofAgentMismatch(agentId, proof.agentId);
        _verifyServeProof(proof);

        // Bound the entry so it can't brick reads: valueDecimals within the
        // 18-decimal normalization window, and |value| capped so a single
        // normalized entry fits int128 and summaries stay finite.
        if (valueDecimals > 18) revert ReputationValueDecimalsTooLarge(valueDecimals);
        if (value < -MAX_ABS_VALUE || value > MAX_ABS_VALUE) revert ReputationValueOutOfRange(value);

        ReputationStorage storage $ = _getReputationStorage();

        if (!$.isClient[agentId][msg.sender]) {
            $.isClient[agentId][msg.sender] = true;
            $.clients[agentId].push(msg.sender);
        }

        // feedbackIndex is 1-based per ERC-8004: first feedback is index 1,
        // so 0 is a clean "no feedback" sentinel.
        uint64 feedbackIndex = uint64($.feedbacks[agentId][msg.sender].length + 1);

        $.feedbacks[agentId][msg.sender].push(FeedbackEntry({
            value:             value,
            valueDecimals:     valueDecimals,
            tag1:              tag1,
            tag2:              tag2,
            isRevoked:         false,
            dataHashes:        proof.dataHashes,
            frameworkHash: proof.frameworkHash
        }));

        emit NewFeedback(
            agentId, msg.sender, feedbackIndex,
            value, valueDecimals,
            tag1, tag1, tag2,
            endpoint, feedbackURI, feedbackHash
        );

        emit FeedbackWithProof(
            agentId, msg.sender, feedbackIndex,
            proof.dataHashes, proof.frameworkHash
        );
    }

    // ── IERC8004ReputationRegistry — write ────────────────────────────────────

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external whenNotPaused {
        ReputationStorage storage $ = _getReputationStorage();
        FeedbackEntry[] storage entries = $.feedbacks[agentId][msg.sender];
        if (feedbackIndex == 0 || feedbackIndex > entries.length)
            revert ReputationInvalidIndex(feedbackIndex, entries.length);
        FeedbackEntry storage entry = entries[feedbackIndex - 1]; // 1-based → 0-based
        if (entry.isRevoked) revert ReputationAlreadyRevoked();

        entry.isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external whenNotPaused {
        ReputationStorage storage $ = _getReputationStorage();

        if (IAgenticID($.identityRegistry).ownerOf(agentId) != msg.sender)
            revert ReputationNotAgentOwner();

        FeedbackEntry[] storage entries = $.feedbacks[agentId][clientAddress];
        if (feedbackIndex == 0 || feedbackIndex > entries.length)
            revert ReputationInvalidIndex(feedbackIndex, entries.length);
        if ($.hasResponse[agentId][clientAddress][feedbackIndex][msg.sender])
            revert ReputationAlreadyResponded();

        $.hasResponse[agentId][clientAddress][feedbackIndex][msg.sender] = true;
        $.responseAuthors[agentId][clientAddress][feedbackIndex].push(msg.sender);

        emit ResponseAppended(agentId, clientAddress, feedbackIndex, msg.sender, responseURI, responseHash);
    }

    // ── IERC8004ReputationRegistry — read ─────────────────────────────────────

    function getIdentityRegistry() external view returns (address) {
        return _getReputationStorage().identityRegistry;
    }

    function readFeedback(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (
        int128  value,
        uint8   valueDecimals,
        string memory tag1,
        string memory tag2,
        bool    isRevoked
    ) {
        FeedbackEntry[] storage entries = _getReputationStorage().feedbacks[agentId][clientAddress];
        if (feedbackIndex == 0 || feedbackIndex > entries.length)
            revert ReputationInvalidIndex(feedbackIndex, entries.length);
        FeedbackEntry storage e = entries[feedbackIndex - 1]; // 1-based → 0-based
        return (e.value, e.valueDecimals, e.tag1, e.tag2, e.isRevoked);
    }

    function readAllFeedback(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2,
        bool includeRevoked
    ) external view returns (
        address[] memory clients_,
        uint64[]  memory feedbackIndexes,
        int128[]  memory values,
        uint8[]   memory valueDecimals,
        string[]  memory tag1s,
        string[]  memory tag2s,
        bool[]    memory revokedStatuses
    ) {
        ReputationStorage storage $ = _getReputationStorage();
        address[] memory targets;
        if (clientAddresses.length > 0) {
            targets = new address[](clientAddresses.length);
            for (uint256 t = 0; t < clientAddresses.length; t++) targets[t] = clientAddresses[t];
        } else {
            targets = $.clients[agentId];
        }

        uint256 total;
        for (uint256 i = 0; i < targets.length; i++) {
            FeedbackEntry[] storage entries = $.feedbacks[agentId][targets[i]];
            for (uint256 j = 0; j < entries.length; j++) {
                if (_matchesFilter(entries[j], tag1, tag2, includeRevoked)) total++;
            }
        }

        clients_        = new address[](total);
        feedbackIndexes = new uint64[](total);
        values          = new int128[](total);
        valueDecimals   = new uint8[](total);
        tag1s           = new string[](total);
        tag2s           = new string[](total);
        revokedStatuses = new bool[](total);

        uint256 idx;
        for (uint256 i = 0; i < targets.length; i++) {
            FeedbackEntry[] storage entries = $.feedbacks[agentId][targets[i]];
            for (uint256 j = 0; j < entries.length; j++) {
                if (!_matchesFilter(entries[j], tag1, tag2, includeRevoked)) continue;
                clients_[idx]        = targets[i];
                feedbackIndexes[idx] = uint64(j + 1); // 1-based per ERC-8004
                values[idx]          = entries[j].value;
                valueDecimals[idx]   = entries[j].valueDecimals;
                tag1s[idx]           = entries[j].tag1;
                tag2s[idx]           = entries[j].tag2;
                revokedStatuses[idx] = entries[j].isRevoked;
                idx++;
            }
        }
    }

    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {
        // ERC-8004: clientAddresses MUST be provided (non-empty) so the caller
        // picks whom to trust — an all-clients aggregate would fold in sybil
        // feedback.
        if (clientAddresses.length == 0) revert ReputationClientsRequired();
        ReputationStorage storage $ = _getReputationStorage();
        address[] memory targets = clientAddresses;

        summaryValueDecimals = 18;
        int256 acc;
        for (uint256 i = 0; i < targets.length; i++) {
            FeedbackEntry[] storage entries = $.feedbacks[agentId][targets[i]];
            for (uint256 j = 0; j < entries.length; j++) {
                FeedbackEntry storage e = entries[j];
                if (e.isRevoked) continue;
                if (!_tagMatches(e.tag1, tag1)) continue;
                if (!_tagMatches(e.tag2, tag2)) continue;
                count++;
                acc += _normalizeTo18(e.value, e.valueDecimals);
            }
        }
        // Bounded writes keep this in range; the guard turns a would-be silent
        // int128 truncation into a clean revert (unreachable in practice).
        if (acc < type(int128).min || acc > type(int128).max) revert ReputationSummaryOverflow();
        summaryValue = int128(acc);
    }

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex,
        address[] calldata responders
    ) external view returns (uint64 count) {
        ReputationStorage storage $ = _getReputationStorage();
        if (responders.length == 0) {
            return uint64($.responseAuthors[agentId][clientAddress][feedbackIndex].length);
        }
        for (uint256 i = 0; i < responders.length; i++) {
            if ($.hasResponse[agentId][clientAddress][feedbackIndex][responders[i]]) count++;
        }
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        return _getReputationStorage().clients[agentId];
    }

    /// @notice Returns the 1-based index of the most recent feedback from
    ///         `clientAddress` for `agentId`, or 0 if there is none (ERC-8004).
    /// @dev With 1-based feedbackIndex this equals the entry count: 0 = none,
    ///      1 = one entry (at index 1), … — no none/first ambiguity.
    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        return uint64(_getReputationStorage().feedbacks[agentId][clientAddress].length);
    }

    // ── IAgenticIDReputationRegistry — serve data ─────────────────────────────

    function getServeData(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash) {
        FeedbackEntry[] storage entries = _getReputationStorage().feedbacks[agentId][clientAddress];
        if (feedbackIndex == 0 || feedbackIndex > entries.length)
            revert ReputationInvalidIndex(feedbackIndex, entries.length);
        FeedbackEntry storage e = entries[feedbackIndex - 1]; // 1-based → 0-based
        return (e.dataHashes, e.frameworkHash);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// @dev Verifies the ServeProof signature against the agent's agentSeal AND
    ///      consumes the nonce (derived from signature bytes) via NonceRegistry.
    ///      State-mutating despite the "verify" name — this is the single entrypoint
    ///      that guarantees each ServeProof can be redeemed at most once.
    function _verifyServeProof(ServeProof calldata proof) internal {
        // Only the address the proof was signed for may redeem it. This is the
        // front-running / theft guard: a copied proof carries the honest
        // client's `submitter`, so an attacker's own call fails here. Checked
        // before signature recovery so a mismatched caller reverts cheaply.
        if (proof.submitter != msg.sender)
            revert ReputationProofSubmitterMismatch(proof.submitter, msg.sender);

        address identityRegistry = _getReputationStorage().identityRegistry;
        address agentSeal = IAgenticID(identityRegistry).getAgentSeal(proof.agentId);
        if (agentSeal == address(0)) revert ReputationNoAgentSeal();

        // Domain + submitter separation: binding block.chainid and the
        // identity registry this reputation contract is anchored to makes a proof
        // non-portable across chains and across protocol deployments, and binding
        // `submitter` makes it non-transferable. The digest is built only from
        // fixed-width words (uint256/address/bytes32), so abi.encode has no
        // encoding ambiguity. (The key layer also scopes agentSeal per deployment,
        // but that is an off-chain property; this binds it on-chain regardless.)
        bytes32 proofHash = keccak256(abi.encode(
            block.chainid,
            identityRegistry,
            proof.submitter,
            proof.agentId,
            proof.timestamp,
            proof.deadline,
            proof.taskHash,
            keccak256(abi.encodePacked(proof.dataHashes)),
            proof.frameworkHash
        ));
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(proofHash);
        if (ethHash.recover(proof.signature) != agentSeal)
            revert ReputationInvalidProofSignature();

        // Replay protection: signature is unique per sealed payload.
        bytes32 nonceKey = keccak256(abi.encode(_SERVEPROOF_TAG, proof.agentId, proof.signature));
        _checkAndMarkNonce(nonceKey, proof.deadline);
    }

    function _matchesFilter(
        FeedbackEntry storage e,
        string calldata tag1,
        string calldata tag2,
        bool includeRevoked
    ) private view returns (bool) {
        if (e.isRevoked && !includeRevoked) return false;
        if (!_tagMatches(e.tag1, tag1)) return false;
        if (!_tagMatches(e.tag2, tag2)) return false;
        return true;
    }

    /// @dev Empty filter = wildcard (matches any stored value).
    function _tagMatches(string storage stored, string calldata filter) private view returns (bool) {
        if (bytes(filter).length == 0) return true;
        return keccak256(bytes(stored)) == keccak256(bytes(filter));
    }

    /// @dev Normalize a feedback value to 18 decimals, returning int256 so no
    ///      single entry can overflow (values are further bounded at write
    ///      time). decimals above 18+77 round to zero rather than overflowing 10**().
    function _normalizeTo18(int128 value, uint8 decimals) private pure returns (int256) {
        if (decimals == 18) return value;
        if (decimals < 18) return int256(value) * int256(10 ** (18 - decimals));
        uint256 shift = uint256(decimals) - 18;
        if (shift > 77) return 0; // 10**78 exceeds uint256 max; the value underflows to 0 anyway
        return int256(value) / int256(10 ** shift);
    }
}
