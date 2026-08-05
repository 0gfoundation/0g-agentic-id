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
/// @dev Feedback `value` outside [-MAX_ABS_VALUE, MAX_ABS_VALUE] (#87).
error ReputationValueOutOfRange(int128 value);
/// @dev `valueDecimals` above 18 — outside the 18-decimal normalization window (#87).
error ReputationValueDecimalsTooLarge(uint8 valueDecimals);
/// @dev A tag/client summation exceeded int128 — unreachable given bounded writes (#87).
error ReputationSummaryOverflow();

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
    /// @dev 1.1.0 — ABI/behavior change (beacon upgrade): `ServeProof` drops `client`,
    ///      attribution is now `msg.sender` at giveFeedback (signed digest + giveFeedback
    ///      ABI changed).
    ///      1.0.0 — initial (client-bound ServeProof).
    string public constant VERSION = "1.1.0";

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
        _verifyServeProof(proof);

        // Bound the entry so it can't brick reads (#87): valueDecimals within the
        // 18-decimal normalization window, and |value| capped so a single
        // normalized entry fits int128 and summaries stay finite.
        if (valueDecimals > 18) revert ReputationValueDecimalsTooLarge(valueDecimals);
        if (value < -MAX_ABS_VALUE || value > MAX_ABS_VALUE) revert ReputationValueOutOfRange(value);

        ReputationStorage storage $ = _getReputationStorage();

        if (!$.isClient[agentId][msg.sender]) {
            $.isClient[agentId][msg.sender] = true;
            $.clients[agentId].push(msg.sender);
        }

        uint64 feedbackIndex = uint64($.feedbacks[agentId][msg.sender].length);

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
        if (feedbackIndex >= entries.length)
            revert ReputationInvalidIndex(feedbackIndex, entries.length);
        if (entries[feedbackIndex].isRevoked) revert ReputationAlreadyRevoked();

        entries[feedbackIndex].isRevoked = true;
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
        if (feedbackIndex >= entries.length)
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
        FeedbackEntry storage e = _getReputationStorage().feedbacks[agentId][clientAddress][feedbackIndex];
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
                feedbackIndexes[idx] = uint64(j);
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
        ReputationStorage storage $ = _getReputationStorage();
        address[] memory targets;
        if (clientAddresses.length > 0) {
            targets = new address[](clientAddresses.length);
            for (uint256 t = 0; t < clientAddresses.length; t++) targets[t] = clientAddresses[t];
        } else {
            targets = $.clients[agentId];
        }

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
        // int128 truncation into a clean revert (unreachable in practice, #87).
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

    /// @notice Returns the number of feedback entries from `clientAddress` for `agentId`.
    /// @dev Returns 0 when there are no entries. Callers can distinguish "no entries"
    ///      from "one entry at index 0" by checking getClients(agentId) first, or by
    ///      calling readFeedback and checking for a revert.
    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        uint256 len = _getReputationStorage().feedbacks[agentId][clientAddress].length;
        return len == 0 ? 0 : uint64(len - 1);
    }

    // ── IAgenticIDReputationRegistry — serve data ─────────────────────────────

    function getServeData(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (bytes32[] memory dataHashes, bytes32 frameworkHash) {
        FeedbackEntry storage e = _getReputationStorage().feedbacks[agentId][clientAddress][feedbackIndex];
        return (e.dataHashes, e.frameworkHash);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// @dev Verifies the ServeProof signature against the agent's agentSeal AND
    ///      consumes the nonce (derived from signature bytes) via NonceRegistry.
    ///      State-mutating despite the "verify" name — this is the single entrypoint
    ///      that guarantees each ServeProof can be redeemed at most once.
    function _verifyServeProof(ServeProof calldata proof) internal {
        address agentSeal = IAgenticID(
            _getReputationStorage().identityRegistry
        ).getAgentSeal(proof.agentId);
        if (agentSeal == address(0)) revert ReputationNoAgentSeal();

        // No (chainId, contract) domain separation in the envelope on purpose:
        // cross-chain / cross-contract replay of a ServeProof is prevented at the
        // KEY layer — agentSeal is derived per (chainId, agenticID, sealId), so the
        // same agentId on another chain/contract has a different agentSeal and the
        // recovered signer won't match. Keeping the envelope minimal means the
        // off-chain agentSeal signer needs no extra fields. (Seal derivation
        // scoping is tracked separately; see the KMS threshold-derivation issue.)
        bytes32 proofHash = keccak256(abi.encode(
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
    ///      single entry can overflow (values are further bounded at write time,
    ///      #87). decimals above 18+77 round to zero rather than overflowing 10**().
    function _normalizeTo18(int128 value, uint8 decimals) private pure returns (int256) {
        if (decimals == 18) return value;
        if (decimals < 18) return int256(value) * int256(10 ** (18 - decimals));
        uint256 shift = uint256(decimals) - 18;
        if (shift > 77) return 0; // 10**78 exceeds uint256 max; the value underflows to 0 anyway
        return int256(value) / int256(10 ** shift);
    }
}
