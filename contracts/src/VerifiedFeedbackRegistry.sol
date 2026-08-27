// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IVerifiedFeedbackRegistry} from "./interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "./interfaces/IAgenticIDReputationRegistry.sol";
import {ICanonicalReputationRegistry} from "./interfaces/ICanonicalReputationRegistry.sol";
import {IAgenticID} from "./interfaces/IAgenticID.sol";
import {NonceRegistryUpgradeable} from "./utils/NonceRegistryUpgradeable.sol";

error VerifiedFeedbackNoAgentSeal();
error VerifiedFeedbackInvalidProofSignature();
error VerifiedFeedbackNotPauser();
/// @dev The outer `agentId` does not match the agent the ServeProof attests to
/// (`proof.agentId`, whose seal signs it).
error VerifiedFeedbackProofAgentMismatch(uint256 agentId, uint256 proofAgentId);
/// @dev The proof was signed for a different redeemer — `proof.submitter` must
/// equal the attestFeedback caller. Closes front-running / proof theft.
error VerifiedFeedbackProofSubmitterMismatch(address submitter, address sender);
/// @dev ERC-8004: the agent owner or an approved operator must not attest
/// feedback on their own agent. Conformance guard, not sybil resistance (a
/// determined owner can still self-rate from an unrelated second wallet).
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
/// @dev The ServeProof digest is IDENTICAL to the one the (deprecated)
///      AgenticIDReputationRegistry verifies — bound to (chainId,
///      identityRegistry, submitter), NOT to this contract's address — so the
///      sealed runtime and SDK signing paths are unchanged. Consequence: while
///      both contracts are live on one deployment, a single proof can be
///      redeemed once on EACH (their nonce stores are separate) — and the same
///      generalizes to any extra VerifiedFeedbackRegistry instance anchored to
///      the same pair, so readers should pin ONE registry address per
///      deployment (DEPLOYMENT.md §6). Acceptable — the fork registry is
///      deprecated and new stacks deploy only this one.
contract VerifiedFeedbackRegistry is
    IVerifiedFeedbackRegistry,
    OwnableUpgradeable,
    PausableUpgradeable,
    NonceRegistryUpgradeable
{
    using ECDSA for bytes32;

    /// @notice Current implementation version. See contracts/UPGRADING.md for
    ///         the bump rules.
    /// @dev 1.0.0 — initial: attest-only companion to the canonical ERC-8004
    ///      Reputation Registry, replacing the AgenticIDReputationRegistry fork.
    string public constant VERSION = "1.0.0";

    /// @dev Same tag as the fork registry — the digest and nonce-key derivation
    ///      are consensus-critical, shared with sealed/ and the SDK.
    bytes32 private constant _SERVEPROOF_TAG = keccak256("SERVEPROOF");

    event PauserUpdated(address indexed previousPauser, address indexed newPauser);

    // ── Storage ───────────────────────────────────────────────────────────────

    struct ServeData {
        bool      exists;
        bytes32   frameworkHash;
        bytes32[] dataHashes;
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
        // The verification mark is stored under the outer `agentId`, but the
        // proof is verified against `proof.agentId` (the agent whose seal signs
        // it). Require them to match — otherwise a valid proof for agent A
        // could mark entries on any other agent B.
        if (agentId != proof.agentId) revert VerifiedFeedbackProofAgentMismatch(agentId, proof.agentId);
        _verifyServeProof(proof);

        // ERC-8004 conformance: the attester must not be the agent owner or an
        // approved operator. Conformance guard, NOT sybil resistance — the
        // serve proof is obtainable from the unauthenticated /hello, so a
        // determined owner can still self-rate from an unrelated second
        // wallet. msg.sender == proof.submitter here (enforced above), so this
        // checks the real redeemer.
        if (_isOwnerOrApproved(agentId, msg.sender)) revert VerifiedFeedbackSelfFeedback(agentId, msg.sender);

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
        $.verifiedIndexes[agentId][msg.sender].push(feedbackIndex);

        if (!$.isVerifiedClient[agentId][msg.sender]) {
            $.isVerifiedClient[agentId][msg.sender] = true;
            $.verifiedClients[agentId].push(msg.sender);
        }

        emit FeedbackVerified(agentId, msg.sender, feedbackIndex, proof.dataHashes, proof.frameworkHash);
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
    ///      consumes the nonce (derived from signature bytes) via NonceRegistry.
    ///      State-mutating despite the "verify" name — this is the single
    ///      entrypoint that guarantees each ServeProof is redeemed at most once
    ///      here. Digest and nonce-key derivation are byte-identical to the
    ///      fork registry's (consensus-critical, shared with sealed/ and SDK).
    function _verifyServeProof(ServeProof calldata proof) internal {
        // Only the address the proof was signed for may redeem it — the
        // front-running / theft guard. Checked before signature recovery so a
        // mismatched caller reverts cheaply.
        if (proof.submitter != msg.sender)
            revert VerifiedFeedbackProofSubmitterMismatch(proof.submitter, msg.sender);

        address identityRegistry = _getVerifiedFeedbackStorage().identityRegistry;
        address agentSeal = IAgenticID(identityRegistry).getAgentSeal(proof.agentId);
        if (agentSeal == address(0)) revert VerifiedFeedbackNoAgentSeal();

        // Domain + submitter separation: block.chainid and the identity
        // registry make the proof non-portable across chains and protocol
        // deployments; `submitter` makes it non-transferable. Fixed-width
        // words only, so abi.encode has no encoding ambiguity.
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
            revert VerifiedFeedbackInvalidProofSignature();

        // Replay protection: signature is unique per sealed payload.
        bytes32 nonceKey = keccak256(abi.encode(_SERVEPROOF_TAG, proof.agentId, proof.signature));
        _checkAndMarkNonce(nonceKey, proof.deadline);
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
