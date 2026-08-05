// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @notice The nonce has already been consumed.
error NonceAlreadyUsed(bytes32 key);

/// @notice The deadline has already passed.
error NonceExpired(uint256 deadline, uint256 nowTimestamp);

/// @notice The deadline outlives the nonce's retention (`now + maxAge`), so the
///         permissionless cleanup could delete the record while the proof is still
///         valid and reopen it to replay.
error NonceDeadlineTooFar(uint256 deadline, uint256 maxDeadline);

/// @title NonceRegistryUpgradeable
/// @notice Shared replay-protection primitive used by all proof-accepting contracts
///         in the protocol (transfer verifiers, reputation registry, identity
///         registry's setAgentWallet).
///
///         Consumed (key, deadline) pairs are rejected atomically:
///           • block.timestamp > deadline → NonceExpired
///           • key already consumed        → NonceAlreadyUsed
///           • otherwise                   → record consumption timestamp
///
/// @dev Key namespacing is the inheriting contract's responsibility. Every key MUST
///      be derived to include (a) a static domain tag, (b) the binding context
///      (msg.sender, target contract, agentId, etc.), and (c) the caller-supplied
///      nonce value. Without (a) and (b), one operation's nonce could collide with
///      or preempt another's.
///
///      Cleanup is safe under two assumptions:
///        1. Signers do not reuse a nonce across different signed messages.
///        2. maxAge is set no shorter than the longest deadline horizon the
///           protocol issues. Otherwise a cleaned record could expose a still-
///           valid alternative proof to replay.
abstract contract NonceRegistryUpgradeable is Initializable {

    /// @custom:storage-location erc7857:0g.storage.NonceRegistry
    struct NonceRegistryStorage {
        /// @dev consumedAt[key] == 0 → unused; non-zero → timestamp of consumption
        mapping(bytes32 => uint256) consumedAt;
        uint256 maxAge;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.NonceRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant NonceRegistryStorageLocation =
        0xd789013f031db4b6a1323b9e61ff1f12235bc6145ae87cd856aaccdef4ff2900;

    function _getNonceRegistryStorage() private pure returns (NonceRegistryStorage storage $) {
        assembly {
            $.slot := NonceRegistryStorageLocation
        }
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function __NonceRegistry_init_unchained(uint256 maxAge_) internal onlyInitializing {
        _getNonceRegistryStorage().maxAge = maxAge_;
    }

    // ── Admin (subclass exposes gated setter) ─────────────────────────────────

    function _setNonceMaxAge(uint256 maxAge_) internal {
        _getNonceRegistryStorage().maxAge = maxAge_;
    }

    // ── Core consume ──────────────────────────────────────────────────────────

    /// @dev Atomically verifies (key, deadline) and marks the key consumed.
    ///      Pure logic — no events — so concrete contracts can emit whatever
    ///      domain-specific event makes sense for their operation.
    function _checkAndMarkNonce(bytes32 key, uint256 deadline) internal {
        if (block.timestamp > deadline) revert NonceExpired(deadline, block.timestamp);
        NonceRegistryStorage storage $ = _getNonceRegistryStorage();
        // Enforce the cleanup invariant on-chain: the consumption record must
        // outlive the proof's deadline. Otherwise the permissionless cleanup could
        // delete it (once `now > consumedAt + maxAge`) while the proof is still
        // valid, reopening the nonce to replay.
        uint256 maxDeadline = block.timestamp + $.maxAge;
        if (deadline > maxDeadline) revert NonceDeadlineTooFar(deadline, maxDeadline);
        if ($.consumedAt[key] != 0) revert NonceAlreadyUsed(key);
        $.consumedAt[key] = block.timestamp;
    }

    // ── Storage GC ────────────────────────────────────────────────────────────

    /// @dev Permissionless cleanup of consumed nonces older than maxAge.
    ///      Callers providing too-short maxAge + too-long deadline weaken replay
    ///      protection — see contract-level natspec for the invariant.
    function _cleanExpiredNonces(bytes32[] calldata keys) internal {
        NonceRegistryStorage storage $ = _getNonceRegistryStorage();
        uint256 maxAge = $.maxAge;
        for (uint256 i = 0; i < keys.length; i++) {
            bytes32 key = keys[i];
            uint256 consumedAt_ = $.consumedAt[key];
            if (consumedAt_ != 0 && block.timestamp > consumedAt_ + maxAge) {
                delete $.consumedAt[key];
            }
        }
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function nonceMaxAge() public view returns (uint256) {
        return _getNonceRegistryStorage().maxAge;
    }

    function isNonceConsumed(bytes32 key) public view returns (bool) {
        return _getNonceRegistryStorage().consumedAt[key] != 0;
    }

    function nonceConsumedAt(bytes32 key) public view returns (uint256) {
        return _getNonceRegistryStorage().consumedAt[key];
    }
}
