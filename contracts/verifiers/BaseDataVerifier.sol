// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {
    IERC7857DataVerifier,
    AccessProof,
    OwnershipProof,
    TransferValidityProof,
    TransferValidityProofOutput
} from "../interfaces/IERC7857DataVerifier.sol";
import {NonceRegistryUpgradeable} from "../utils/NonceRegistryUpgradeable.sol";

/// @notice The access proof signature is invalid (zero address recovered).
error DataVerifierInvalidAccessProof();

/// @notice The access proof dataHash does not match the ownership proof dataHash.
error DataVerifierDataHashMismatch();

/// @title BaseDataVerifier
/// @notice Abstract base for ERC-7857 transfer validity verifiers.
///
///         Handles logic common to all oracle backends:
///           • Access proof verification (receiver-signed intent)
///           • Replay protection via NonceRegistryUpgradeable (nonce + deadline)
///           • Pause / reentrancy guard
///
///         Subclasses implement `_verifyOwnershipProof` for their specific oracle
///         (TEE, ZKP, etc.) and call `__BaseDataVerifier_init` in their initializer.
abstract contract BaseDataVerifier is
    IERC7857DataVerifier,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    NonceRegistryUpgradeable
{
    using ECDSA for bytes32;

    bytes32 private constant _TRANSFER_ACCESS_TAG    = keccak256("ERC7857_TRANSFER_ACCESS");
    bytes32 private constant _TRANSFER_OWNERSHIP_TAG = keccak256("ERC7857_TRANSFER_OWNERSHIP");

    // ── Initializer ───────────────────────────────────────────────────────────

    function __BaseDataVerifier_init(address owner_, uint256 maxProofAge_) internal onlyInitializing {
        __Ownable_init(owner_);
        __Pausable_init();
        __ReentrancyGuard_init();
        __NonceRegistry_init_unchained(maxProofAge_);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setMaxProofAge(uint256 maxProofAge_) external onlyOwner {
        _setNonceMaxAge(maxProofAge_);
    }

    function pause() external onlyOwner { _pause(); }

    function unpause() external onlyOwner { _unpause(); }

    // ── Nonce cleanup (permissionless) ────────────────────────────────────────

    /// @notice Delete expired nonce records to reclaim storage.
    function cleanExpiredNonces(bytes32[] calldata keys) external {
        _cleanExpiredNonces(keys);
    }

    // ── Nonce key derivation ──────────────────────────────────────────────────

    /// @dev Transfer access proof nonce key:
    ///      keccak256("ERC7857_TRANSFER_ACCESS" ‖ msg.sender ‖ nonce).
    function _accessNonceKey(bytes memory nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(_TRANSFER_ACCESS_TAG, msg.sender, nonce));
    }

    /// @dev Transfer ownership proof nonce key:
    ///      keccak256("ERC7857_TRANSFER_OWNERSHIP" ‖ msg.sender ‖ nonce).
    function _ownershipNonceKey(bytes memory nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(_TRANSFER_OWNERSHIP_TAG, msg.sender, nonce));
    }

    // ── EIP-191 hash ──────────────────────────────────────────────────────────

    /// @dev Matches the off-chain personal_sign format used by both receivers and the TEE.
    ///      The inner hash is hex-encoded (0x + 64 chars = 66 chars) before hashing so
    ///      the message is human-readable when displayed in a wallet signing prompt.
    function _eip191Hash(bytes32 inner) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n66",
            Strings.toHexString(uint256(inner), 32)
        ));
    }

    // ── Access proof ──────────────────────────────────────────────────────────

    /// @dev Signed message: keccak256(abi.encodePacked(dataHash, targetPubkey, nonce, deadline)).
    function _verifyAccessProof(AccessProof calldata ap) internal pure returns (address accessAssistant) {
        bytes32 inner = keccak256(abi.encodePacked(ap.dataHash, ap.targetPubkey, ap.nonce, ap.deadline));
        accessAssistant = _eip191Hash(inner).recover(ap.proof);
        if (accessAssistant == address(0)) revert DataVerifierInvalidAccessProof();
    }

    // ── Ownership proof (oracle-specific) ─────────────────────────────────────

    /// @dev Subclasses verify the oracle-specific ownership proof.
    ///      Must revert with an appropriate error on failure.
    function _verifyOwnershipProof(OwnershipProof calldata op) internal virtual;

    // ── IERC7857DataVerifier ──────────────────────────────────────────────────

    function verifyTransferValidity(
        TransferValidityProof[] calldata proofs
    ) external virtual override whenNotPaused nonReentrant returns (TransferValidityProofOutput[] memory outputs) {
        outputs = new TransferValidityProofOutput[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            AccessProof    calldata ap = proofs[i].accessProof;
            OwnershipProof calldata op = proofs[i].ownershipProof;

            if (ap.dataHash != op.dataHash) revert DataVerifierDataHashMismatch();

            address accessAssistant = _verifyAccessProof(ap);
            _verifyOwnershipProof(op); // reverts on failure

            _checkAndMarkNonce(_accessNonceKey(ap.nonce),    ap.deadline);
            _checkAndMarkNonce(_ownershipNonceKey(op.nonce), op.deadline);

            outputs[i] = TransferValidityProofOutput({
                oracleType:          op.oracleType,
                dataHash:            ap.dataHash,
                sealedKey:           op.sealedKey,
                targetPubkey:        op.targetPubkey,
                wantedKey:           ap.targetPubkey,
                accessAssistant:     accessAssistant,
                accessProofNonce:    ap.nonce,
                ownershipProofNonce: op.nonce
            });
        }
    }

    // ── Legacy view ───────────────────────────────────────────────────────────

    /// @dev Alias for backward-compat with earlier `maxProofAge()` callers.
    function maxProofAge() external view returns (uint256) {
        return nonceMaxAge();
    }
}
