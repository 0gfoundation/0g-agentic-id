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

/// @notice Caller is not the pauser.
error DataVerifierNotPauser();

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

    /// @custom:storage-location erc7201:0g.storage.BaseDataVerifier
    struct BaseDataVerifierStorage {
        address pauser;
    }

    // NOTE: fixed literal, NOT the ERC-7201 derivation of the namespace above.
    // The canonical derivation of "0g.storage.BaseDataVerifier" is
    // 0xebd3f1ab6f96c5a8aa3a8f7ae4cb91de9050e806218c0e227b71fda38a32fd00; this
    // slot differs. It is kept as-is because `pauser` already lives here on the
    // live deployment — changing it would strand that state. The slot is
    // otherwise unoccupied, so there is no collision. Pinned by
    // StorageLayout.t.sol so the discrepancy stays intentional and visible.
    bytes32 private constant BaseDataVerifierStorageLocation =
        0x2a6e9d47b6f4c10d00c1ba6c2a83e5a99f9ffd6b1a85ca0f0b97a3c3c3a27c00;

    function _getBaseDataVerifierStorage() private pure returns (BaseDataVerifierStorage storage $) {
        assembly { $.slot := BaseDataVerifierStorageLocation }
    }

    event PauserUpdated(address indexed previousPauser, address indexed newPauser);

    // ── Initializer ───────────────────────────────────────────────────────────

    function __BaseDataVerifier_init(address owner_, address pauser_, uint256 maxProofAge_) internal onlyInitializing {
        __Ownable_init(owner_);
        __Pausable_init();
        __ReentrancyGuard_init();
        __NonceRegistry_init_unchained(maxProofAge_);
        _getBaseDataVerifierStorage().pauser = pauser_;
        emit PauserUpdated(address(0), pauser_);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setMaxProofAge(uint256 maxProofAge_) external onlyOwner {
        _setNonceMaxAge(maxProofAge_);
    }

    // ── Pauser ────────────────────────────────────────────────────────────────

    function pauser() external view returns (address) {
        return _getBaseDataVerifierStorage().pauser;
    }

    function setPauser(address newPauser) external onlyOwner {
        BaseDataVerifierStorage storage $ = _getBaseDataVerifierStorage();
        emit PauserUpdated($.pauser, newPauser);
        $.pauser = newPauser;
    }

    function pause() external {
        if (msg.sender != _getBaseDataVerifierStorage().pauser) revert DataVerifierNotPauser();
        _pause();
    }

    function unpause() external {
        if (msg.sender != _getBaseDataVerifierStorage().pauser) revert DataVerifierNotPauser();
        _unpause();
    }

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

    /// @dev Signed message:
    ///      keccak256(abi.encode(chainId, erc7857, dataHash, targetPubkey, nonce, deadline)).
    ///      Uses abi.encode, NOT encodePacked: targetPubkey and nonce are adjacent
    ///      dynamic-length fields, and packing them omits the length boundary so a
    ///      signature over one (targetPubkey, nonce) split is equally valid for a
    ///      different split — letting a re-split seal the data to an attacker's key.
    ///      abi.encode length-prefixes each dynamic value, so the boundary is part
    ///      of the signed digest. `chainId` and `erc7857` (the ERC-7857 token
    ///      contract this transfer is for) domain-separate the proof so a buyer's
    ///      AccessProof cannot be replayed against the same dataHash on another
    ///      chain or another token contract. NOTE: the off-chain buyer signer MUST
    ///      match this encoding exactly.
    function _verifyAccessProof(AccessProof calldata ap, address erc7857)
        internal view returns (address accessAssistant)
    {
        bytes32 inner = keccak256(abi.encode(
            block.chainid, erc7857, ap.dataHash, ap.targetPubkey, ap.nonce, ap.deadline
        ));
        accessAssistant = _eip191Hash(inner).recover(ap.proof);
        if (accessAssistant == address(0)) revert DataVerifierInvalidAccessProof();
    }

    // ── Ownership proof (oracle-specific) ─────────────────────────────────────

    /// @dev Subclasses verify the oracle-specific ownership proof for the given
    ///      ERC-7857 token contract. Must revert on failure.
    function _verifyOwnershipProof(OwnershipProof calldata op, address erc7857) internal virtual;

    // ── IERC7857DataVerifier ──────────────────────────────────────────────────

    function verifyTransferValidity(
        TransferValidityProof[] calldata proofs
    ) external virtual override whenNotPaused nonReentrant returns (TransferValidityProofOutput[] memory outputs) {
        outputs = new TransferValidityProofOutput[](proofs.length);

        // The ERC-7857 token contract calling this verifier; proofs are bound to
        // it (plus chainId) so they cannot be replayed against another contract.
        address erc7857 = msg.sender;

        for (uint256 i = 0; i < proofs.length; i++) {
            AccessProof    calldata ap = proofs[i].accessProof;
            OwnershipProof calldata op = proofs[i].ownershipProof;

            if (ap.dataHash != op.dataHash) revert DataVerifierDataHashMismatch();

            address accessAssistant = _verifyAccessProof(ap, erc7857);
            _verifyOwnershipProof(op, erc7857); // reverts on failure

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
