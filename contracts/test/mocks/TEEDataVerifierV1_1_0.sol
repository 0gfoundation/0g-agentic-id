// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// TEST FIXTURE — FROZEN copy of the TEEDataVerifier 1.1.0 source (the impl
// every environment runs), together with the BaseDataVerifier it inherited,
// taken verbatim from git 5e9ab03:contracts/src/verifiers/{BaseDataVerifier,
// TEEDataVerifier}.sol (unchanged through a417c65) and concatenated into one
// file. Only the import paths (merged into one block) and the two contract
// names differ.
// Its runtime bytecode, CBOR metadata stripped, is identical to the mainnet
// impl 0x6D82f34CD671E4593A7E3BCDa253B23a2722403a (5,556 B; compared
// 2026-10-19). UpgradeGovernance.t.sol uses it as the pre-upgrade beacon
// impl. Never edit — it stands in for the deployed 1.1.0.
// ─────────────────────────────────────────────────────────────────────────────

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IERC7857DataVerifierV1_1_0 as IERC7857DataVerifier} from "./v1_1_0/IERC7857DataVerifierV1_1_0.sol";
import {
    OracleType,
    AccessProof,
    OwnershipProof,
    TransferValidityProof,
    TransferValidityProofOutput
} from "../../src/interfaces/IERC7857DataVerifier.sol";
import {NonceRegistryUpgradeableV1_1_0 as NonceRegistryUpgradeable} from "./v1_1_0/NonceRegistryUpgradeableV1_1_0.sol";

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
abstract contract BaseDataVerifierV1_1_0 is
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

// ── TEEDataVerifier 1.1.0 ──────────────────────────────────────────────────

/// @notice The ownership proof was not signed by the registered TEE oracle address.
error TEEDataVerifierInvalidSignature();

/// @notice The ownership proof oracleType is not TEE.
error TEEDataVerifierWrongOracleType();

/// @title TEEDataVerifier
/// @notice Verifies ERC-7857 transfer validity proofs using a TEE oracle backend.
///
///         The TEE oracle signs an OwnershipProof attesting that:
///           1. It holds the data key for the given dataHash.
///           2. It has re-encrypted the key to targetPubkey, producing sealedKey.
///
///         The oracle's signing key is registered as `teeOracleAddress`. Updating
///         this address (e.g. key rotation) takes effect immediately for all future
///         proof verifications.
contract TEEDataVerifierV1_1_0 is BaseDataVerifierV1_1_0 {
    using ECDSA for bytes32;

    /// @notice Current implementation version. Bump on every upgrade.
    /// @dev 1.1.0 — proof preimages switch from abi.encodePacked to abi.encode
    ///      (access + ownership). Adjacent dynamic fields (targetPubkey, nonce,
    ///      sealedKey) were packed without length boundaries, so a signature over
    ///      one field split verified for another — a re-split could seal the data
    ///      to an attacker's key while the buyer took the token. Length-prefixing
    ///      each dynamic value makes the boundary part of the signed digest.
    ///      Off-chain signers (out of this repo) MUST match the new encoding.
    ///      1.0.0 — initial (packed preimages).
    string public constant VERSION = "1.1.0";

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:0g.storage.TEEDataVerifier
    struct TEEDataVerifierStorage {
        address teeOracleAddress;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.TEEDataVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TEEDataVerifierStorageLocation =
        0x0d76357bf08e616bcf0d33ff28efd363c728d41b39fd849c3cb35d7bc6d0f500;

    function _getTEEDataVerifierStorage() private pure returns (TEEDataVerifierStorage storage $) {
        assembly {
            $.slot := TEEDataVerifierStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    /// @param owner_            Contract owner (config: oracle address, maxProofAge). Timelock in prod.
    /// @param pauser_           Pauser (immediate pause/unpause). Not timelocked.
    /// @param teeOracleAddress_ Ethereum address corresponding to the TEE oracle's signing key.
    /// @param maxProofAge_      Maximum age (seconds) before a used nonce record can be deleted.
    function initialize(
        address owner_,
        address pauser_,
        address teeOracleAddress_,
        uint256 maxProofAge_
    ) external initializer {
        __BaseDataVerifier_init(owner_, pauser_, maxProofAge_);
        _getTEEDataVerifierStorage().teeOracleAddress = teeOracleAddress_;
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setTeeOracleAddress(address newAddress) external onlyOwner {
        _getTEEDataVerifierStorage().teeOracleAddress = newAddress;
    }

    // ── Ownership proof ───────────────────────────────────────────────────────

    /// @dev Signed message:
    ///      keccak256(abi.encode(chainId, erc7857, dataHash, sealedKey, targetPubkey, nonce, deadline)).
    ///      Uses abi.encode, NOT encodePacked: sealedKey, targetPubkey and nonce are
    ///      three adjacent dynamic-length fields, so packing them lets a re-split of
    ///      the same bytes make the stored sealedKey differ from the blob actually
    ///      sealed (buyer-denial griefing). abi.encode length-prefixes each dynamic
    ///      value so the boundaries are part of the signed digest. Same EIP-191
    ///      hex-encoded format as the access proof. `chainId` and `erc7857`
    ///      domain-separate the oracle's OwnershipProof against cross-chain /
    ///      cross-contract replay. NOTE: the off-chain oracle signer MUST match this
    ///      encoding exactly.
    function _verifyOwnershipProof(OwnershipProof calldata op, address erc7857) internal override {
        if (op.oracleType != OracleType.TEE) revert TEEDataVerifierWrongOracleType();

        bytes32 inner = keccak256(abi.encode(
            block.chainid, erc7857, op.dataHash, op.sealedKey, op.targetPubkey, op.nonce, op.deadline
        ));
        address signer = _eip191Hash(inner).recover(op.proof);

        if (signer != _getTEEDataVerifierStorage().teeOracleAddress)
            revert TEEDataVerifierInvalidSignature();
    }

    // ── View ──────────────────────────────────────────────────────────────────

    function teeOracleAddress() external view returns (address) {
        return _getTEEDataVerifierStorage().teeOracleAddress;
    }
}
