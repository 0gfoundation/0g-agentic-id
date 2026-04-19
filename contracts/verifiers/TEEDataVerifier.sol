// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {OracleType, OwnershipProof} from "../interfaces/IERC7857DataVerifier.sol";
import {BaseDataVerifier} from "./BaseDataVerifier.sol";

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
contract TEEDataVerifier is BaseDataVerifier {
    using ECDSA for bytes32;

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7857:0g.storage.TEEDataVerifier
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

    /// @param owner_            Contract owner (can update oracle address and pause).
    /// @param teeOracleAddress_ Ethereum address corresponding to the TEE oracle's signing key.
    /// @param maxProofAge_      Maximum age (seconds) before a used nonce record can be deleted.
    function initialize(
        address owner_,
        address teeOracleAddress_,
        uint256 maxProofAge_
    ) external initializer {
        __BaseDataVerifier_init(owner_, maxProofAge_);
        _getTEEDataVerifierStorage().teeOracleAddress = teeOracleAddress_;
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setTeeOracleAddress(address newAddress) external onlyOwner {
        _getTEEDataVerifierStorage().teeOracleAddress = newAddress;
    }

    // ── Ownership proof ───────────────────────────────────────────────────────

    /// @dev Signed message: keccak256(abi.encodePacked(dataHash, sealedKey, targetPubkey, nonce, deadline)).
    ///      Uses the same EIP-191 hex-encoded format as the access proof.
    function _verifyOwnershipProof(OwnershipProof calldata op) internal override {
        if (op.oracleType != OracleType.TEE) revert TEEDataVerifierWrongOracleType();

        bytes32 inner = keccak256(abi.encodePacked(op.dataHash, op.sealedKey, op.targetPubkey, op.nonce, op.deadline));
        address signer = _eip191Hash(inner).recover(op.proof);

        if (signer != _getTEEDataVerifierStorage().teeOracleAddress)
            revert TEEDataVerifierInvalidSignature();
    }

    // ── View ──────────────────────────────────────────────────────────────────

    function teeOracleAddress() external view returns (address) {
        return _getTEEDataVerifierStorage().teeOracleAddress;
    }
}
