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

/// @notice setTeeOracleAddress was given the zero address.
error TEEDataVerifierZeroAddress();

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

    /// @notice Current implementation version. Bump on every upgrade.
    /// @dev 1.2.0 — governance hardening (beacon upgrade; audit FIND-12 /
    ///      FIND-16): ownership becomes two-step (BaseDataVerifier moves to
    ///      Ownable2StepUpgradeable — transferOwnership only proposes, the new
    ///      owner must acceptOwnership; pending owner in OZ's ERC-7201
    ///      namespace, no existing storage moves); setTeeOracleAddress rejects
    ///      address(0) (TEEDataVerifierZeroAddress) and emits TeeOracleUpdated.
    ///      Audit Low fixes in the same build: both proof preimages gain
    ///      (tokenId, from, isClone) right after (chainId, erc7857), and
    ///      verifyTransferValidity takes them as arguments — a new selector,
    ///      so AgenticID 1.2.0 must land in the same window, and 1.1.0-format
    ///      proofs stop verifying (FIND-05; consensus-critical for the
    ///      off-repo buyer and oracle signers — none sign today). The access
    ///      nonce key adds the recovered signer (FIND-06) and the ownership
    ///      nonce key the tokenId (storage keys only).
    ///      setMaxProofAge only raises, within [2 hours, 365 days], and emits
    ///      NonceMaxAgeUpdated; initialize enforces the same range (FIND-07).
    ///      1.1.0 — proof preimages switch from abi.encodePacked to abi.encode
    ///      (access + ownership). Adjacent dynamic fields (targetPubkey, nonce,
    ///      sealedKey) were packed without length boundaries, so a signature over
    ///      one field split verified for another — a re-split could seal the data
    ///      to an attacker's key while the buyer took the token. Length-prefixing
    ///      each dynamic value makes the boundary part of the signed digest.
    ///      Off-chain signers (out of this repo) MUST match the new encoding.
    ///      1.0.0 — initial (packed preimages).
    string public constant VERSION = "1.2.0";

    event TeeOracleUpdated(address indexed previousOracle, address indexed newOracle);

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

    /// @param owner_            Contract owner (config: oracle address, maxProofAge, pauser).
    ///                          Direct calls, not timelocked — only beacon upgrades are.
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

    /// @notice Rotate the TEE oracle signing address. Takes effect for every
    ///         subsequent proof. Zero is rejected: no signature recovers to
    ///         it, so every proof-gated iTransferFrom / iCloneFrom would revert
    ///         until the next rotation.
    function setTeeOracleAddress(address newAddress) external onlyOwner {
        if (newAddress == address(0)) revert TEEDataVerifierZeroAddress();
        TEEDataVerifierStorage storage $ = _getTEEDataVerifierStorage();
        emit TeeOracleUpdated($.teeOracleAddress, newAddress);
        $.teeOracleAddress = newAddress;
    }

    // ── Ownership proof ───────────────────────────────────────────────────────

    /// @dev Signed message:
    ///      keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone, dataHash, sealedKey, targetPubkey, nonce, deadline)).
    ///      `tokenId` / `from` / `isClone` bind the oracle's re-seal to the
    ///      token being moved, its owner and the action (audit FIND-05, same
    ///      as the access proof).
    ///      Uses abi.encode, NOT encodePacked: sealedKey, targetPubkey and nonce are
    ///      three adjacent dynamic-length fields, so packing them lets a re-split of
    ///      the same bytes make the stored sealedKey differ from the blob actually
    ///      sealed (buyer-denial griefing). abi.encode length-prefixes each dynamic
    ///      value so the boundaries are part of the signed digest. Same EIP-191
    ///      hex-encoded format as the access proof. `chainId` and `erc7857`
    ///      domain-separate the oracle's OwnershipProof against cross-chain /
    ///      cross-contract replay. NOTE: the off-chain oracle signer MUST match this
    ///      encoding exactly.
    function _verifyOwnershipProof(
        OwnershipProof calldata op, address erc7857, uint256 tokenId, address from, bool isClone
    ) internal override {
        if (op.oracleType != OracleType.TEE) revert TEEDataVerifierWrongOracleType();

        bytes32 inner = keccak256(abi.encode(
            block.chainid, erc7857, tokenId, from, isClone,
            op.dataHash, op.sealedKey, op.targetPubkey, op.nonce, op.deadline
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
