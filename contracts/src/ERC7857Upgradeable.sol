// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";

import {IERC7857, SealedKeyEntry} from "./interfaces/IERC7857.sol";
import {IERC7857Delegate} from "./interfaces/IERC7857Delegate.sol";
import {IntelligentData} from "./interfaces/IERC7857Metadata.sol";
import {
    IERC7857DataVerifier,
    TransferValidityProof,
    TransferValidityProofOutput
} from "./interfaces/IERC7857DataVerifier.sol";

contract ERC7857Upgradeable is IERC7857, IERC7857Delegate, ERC721Upgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {

    /// @custom:storage-location erc7857:0g.storage.ERC7857
    struct ERC7857Storage {
        mapping(address => address) accessDelegates;
        IERC7857DataVerifier verifier;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857StorageLocation =
        0xa2b40c657abdbf180a6038c081d3a0af6206dcea36f4558f991bf8c787ef3c00;

    function _getERC7857Storage() private pure returns (ERC7857Storage storage $) {
        assembly {
            $.slot := ERC7857StorageLocation
        }
    }

    constructor() {
        _disableInitializers();
    }

    function __ERC7857_init(
        string memory name_,
        string memory symbol_,
        address verifier_
    ) internal onlyInitializing {
        __ERC721_init(name_, symbol_);
        __Pausable_init();
        __ERC7857_init_unchained(verifier_);
    }

    function __ERC7857_init_unchained(address verifier_) internal onlyInitializing {
        __Pausable_init();
        _setVerifier(verifier_);
    }

    function _setVerifier(address verifier_) internal {
        _getERC7857Storage().verifier = IERC7857DataVerifier(verifier_);
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC721Upgradeable, IERC165) returns (bool) {
        return
            interfaceId == type(IERC7857).interfaceId ||
            interfaceId == type(IERC7857Delegate).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ── IERC7857Delegate ──────────────────────────────────────────────────────

    function setAccessDelegate(address delegate) public virtual whenNotPaused {
        _getERC7857Storage().accessDelegates[msg.sender] = delegate;
        emit DelegateUpdated(msg.sender, delegate);
    }

    function getAccessDelegate(address user) public view virtual returns (address) {
        return _getERC7857Storage().accessDelegates[user];
    }

    // ── Disabled ERC721 transfers ─────────────────────────────────────────────
    // Declared virtual so application contracts can selectively re-enable
    // transferFrom for non-intelligent tokens if needed.

    function transferFrom(address, address, uint256) public virtual override(ERC721Upgradeable, IERC721) {
        revert ERC7857UseITransferFrom();
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public virtual override(ERC721Upgradeable, IERC721) {
        revert ERC7857UseITransferFrom();
    }

    // ── iTransferFrom ─────────────────────────────────────────────────────────

    function iTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) public virtual whenNotPaused nonReentrant returns (SealedKeyEntry[] memory entries) {
        // Authorization checked BEFORE proof verification so unauthorised
        // callers fail cheaply without spending gas on proof validation.
        _checkAuthorized(from, msg.sender, tokenId);

        entries = _proofCheck(from, to, tokenId, proofs);

        // Checks-effects-interactions: persist the new sealedKeys (wrapped to
        // `to`) BEFORE handing control to `to` via _safeTransfer's
        // onERC721Received callback. Writing keys after the callback let a
        // malicious receiver re-enter and forward the token onward, so the
        // outer frame's key write clobbered the inner one — leaving ownership
        // and the stored keys desynced. dataHashes don't change on transfer;
        // only the wrap target does. The key write is keyed by tokenId (not by
        // owner), so doing it while the token still belongs to `from` is fine,
        // and if the receiver rejects, the whole tx (including this write)
        // reverts — atomicity preserved. nonReentrant is belt-and-suspenders.
        bytes[] memory sealedKeys = new bytes[](entries.length);
        for (uint256 i; i < entries.length; ++i) {
            sealedKeys[i] = entries[i].sealedKey;
        }
        _updateSealedKeys(tokenId, sealedKeys);

        // Use internal transfer to avoid a redundant _checkAuthorized call
        // and to bypass our own transferFrom override.
        _safeTransfer(from, to, tokenId, "");

        emit ITransferred(from, to, tokenId, entries);
    }

    // ── Proof validation ──────────────────────────────────────────────────────

    function _proofCheck(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) internal returns (SealedKeyEntry[] memory entries) {
        if (to == address(0)) revert ERC721InvalidReceiver(to);
        if (_ownerOf(tokenId) != from) revert ERC721InvalidSender(from);
        if (proofs.length == 0) revert ERC7857InvalidProof();

        ERC7857Storage storage $ = _getERC7857Storage();
        TransferValidityProofOutput[] memory proofOutput = $.verifier.verifyTransferValidity(proofs);

        IntelligentData[] memory datas = _intelligentDatasOf(tokenId);
        if (proofOutput.length != datas.length) revert ERC7857InvalidProof();

        address delegate = $.accessDelegates[to];
        entries = new SealedKeyEntry[](proofOutput.length);

        for (uint256 i = 0; i < proofOutput.length; i++) {
            // Verify proof covers the correct data
            if (proofOutput[i].dataHash != datas[i].dataHash) revert ERC7857InvalidProof();

            // Access proof must be signed by the receiver or their registered delegate
            address assistant = proofOutput[i].accessAssistant;
            if (assistant != to && assistant != delegate) revert ERC7857InvalidProof();

            // Verify the encryption target matches the receiver
            bytes memory wantedKey = proofOutput[i].wantedKey;
            bytes memory targetPubkey = proofOutput[i].targetPubkey;
            if (wantedKey.length == 0) {
                // Ethereum key mode: derive address from the 64-byte uncompressed public key
                if (targetPubkey.length != 64) revert ERC7857InvalidProof();
                address derived = address(uint160(uint256(keccak256(targetPubkey))));
                if (derived != to) revert ERC7857InvalidProof();
            } else {
                // Custom key mode: verify encryption target matches the requested key
                if (keccak256(targetPubkey) != keccak256(wantedKey)) revert ERC7857InvalidProof();
            }

            entries[i] = SealedKeyEntry({
                dataHash: proofOutput[i].dataHash,
                sealedKey: proofOutput[i].sealedKey
            });
        }
    }

    // ── View ──────────────────────────────────────────────────────────────────

    function verifier() public view virtual returns (IERC7857DataVerifier) {
        return _getERC7857Storage().verifier;
    }

    function intelligentDatasOf(uint256 tokenId) public view virtual returns (IntelligentData[] memory) {
        if (_ownerOf(tokenId) == address(0)) revert ERC721NonexistentToken(tokenId);
        return _intelligentDatasOf(tokenId);
    }

    function sealedKeysOf(uint256 tokenId) public view virtual returns (bytes[] memory) {
        if (_ownerOf(tokenId) == address(0)) revert ERC721NonexistentToken(tokenId);
        return _sealedKeysOf(tokenId);
    }

    // ── Internal hooks (override in subcontracts) ─────────────────────────────

    function _intelligentDatasOf(uint256) internal view virtual returns (IntelligentData[] memory) {
        return new IntelligentData[](0);
    }

    function _intelligentDatasLengthOf(uint256) internal view virtual returns (uint256) {
        return 0;
    }

    function _sealedKeysOf(uint256) internal view virtual returns (bytes[] memory) {
        return new bytes[](0);
    }

    /// @dev Rewrite the sealedKeys array for `tokenId` without touching
    ///      the IntelligentData entries. Called by `iTransferFrom` to
    ///      re-wrap to the new owner; `_updateData` handles the combined
    ///      datas+keys rewrite when the dataHashes themselves change.
    function _updateSealedKeys(uint256 tokenId, bytes[] memory sealedKeys) internal virtual {}

    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    ) internal virtual {}

    function _updateDataAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData memory newData,
        bytes memory sealedKey
    ) internal virtual {}
}
