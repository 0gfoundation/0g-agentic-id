// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";
import {IERC7857Updatable} from "../interfaces/IERC7857Updatable.sol";
import {IntelligentData} from "../interfaces/IERC7857Metadata.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract ERC7857IDataStorageUpgradeable is IERC7857Updatable, ERC7857Upgradeable {

    /// @custom:storage-location erc7857:0g.storage.ERC7857IDataStorage
    /// @dev `sealedKeys[tokenId][i]` is the wrap for `iDatas[tokenId][i]`.
    ///      Maintained 1:1 with iDatas by _updateData / _updateDataAt /
    ///      _updateSealedKeys. Appended to the struct in V2 — safe across
    ///      upgrade because the ERC-7201 slot anchors the struct base
    ///      and Solidity packs new fields at higher slots; pre-upgrade
    ///      tokens read an empty array, which clients must fall back to
    ///      the event log to resolve.
    struct ERC7857IDataStorageStorage {
        mapping(uint256 => IntelligentData[]) iDatas;
        mapping(uint256 => bytes[]) sealedKeys;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857IDataStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857IDataStorageStorageLocation =
        0xcee27158032fdbe7e1246476ff878669b520bc82ee1a949d22135b88cc5f5b00;

    function _getERC7857IDataStorageStorage() private pure returns (ERC7857IDataStorageStorage storage $) {
        assembly {
            $.slot := ERC7857IDataStorageStorageLocation
        }
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC7857Upgradeable) returns (bool) {
        return interfaceId == type(IERC7857Updatable).interfaceId || super.supportsInterface(interfaceId);
    }

    // ── IERC7857Updatable ─────────────────────────────────────────────────────

    function update(
        uint256 tokenId,
        IntelligentData[] calldata newDatas,
        bytes[] calldata sealedKeys
    ) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        if (newDatas.length == 0) revert ERC7857EmptyData();
        if (newDatas.length != sealedKeys.length) {
            revert ERC7857SealedKeyArityMismatch(newDatas.length, sealedKeys.length);
        }
        _updateData(tokenId, newDatas, sealedKeys);
    }

    function updateAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData calldata newData,
        bytes calldata sealedKey
    ) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        _updateDataAt(tokenId, index, newData, sealedKey);
    }

    function _intelligentDatasOf(uint256 tokenId) internal view virtual override returns (IntelligentData[] memory) {
        return _getERC7857IDataStorageStorage().iDatas[tokenId];
    }

    function _intelligentDatasLengthOf(uint256 tokenId) internal view virtual override returns (uint256) {
        return _getERC7857IDataStorageStorage().iDatas[tokenId].length;
    }

    function _sealedKeysOf(uint256 tokenId) internal view virtual override returns (bytes[] memory) {
        return _getERC7857IDataStorageStorage().sealedKeys[tokenId];
    }

    function _updateDataAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData memory newData,
        bytes memory sealedKey
    ) internal virtual override {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();
        uint256 len = $.iDatas[tokenId].length;
        if (index >= len) revert ERC7857IndexOutOfBounds(index, len);
        IntelligentData memory oldData = $.iDatas[tokenId][index];
        $.iDatas[tokenId][index] = newData;
        // Pre-V2 rows only had `iDatas` populated, so `sealedKeys` may
        // be empty here even though `iDatas[index]` exists. Grow the
        // array up to len so the [index] write doesn't OOB.
        while ($.sealedKeys[tokenId].length < len) {
            $.sealedKeys[tokenId].push("");
        }
        $.sealedKeys[tokenId][index] = sealedKey;
        emit EntryUpdated(tokenId, index, oldData, newData, sealedKey);
    }

    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    ) internal virtual override {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();

        IntelligentData[] memory oldDatas = $.iDatas[tokenId];

        delete $.iDatas[tokenId];
        delete $.sealedKeys[tokenId];
        for (uint256 i = 0; i < newDatas.length; i++) {
            $.iDatas[tokenId].push(newDatas[i]);
            $.sealedKeys[tokenId].push(sealedKeys[i]);
        }

        emit Updated(tokenId, oldDatas, newDatas, sealedKeys);
    }

    function _updateSealedKeys(
        uint256 tokenId,
        bytes[] memory sealedKeys
    ) internal virtual override {
        // iTransferFrom path: dataHashes unchanged, only the wrap target
        // changes. Caller (ERC7857.iTransferFrom) has already ensured
        // sealedKeys.length == iDatas.length via _proofCheck's arity
        // check; we don't need to defensively re-validate here.
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();
        delete $.sealedKeys[tokenId];
        for (uint256 i = 0; i < sealedKeys.length; i++) {
            $.sealedKeys[tokenId].push(sealedKeys[i]);
        }
    }
}
