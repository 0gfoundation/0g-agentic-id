// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";
import {IERC7857Updatable} from "../interfaces/IERC7857Updatable.sol";
import {IntelligentData} from "../interfaces/IERC7857Metadata.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract ERC7857IDataStorageUpgradeable is IERC7857Updatable, ERC7857Upgradeable {

    /// @custom:storage-location erc7857:0g.storage.ERC7857IDataStorage
    struct ERC7857IDataStorageStorage {
        mapping(uint256 => IntelligentData[]) iDatas;
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

    function update(uint256 tokenId, IntelligentData[] calldata newDatas) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        if (newDatas.length == 0) revert ERC7857EmptyData();
        _updateData(tokenId, newDatas);
    }

    function updateAt(uint256 tokenId, uint256 index, IntelligentData calldata newData) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        _updateDataAt(tokenId, index, newData);
    }

    function _intelligentDatasOf(uint256 tokenId) internal view virtual override returns (IntelligentData[] memory) {
        return _getERC7857IDataStorageStorage().iDatas[tokenId];
    }

    function _intelligentDatasLengthOf(uint256 tokenId) internal view virtual override returns (uint256) {
        return _getERC7857IDataStorageStorage().iDatas[tokenId].length;
    }

    function _updateDataAt(uint256 tokenId, uint256 index, IntelligentData memory newData) internal virtual override {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();
        uint256 len = $.iDatas[tokenId].length;
        if (index >= len) revert ERC7857IndexOutOfBounds(index, len);
        IntelligentData memory oldData = $.iDatas[tokenId][index];
        $.iDatas[tokenId][index] = newData;
        emit EntryUpdated(tokenId, index, oldData, newData);
    }

    function _updateData(uint256 tokenId, IntelligentData[] memory newDatas) internal virtual override {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();

        IntelligentData[] memory oldDatas = $.iDatas[tokenId];

        delete $.iDatas[tokenId];
        for (uint256 i = 0; i < newDatas.length; i++) {
            $.iDatas[tokenId].push(newDatas[i]);
        }

        emit Updated(tokenId, oldDatas, newDatas);
    }
}
