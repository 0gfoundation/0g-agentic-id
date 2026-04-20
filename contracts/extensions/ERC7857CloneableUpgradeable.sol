// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7857Cloneable, SealedKeyEntry} from "../interfaces/IERC7857Cloneable.sol";
import {IntelligentData} from "../interfaces/IERC7857Metadata.sol";
import {TransferValidityProof} from "../interfaces/IERC7857DataVerifier.sol";
import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract ERC7857CloneableUpgradeable is IERC7857Cloneable, ERC7857Upgradeable {

    /// @custom:storage-location erc7857:0g.storage.ERC7857Cloneable
    struct ERC7857CloneableStorage {
        uint256 nextTokenId;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857Cloneable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857CloneableStorageLocation =
        0x03de6cf14ecf4575e0ed0cc2fdb9b7ee13500cb3c0c403254fc893bf6e0c8000;

    function _getERC7857CloneableStorage() private pure returns (ERC7857CloneableStorage storage $) {
        assembly {
            $.slot := ERC7857CloneableStorageLocation
        }
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC7857Upgradeable) returns (bool) {
        return interfaceId == type(IERC7857Cloneable).interfaceId || super.supportsInterface(interfaceId);
    }

    // ── Token ID management ───────────────────────────────────────────────────

    function _incrementTokenId() internal virtual returns (uint256 nextTokenId) {
        ERC7857CloneableStorage storage $ = _getERC7857CloneableStorage();
        nextTokenId = $.nextTokenId;
        $.nextTokenId++;
    }

    // ── iCloneFrom ────────────────────────────────────────────────────────────

    function iCloneFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) public virtual whenNotPaused returns (uint256 newTokenId) {
        // Authorization checked BEFORE proof verification
        if (_ownerOf(tokenId) != from) revert ERC721InvalidSender(from);
        _checkAuthorized(from, msg.sender, tokenId);

        SealedKeyEntry[] memory entries = _proofCheck(from, to, tokenId, proofs);

        newTokenId = _incrementTokenId();
        _safeMint(to, newTokenId);

        IntelligentData[] memory datas = _intelligentDatasOf(tokenId);
        _updateData(newTokenId, datas);

        emit Cloned(tokenId, newTokenId, from, to, entries);
    }
}
