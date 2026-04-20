// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7857} from "./IERC7857.sol";
import {IntelligentData} from "./IERC7857Metadata.sol";

/// @notice Optional extension: allows a token owner to update IntelligentData after minting.
///
/// @dev Detect support via ERC-165: type(IERC7857Updatable).interfaceId.
///      Implementors MUST also register type(IERC7857).interfaceId.
interface IERC7857Updatable is IERC7857 {

    // ── Errors ────────────────────────────────────────────────────────────────

    /// @notice Raised when update is called with an empty data array.
    error ERC7857EmptyData();

    /// @notice Raised when updateAt is called with an out-of-bounds index.
    error ERC7857IndexOutOfBounds(uint256 index, uint256 length);

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted when all IntelligentData entries of a token are replaced at once.
    /// @dev After this event all of the owner's existing sealedKeys become invalid.
    ///      The owner must re-request sealedKeys from the oracle for all new dataHashes.
    event Updated(
        uint256 indexed tokenId,
        IntelligentData[] oldDatas,
        IntelligentData[] newDatas
    );

    /// @notice Emitted when a single IntelligentData entry is updated in place.
    /// @dev Only the sealedKey for the entry at `index` becomes invalid.
    ///      sealedKeys for other entries remain valid.
    event EntryUpdated(
        uint256 indexed tokenId,
        uint256 indexed index,
        IntelligentData oldData,
        IntelligentData newData
    );

    // ── Functions ─────────────────────────────────────────────────────────────

    /// @notice Replace all IntelligentData entries for a token.
    /// @dev Only the token owner may call this.
    ///      After this call all existing sealedKeys for the token become invalid.
    ///      The owner must re-request sealedKeys from the oracle for all new dataHashes.
    function update(uint256 tokenId, IntelligentData[] calldata newDatas) external;

    /// @notice Update a single IntelligentData entry in place.
    /// @dev Only the token owner may call this.
    ///      Only the sealedKey for the entry at `index` becomes invalid;
    ///      sealedKeys for all other entries remain valid.
    function updateAt(uint256 tokenId, uint256 index, IntelligentData calldata newData) external;
}
