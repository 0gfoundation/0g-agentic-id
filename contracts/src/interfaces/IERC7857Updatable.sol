// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7857} from "./IERC7857.sol";
import {IntelligentData} from "./IERC7857Metadata.sol";

/// @notice Optional extension: allows the authorized party to update
///         IntelligentData after minting.
///
/// @dev Detect support via ERC-165: type(IERC7857Updatable).interfaceId.
///      Implementors MUST also register type(IERC7857).interfaceId.
///
///      sealedKeys travel with the data — same pattern as `IERC7857`
///      mint / transfer events — so the on-chain event log remains the
///      single source of truth for "how to decrypt this dataHash".
///      The caller is responsible for wrapping each sealedKey to the
///      appropriate recipient pubkey (typically the current owner).
interface IERC7857Updatable is IERC7857 {

    // ── Errors ────────────────────────────────────────────────────────────────

    /// @notice Raised when update is called with an empty data array.
    error ERC7857EmptyData();

    /// @notice Raised when updateAt is called with an out-of-bounds index.
    error ERC7857IndexOutOfBounds(uint256 index, uint256 length);

    /// @notice Raised when `newDatas.length != sealedKeys.length`.
    /// @dev    Each entry must have exactly one matching sealedKey.
    error ERC7857SealedKeyArityMismatch(uint256 dataLen, uint256 keyLen);

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted when all IntelligentData entries of a token are replaced at once.
    /// @dev `sealedKeys[i]` is the new wrap for `newDatas[i].dataHash`,
    ///      wrapped to the recipient the caller chose (typically the
    ///      current owner). Consumers reading the event recover decrypt
    ///      capability without any extra round trip.
    event Updated(
        uint256 indexed tokenId,
        IntelligentData[] oldDatas,
        IntelligentData[] newDatas,
        bytes[]           sealedKeys
    );

    /// @notice Emitted when a single IntelligentData entry is updated in place.
    /// @dev `sealedKey` is the new wrap for `newData.dataHash`. Other
    ///      entries' sealedKeys are untouched.
    event EntryUpdated(
        uint256 indexed tokenId,
        uint256 indexed index,
        IntelligentData oldData,
        IntelligentData newData,
        bytes           sealedKey
    );

    // ── Functions ─────────────────────────────────────────────────────────────

    /// @notice Replace all IntelligentData entries for a token.
    /// @dev Authorization is implementation-defined (owner-only by
    ///      default in the reference storage extension; AgenticID-style
    ///      profiles may gate on a bound agentSeal instead).
    ///      `sealedKeys[i]` MUST be the wrap of the data_key for
    ///      `newDatas[i].dataHash`. Arity is enforced.
    function update(
        uint256 tokenId,
        IntelligentData[] calldata newDatas,
        bytes[]           calldata sealedKeys
    ) external;

    /// @notice Update a single IntelligentData entry in place.
    /// @dev `sealedKey` MUST be the wrap of the new data_key for
    ///      `newData.dataHash`. sealedKeys for all other entries
    ///      remain valid.
    function updateAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData calldata newData,
        bytes           calldata sealedKey
    ) external;
}
