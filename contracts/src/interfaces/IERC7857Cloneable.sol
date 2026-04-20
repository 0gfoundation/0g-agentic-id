// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7857, SealedKeyEntry} from "./IERC7857.sol";
import {TransferValidityProof} from "./IERC7857DataVerifier.sol";

/// @notice Optional extension: clone a token without burning the original.
/// @dev Detect support via ERC-165: type(IERC7857Cloneable).interfaceId.
///      Implementors MUST also register type(IERC7857).interfaceId.
interface IERC7857Cloneable is IERC7857 {

    /// @notice Emitted when a token is successfully cloned.
    /// @param tokenId    Source token (unchanged).
    /// @param newTokenId Newly minted clone.
    /// @param from       Owner of the source token.
    /// @param to         Recipient of the clone.
    /// @param entries    Sealed key for each IntelligentData entry of the clone,
    ///                   keyed by dataHash so consumers need not rely on array order.
    event Cloned(
        uint256 indexed tokenId,
        uint256 indexed newTokenId,
        address from,
        address to,
        SealedKeyEntry[] entries
    );

    /// @notice Clone a token: mint a new token with the same IntelligentData and
    ///         deliver the data key to `to`. The source token is NOT burned.
    ///
    /// @dev Authorization is checked BEFORE proof verification.
    ///      The caller must be the owner or an ERC721-approved operator of `tokenId`.
    ///
    ///      Proof ordering: proofs[i] must correspond to the i-th entry returned
    ///      by intelligentDatasOf(tokenId).
    ///
    /// @param from    Owner of the source token.
    /// @param to      Recipient of the clone. Must not be address(0).
    /// @param tokenId Source token.
    /// @param proofs  One proof per IntelligentData entry, in intelligentDatasOf order.
    /// @return newTokenId The ID of the newly minted clone.
    function iCloneFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) external returns (uint256 newTokenId);
}
