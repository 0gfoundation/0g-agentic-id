// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A single piece of intelligent data bound to a token.
struct IntelligentData {
    string  dataDescription;
    bytes32 dataHash;
}

/// @notice Metadata interface for ERC7857 intelligent tokens.
/// @dev Intentionally does NOT inherit IERC721Metadata. Support for tokenURI
///      is an optional application-layer concern and not a requirement of this standard.
interface IERC7857Metadata {
    /// @notice Returns all intelligent data entries bound to `tokenId`.
    function intelligentDatasOf(uint256 tokenId) external view returns (IntelligentData[] memory);
}
