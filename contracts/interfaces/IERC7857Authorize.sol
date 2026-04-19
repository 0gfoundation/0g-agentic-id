// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7857} from "./IERC7857.sol";

/// @notice Optional extension: off-chain usage authorization registry.
///
/// @dev PURPOSE — This interface maintains a per-token allowlist that external
///      off-chain systems (e.g. AI inference services) query to determine whether
///      a caller is permitted to use a token's capabilities.
///
///      IMPORTANT: The authorized-user set does NOT gate any on-chain operation.
///      Functions such as iTransferFrom and iCloneFrom check ERC721 ownership and
///      approval only. An address in authorizedUsersOf() gains no on-chain privilege.
///
///      The authorization list is automatically cleared when a token is transferred,
///      so the new owner always starts with an empty allowlist.
///
///      Detect support via ERC-165: type(IERC7857Authorize).interfaceId.
///      Implementors MUST also register type(IERC7857).interfaceId.
interface IERC7857Authorize is IERC7857 {

    // ── Errors ────────────────────────────────────────────────────────────────

    error ERC7857InvalidAuthorizedUser(address user);
    error ERC7857TooManyAuthorizedUsers();
    error ERC7857AlreadyAuthorized();
    error ERC7857NotAuthorized();

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted when a user is granted off-chain usage authorization.
    event AuthorizationGranted(address indexed owner, address indexed user, uint256 indexed tokenId);

    /// @notice Emitted when a user's off-chain usage authorization is revoked.
    event AuthorizationRevoked(address indexed owner, address indexed user, uint256 indexed tokenId);

    /// @notice Emitted when all off-chain authorizations for a token are cleared.
    event AuthorizationCleared(address indexed owner, uint256 indexed tokenId);

    // ── Functions ─────────────────────────────────────────────────────────────

    /// @notice Grant off-chain usage authorization to `user` for `tokenId`.
    /// @dev Only the token owner may call this.
    function authorizeUsage(uint256 tokenId, address user) external;

    /// @notice Grant off-chain usage authorization to multiple users in one call.
    /// @dev Only the token owner may call this.
    function batchAuthorizeUsage(uint256 tokenId, address[] calldata users) external;

    /// @notice Revoke off-chain usage authorization from `user` for `tokenId`.
    /// @dev Only the token owner may call this.
    function revokeAuthorization(uint256 tokenId, address user) external;

    /// @notice Revoke all off-chain usage authorizations for `tokenId`.
    /// @dev Only the token owner may call this.
    function clearAuthorizedUsers(uint256 tokenId) external;

    /// @notice Returns all currently authorized users for `tokenId`.
    function authorizedUsersOf(uint256 tokenId) external view returns (address[] memory);
}
