// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IERC7857Authorize} from "../interfaces/IERC7857Authorize.sol";
import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";

contract ERC7857AuthorizeUpgradeable is IERC7857Authorize, ERC7857Upgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    uint256 public constant MAX_AUTHORIZED_USERS = 100;

    /// @custom:storage-location erc7857:0g.storage.ERC7857Authorize
    struct ERC7857AuthorizeStorage {
        mapping(uint256 => EnumerableSet.AddressSet) authorizedUsers;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857Authorize")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857AuthorizeStorageLocation =
        0xf386e9faca35fbde2fe950510f665060c1dd15a136a76c268b6e6459b9945700;

    function _getERC7857AuthorizeStorage() private pure returns (ERC7857AuthorizeStorage storage $) {
        assembly {
            $.slot := ERC7857AuthorizeStorageLocation
        }
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC7857Upgradeable) returns (bool) {
        return interfaceId == type(IERC7857Authorize).interfaceId || super.supportsInterface(interfaceId);
    }

    // ── IERC7857Authorize ─────────────────────────────────────────────────────

    function authorizeUsage(uint256 tokenId, address user) public virtual whenNotPaused {
        if (user == address(0)) revert ERC7857InvalidAuthorizedUser(user);
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        _authorizeUser(tokenId, user);
    }

    function batchAuthorizeUsage(uint256 tokenId, address[] calldata users) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert ERC7857InvalidAuthorizedUser(users[i]);
            _authorizeUser(tokenId, users[i]);
        }
    }

    function revokeAuthorization(uint256 tokenId, address user) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721InvalidSender(msg.sender);
        if (user == address(0)) revert ERC7857InvalidAuthorizedUser(user);

        ERC7857AuthorizeStorage storage $ = _getERC7857AuthorizeStorage();
        if (!$.authorizedUsers[tokenId].remove(user)) revert ERC7857NotAuthorized();

        emit AuthorizationRevoked(msg.sender, user, tokenId);
    }

    function clearAuthorizedUsers(uint256 tokenId) public virtual whenNotPaused {
        if (_ownerOf(tokenId) != msg.sender) revert ERC721IncorrectOwner(msg.sender, tokenId, _ownerOf(tokenId));
        _clearAuthorized(tokenId);
        emit AuthorizationCleared(msg.sender, tokenId);
    }

    function authorizedUsersOf(uint256 tokenId) public view virtual returns (address[] memory) {
        if (_ownerOf(tokenId) == address(0)) revert ERC721NonexistentToken(tokenId);
        return _getERC7857AuthorizeStorage().authorizedUsers[tokenId].values();
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _authorizeUser(uint256 tokenId, address user) internal {
        ERC7857AuthorizeStorage storage $ = _getERC7857AuthorizeStorage();
        EnumerableSet.AddressSet storage set = $.authorizedUsers[tokenId];

        if (set.length() >= MAX_AUTHORIZED_USERS) revert ERC7857TooManyAuthorizedUsers();
        if (set.contains(user)) revert ERC7857AlreadyAuthorized();

        set.add(user);
        emit AuthorizationGranted(msg.sender, user, tokenId);
    }

    function _clearAuthorized(uint256 tokenId) internal {
        ERC7857AuthorizeStorage storage $ = _getERC7857AuthorizeStorage();
        address[] memory values = $.authorizedUsers[tokenId].values();
        for (uint256 i = 0; i < values.length; i++) {
            $.authorizedUsers[tokenId].remove(values[i]);
        }
    }

    // ── Override ERC721 _update to clear authorized users on transfer ──────────

    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        address from = super._update(to, tokenId, auth);
        if (from != address(0)) {
            _clearAuthorized(tokenId);
        }
        return from;
    }
}
