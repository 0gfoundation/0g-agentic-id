// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IERC8004IdentityRegistry, MetadataEntry} from "./interfaces/IERC8004IdentityRegistry.sol";
import {NonceRegistryUpgradeable} from "./utils/NonceRegistryUpgradeable.sol";

/// @notice The agentWallet signature was not made by newWallet.
error ERC8004InvalidWalletSignature();

/// @title ERC8004IdentityRegistryUpgradeable
/// @notice Base implementation of the ERC-8004 Identity Registry.
///
///         Each agent is an ERC-721 token. Registration mints a new token and
///         assigns a globally unique agentId (the token ID). The token carries
///         an optional URI, arbitrary key-value metadata, and an optional payment
///         wallet address that requires cryptographic consent from the wallet owner.
///
///         agentWallet is automatically cleared on every token transfer so the
///         new owner starts with a clean state.
///
/// @dev Subclasses must call `__ERC8004IdentityRegistry_init` in their initializer.
///      If combined with ERC-7857 (e.g. AgenticID), override `_incrementTokenId()`
///      to share a single token-ID counter across all minting paths.
abstract contract ERC8004IdentityRegistryUpgradeable is
    IERC8004IdentityRegistry,
    ERC721Upgradeable,
    EIP712Upgradeable,
    NonceRegistryUpgradeable
{
    using ECDSA for bytes32;

    // ── EIP-712 ───────────────────────────────────────────────────────────────

    bytes32 private constant SET_AGENT_WALLET_TYPEHASH = keccak256(
        "SetAgentWallet(uint256 agentId,address wallet,uint256 deadline,bytes32 nonce)"
    );

    bytes32 private constant _SET_AGENT_WALLET_TAG = keccak256("SET_AGENT_WALLET");

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7857:0g.storage.ERC8004IdentityRegistry
    struct ERC8004IdentityRegistryStorage {
        uint256 nextTokenId;
        mapping(uint256 => string)              agentURIs;
        /// @dev Key is keccak256(abi.encodePacked(metadataKey)) to avoid
        ///      the gas cost of string comparison in mapping lookups.
        mapping(uint256 => mapping(bytes32 => bytes)) metadata;
        mapping(uint256 => address)             agentWallets;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC8004IdentityRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC8004IdentityRegistryStorageLocation =
        0x28b8f0e2c72a8d128785c1f8d9cea1554c0fb46582def61ff513490ce1754d00;

    function _getERC8004Storage() private pure returns (ERC8004IdentityRegistryStorage storage $) {
        assembly {
            $.slot := ERC8004IdentityRegistryStorageLocation
        }
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function __ERC8004IdentityRegistry_init(
        string memory name_,
        string memory symbol_,
        uint256 maxProofAge_
    ) internal onlyInitializing {
        __ERC721_init(name_, symbol_);
        __EIP712_init(name_, "1");
        __NonceRegistry_init_unchained(maxProofAge_);
        __ERC8004IdentityRegistry_init_unchained();
    }

    function __ERC8004IdentityRegistry_init_unchained() internal onlyInitializing {
        // Start at 1; token ID 0 is reserved as a sentinel for "no token".
        _getERC8004Storage().nextTokenId = 1;
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public view virtual
        override(ERC721Upgradeable, IERC165)
        returns (bool)
    {
        return interfaceId == type(IERC8004IdentityRegistry).interfaceId
            || super.supportsInterface(interfaceId);
    }

    // ── Token ID counter ──────────────────────────────────────────────────────

    /// @dev Returns the next token ID and advances the counter.
    ///      Declared virtual so AgenticID (which combines ERC-8004 and ERC-7857)
    ///      can override to share this counter with ERC7857CloneableUpgradeable.
    function _incrementTokenId() internal virtual returns (uint256 tokenId) {
        ERC8004IdentityRegistryStorage storage $ = _getERC8004Storage();
        tokenId = $.nextTokenId;
        $.nextTokenId++;
    }

    // ── Registration ──────────────────────────────────────────────────────────

    function register(string calldata agentURI, MetadataEntry[] calldata metadata)
        external virtual returns (uint256 agentId)
    {
        agentId = _mintAgent(msg.sender, agentURI);
        _setMetadataBatch(agentId, metadata);
    }

    function register(string calldata agentURI) external virtual returns (uint256 agentId) {
        return _mintAgent(msg.sender, agentURI);
    }

    function register() external virtual returns (uint256 agentId) {
        return _mintAgent(msg.sender, "");
    }

    function _mintAgent(address to, string memory agentURI) internal returns (uint256 agentId) {
        agentId = _incrementTokenId();
        _safeMint(to, agentId);
        if (bytes(agentURI).length > 0) {
            _getERC8004Storage().agentURIs[agentId] = agentURI;
        }
        emit Registered(agentId, agentURI, to);
    }

    // ── URI ───────────────────────────────────────────────────────────────────

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        if (_ownerOf(tokenId) == address(0)) revert ERC721NonexistentToken(tokenId);
        return _getERC8004Storage().agentURIs[tokenId];
    }

    function setAgentURI(uint256 agentId, string calldata newURI) external {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        _getERC8004Storage().agentURIs[agentId] = newURI;
        emit URIUpdated(agentId, newURI, msg.sender);
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    function getMetadata(uint256 agentId, string memory metadataKey)
        external view returns (bytes memory)
    {
        return _getERC8004Storage().metadata[agentId][
            keccak256(abi.encodePacked(metadataKey))
        ];
    }

    function setMetadata(
        uint256 agentId,
        string memory metadataKey,
        bytes memory metadataValue
    ) external {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        _setMetadataEntry(agentId, metadataKey, metadataValue);
    }

    function _setMetadataBatch(uint256 agentId, MetadataEntry[] calldata entries) internal {
        for (uint256 i = 0; i < entries.length; i++) {
            _setMetadataEntry(agentId, entries[i].metadataKey, entries[i].metadataValue);
        }
    }

    function _setMetadataEntry(
        uint256 agentId,
        string memory metadataKey,
        bytes memory metadataValue
    ) internal {
        _getERC8004Storage().metadata[agentId][
            keccak256(abi.encodePacked(metadataKey))
        ] = metadataValue;
        emit MetadataSet(agentId, metadataKey, metadataKey, metadataValue);
    }

    function _getMetadataEntry(uint256 agentId, string memory metadataKey)
        internal view returns (bytes memory)
    {
        return _getERC8004Storage().metadata[agentId][
            keccak256(abi.encodePacked(metadataKey))
        ];
    }

    function _deleteMetadataEntry(uint256 agentId, string memory metadataKey) internal {
        delete _getERC8004Storage().metadata[agentId][
            keccak256(abi.encodePacked(metadataKey))
        ];
    }

    // ── Agent wallet ──────────────────────────────────────────────────────────

    /// @notice Set the wallet that receives service payments for this agent.
    /// @dev `signature` must be an EIP-712 signature from `newWallet` proving consent.
    ///      Signed type: SetAgentWallet(uint256 agentId,address wallet,uint256 deadline,bytes32 nonce).
    ///      Deadline + nonce checks go through NonceRegistry — each (agentId, newWallet, nonce)
    ///      signature is redeemable at most once.
    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 deadline,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            SET_AGENT_WALLET_TYPEHASH,
            agentId,
            newWallet,
            deadline,
            nonce
        )));
        if (digest.recover(signature) != newWallet)
            revert ERC8004InvalidWalletSignature();

        bytes32 nonceKey = keccak256(abi.encode(_SET_AGENT_WALLET_TAG, agentId, newWallet, nonce));
        _checkAndMarkNonce(nonceKey, deadline);

        _getERC8004Storage().agentWallets[agentId] = newWallet;
    }

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return _getERC8004Storage().agentWallets[agentId];
    }

    /// @notice Clear the agent wallet. Called automatically on transfer; also
    ///         callable by the agent owner to revoke without transferring.
    function unsetAgentWallet(uint256 agentId) external {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        delete _getERC8004Storage().agentWallets[agentId];
    }

    // ── _update — clear agentWallet on transfer ───────────────────────────────

    function _update(address to, uint256 tokenId, address auth)
        internal virtual override
        returns (address from)
    {
        from = super._update(to, tokenId, auth);
        if (from != address(0)) {
            delete _getERC8004Storage().agentWallets[tokenId];
        }
    }
}
