// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import {IERC8004IdentityRegistry, MetadataEntry} from "./interfaces/IERC8004IdentityRegistry.sol";
import {ICanonicalIdentityRegistry} from "./interfaces/ICanonicalIdentityRegistry.sol";

/// @title ERC8004CanonicalBoundUpgradeable
/// @notice ERC-8004 identity layer for AgenticID, implemented as a **custody
///         binding** to a fixed, unmodifiable canonical ERC-8004 registry
///         (see {ICanonicalIdentityRegistry}) rather than a private reimplementation.
///
///         Registration mints the canonical token to *this contract* — the
///         AgenticID contract custodies it permanently — and mints a local
///         ERC-721 token with the **same** agentId to the real owner. The
///         canonical token never leaves custody (this contract exposes no path
///         to transfer it), which is what lets ERC-7857's proof-gated transfer
///         govern ownership while the canonical record stays the single source
///         of truth that ecosystem 8004 indexers already read.
///
///         Reads (tokenURI / metadata / agentWallet) pass through to the
///         canonical contract. Writes are authorized locally (owner / — in
///         AgenticID — trusted attestor) and then forwarded as the canonical
///         token holder.
///
/// @dev Subclasses MUST call `__ERC8004CanonicalBound_init` and implement the
///      diamond `_update` / `supportsInterface` disambiguation. The agentId
///      space is the canonical registry's global counter, so it starts at 0 and
///      is shared with every other registrant — never assume a clean range.
abstract contract ERC8004CanonicalBoundUpgradeable is
    IERC8004IdentityRegistry,
    IERC721Receiver,
    ERC721Upgradeable,
    EIP712Upgradeable
{
    // ── Storage ───────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:0g.storage.ERC8004CanonicalBound
    struct ERC8004CanonicalBoundStorage {
        ICanonicalIdentityRegistry canonical;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC8004CanonicalBound")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC8004CanonicalBoundStorageLocation =
        0x953584d91cd6cf2e9540e8374496977361c15fe8ae3bbddea54d6d71100f4d00;

    function _getCanonicalBoundStorage() private pure returns (ERC8004CanonicalBoundStorage storage $) {
        assembly {
            $.slot := ERC8004CanonicalBoundStorageLocation
        }
    }

    /// @notice The canonical ERC-8004 registry this contract binds to.
    function canonical() public view returns (address) {
        return address(_getCanonicalBoundStorage().canonical);
    }

    function _canonical() internal view returns (ICanonicalIdentityRegistry) {
        return _getCanonicalBoundStorage().canonical;
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function __ERC8004CanonicalBound_init(
        string memory name_,
        string memory symbol_,
        address canonical_
    ) internal onlyInitializing {
        __ERC721_init(name_, symbol_);
        __EIP712_init(name_, "1");
        __ERC8004CanonicalBound_init_unchained(canonical_);
    }

    function __ERC8004CanonicalBound_init_unchained(address canonical_) internal onlyInitializing {
        require(canonical_ != address(0), "canonical=0");
        _getCanonicalBoundStorage().canonical = ICanonicalIdentityRegistry(canonical_);
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public view virtual
        override(ERC721Upgradeable, IERC165)
        returns (bool)
    {
        return interfaceId == type(IERC8004IdentityRegistry).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId
            || super.supportsInterface(interfaceId);
    }

    // ── Custody: accept the canonical token minted to this contract ────────────

    /// @dev The canonical registry mints via `_safeMint`, so this contract must
    ///      accept that mint. Only the bound canonical registry may call this,
    ///      and only for a mint into custody (`from == address(0)`, which is what
    ///      our own registration triggers). A stray `safeTransferFrom` of an
    ///      already-existing canonical token is rejected: there is no withdrawal
    ///      path, so accepting one would lock it here permanently.
    function onERC721Received(address, address from, uint256, bytes calldata)
        external view returns (bytes4)
    {
        require(msg.sender == address(_canonical()), "unexpected token");
        require(from == address(0), "no stray deposits");
        return IERC721Receiver.onERC721Received.selector;
    }

    // ── Token ID counter — canonical assigns it ────────────────────────────────

    /// @dev Registers on the canonical registry (minting the canonical token to
    ///      this contract) and returns the global agentId. Virtual so AgenticID,
    ///      which also inherits ERC7857Cloneable's counter, can disambiguate and
    ///      route every mint path through here.
    ///
    ///      canonical.register() seeds agentWallet = msg.sender (this contract);
    ///      it is cleared here — at the single point the canonical token is born —
    ///      so EVERY mint path (register, registerWithSeal, iCloneFrom) starts the
    ///      agent with an empty payment wallet rather than the wrapper address.
    function _incrementTokenId() internal virtual returns (uint256 agentId) {
        ICanonicalIdentityRegistry c = _canonical();
        agentId = c.register();
        c.unsetAgentWallet(agentId);
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

    /// @dev Mint the canonical token (to this contract) + the local token (to
    ///      `to`) under one shared agentId. The canonical `register()` seeds
    ///      agentWallet = msg.sender (= this contract); clear it so the agent
    ///      starts with an empty payment wallet. `Registered` is emitted by the
    ///      canonical registry, the single source of truth — not re-emitted here.
    function _mintAgent(address to, string memory agentURI) internal returns (uint256 agentId) {
        agentId = _incrementTokenId(); // mints canonical token to custody + clears agentWallet
        _safeMint(to, agentId);
        if (bytes(agentURI).length > 0) {
            _canonical().setAgentURI(agentId, agentURI);
        }
    }

    // ── URI (read-through / authorized write-forward) ──────────────────────────

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        if (_ownerOf(tokenId) == address(0)) revert ERC721NonexistentToken(tokenId);
        return _canonical().tokenURI(tokenId);
    }

    // NOTE on events: URIUpdated / MetadataSet are emitted by the canonical
    // registry (the single source of truth), which carries the agentId — so
    // indexers read them there. AgenticID intentionally does NOT re-emit them
    // on forward, to avoid duplicate events for one logical change.
    function setAgentURI(uint256 agentId, string calldata newURI) external {
        _authorizeSetAgentURI(agentId);
        _canonical().setAgentURI(agentId, newURI);
    }

    /// @dev Authorize a setAgentURI call. Default: only the local token owner.
    ///      AgenticID widens this to also allow trusted attestors.
    function _authorizeSetAgentURI(uint256 agentId) internal view virtual {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
    }

    // ── Metadata (read-through / authorized write-forward) ─────────────────────

    function getMetadata(uint256 agentId, string memory metadataKey)
        external view returns (bytes memory)
    {
        return _canonical().getMetadata(agentId, metadataKey);
    }

    function setMetadata(uint256 agentId, string memory metadataKey, bytes memory metadataValue)
        external
    {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        _setMetadataEntry(agentId, metadataKey, metadataValue);
    }

    function _setMetadataBatch(uint256 agentId, MetadataEntry[] calldata entries) internal {
        for (uint256 i = 0; i < entries.length; i++) {
            _setMetadataEntry(agentId, entries[i].metadataKey, entries[i].metadataValue);
        }
    }

    function _setMetadataEntry(uint256 agentId, string memory metadataKey, bytes memory metadataValue)
        internal
    {
        // canonical emits MetadataSet; see the note on setAgentURI for why we don't mirror it.
        _canonical().setMetadata(agentId, metadataKey, metadataValue);
    }

    // ── Agent wallet (read-through / authorized write-forward) ─────────────────
    //
    // Forwarded verbatim to the canonical contract, which enforces the *official*
    // EIP-712 consent scheme: signature is from `newWallet` over
    // AgentWalletSet(agentId,newWallet,owner,deadline) where `owner` is the
    // canonical token holder (this contract), under domain
    // "ERC8004IdentityRegistry"/"1"; deadline must be within 5 minutes. The
    // official contract also auto-clears agentWallet whenever the canonical token
    // transfers — but it never does (custody), so AgenticID's _update mirrors the
    // clear explicitly on the *local* transfer instead.

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return _canonical().getAgentWallet(agentId);
    }

    function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature)
        external
    {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        _canonical().setAgentWallet(agentId, newWallet, deadline, signature);
    }

    function unsetAgentWallet(uint256 agentId) external {
        if (_ownerOf(agentId) != msg.sender)
            revert ERC721IncorrectOwner(msg.sender, agentId, _ownerOf(agentId));
        _canonical().unsetAgentWallet(agentId);
    }

    // ── _update — mirror the canonical "clear agentWallet on transfer" ─────────

    function _update(address to, uint256 tokenId, address auth)
        internal virtual override
        returns (address from)
    {
        from = super._update(to, tokenId, auth);
        // Local transfer (not mint, not burn): the canonical token stays put in
        // custody, so its own transfer hook never fires — clear agentWallet here
        // to keep the canonical record consistent with the new local owner.
        if (from != address(0) && to != address(0)) {
            _canonical().unsetAgentWallet(tokenId);
        }
    }
}
