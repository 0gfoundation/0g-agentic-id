// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IAgenticID} from "./interfaces/IAgenticID.sol";
import {IERC8004IdentityRegistry, MetadataEntry} from "./interfaces/IERC8004IdentityRegistry.sol";
import {IntelligentData} from "./interfaces/IERC7857Metadata.sol";
import {IERC7857, SealedKeyEntry} from "./interfaces/IERC7857.sol";
import {TransferValidityProof} from "./interfaces/IERC7857DataVerifier.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC7857Upgradeable} from "./ERC7857Upgradeable.sol";
import {ERC8004CanonicalBoundUpgradeable} from "./ERC8004CanonicalBoundUpgradeable.sol";
import {ERC7857IDataStorageUpgradeable} from "./extensions/ERC7857IDataStorageUpgradeable.sol";
import {ERC7857AuthorizeUpgradeable} from "./extensions/ERC7857AuthorizeUpgradeable.sol";
import {ERC7857CloneableUpgradeable} from "./extensions/ERC7857CloneableUpgradeable.sol";

/// @notice Caller is not a trusted attestor.
error AgenticIDNotTrustedAttestor();

/// @notice The sealId is already bound to a different agentId.
error AgenticIDSealIdTaken(bytes32 sealId, uint256 existingAgentId);

/// @notice The agent already has an agentSeal set. Seals are one-time bindings.
error AgenticIDSealAlreadySet(uint256 agentId);

/// @notice agentSeal or sealId is the zero value. Both must be non-zero.
error AgenticIDZeroSeal();

/// @notice intelligentDatas.length does not match sealedKeys.length.

/// @notice Use register(agentURI, metadata, intelligentDatas, sealedKeys) instead.
error AgenticIDUseRegisterWithData();

/// @notice Caller is not the pauser.
error AgenticIDNotPauser();

/// @notice update / updateAt was called by an address that is not
///         the agent's bound agentSeal. Once a seal is bound, iData
///         updates are gated agentSeal-only because they represent
///         the agent's own runtime state (memory, learned skills,
///         refreshed config). When no seal is bound (post-mint
///         pre-/provision, or legacy tokens), the contract falls
///         back to owner-only and reverts with ERC721IncorrectOwner
///         instead.
error AgenticIDNotAgentSeal(uint256 agentId, address sender, address expected);

/// @notice iTransferFrom was called on a seal-bound agent. Seal-bound agents
///         transfer as ownership-only via transferFrom (data stays TEE-locked
///         under the immutable agentSeal); the proof-gated re-encryption path is
///         only for non-seal agents.
error AgenticIDSealedAgentUseTransfer(uint256 agentId);

/// @notice iCloneFrom was called on a seal-bound source. Cloning would re-seal
///         the shared dataKey to the clone target (leaking the source agent's
///         data outside the TEE) and the clone could not operate under its own
///         seal anyway. Fork a seal-bound agent through the attestor instead.
error AgenticIDCannotCloneSealedAgent(uint256 agentId);

/// @title AgenticID
/// @notice Main contract of the AgenticID protocol.
///
///         Combines two standards under a single ERC-721 token per agent:
///           • ERC-8004 Identity Registry — registration, URI, metadata, payment wallet.
///           • ERC-7857 — intelligent data carried by the token; cryptographic proof
///             required on every transfer to atomically deliver the data key.
///
///         agentSeal is a TEE-derived address whose private key never leaves TEE memory.
///         Only trusted attestors (whitelisted by the owner) can register an agentSeal.
///         Attestors read the validFrameworkHashes whitelist off-chain to decide whether
///         to provision the agentSeal private key to the agent runtime.
///         sealId provides a stable cross-hardware identity for the TEE instance.
///
/// @dev Inheritance (C3 MRO, most-derived first):
///        AgenticID
///          ERC8004CanonicalBoundUpgradeable     (ERC-8004 custody-bound, ERC721, EIP712)
///          ERC7857IDataStorageUpgradeable       (IERC7857Updatable)
///          ERC7857AuthorizeUpgradeable          (IERC7857Authorize, overrides _update)
///          ERC7857CloneableUpgradeable          (IERC7857Cloneable)
///          ERC7857Upgradeable                   (IERC7857 core)
///          ERC721Upgradeable
///
///      The ERC-8004 identity record lives on a fixed external canonical registry;
///      this contract custodies the canonical token and assigns agentId from the
///      canonical global counter (see {ERC8004CanonicalBoundUpgradeable}).
///
///      agentSeal / sealId are one-time bindings per agentId and persist across
///      transfers. _update only needs to exist for diamond disambiguation:
///        AgenticID (no-op)
///          → ERC8004CanonicalBoundUpgradeable (clear canonical agentWallet)
///          → ERC7857AuthorizeUpgradeable (clear authorized users)
///          → ERC721Upgradeable (base transfer)
contract AgenticID is
    IAgenticID,
    ERC8004CanonicalBoundUpgradeable,
    ERC7857IDataStorageUpgradeable,
    ERC7857AuthorizeUpgradeable,
    ERC7857CloneableUpgradeable,
    OwnableUpgradeable
{
    // ── Storage ───────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7857:0g.storage.AgenticID
    struct AgenticIDStorage {
        mapping(uint256 => address) agentSeals;
        mapping(uint256 => bytes32) agentIdToSealId;
        mapping(bytes32 => uint256) sealIdToAgentId;
        mapping(address => bool)    trustedAttestors;
        mapping(bytes32 => bool)    validFrameworkHashes;
        address                     pauser;
        // Explicit existence bit for sealId bindings. Required because the
        // canonical registry numbers agentIds from 0 (and the live registry
        // already has an agentId 0 owned by a third party): sealIdToAgentId == 0
        // is ambiguous between "unbound" and "bound to agent 0", so uniqueness
        // and existence checks key off this flag instead of the zero sentinel.
        mapping(bytes32 => bool)    sealIdBound;
    }

    /// @notice Current implementation version. Bump on every upgrade.
    string public constant VERSION = "1.0.0";

    event PauserUpdated(address indexed previousPauser, address indexed newPauser);

    // keccak256(abi.encode(uint256(keccak256("0g.storage.AgenticID")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AgenticIDStorageLocation =
        0xaa0e3d57ddf5d2f322a098202cb27f2804b292978acf041b4edd6beb821d4000;

    function _getAgenticIDStorage() private pure returns (AgenticIDStorage storage $) {
        assembly {
            $.slot := AgenticIDStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ───────────────────────────────────────────────────────────

    function initialize(
        string memory name_,
        string memory symbol_,
        address verifier_,
        address owner_,
        address pauser_,
        address canonical_
    ) external initializer {
        __ERC8004CanonicalBound_init(name_, symbol_, canonical_);
        __ERC7857_init_unchained(verifier_);
        __Ownable_init(owner_);
        _getAgenticIDStorage().pauser = pauser_;
        emit PauserUpdated(address(0), pauser_);
    }

    // ── ERC-165 ───────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public view virtual
        override(IERC165, ERC8004CanonicalBoundUpgradeable, ERC7857IDataStorageUpgradeable, ERC7857AuthorizeUpgradeable, ERC7857CloneableUpgradeable)
        returns (bool)
    {
        return interfaceId == type(IAgenticID).interfaceId || super.supportsInterface(interfaceId);
    }

    // ── Transfer: seal-bound vs non-seal split ─────────────────────────────────
    //
    // Seal-bound agent = an operating entity. Its iData stays TEE-locked under the
    // immutable agentSeal, so a transfer is a plain ownership handover — re-enable
    // the standard ERC-721 transfer (which ERC7857 disables) for it. Operation
    // rights follow ownership off-chain (attestor owner-gating). Re-sealing dataKey
    // to the buyer (the iTransferFrom path) would be useless (framework only
    // decrypts with agentSeal) and would leak dataKey outside the TEE — so
    // iTransferFrom / iCloneFrom revert for seal-bound tokens.
    //
    // Non-seal agent = a data blob. Plain transfer stays disabled; ownership moves
    // only via iTransferFrom, which atomically re-encrypts the dataKey to the buyer.

    function transferFrom(address from, address to, uint256 tokenId)
        public virtual
        override(ERC7857Upgradeable, ERC721Upgradeable, IERC721)
        whenNotPaused
    {
        if (_getAgenticIDStorage().agentSeals[tokenId] != address(0)) {
            ERC721Upgradeable.transferFrom(from, to, tokenId);
        } else {
            super.transferFrom(from, to, tokenId); // ERC7857: revert, use iTransferFrom
        }
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public virtual
        override(ERC7857Upgradeable, ERC721Upgradeable, IERC721)
        whenNotPaused
    {
        if (_getAgenticIDStorage().agentSeals[tokenId] != address(0)) {
            ERC721Upgradeable.safeTransferFrom(from, to, tokenId, data);
        } else {
            super.safeTransferFrom(from, to, tokenId, data);
        }
    }

    function iTransferFrom(address from, address to, uint256 tokenId, TransferValidityProof[] calldata proofs)
        public virtual
        override(ERC7857Upgradeable, IERC7857)
        returns (SealedKeyEntry[] memory)
    {
        if (_getAgenticIDStorage().agentSeals[tokenId] != address(0)) {
            revert AgenticIDSealedAgentUseTransfer(tokenId);
        }
        return super.iTransferFrom(from, to, tokenId, proofs);
    }

    function iCloneFrom(address from, address to, uint256 tokenId, TransferValidityProof[] calldata proofs)
        public virtual
        override(ERC7857CloneableUpgradeable)
        returns (uint256)
    {
        if (_getAgenticIDStorage().agentSeals[tokenId] != address(0)) {
            revert AgenticIDCannotCloneSealedAgent(tokenId);
        }
        return super.iCloneFrom(from, to, tokenId, proofs);
    }

    function tokenURI(uint256 tokenId)
        public view virtual
        override(ERC8004CanonicalBoundUpgradeable, ERC721Upgradeable)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    /// @dev Allow trusted attestors to set the URI in addition to the token
    ///      owner. Deploy flow mints first (with empty URI), then the
    ///      attestor uploads the canonical AgentCard JSON to off-chain
    ///      storage and writes the resulting URL back via setAgentURI.
    function _authorizeSetAgentURI(uint256 agentId)
        internal view virtual
        override(ERC8004CanonicalBoundUpgradeable)
    {
        if (_getAgenticIDStorage().trustedAttestors[msg.sender]) return;
        super._authorizeSetAgentURI(agentId);
    }

    function _intelligentDatasOf(uint256 tokenId)
        internal view virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
        returns (IntelligentData[] memory)
    {
        return super._intelligentDatasOf(tokenId);
    }

    function _intelligentDatasLengthOf(uint256 tokenId)
        internal view virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
        returns (uint256)
    {
        return super._intelligentDatasLengthOf(tokenId);
    }

    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    )
        internal virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
    {
        super._updateData(tokenId, newDatas, sealedKeys);
    }

    function _updateDataAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData memory newData,
        bytes memory sealedKey
    )
        internal virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
    {
        super._updateDataAt(tokenId, index, newData, sealedKey);
    }

    function _updateSealedKeys(uint256 tokenId, bytes[] memory sealedKeys)
        internal virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
    {
        super._updateSealedKeys(tokenId, sealedKeys);
    }

    function _sealedKeysOf(uint256 tokenId)
        internal view virtual
        override(ERC7857Upgradeable, ERC7857IDataStorageUpgradeable)
        returns (bytes[] memory)
    {
        return super._sealedKeysOf(tokenId);
    }

    // ── iData update authorization: agentSeal-first, owner fallback ───────────
    //
    // ERC-7857's default storage extension gates `update` / `updateAt`
    // on `_ownerOf(tokenId) == msg.sender` (NFT-owner-only). AgenticID
    // diverges: iData represents the agent's own runtime state
    // (learned skills, memory, refreshed config), which the agent —
    // running in TEE with `agentSeal_priv` — is best positioned to
    // author. Once a seal is bound, *only* the agentSeal can update.
    //
    // Fallback: when agentSeal is zero (the brief window between mint
    // and setAgentSeal, or legacy tokens that never got a seal bound),
    // the original owner-only check applies — otherwise the token
    // would be stuck with no one able to update it. Owner still
    // controls transfer / authorize / setAgentURI in both branches.

    function update(
        uint256 tokenId,
        IntelligentData[] calldata newDatas,
        bytes[] calldata sealedKeys
    )
        public override(ERC7857IDataStorageUpgradeable) whenNotPaused
    {
        _authorizeIDataUpdate(tokenId);
        if (newDatas.length == 0) revert ERC7857EmptyData();
        if (newDatas.length != sealedKeys.length) {
            revert ERC7857SealedKeyArityMismatch(newDatas.length, sealedKeys.length);
        }
        _updateData(tokenId, newDatas, sealedKeys);
    }

    function updateAt(
        uint256 tokenId,
        uint256 index,
        IntelligentData calldata newData,
        bytes calldata sealedKey
    )
        public override(ERC7857IDataStorageUpgradeable) whenNotPaused
    {
        _authorizeIDataUpdate(tokenId);
        _updateDataAt(tokenId, index, newData, sealedKey);
    }

    function _authorizeIDataUpdate(uint256 tokenId) internal view {
        address seal = _getAgenticIDStorage().agentSeals[tokenId];
        if (seal != address(0)) {
            // Bound seal: agentSeal-only.
            if (msg.sender != seal) {
                revert AgenticIDNotAgentSeal(tokenId, msg.sender, seal);
            }
        } else {
            // No seal yet: fall back to ERC-7857 owner-only behaviour.
            address owner_ = _ownerOf(tokenId);
            if (msg.sender != owner_) {
                revert ERC721IncorrectOwner(msg.sender, tokenId, owner_);
            }
        }
    }

    // ── Shared token-ID counter ───────────────────────────────────────────────

    function _incrementTokenId()
        internal
        override(ERC8004CanonicalBoundUpgradeable, ERC7857CloneableUpgradeable)
        returns (uint256)
    {
        return ERC8004CanonicalBoundUpgradeable._incrementTokenId();
    }

    // ── Registration ──────────────────────────────────────────────────────────

    // Disable base ERC-8004 register overloads — IntelligentData is required.
    function register()
        external pure
        override(ERC8004CanonicalBoundUpgradeable, IERC8004IdentityRegistry)
        returns (uint256)
    { revert AgenticIDUseRegisterWithData(); }

    function register(string calldata)
        external pure
        override(ERC8004CanonicalBoundUpgradeable, IERC8004IdentityRegistry)
        returns (uint256)
    { revert AgenticIDUseRegisterWithData(); }

    function register(string calldata, MetadataEntry[] calldata)
        external pure
        override(ERC8004CanonicalBoundUpgradeable, IERC8004IdentityRegistry)
        returns (uint256)
    { revert AgenticIDUseRegisterWithData(); }

    /// @notice Register a new agent. Mints to msg.sender.
    /// @dev sealedKeys[i] corresponds to intelligentDatas[i].dataHash. The contract
    ///      does NOT verify how sealedKeys are encrypted. The caller is responsible
    ///      for retaining the ability to unseal — otherwise a future iTransferFrom
    ///      cannot produce a valid OwnershipProof and the agent is effectively frozen.
    function register(
        string calldata agentURI,
        MetadataEntry[] calldata metadata,
        IntelligentData[] calldata intelligentDatas,
        bytes[] calldata sealedKeys
    ) external whenNotPaused returns (uint256 agentId) {
        if (intelligentDatas.length == 0) revert ERC7857EmptyData();
        if (intelligentDatas.length != sealedKeys.length) {
            revert ERC7857SealedKeyArityMismatch(intelligentDatas.length, sealedKeys.length);
        }
        agentId = _mintAgent(msg.sender, agentURI);
        _setMetadataBatch(agentId, metadata);
        _updateData(agentId, intelligentDatas, sealedKeys);
        _emitMintedKeys(agentId, msg.sender, intelligentDatas, sealedKeys);
    }

    /// @notice Register a new agent with IntelligentData, sealedKeys, and agentSeal.
    /// @dev Only a trusted attestor may call this. Off-chain, the attestor has
    ///      generated dataKey_i per IntelligentData, encrypted the plaintext data,
    ///      and produced sealedKeys[i] = E(dataKey_i, agentSeal_pub) so a future
    ///      Agent TEE (provisioned with agentSeal_priv) can unseal dataKey_i.
    /// @param to           Address that will own the minted token.
    /// @param sealedKeys   sealedKeys[i] targets agentSeal_pub for intelligentDatas[i].
    /// @param agentSeal_   TEE-derived signing address for this agent.
    /// @param sealId       Stable identifier for the TEE instance derivation path.
    function registerWithSeal(
        address to,
        string calldata agentURI,
        MetadataEntry[] calldata metadata,
        IntelligentData[] calldata intelligentDatas,
        bytes[] calldata sealedKeys,
        address agentSeal_,
        bytes32 sealId
    ) external whenNotPaused returns (uint256 agentId) {
        if (!_getAgenticIDStorage().trustedAttestors[msg.sender]) revert AgenticIDNotTrustedAttestor();

        if (intelligentDatas.length == 0) revert ERC7857EmptyData();
        if (intelligentDatas.length != sealedKeys.length) {
            revert ERC7857SealedKeyArityMismatch(intelligentDatas.length, sealedKeys.length);
        }
        agentId = _mintAgent(to, agentURI);
        _setMetadataBatch(agentId, metadata);
        _updateData(agentId, intelligentDatas, sealedKeys);
        _setAgentSeal(agentId, agentSeal_, sealId);
        _emitMintedKeys(agentId, to, intelligentDatas, sealedKeys);
    }

    // ── Mint sealed-key emission ──────────────────────────────────────────────

    /// @dev Emits ITransferred(address(0), to, agentId, entries) so indexers can
    ///      treat mint and transfer symmetrically. from = address(0) marks mint.
    function _emitMintedKeys(
        uint256 agentId,
        address to,
        IntelligentData[] calldata iDatas,
        bytes[] calldata sealedKeys
    ) internal {
        // Arity is checked by the public callers (register / registerWithSeal)
        // before reaching here, using ERC7857SealedKeyArityMismatch.
        SealedKeyEntry[] memory entries = new SealedKeyEntry[](iDatas.length);
        for (uint256 i = 0; i < iDatas.length; i++) {
            entries[i] = SealedKeyEntry({
                dataHash: iDatas[i].dataHash,
                sealedKey: sealedKeys[i]
            });
        }
        emit ITransferred(address(0), to, agentId, entries);
    }

    // ── agentSeal ─────────────────────────────────────────────────────────────

    function setAgentSeal(
        uint256 agentId,
        address agentSeal_,
        bytes32 sealId
    ) external whenNotPaused {
        if (!_getAgenticIDStorage().trustedAttestors[msg.sender]) revert AgenticIDNotTrustedAttestor();
        _setAgentSeal(agentId, agentSeal_, sealId);
    }

    function _setAgentSeal(uint256 agentId, address agentSeal_, bytes32 sealId) internal {
        if (agentSeal_ == address(0) || sealId == bytes32(0)) revert AgenticIDZeroSeal();

        AgenticIDStorage storage $ = _getAgenticIDStorage();

        // One-time binding: once a seal is set it is immutable for the token's lifetime.
        // (sealId is a random non-zero 32-byte value, so the zero check here is safe.)
        if ($.agentIdToSealId[agentId] != bytes32(0)) revert AgenticIDSealAlreadySet(agentId);

        // sealId must not already be bound to another agent. Keyed off the
        // explicit existence flag, not sealIdToAgentId != 0, because agentId 0
        // is a valid (third-party) agent on the canonical registry.
        if ($.sealIdBound[sealId]) revert AgenticIDSealIdTaken(sealId, $.sealIdToAgentId[sealId]);

        $.agentSeals[agentId]      = agentSeal_;
        $.agentIdToSealId[agentId] = sealId;
        $.sealIdToAgentId[sealId]  = agentId;
        $.sealIdBound[sealId]      = true;

        emit AgentSealSet(agentId, agentSeal_, sealId);
    }

    function getAgentSeal(uint256 agentId) external view returns (address) {
        return _getAgenticIDStorage().agentSeals[agentId];
    }

    function getSealId(uint256 agentId) external view returns (bytes32) {
        return _getAgenticIDStorage().agentIdToSealId[agentId];
    }

    function getAgentIdBySealId(bytes32 sealId) external view returns (uint256) {
        return _getAgenticIDStorage().sealIdToAgentId[sealId];
    }

    /// @notice Whether a sealId is bound to any agent. Disambiguates the 0 return
    ///         of {getAgentIdBySealId}, since agentId 0 is a valid canonical agent.
    function isSealIdBound(bytes32 sealId) external view returns (bool) {
        return _getAgenticIDStorage().sealIdBound[sealId];
    }

    // ── Trusted attestors ─────────────────────────────────────────────────────

    function addTrustedAttestor(address attestor) external onlyOwner {
        _getAgenticIDStorage().trustedAttestors[attestor] = true;
        emit TrustedAttestorAdded(attestor);
    }

    function removeTrustedAttestor(address attestor) external onlyOwner {
        delete _getAgenticIDStorage().trustedAttestors[attestor];
        emit TrustedAttestorRemoved(attestor);
    }

    function isTrustedAttestor(address attestor) external view returns (bool) {
        return _getAgenticIDStorage().trustedAttestors[attestor];
    }

    // ── Valid framework hashes ────────────────────────────────────────────────

    function addValidFrameworkHash(bytes32 frameworkHash) external onlyOwner {
        _getAgenticIDStorage().validFrameworkHashes[frameworkHash] = true;
        emit ValidFrameworkHashAdded(frameworkHash);
    }

    function removeValidFrameworkHash(bytes32 frameworkHash) external onlyOwner {
        delete _getAgenticIDStorage().validFrameworkHashes[frameworkHash];
        emit ValidFrameworkHashRemoved(frameworkHash);
    }

    function isValidFrameworkHash(bytes32 frameworkHash) external view returns (bool) {
        return _getAgenticIDStorage().validFrameworkHashes[frameworkHash];
    }

    // ── Pauser ────────────────────────────────────────────────────────────────

    function pauser() external view returns (address) {
        return _getAgenticIDStorage().pauser;
    }

    function setPauser(address newPauser) external onlyOwner {
        AgenticIDStorage storage $ = _getAgenticIDStorage();
        emit PauserUpdated($.pauser, newPauser);
        $.pauser = newPauser;
    }

    function pause() external {
        if (msg.sender != _getAgenticIDStorage().pauser) revert AgenticIDNotPauser();
        _pause();
    }

    function unpause() external {
        if (msg.sender != _getAgenticIDStorage().pauser) revert AgenticIDNotPauser();
        _unpause();
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setVerifier(address newVerifier) external onlyOwner {
        _setVerifier(newVerifier);
    }

    // NonceRegistry was dropped from this contract: setAgentWallet forwards to the
    // canonical registry (which uses a 5-minute deadline, no nonce), so AgenticID
    // no longer consumes any local nonce. The transfer verifier and reputation
    // registry keep their own NonceRegistry independently.

    // ── _update — diamond disambiguation ──────────────────────────────────────
    // agentSeal / sealId are NOT cleared on transfer: seals are one-time bindings
    // for the token's lifetime, so clearing would leave the token permanently unsealable.

    function _update(address to, uint256 tokenId, address auth)
        internal virtual
        override(ERC721Upgradeable, ERC8004CanonicalBoundUpgradeable, ERC7857AuthorizeUpgradeable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }
}
