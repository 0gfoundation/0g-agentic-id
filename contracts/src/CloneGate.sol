// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IAgenticID} from "./interfaces/IAgenticID.sol";
import {ICloneAuthorizer} from "./interfaces/ICloneAuthorizer.sol";
import {IERC7857Metadata, IntelligentData} from "./interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "./interfaces/IERC8004IdentityRegistry.sol";

/// @notice Caller of cloneFrom is not on AgenticID's trusted-attestor list.
error CloneGateNotTrustedAttestor();
/// @notice setCloneAuthorizer caller is not the token's current owner.
error CloneGateNotTokenOwner(address caller, uint256 tokenId, address owner);
/// @notice No effective clone authorizer for the source (never set, cleared,
///         or auto-invalidated by an ownership transfer since it was set),
///         or the configured authorizer declined. Fail-closed.
error CloneGateDenied(uint256 sourceAgentId, address authorizer);
/// @notice Submitted dataHashes don't match the source's LIVE on-chain iData —
///         the attestor re-sealed against a stale snapshot; re-seal and retry.
error CloneGateDataHashMismatch(uint256 index, bytes32 onChain, bytes32 submitted);
/// @notice dataHashes/sealedKeys length differs from the source's iData count.
error CloneGateArityMismatch(uint256 expected, uint256 got);

/// @title CloneGate
/// @notice Policy-mode cloning (issue #133) as a SATELLITE of AgenticID: the
///         owner-configurable clone policy, its atomic consult, and clone
///         lineage all live here — AgenticID itself is untouched (it sits at
///         the EIP-170 bytecode ceiling; new capabilities ship as companion
///         contracts, like VerifiedFeedbackRegistry).
///
///         Flow: the source owner opts in once (`setCloneAuthorizer`); the
///         trusted attestor performs the TEE re-seal off-chain and submits
///         `cloneFrom`, which consults the owner's policy and mints through
///         AgenticID's existing `registerWithSeal` in the SAME transaction —
///         a deny or a stale-data revert rolls everything back, so there is
///         no verify-mint race window by construction.
///
///         Authorization surfaces reused, none added:
///           - `cloneFrom` callers must pass AgenticID's `isTrustedAttestor`
///             (the same allowlist the attestor already lives on);
///           - the gate itself must be on that allowlist too (it is the
///             `msg.sender` of the inner `registerWithSeal`) — one
///             `addTrustedAttestor(gate)` by the AgenticID owner at setup;
///           - pausing AgenticID pauses cloning (registerWithSeal is
///             `whenNotPaused`); the gate carries no pause of its own.
///
///         Transfer invalidation WITHOUT a transfer hook (a satellite cannot
///         hook `_update`): the policy stores the owner who configured it,
///         and is effective only while `ownerOf(source)` still equals that
///         owner — an ownership transfer auto-invalidates the previous
///         owner's policy, fail-closed, exactly as issue #133 requires.
///         One semantic delta vs a hook-based clear: the config goes DORMANT,
///         it is not erased. If the owner who set it re-acquires the token
///         (A→B→A), their old policy becomes effective again silently; any
///         holder can erase it permanently via `setCloneAuthorizer(id, 0)`.
contract CloneGate is Initializable, ReentrancyGuardUpgradeable {
    /// @notice Current implementation version. See contracts/UPGRADING.md.
    /// @dev 1.0.0 — initial (policy-mode cloning satellite; supersedes the
    ///      in-AgenticID cloneFrom of the unreleased 1.2.0, which exceeded
    ///      the EIP-170 deploy limit).
    ///      1.0.1 — CloneGateArityMismatch reports the sealedKeys length when
    ///      that is the mismatched side (was always dataHashes.length).
    string public constant VERSION = "1.0.1";

    /// @notice A token's clone policy was set or cleared (authorizer 0 = cleared).
    event CloneAuthorizerSet(uint256 indexed tokenId, address indexed authorizer, address owner);

    /// @notice A policy-mode clone was minted. Pairs with the ITransferred
    ///         mint event AgenticID emits from registerWithSeal.
    event ClonedFrom(uint256 indexed sourceAgentId, uint256 indexed newAgentId, address indexed to, address caller);

    /// @dev The policy plus the owner whose intent it expresses — the config
    ///      is live only while that owner still owns the token.
    struct PolicyConfig {
        address authorizer;
        address ownerAtSet;
    }

    /// @custom:storage-location erc7201:0g.storage.CloneGate
    struct CloneGateStorage {
        IAgenticID agenticId;
        mapping(uint256 => PolicyConfig) policies;
        // Lineage: newAgentId → sourceAgentId (0 = not a clone). Never
        // cleared — lineage is a historical fact, not owner intent.
        mapping(uint256 => uint256) cloneSource;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.CloneGate")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant CloneGateStorageLocation =
        0x70c420e34ba808fea9cb59170b4cd5f9b7bcf6408241b0008bcba5d7b854d100;

    function _getCloneGateStorage() private pure returns (CloneGateStorage storage $) {
        assembly {
            $.slot := CloneGateStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address agenticId_) external initializer {
        require(agenticId_ != address(0), "agenticId=0");
        __ReentrancyGuard_init();
        _getCloneGateStorage().agenticId = IAgenticID(agenticId_);
    }

    /// @notice The AgenticID deployment this gate mints through.
    function agenticId() external view returns (address) {
        return address(_getCloneGateStorage().agenticId);
    }

    // ── Policy configuration (source owner) ───────────────────────────────────

    /// @notice Set or clear (0) the clone authorizer for a token you own.
    ///         The config expresses YOUR intent: it auto-invalidates if the
    ///         token changes hands (fail-closed for the next owner). Dormant,
    ///         not erased — if you re-acquire the token later your old config
    ///         is effective again; clear with 0 if that is not what you want.
    /// @dev Deliberately NOT `whenNotPaused`: revoking a policy must remain
    ///      possible while AgenticID is paused (the clone MINT path is already
    ///      blocked by registerWithSeal's own pause gate).
    function setCloneAuthorizer(uint256 tokenId, address authorizer) external {
        CloneGateStorage storage $ = _getCloneGateStorage();
        address tokenOwner = $.agenticId.ownerOf(tokenId); // reverts on nonexistent
        if (msg.sender != tokenOwner) revert CloneGateNotTokenOwner(msg.sender, tokenId, tokenOwner);
        $.policies[tokenId] = authorizer == address(0)
            ? PolicyConfig({authorizer: address(0), ownerAtSet: address(0)})
            : PolicyConfig({authorizer: authorizer, ownerAtSet: tokenOwner});
        emit CloneAuthorizerSet(tokenId, authorizer, tokenOwner);
    }

    /// @notice The EFFECTIVE clone authorizer for a token: the configured one,
    ///         or 0 when none is set or the token has changed owners since it
    ///         was set (auto-invalidated). 0 means cloneFrom fails closed.
    function cloneAuthorizerOf(uint256 tokenId) public view returns (address) {
        CloneGateStorage storage $ = _getCloneGateStorage();
        PolicyConfig storage cfg = $.policies[tokenId];
        if (cfg.authorizer == address(0)) return address(0);
        if ($.agenticId.ownerOf(tokenId) != cfg.ownerAtSet) return address(0);
        return cfg.authorizer;
    }

    /// @notice For a clone minted through this gate, the agentId it was forked
    ///         from (0 = not a gate clone). Survives transfers.
    function cloneSourceOf(uint256 agentId_) external view returns (uint256) {
        return _getCloneGateStorage().cloneSource[agentId_];
    }

    // ── Policy-mode clone mint (trusted attestor) ──────────────────────────────

    /// @notice Mint a policy-authorized clone. Trusted attestors only — the
    ///         attestor re-seals off-chain (fresh agentSeal, decrypt +
    ///         re-encrypt under the new seal) and submits the result here;
    ///         the owner's policy is consulted atomically with the mint.
    ///
    /// @param sourceAgentId source token to fork (its LIVE iData hashes must
    ///                      match `dataHashes` — staleness reverts)
    /// @param to            owner of the clone
    /// @param dataHashes    hashes the attestor re-sealed against
    /// @param sealedKeys    re-sealed ciphertexts (per entry, under newAgentSeal)
    /// @param newAgentSeal  the clone's fresh agentSeal address
    /// @param newSealId     fresh sealId for the clone
    /// @param caller        wallet that initiated the off-chain /clone — passed
    ///                      to the authorizer so purchases bind to buyers
    /// @param authData      opaque bytes forwarded to the authorizer
    function cloneFrom(
        uint256 sourceAgentId,
        address to,
        bytes32[] calldata dataHashes,
        bytes[] calldata sealedKeys,
        address newAgentSeal,
        bytes32 newSealId,
        address caller,
        bytes calldata authData
    ) external nonReentrant returns (uint256 agentId_) {
        CloneGateStorage storage $ = _getCloneGateStorage();
        IAgenticID id = $.agenticId;
        if (!id.isTrustedAttestor(msg.sender)) revert CloneGateNotTrustedAttestor();

        // Existence first (bubbles ERC721NonexistentToken — precise error for
        // a missing source), then the effective policy (unset / cleared /
        // owner-changed → 0, fail-closed). NOTE: an authorizer REVERT bubbles
        // unchanged (no try/catch) — deliberate, it preserves the policy's
        // diagnostic; a clean deny is `false` → CloneGateDenied.
        id.ownerOf(sourceAgentId);
        address authorizer = cloneAuthorizerOf(sourceAgentId);
        if (authorizer == address(0) ||
            !ICloneAuthorizer(authorizer).canClone(sourceAgentId, to, caller, authData)) {
            revert CloneGateDenied(sourceAgentId, authorizer);
        }

        // The re-sealed ciphertexts must correspond to the CURRENT hashes: a
        // stale snapshot (source evolved after the TEE re-seal) would mint
        // keys that decrypt nothing — reject, re-seal, retry.
        IntelligentData[] memory datas = IERC7857Metadata(address(id)).intelligentDatasOf(sourceAgentId);
        if (dataHashes.length != datas.length) {
            revert CloneGateArityMismatch(datas.length, dataHashes.length);
        }
        if (sealedKeys.length != datas.length) {
            revert CloneGateArityMismatch(datas.length, sealedKeys.length);
        }
        for (uint256 i = 0; i < datas.length; i++) {
            if (datas[i].dataHash != dataHashes[i]) {
                revert CloneGateDataHashMismatch(i, datas[i].dataHash, dataHashes[i]);
            }
        }

        // Mint through the existing trusted path (this gate is allowlisted).
        // registerWithSeal enforces whenNotPaused, non-empty data, seal/sealId
        // validity and sealId uniqueness, and emits the ITransferred mint
        // event — full parity with a direct attestor mint.
        agentId_ = id.registerWithSeal(
            to, "", new MetadataEntry[](0), datas, sealedKeys, newAgentSeal, newSealId
        );
        $.cloneSource[agentId_] = sourceAgentId;
        emit ClonedFrom(sourceAgentId, agentId_, to, caller);
    }
}
