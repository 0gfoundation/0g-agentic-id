// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// TEST FIXTURE — FROZEN copy of the TrustRegistry 1.0.0 source (the version dev
// runs since 2026-11-12), taken verbatim from git
// df03be6:contracts/src/TrustRegistry.sol. Only the import paths and the
// contract name differ. TrustRegistry.t.sol uses it as the pre-upgrade beacon
// impl. Never edit — it stands in for the deployed 1.0.0. ITrustRegistry comes
// from the frozen copy in ./v1_0_0/ (src changed it in 1.1.0);
// AttestorAppBindingLib is still src's, unchanged since df03be6, so if it
// changes the fixture may no longer behave like (or share storage layout with)
// the deployed 1.0.0 — re-check it then.
// ─────────────────────────────────────────────────────────────────────────────

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {MulticallUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";

import {ITrustRegistryV1_0_0 as ITrustRegistry} from "./v1_0_0/ITrustRegistryV1_0_0.sol";
import {AttestorAppBinding, AttestorAppBindingLib, IAttestorAppBindingErrors} from "../../src/AttestorAppBindingLib.sol";

/// @notice A code-list kind or hash is zero; zero marks the end of a list.
error TrustRegistryZeroValue();

/// @notice `hash` is already on the `kind` list.
error TrustRegistryAlreadyListed(bytes32 kind, bytes32 hash);

/// @notice `hash` is not on the `kind` list.
error TrustRegistryNotListed(bytes32 kind, bytes32 hash);

/// @title TrustRegistry
/// @notice The deployer's trust decisions — see {ITrustRegistry}. Two parts:
///           • attestors: which addresses may act for the platform (mint
///             through AgenticID.registerWithSeal, set agent URIs), optionally
///             bound to one live Tapp app instance;
///           • code lists: which hashes may run an agent, by kind. The kinds in
///             use are IMAGE (the container image, i.e. base), SEALED (the
///             sealed program the loader runs) and HARNESS (the official
///             harness package). A kind is just a key: another layer later is
///             another kind, with no contract change.
///
/// @dev Owner calls are direct (not timelocked) and take effect immediately,
///      like AgenticID's owner calls; only beacon upgrades go through the
///      Timelock. `multicall` batches owner calls into one transaction (the
///      list migration from AgenticID 1.3.0 is one).
contract TrustRegistryV1_0_0 is ITrustRegistry, IAttestorAppBindingErrors, Ownable2StepUpgradeable, MulticallUpgradeable {
    using AttestorAppBindingLib for AttestorAppBinding;

    /// @notice Current implementation version. Bump on every upgrade.
    /// @dev 1.0.0 — initial: the attestor list and app bindings moved from
    ///      AgenticID 1.3.0 (same functions, events and errors), plus code
    ///      lists by kind.
    string public constant VERSION = "1.0.0";

    bytes32 public constant IMAGE = keccak256("image");
    bytes32 public constant SEALED = keccak256("sealed");
    bytes32 public constant HARNESS = keccak256("harness");

    /// @dev One kind's list, linked in listing order: `last` is the latest
    ///      entry, and delisting keeps the order of the rest.
    struct CodeList {
        mapping(bytes32 => bytes32) prev;
        mapping(bytes32 => bytes32) next;
        mapping(bytes32 => bool) listed;
        bytes32 first;
        bytes32 last;
        uint256 length;
    }

    /// @custom:storage-location erc7201:0g.storage.TrustRegistry
    struct TrustRegistryStorage {
        mapping(address => bool) trustedAttestors;
        mapping(address => AttestorAppBinding) attestorAppBindings;
        bool instanceBoundAttestorsRequired;
        mapping(bytes32 => CodeList) codeLists;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.TrustRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TrustRegistryStorageLocation =
        0x955d528b0519d716790edec9a92352a4ea6b21e7ba2e05977e7147878d775100;

    function _getTrustRegistryStorage() private pure returns (TrustRegistryStorage storage $) {
        assembly {
            $.slot := TrustRegistryStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Multicall_init();
    }

    // ── Attestors ─────────────────────────────────────────────────────────────

    function addTrustedAttestor(address attestor) external onlyOwner {
        _getTrustRegistryStorage().trustedAttestors[attestor] = true;
        emit TrustedAttestorAdded(attestor);
    }

    function removeTrustedAttestor(address attestor) external onlyOwner {
        TrustRegistryStorage storage $ = _getTrustRegistryStorage();
        delete $.trustedAttestors[attestor];
        delete $.attestorAppBindings[attestor];
        emit TrustedAttestorRemoved(attestor);
    }

    /// Bind the stable service key to one live registration, never just a reusable appId.
    function bindTrustedAttestorApp(address attestor, address registry, string calldata appId, uint256 registeredAt)
        external
        onlyOwner
    {
        TrustRegistryStorage storage $ = _getTrustRegistryStorage();
        $.attestorAppBindings[attestor].bind(attestor, registry, appId, registeredAt);
        $.trustedAttestors[attestor] = true;
        emit TrustedAttestorAppBound(attestor, registry, appId, registeredAt);
    }

    /// One-way. Bind every production attestor before enabling this mode.
    function requireInstanceBoundAttestors() external onlyOwner {
        _getTrustRegistryStorage().instanceBoundAttestorsRequired = true;
        emit InstanceBoundAttestorsRequired();
    }

    function isTrustedAttestor(address attestor) external view returns (bool) {
        TrustRegistryStorage storage $ = _getTrustRegistryStorage();
        if (!$.trustedAttestors[attestor]) return false;
        return $.attestorAppBindings[attestor].isCurrent($.instanceBoundAttestorsRequired);
    }

    function instanceBoundAttestorsRequired() external view returns (bool) {
        return _getTrustRegistryStorage().instanceBoundAttestorsRequired;
    }

    function trustedAttestorAppBinding(address attestor)
        external
        view
        returns (address registry, string memory appId, uint256 registeredAt, address appOwner)
    {
        AttestorAppBinding storage b = _getTrustRegistryStorage().attestorAppBindings[attestor];
        return (b.registry, b.appId, b.registeredAt, b.appOwner);
    }

    // ── Code lists ────────────────────────────────────────────────────────────

    function list(bytes32 kind, bytes32 hash) external onlyOwner {
        if (kind == bytes32(0) || hash == bytes32(0)) revert TrustRegistryZeroValue();
        CodeList storage l = _getTrustRegistryStorage().codeLists[kind];
        if (l.listed[hash]) revert TrustRegistryAlreadyListed(kind, hash);
        bytes32 tail = l.last;
        if (tail == bytes32(0)) {
            l.first = hash;
        } else {
            l.next[tail] = hash;
            l.prev[hash] = tail;
        }
        l.last = hash;
        l.listed[hash] = true;
        l.length += 1;
        emit Listed(kind, hash);
    }

    function delist(bytes32 kind, bytes32 hash) external onlyOwner {
        CodeList storage l = _getTrustRegistryStorage().codeLists[kind];
        if (!l.listed[hash]) revert TrustRegistryNotListed(kind, hash);
        bytes32 before = l.prev[hash];
        bytes32 after_ = l.next[hash];
        if (before == bytes32(0)) l.first = after_;
        else l.next[before] = after_;
        if (after_ == bytes32(0)) l.last = before;
        else l.prev[after_] = before;
        delete l.prev[hash];
        delete l.next[hash];
        delete l.listed[hash];
        l.length -= 1;
        emit Delisted(kind, hash);
    }

    function isListed(bytes32 kind, bytes32 hash) external view returns (bool) {
        return _getTrustRegistryStorage().codeLists[kind].listed[hash];
    }

    function latest(bytes32 kind) external view returns (bytes32) {
        return _getTrustRegistryStorage().codeLists[kind].last;
    }

    function listed(bytes32 kind) external view returns (bytes32[] memory hashes) {
        CodeList storage l = _getTrustRegistryStorage().codeLists[kind];
        hashes = new bytes32[](l.length);
        bytes32 h = l.first;
        for (uint256 i; i < hashes.length; ++i) {
            hashes[i] = h;
            h = l.next[h];
        }
    }
}
