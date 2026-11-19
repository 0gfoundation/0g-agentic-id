// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TrustRegistry} from "../src/TrustRegistry.sol";

/// @notice AgenticID 1.3.0's trust reads — what the migration copies.
interface ILegacyTrust {
    function isTrustedAttestor(address attestor) external view returns (bool);
    function trustedAttestorAppBinding(address attestor)
        external view returns (address registry, string memory appId, uint256 registeredAt, address appOwner);
    function instanceBoundAttestorsRequired() external view returns (bool);
    function isValidFrameworkHash(bytes32 frameworkHash) external view returns (bool);
}

/// @title TrustMigration
/// @notice Moves AgenticID 1.3.0's trust lists into a TrustRegistry
///         (UPGRADING.md, "AgenticID 1.4.0"). AgenticID's lists are mappings
///         and cannot be enumerated, so events name the candidates (every
///         attestor and image hash AgenticID ever added or removed, and every
///         attestor the registry ever named) and AgenticID's views give each
///         candidate's current state:
///           - an attestor AgenticID trusts now: re-bound to its app instance
///             when it has a binding, added when it has none;
///           - the instance-binding mode, when set;
///           - the image hashes to keep (`keep`; empty = every hash AgenticID
///             lists now): listed under IMAGE, in the order the events first
///             name them. A listed hash left out of `keep` is delisted by the
///             upgrade — `dropped` names them.
///         Attestors AgenticID does not trust now are left out, including a
///         stale binding, which no longer authorizes anyone. `check` then
///         compares every candidate's reads on both contracts and the
///         registry's image list as a whole.
///
///         LEGACY(pre-1.4.0): one-off, like MigrateTrust.s.sol and
///         DeployTrustRegistry.s.sol. Delete them, with the TrustMigration
///         cases in test/UpgradeAgenticID.t.sol, once test and mainnet run
///         AgenticID 1.4.0.
library TrustMigration {
    bytes32 internal constant TRUSTED_ATTESTOR_ADDED = keccak256("TrustedAttestorAdded(address)");
    bytes32 internal constant TRUSTED_ATTESTOR_REMOVED = keccak256("TrustedAttestorRemoved(address)");
    bytes32 internal constant TRUSTED_ATTESTOR_APP_BOUND =
        keccak256("TrustedAttestorAppBound(address,address,string,uint256)");
    bytes32 internal constant FRAMEWORK_HASH_ADDED = keccak256("ValidFrameworkHashAdded(bytes32)");
    bytes32 internal constant FRAMEWORK_HASH_REMOVED = keccak256("ValidFrameworkHashRemoved(bytes32)");

    struct Candidates {
        address[] attestors;
        bytes32[] images;
    }

    /// @notice The event signatures whose first indexed topic names a
    ///         candidate. The TrustRegistry emits the three attestor events
    ///         too, so its logs name the attestors trusted there.
    function candidateTopics() internal pure returns (bytes32[5] memory) {
        return [
            TRUSTED_ATTESTOR_ADDED,
            TRUSTED_ATTESTOR_REMOVED,
            TRUSTED_ATTESTOR_APP_BOUND,
            FRAMEWORK_HASH_ADDED,
            FRAMEWORK_HASH_REMOVED
        ];
    }

    /// @notice Adds the candidate a log names. Logs of other events are ignored.
    function collect(Candidates memory c, bytes32[] memory topics) internal pure {
        if (topics.length < 2) return;
        bytes32 sig = topics[0];
        if (sig == TRUSTED_ATTESTOR_ADDED || sig == TRUSTED_ATTESTOR_REMOVED || sig == TRUSTED_ATTESTOR_APP_BOUND) {
            c.attestors = _addAddress(c.attestors, address(uint160(uint256(topics[1]))));
        } else if (sig == FRAMEWORK_HASH_ADDED || sig == FRAMEWORK_HASH_REMOVED) {
            c.images = _addHash(c.images, topics[1]);
        }
    }

    /// @notice The owner calls that give a fresh TrustRegistry `legacy`'s
    ///         current trust state, in order: attestors, the instance-binding
    ///         mode, the kept image hashes. Reverts if `keep` names a hash
    ///         `legacy` does not list now (a typo would otherwise drop it).
    function calls(ILegacyTrust legacy, Candidates memory c, bytes32 imageKind, bytes32[] memory keep)
        internal
        view
        returns (bytes[] memory out)
    {
        for (uint256 i; i < keep.length; ++i) {
            require(legacy.isValidFrameworkHash(keep[i]), "keep names an image hash AgenticID does not list");
        }
        bytes[] memory buf = new bytes[](c.attestors.length + 1 + c.images.length);
        uint256 n;
        for (uint256 i; i < c.attestors.length; ++i) {
            address a = c.attestors[i];
            if (!legacy.isTrustedAttestor(a)) continue;
            (address registry, string memory appId, uint256 registeredAt,) = legacy.trustedAttestorAppBinding(a);
            buf[n++] = registeredAt != 0
                ? abi.encodeCall(TrustRegistry.bindTrustedAttestorApp, (a, registry, appId, registeredAt))
                : abi.encodeCall(TrustRegistry.addTrustedAttestor, (a));
        }
        if (legacy.instanceBoundAttestorsRequired()) {
            buf[n++] = abi.encodeCall(TrustRegistry.requireInstanceBoundAttestors, ());
        }
        for (uint256 i; i < c.images.length; ++i) {
            if (_kept(legacy, c, keep, c.images[i])) {
                buf[n++] = abi.encodeCall(TrustRegistry.list, (imageKind, c.images[i]));
            }
        }
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) out[i] = buf[i];
    }

    /// @notice The image hashes `legacy` lists now that `keep` leaves out —
    ///         the ones the upgrade delists. Empty when `keep` is empty.
    function dropped(ILegacyTrust legacy, Candidates memory c, bytes32[] memory keep)
        internal
        view
        returns (bytes32[] memory out)
    {
        if (keep.length == 0) return out;
        bytes32[] memory buf = new bytes32[](c.images.length);
        uint256 n;
        for (uint256 i; i < c.images.length; ++i) {
            bytes32 h = c.images[i];
            if (legacy.isValidFrameworkHash(h) && !_contains(keep, h)) buf[n++] = h;
        }
        out = new bytes32[](n);
        for (uint256 i; i < n; ++i) out[i] = buf[i];
    }

    /// @notice Whether `registry` holds exactly what the migration intends,
    ///         read against AgenticID 1.3.0 (`legacy`) before the upgrade:
    ///         every candidate attestor's trust and (when trusted) its binding,
    ///         and the instance-binding mode, as on `legacy`; the registry's
    ///         image list equal to the kept set — nothing missing, nothing
    ///         else. Returns the first difference.
    /// @dev The registry cannot enumerate attestors, so an attestor counts
    ///      only when it is a candidate: feed `c` the logs of both contracts,
    ///      over a range that starts no later than AgenticID's deployment.
    ///      After the upgrade AgenticID forwards to the registry, and this
    ///      comparison is the registry against itself — {checkKept} is what
    ///      such a run can still prove.
    function check(ILegacyTrust legacy, TrustRegistry registry, Candidates memory c, bytes32[] memory keep)
        internal
        view
        returns (bool ok, string memory why)
    {
        if (registry.instanceBoundAttestorsRequired() != legacy.instanceBoundAttestorsRequired()) {
            return (false, "instance-binding mode");
        }
        for (uint256 i; i < c.attestors.length; ++i) {
            address a = c.attestors[i];
            bool trusted = legacy.isTrustedAttestor(a);
            if (registry.isTrustedAttestor(a) != trusted) return (false, "attestor trust");
            if (!trusted) continue;
            (address r1, string memory id1, uint256 at1, address o1) = legacy.trustedAttestorAppBinding(a);
            (address r2, string memory id2, uint256 at2, address o2) = registry.trustedAttestorAppBinding(a);
            if (r1 != r2 || keccak256(bytes(id1)) != keccak256(bytes(id2)) || at1 != at2 || o1 != o2) {
                return (false, "attestor binding");
            }
        }
        bytes32 imageKind = registry.IMAGE();
        for (uint256 i; i < c.images.length; ++i) {
            bytes32 h = c.images[i];
            if (registry.isListed(imageKind, h) != _kept(legacy, c, keep, h)) return (false, "image hash");
        }
        (ok, why) = checkKept(registry, keep);
        if (!ok) return (ok, why);
        bytes32[] memory onRegistry = registry.listed(imageKind);
        for (uint256 i; i < onRegistry.length; ++i) {
            if (!_kept(legacy, c, keep, onRegistry[i])) return (false, "extra image hash");
        }
        return (true, "");
    }

    /// @notice Whether every kept image hash is on `registry`'s image list —
    ///         what a check after the upgrade can still prove.
    function checkKept(TrustRegistry registry, bytes32[] memory keep)
        internal
        view
        returns (bool ok, string memory why)
    {
        bytes32 imageKind = registry.IMAGE();
        for (uint256 i; i < keep.length; ++i) {
            if (!registry.isListed(imageKind, keep[i])) return (false, "kept image hash");
        }
        return (true, "");
    }

    /// @dev Whether `h` belongs on the registry's image list: named in `keep`,
    ///      or, with `keep` empty, a candidate AgenticID lists now.
    function _kept(ILegacyTrust legacy, Candidates memory c, bytes32[] memory keep, bytes32 h)
        private
        view
        returns (bool)
    {
        if (keep.length != 0) return _contains(keep, h);
        return _contains(c.images, h) && legacy.isValidFrameworkHash(h);
    }

    function _contains(bytes32[] memory set, bytes32 h) private pure returns (bool) {
        for (uint256 i; i < set.length; ++i) if (set[i] == h) return true;
        return false;
    }

    function _addAddress(address[] memory set, address a) private pure returns (address[] memory out) {
        for (uint256 i; i < set.length; ++i) if (set[i] == a) return set;
        out = new address[](set.length + 1);
        for (uint256 i; i < set.length; ++i) out[i] = set[i];
        out[set.length] = a;
    }

    function _addHash(bytes32[] memory set, bytes32 h) private pure returns (bytes32[] memory out) {
        for (uint256 i; i < set.length; ++i) if (set[i] == h) return set;
        out = new bytes32[](set.length + 1);
        for (uint256 i; i < set.length; ++i) out[i] = set[i];
        out[set.length] = h;
    }
}
