// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {TrustRegistry} from "../src/TrustRegistry.sol";
import {TrustMigration, ILegacyTrust} from "./TrustMigration.sol";

interface IAgenticIDTrustRegistry {
    function trustRegistry() external view returns (address);
}

/// @notice Copy AgenticID 1.3.0's trust lists into a TrustRegistry and check
///         the copy — UPGRADING.md, "AgenticID 1.4.0". Run against the chain
///         (`--rpc-url`); the logic is TrustMigration's. LEGACY(pre-1.4.0):
///         one-off — see TrustMigration.
///
///         Environment variables:
///           AGENTIC_ID      — the AgenticID proxy
///           TRUST_REGISTRY  — the TrustRegistry proxy (not used by rehearse;
///                             optional for plan, which then prints calldata
///                             without a target)
///           IMAGES          — comma-separated image hashes to carry over;
///                             every one must be on AgenticID's list now. The
///                             listed hashes left out are delisted by the
///                             upgrade, and every mode prints them. Unset:
///                             every hash AgenticID lists now. plan, apply and
///                             check of one migration take the same IMAGES.
///           MODE            — plan (default): print the owner calls as
///                             `multicall` calldata, for an owner that signs
///                             outside forge (the mainnet vault);
///                             apply: broadcast them as the TrustRegistry
///                             owner (with --broadcast and the owner key), then
///                             check;
///                             check: before the upgrade, that the registry
///                             holds exactly what the migration intends — every
///                             candidate attestor (named by either contract's
///                             events) reads the same on both contracts, and
///                             the registry's image list is the kept set, no
///                             more, no less; after the upgrade AgenticID reads
///                             the registry, so comparing the two would compare
///                             the registry with itself: the run then proves
///                             only that AgenticID reads TRUST_REGISTRY and
///                             that every kept image hash is listed;
///                             rehearse: on the fork only, never broadcast —
///                             deploy a TrustRegistry, apply the calls, check,
///                             and with AGENTIC_ID_BEACON set also upgrade the
///                             beacon to 1.4.0 (as its owner) and compare
///                             every candidate's reads before and after.
///           AGENTIC_ID_BEACON — AgenticID's beacon (rehearse only)
///           FROM_BLOCK      — first block of the events read (default 0). 0
///                             or AgenticID's deployment block, never later:
///                             an attestor or image hash named only before it
///                             would be neither copied nor checked. A non-zero
///                             FROM_BLOCK is refused unless the range holds
///                             AgenticID's deployment (its proxy's
///                             BeaconUpgraded / Upgraded log).
///           TO_BLOCK        — last block (default: the latest)
///           LOG_CHUNK       — blocks per eth_getLogs; 0 = the whole range in
///                             one call (default 0; 0G's RPC accepts it)
///           BATCH           — owner calls per multicall (default 40)
///
///         plan and apply expect AgenticID still on 1.3.0 and a TrustRegistry
///         with nothing in it yet; check runs any time. Lists must not change
///         on AgenticID between plan/apply and the upgrade — run check again
///         right before it.
contract MigrateTrust is Script {
    bytes32 internal constant BEACON_UPGRADED = keccak256("BeaconUpgraded(address)");
    bytes32 internal constant UPGRADED = keccak256("Upgraded(address)");

    function run() external {
        address agenticId = vm.envAddress("AGENTIC_ID");
        TrustRegistry registry = TrustRegistry(vm.envOr("TRUST_REGISTRY", address(0)));
        string memory mode = vm.envOr("MODE", string("plan"));
        bytes32[] memory keep = vm.envOr("IMAGES", ",", new bytes32[](0));

        TrustMigration.Candidates memory c =
            _candidates(agenticId, _is(mode, "rehearse") ? address(0) : address(registry));
        console2.log("candidates from the events: attestors", c.attestors.length);
        console2.log("                            image hashes", c.images.length);
        _reportDropped(agenticId, c, keep);

        if (_is(mode, "rehearse")) {
            _rehearse(agenticId, c, keep);
            return;
        }
        if (_is(mode, "check")) {
            _check(agenticId, registry, c, keep);
            return;
        }
        require(_is(mode, "plan") || _is(mode, "apply"), "MODE must be plan, apply, check or rehearse");
        require(address(registry) != address(0) || _is(mode, "plan"), "TRUST_REGISTRY is required");

        bytes[] memory calls = TrustMigration.calls(ILegacyTrust(agenticId), c, keccak256("image"), keep);
        _summarize(calls);
        uint256 batch = vm.envOr("BATCH", uint256(40));
        require(batch > 0, "BATCH=0");

        if (_is(mode, "apply")) vm.startBroadcast();
        for (uint256 start; start < calls.length; start += batch) {
            uint256 end = start + batch < calls.length ? start + batch : calls.length;
            bytes[] memory slice = new bytes[](end - start);
            for (uint256 i = start; i < end; ++i) slice[i - start] = calls[i];
            if (_is(mode, "apply")) {
                registry.multicall(slice);
            } else {
                console2.log("multicall to", address(registry), "calls", end - start);
                console2.logBytes(abi.encodeCall(registry.multicall, (slice)));
            }
        }
        if (_is(mode, "apply")) {
            vm.stopBroadcast();
            _check(agenticId, registry, c, keep);
        }
    }

    /// @dev Candidates in event order: additions first, so image hashes keep
    ///      the order AgenticID first listed them; then the attestors the
    ///      registry's own events name (zero `registry`: none), so an attestor
    ///      trusted there but not on AgenticID is compared too.
    function _candidates(address agenticId, address registry)
        internal
        returns (TrustMigration.Candidates memory c)
    {
        uint256 from = vm.envOr("FROM_BLOCK", uint256(0));
        uint256 to = vm.envOr("TO_BLOCK", vm.getBlockNumber());
        if (from != 0) {
            require(
                _logs(agenticId, BEACON_UPGRADED, from, to).length + _logs(agenticId, UPGRADED, from, to).length > 0,
                "FROM_BLOCK is after AgenticID's deployment: use 0 or its deployment block"
            );
        }
        bytes32[5] memory sigs = TrustMigration.candidateTopics();
        // added, app-bound, hash added — then the removals.
        uint8[5] memory order = [0, 2, 3, 1, 4];
        for (uint256 k; k < order.length; ++k) {
            Vm.EthGetLogs[] memory logs = _logs(agenticId, sigs[order[k]], from, to);
            for (uint256 i; i < logs.length; ++i) TrustMigration.collect(c, logs[i].topics);
        }
        if (registry == address(0)) return c;
        for (uint256 k; k < 3; ++k) {
            Vm.EthGetLogs[] memory logs = _logs(registry, sigs[k], from, to);
            for (uint256 i; i < logs.length; ++i) TrustMigration.collect(c, logs[i].topics);
        }
    }

    /// @dev `target`'s logs with first topic `topic` in [from, to], LOG_CHUNK
    ///      blocks per call.
    function _logs(address target, bytes32 topic, uint256 from, uint256 to)
        internal
        returns (Vm.EthGetLogs[] memory all)
    {
        uint256 chunk = vm.envOr("LOG_CHUNK", uint256(0));
        bytes32[] memory topics = new bytes32[](1);
        topics[0] = topic;
        for (uint256 lo = from; lo <= to; lo = chunk == 0 ? to + 1 : lo + chunk) {
            uint256 hi = chunk == 0 || lo + chunk - 1 > to ? to : lo + chunk - 1;
            Vm.EthGetLogs[] memory part = vm.eth_getLogs(lo, hi, target, topics);
            Vm.EthGetLogs[] memory joined = new Vm.EthGetLogs[](all.length + part.length);
            for (uint256 i; i < all.length; ++i) joined[i] = all[i];
            for (uint256 i; i < part.length; ++i) joined[all.length + i] = part[i];
            all = joined;
        }
    }

    /// @dev Prints what IMAGES leaves out: the image hashes the upgrade delists.
    function _reportDropped(address agenticId, TrustMigration.Candidates memory c, bytes32[] memory keep)
        internal
        view
    {
        if (keep.length == 0) {
            console2.log("IMAGES unset: every image hash AgenticID lists now is carried over");
            return;
        }
        bytes32[] memory gone = TrustMigration.dropped(ILegacyTrust(agenticId), c, keep);
        console2.log("IMAGES keeps", keep.length, "image hashes; delisted by the upgrade:", gone.length);
        for (uint256 i; i < gone.length; ++i) console2.logBytes32(gone[i]);
    }

    /// @dev The whole migration and the upgrade, simulated on the fork.
    function _rehearse(address agenticId, TrustMigration.Candidates memory c, bytes32[] memory keep) internal {
        address rehearsalOwner = address(0x7E57);
        TrustRegistry fresh = TrustRegistry(address(new ERC1967Proxy(
            address(new TrustRegistry()), abi.encodeCall(TrustRegistry.initialize, (rehearsalOwner))
        )));
        bytes[] memory calls = TrustMigration.calls(ILegacyTrust(agenticId), c, fresh.IMAGE(), keep);
        _summarize(calls);
        vm.prank(rehearsalOwner);
        fresh.multicall(calls);
        _check(agenticId, fresh, c, keep);

        address beacon = vm.envOr("AGENTIC_ID_BEACON", address(0));
        if (beacon == address(0)) return;
        bool[] memory trusted = new bool[](c.attestors.length);
        bool[] memory listed = new bool[](c.images.length);
        for (uint256 i; i < trusted.length; ++i) trusted[i] = ILegacyTrust(agenticId).isTrustedAttestor(c.attestors[i]);
        for (uint256 i; i < listed.length; ++i) {
            listed[i] = keep.length == 0
                ? ILegacyTrust(agenticId).isValidFrameworkHash(c.images[i])
                : _contains(keep, c.images[i]);
        }

        address impl = address(new AgenticID(address(fresh)));
        vm.prank(UpgradeableBeacon(beacon).owner());
        UpgradeableBeacon(beacon).upgradeTo(impl);
        require(keccak256(bytes(AgenticID(agenticId).VERSION())) == keccak256("1.4.0"), "not on 1.4.0");
        require(AgenticID(agenticId).trustRegistry() == address(fresh), "reads another registry");
        for (uint256 i; i < trusted.length; ++i) {
            require(ILegacyTrust(agenticId).isTrustedAttestor(c.attestors[i]) == trusted[i], "attestor changed");
            if (trusted[i]) console2.log("trusted before and after:", c.attestors[i]);
        }
        uint256 n;
        for (uint256 i; i < listed.length; ++i) {
            require(ILegacyTrust(agenticId).isValidFrameworkHash(c.images[i]) == listed[i], "image hash changed");
            if (listed[i]) n++;
        }
        console2.log("rehearsed the upgrade: every candidate reads as intended; image hashes listed", n);
    }

    /// @dev Before the upgrade, TrustMigration.check. After it AgenticID
    ///      forwards to the registry, so only the forward and the kept image
    ///      hashes are proven (TrustMigration.checkKept).
    function _check(
        address agenticId,
        TrustRegistry registry,
        TrustMigration.Candidates memory c,
        bytes32[] memory keep
    ) internal view {
        address current;
        try IAgenticIDTrustRegistry(agenticId).trustRegistry() returns (address r) {
            current = r;
        } catch {}
        bool ok;
        string memory why;
        if (current == address(0)) {
            console2.log("AgenticID has no trustRegistry() yet (pre-1.4.0): comparing both contracts");
            (ok, why) = TrustMigration.check(ILegacyTrust(agenticId), registry, c, keep);
            console2.log(ok ? "check: the registry holds exactly what the migration intends" : string.concat("check FAILED: ", why));
        } else {
            console2.log("AgenticID reads its trust from", current);
            require(current == address(registry), "AgenticID reads another TrustRegistry");
            console2.log("after the upgrade AgenticID's reads are the registry's: checking the kept image hashes only");
            (ok, why) = TrustMigration.checkKept(registry, keep);
            console2.log(ok ? "check: every kept image hash is listed" : string.concat("check FAILED: ", why));
        }
        require(ok, why);
    }

    function _summarize(bytes[] memory calls) internal pure {
        uint256 adds;
        uint256 binds;
        uint256 lists;
        bool instance;
        for (uint256 i; i < calls.length; ++i) {
            bytes4 sel = bytes4(calls[i]);
            if (sel == TrustRegistry.addTrustedAttestor.selector) adds++;
            else if (sel == TrustRegistry.bindTrustedAttestorApp.selector) binds++;
            else if (sel == TrustRegistry.list.selector) lists++;
            else if (sel == TrustRegistry.requireInstanceBoundAttestors.selector) instance = true;
        }
        console2.log("owner calls: add attestor", adds);
        console2.log("             bind attestor", binds);
        console2.log("             require instance binding", instance ? "yes" : "no");
        console2.log("             list image hash", lists);
    }

    function _contains(bytes32[] memory set, bytes32 h) internal pure returns (bool) {
        for (uint256 i; i < set.length; ++i) if (set[i] == h) return true;
        return false;
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
