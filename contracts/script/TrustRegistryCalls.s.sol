// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {TrustRegistry} from "../src/TrustRegistry.sol";

/// @notice The TrustRegistry calls a Timelock may run for it, each shown as
///         one line before it is scheduled.
library RegistryCalls {
    bytes4 internal constant TRANSFER_OWNERSHIP = bytes4(keccak256("transferOwnership(address)"));
    bytes4 internal constant ACCEPT_OWNERSHIP = bytes4(keccak256("acceptOwnership()"));

    /// @notice `data` as one line; reverts for anything but the registry's
    ///         owner calls: list / delist, add / remove / bind an attestor,
    ///         requireInstanceBoundAttestors, setGuardian, transferOwnership,
    ///         acceptOwnership. multicall and renounceOwnership are refused.
    function describe(bytes memory data) internal pure returns (string memory) {
        require(data.length >= 4, "a call shorter than a selector");
        bytes4 sel = bytes4(data);
        bytes memory args = new bytes(data.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = data[i + 4];

        if (sel == TrustRegistry.list.selector || sel == TrustRegistry.delist.selector) {
            (bytes32 kind, bytes32 hash) = abi.decode(args, (bytes32, bytes32));
            string memory verb = sel == TrustRegistry.list.selector ? "list " : "delist ";
            return string.concat(verb, _kind(kind), " ", Strings.toHexString(uint256(hash), 32));
        }
        if (sel == TrustRegistry.addTrustedAttestor.selector) {
            return string.concat("trust attestor ", Strings.toHexString(abi.decode(args, (address))));
        }
        if (sel == TrustRegistry.removeTrustedAttestor.selector) {
            return string.concat("untrust attestor ", Strings.toHexString(abi.decode(args, (address))));
        }
        if (sel == TrustRegistry.bindTrustedAttestorApp.selector) {
            (address attestor, address registry, string memory appId, uint256 registeredAt) =
                abi.decode(args, (address, address, string, uint256));
            return string.concat(
                "bind attestor ", Strings.toHexString(attestor), " to app ", appId, " on ",
                Strings.toHexString(registry), " registered at ", Strings.toString(registeredAt)
            );
        }
        if (sel == TrustRegistry.requireInstanceBoundAttestors.selector) return "require instance-bound attestors";
        if (sel == TrustRegistry.setGuardian.selector) {
            return string.concat("set guardian ", Strings.toHexString(abi.decode(args, (address))));
        }
        if (sel == TRANSFER_OWNERSHIP) {
            return string.concat("propose owner ", Strings.toHexString(abi.decode(args, (address))));
        }
        if (sel == ACCEPT_OWNERSHIP) return "accept ownership";
        revert("not a TrustRegistry owner call this script schedules");
    }

    function _kind(bytes32 kind) private pure returns (string memory) {
        if (kind == keccak256("image")) return "IMAGE";
        if (kind == keccak256("sealed")) return "SEALED";
        if (kind == keccak256("harness")) return "HARNESS";
        return Strings.toHexString(uint256(kind), 32);
    }
}

/// @notice TrustRegistry owner calls through the environment's
///         TimelockController — how trust is added once the Timelock owns the
///         registry (TrustRegistry 1.1.0 on): `list`, `addTrustedAttestor`,
///         `bindTrustedAttestorApp`, `requireInstanceBoundAttestors`,
///         `setGuardian`, and the Timelock's own `acceptOwnership` when the
///         registry moves to it. Removing trust needs none of this: the
///         guardian calls `delist` / `removeTrustedAttestor` directly (a
///         Timelock batch may carry them too).
///
///         Environment variables:
///           MODE           — schedule (default) | execute | cancel
///           TIMELOCK       — the environment's TimelockController
///           TRUST_REGISTRY — the TrustRegistry proxy, the target of every call
///           CALLS          — the calls, comma-separated calldata, e.g.
///                            CALLS=$(cast calldata "list(bytes32,bytes32)" $(cast keccak sealed) 0x<hash>)
///           PREDECESSOR    — bytes32 (default 0x0)
///           SALT           — bytes32 (default 0x0); the same batch scheduled
///                            again needs another SALT
///           DELAY          — schedule only: seconds, at least the Timelock's
///                            minDelay (default: minDelay)
///
///         schedule — as a proposer: one scheduleBatch of CALLS, every call on
///           TRUST_REGISTRY. Prints each call, the operation id, the
///           scheduleBatch calldata for a proposer that signs outside forge
///           (the mainnet vault: to = TIMELOCK, value 0; take it from a dry run
///           with --sender <vault>), and the ready time.
///         execute — once ready, by an executor (anyone, where execution is
///           open): the same CALLS / PREDECESSOR / SALT.
///         cancel — by a canceller (every proposer), any time before it runs.
contract TrustRegistryCalls is Script {
    function run() external {
        string memory mode = vm.envOr("MODE", string("schedule"));
        TimelockController timelock = TimelockController(payable(vm.envAddress("TIMELOCK")));
        address registry = vm.envAddress("TRUST_REGISTRY");
        bytes[] memory calls = vm.envBytes("CALLS", ",");
        bytes32 predecessor = vm.envOr("PREDECESSOR", bytes32(0));
        bytes32 salt = vm.envOr("SALT", bytes32(0));
        require(registry.code.length > 0, "TRUST_REGISTRY has no code");
        require(calls.length > 0, "CALLS is empty");

        address[] memory targets = new address[](calls.length);
        uint256[] memory values = new uint256[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            targets[i] = registry;
            console2.log(RegistryCalls.describe(calls[i]));
        }
        bytes32 id = timelock.hashOperationBatch(targets, values, calls, predecessor, salt);
        console2.log("operation id:");
        console2.logBytes32(id);

        if (_is(mode, "schedule")) {
            uint256 delay = vm.envOr("DELAY", timelock.getMinDelay());
            console2.log("scheduleBatch calldata (to = TIMELOCK, value 0):");
            console2.logBytes(abi.encodeCall(timelock.scheduleBatch, (targets, values, calls, predecessor, salt, delay)));
            vm.startBroadcast();
            timelock.scheduleBatch(targets, values, calls, predecessor, salt, delay);
            vm.stopBroadcast();
            console2.log("scheduled, executable at (unix ts):", timelock.getTimestamp(id));
        } else if (_is(mode, "execute")) {
            require(timelock.isOperationReady(id), "operation not ready: not scheduled, still waiting, or done");
            vm.startBroadcast();
            timelock.executeBatch(targets, values, calls, predecessor, salt);
            vm.stopBroadcast();
            console2.log("executed.");
        } else {
            require(_is(mode, "cancel"), "MODE must be schedule, execute or cancel");
            vm.startBroadcast();
            timelock.cancel(id);
            vm.stopBroadcast();
            console2.log("cancelled.");
        }
    }

    function _is(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
