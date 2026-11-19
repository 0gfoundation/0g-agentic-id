// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface ITrustRegistryReader {
    function trustRegistry() external view returns (address);
}

/// @notice What scheduling an AgenticID implementation from 1.4.0 on must
///         check: the implementation fixes its TrustRegistry in its code, so
///         executing the upgrade points every trust read — attestors, image
///         list, sealed and harness lists — at that address.
library TrustRegistryCheck {
    /// @notice The TrustRegistry `impl` reads; zero for an implementation
    ///         without `trustRegistry()` (every contract but AgenticID from
    ///         1.4.0 on). `impl` must have code.
    function registryOf(address impl) internal view returns (address) {
        try ITrustRegistryReader(impl).trustRegistry() returns (address r) {
            return r;
        } catch {
            return address(0);
        }
    }

    /// @notice Refuses unless `named` — the registry the implementation reads
    ///         — is `expected`, has code, and is owned by `expectedOwner`.
    function check(address named, address expected, address expectedOwner) internal view {
        require(named == expected, "NEW_IMPL reads another TrustRegistry than TRUST_REGISTRY");
        require(expected.code.length > 0, "TRUST_REGISTRY has no code");
        require(Ownable(expected).owner() == expectedOwner, "TRUST_REGISTRY's owner is not TRUST_REGISTRY_OWNER");
    }
}

/// @notice Schedule a beacon upgrade via TimelockController.
///
///         Run as a PROPOSER account (see Timelock's PROPOSER_ROLE).
///
///         Environment variables:
///           TIMELOCK      — TimelockController address
///           BEACON        — UpgradeableBeacon to upgrade
///           NEW_IMPL      — new implementation address (deploy separately, e.g. `forge create`)
///           PREDECESSOR   — bytes32, 0x0 unless you're chaining ops (default 0x0)
///           SALT          — bytes32 disambiguator (default 0x0)
///           DELAY         — seconds; must be >= Timelock's minDelay (default: read from Timelock)
///           TRUST_REGISTRY, TRUST_REGISTRY_OWNER — required when NEW_IMPL
///                           answers trustRegistry() (AgenticID from 1.4.0):
///                           the environment's TrustRegistry proxy and its
///                           owner. The run refuses before scheduling unless
///                           NEW_IMPL reads that registry, it has code and
///                           that owner (TrustRegistryCheck).
contract ScheduleUpgrade is Script {
    function run() external {
        address timelockAddr = vm.envAddress("TIMELOCK");
        address beacon       = vm.envAddress("BEACON");
        address newImpl      = vm.envAddress("NEW_IMPL");
        bytes32 predecessor  = vm.envOr("PREDECESSOR", bytes32(0));
        bytes32 salt         = vm.envOr("SALT", bytes32(0));

        require(newImpl.code.length > 0, "NEW_IMPL has no code");
        address reads = TrustRegistryCheck.registryOf(newImpl);
        if (reads != address(0)) {
            TrustRegistryCheck.check(reads, vm.envAddress("TRUST_REGISTRY"), vm.envAddress("TRUST_REGISTRY_OWNER"));
        }

        TimelockController timelock = TimelockController(payable(timelockAddr));
        uint256 delay = vm.envOr("DELAY", timelock.getMinDelay());

        bytes memory data = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        bytes32 opId = timelock.hashOperation(beacon, 0, data, predecessor, salt);

        console2.log("=== Schedule Upgrade ===");
        console2.log("timelock:    ", timelockAddr);
        console2.log("beacon:      ", beacon);
        console2.log("newImpl:     ", newImpl);
        if (reads != address(0)) console2.log("reads TrustRegistry:", reads);
        console2.log("delay (sec): ", delay);
        console2.logBytes32(predecessor);
        console2.logBytes32(salt);
        console2.log("op id:");
        console2.logBytes32(opId);

        vm.startBroadcast();
        timelock.schedule(beacon, 0, data, predecessor, salt, delay);
        vm.stopBroadcast();

        uint256 ready = timelock.getTimestamp(opId);
        console2.log("scheduled, executable at (unix ts):", ready);
    }
}
