// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

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
contract ScheduleUpgrade is Script {
    function run() external {
        address timelockAddr = vm.envAddress("TIMELOCK");
        address beacon       = vm.envAddress("BEACON");
        address newImpl      = vm.envAddress("NEW_IMPL");
        bytes32 predecessor  = vm.envOr("PREDECESSOR", bytes32(0));
        bytes32 salt         = vm.envOr("SALT", bytes32(0));

        TimelockController timelock = TimelockController(payable(timelockAddr));
        uint256 delay = vm.envOr("DELAY", timelock.getMinDelay());

        bytes memory data = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        bytes32 opId = timelock.hashOperation(beacon, 0, data, predecessor, salt);

        console2.log("=== Schedule Upgrade ===");
        console2.log("timelock:    ", timelockAddr);
        console2.log("beacon:      ", beacon);
        console2.log("newImpl:     ", newImpl);
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
