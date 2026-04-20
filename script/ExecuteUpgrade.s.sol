// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

/// @notice Execute a previously-scheduled beacon upgrade.
///
///         Run as an EXECUTOR account (or anyone if Timelock was configured with open
///         execution, i.e. executor = address(0)).
///
///         Inputs MUST match the corresponding ScheduleUpgrade call byte-for-byte —
///         same BEACON, NEW_IMPL, PREDECESSOR, SALT — otherwise the op hash won't
///         match and execute will revert.
///
///         Environment variables:
///           TIMELOCK      — TimelockController address
///           BEACON        — UpgradeableBeacon to upgrade
///           NEW_IMPL      — new implementation address
///           PREDECESSOR   — bytes32 (default 0x0)
///           SALT          — bytes32 (default 0x0)
contract ExecuteUpgrade is Script {
    function run() external {
        address timelockAddr = vm.envAddress("TIMELOCK");
        address beacon       = vm.envAddress("BEACON");
        address newImpl      = vm.envAddress("NEW_IMPL");
        bytes32 predecessor  = vm.envOr("PREDECESSOR", bytes32(0));
        bytes32 salt         = vm.envOr("SALT", bytes32(0));

        TimelockController timelock = TimelockController(payable(timelockAddr));
        bytes memory data = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        bytes32 opId = timelock.hashOperation(beacon, 0, data, predecessor, salt);

        console2.log("=== Execute Upgrade ===");
        console2.log("timelock:    ", timelockAddr);
        console2.log("beacon:      ", beacon);
        console2.log("newImpl:     ", newImpl);
        console2.log("op id:");
        console2.logBytes32(opId);
        console2.log("op ready?    ", timelock.isOperationReady(opId));

        vm.startBroadcast();
        timelock.execute(beacon, 0, data, predecessor, salt);
        vm.stopBroadcast();

        address onChain = UpgradeableBeacon(beacon).implementation();
        console2.log("beacon.implementation() now: ", onChain);
        require(onChain == newImpl, "upgrade did not take effect");
        console2.log("upgrade confirmed.");
    }
}
