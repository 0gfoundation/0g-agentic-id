// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import {CloneGate} from "../src/CloneGate.sol";

/// @notice Incremental deploy: add a CloneGate (impl + beacon + proxy) to an
///         EXISTING AgenticID environment (DEPLOYMENT.md section 6). Fresh
///         full-stack deploys use Deploy.s.sol, which already includes it.
///
///         Env vars: AGENTIC_ID (existing proxy), TIMELOCK (beacon owner).
///
///         Post-deploy (AgenticID owner, one tx): addTrustedAttestor(proxy) —
///         the gate mints through registerWithSeal.
contract DeployCloneGate is Script {
    function run() external returns (address impl, address beacon, address proxy) {
        address agenticId = vm.envAddress("AGENTIC_ID");
        address timelock  = vm.envAddress("TIMELOCK");

        vm.startBroadcast();
        CloneGate cgImpl = new CloneGate();
        UpgradeableBeacon cgBeacon = new UpgradeableBeacon(address(cgImpl), timelock);
        BeaconProxy cgProxy = new BeaconProxy(
            address(cgBeacon), abi.encodeCall(CloneGate.initialize, (agenticId))
        );
        vm.stopBroadcast();

        impl = address(cgImpl);
        beacon = address(cgBeacon);
        proxy = address(cgProxy);
        console2.log("CloneGate impl:  ", impl);
        console2.log("CloneGate beacon:", beacon);
        console2.log("CloneGate proxy: ", proxy);
        console2.log("REMINDER: AgenticID owner must addTrustedAttestor(proxy)");
    }
}
