// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {TrustRegistry} from "../src/TrustRegistry.sol";
import {MainnetGovernance} from "./MainnetGovernance.sol";

/// @notice Incremental deploy: add a TrustRegistry (impl + beacon + proxy) to an
///         EXISTING AgenticID environment, the first step of AgenticID's 1.4.0
///         upgrade (UPGRADING.md "AgenticID 1.4.0"). Fresh full-stack deploys
///         use Deploy.s.sol, which already includes it.
///
///         Env vars: AGENTIC_ID (existing proxy), TIMELOCK (beacon owner; on 0G
///         mainnet (16661) it must have minDelay >= 86400), OWNER (the
///         registry owner; default: AgenticID's owner, who holds the lists
///         today).
///
///         Next: script/MigrateTrust.s.sol copies AgenticID's lists into the
///         proxy; the AgenticID 1.4.0 implementation is then created with the
///         proxy's address as its constructor argument.
contract DeployTrustRegistry is Script {
    function run() external returns (address impl, address beacon, address proxy) {
        address agenticId = vm.envAddress("AGENTIC_ID");
        address timelock = vm.envAddress("TIMELOCK");
        address owner = vm.envOr("OWNER", OwnableUpgradeable(agenticId).owner());
        MainnetGovernance.requireMainnetTimelock(block.chainid, timelock);

        vm.startBroadcast();
        TrustRegistry trImpl = new TrustRegistry();
        UpgradeableBeacon trBeacon = new UpgradeableBeacon(address(trImpl), timelock);
        BeaconProxy trProxy = new BeaconProxy(
            address(trBeacon), abi.encodeCall(TrustRegistry.initialize, (owner))
        );
        vm.stopBroadcast();

        impl = address(trImpl);
        beacon = address(trBeacon);
        proxy = address(trProxy);
        console2.log("TrustRegistry impl:  ", impl);
        console2.log("TrustRegistry beacon:", beacon);
        console2.log("TrustRegistry proxy: ", proxy);
        console2.log("TrustRegistry owner: ", owner);
        console2.log("NEXT: script/MigrateTrust.s.sol with TRUST_REGISTRY = the proxy");
    }
}
