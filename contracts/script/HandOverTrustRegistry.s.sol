// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {TrustRegistry} from "../src/TrustRegistry.sol";
import {MainnetGovernance} from "./MainnetGovernance.sol";

/// @notice The owner calls that move a TrustRegistry to its operating model.
library HandOver {
    /// @notice setGuardian(guardian), then transferOwnership(timelock) — one
    ///         multicall for the registry's current owner. Refuses a registry
    ///         without a guardian (1.0.0: upgrade it to 1.1.0 first), a zero
    ///         guardian, a TIMELOCK that is no TimelockController, and on 0G
    ///         mainnet one with minDelay below 1 day.
    function calls(address registry, address guardian, address timelock, uint256 chainId)
        internal
        view
        returns (bytes[] memory out)
    {
        require(registry.code.length > 0, "TRUST_REGISTRY has no code");
        try TrustRegistry(registry).guardian() returns (address) {}
        catch {
            revert("TRUST_REGISTRY has no guardian(): upgrade it to 1.1.0 first");
        }
        require(guardian != address(0), "GUARDIAN is zero");
        require(timelock.code.length > 0, "TIMELOCK has no code");
        TimelockController(payable(timelock)).getMinDelay();
        MainnetGovernance.requireMainnetTimelock(chainId, timelock);
        out = new bytes[](2);
        out[0] = abi.encodeCall(TrustRegistry.setGuardian, (guardian));
        out[1] = abi.encodeWithSignature("transferOwnership(address)", timelock);
    }
}

/// @notice Move a TrustRegistry to its operating model: adding trust through
///         the environment's TimelockController, removing it at once through
///         the guardian. As the registry's current owner — the governance key,
///         after the deploy and the list migration — set the guardian (that
///         same key) and propose the Timelock as owner, in one multicall. The
///         Timelock then accepts through a scheduled operation:
///           CALLS=$(cast calldata "acceptOwnership()") forge script script/TrustRegistryCalls.s.sol …
///         (MODE=schedule, then MODE=execute once ready). Until it accepts, the
///         governance key stays owner.
///
///         Environment variables:
///           TRUST_REGISTRY — the TrustRegistry proxy (1.1.0 or later)
///           GUARDIAN       — the key that may delist and untrust at once
///           TIMELOCK       — the environment's TimelockController (the
///                            beacons' owner); on 0G mainnet (16661) its
///                            minDelay must be at least 1 day
///           MODE           — apply (default): broadcast as the owner;
///                            plan: print the multicall calldata for an owner
///                            that signs outside forge (the mainnet vault:
///                            to = TRUST_REGISTRY, value 0)
contract HandOverTrustRegistry is Script {
    function run() external {
        TrustRegistry registry = TrustRegistry(vm.envAddress("TRUST_REGISTRY"));
        address guardian = vm.envAddress("GUARDIAN");
        address timelock = vm.envAddress("TIMELOCK");
        string memory mode = vm.envOr("MODE", string("apply"));
        bytes[] memory calls = HandOver.calls(address(registry), guardian, timelock, block.chainid);

        console2.log("TrustRegistry:", address(registry), "owner now:", registry.owner());
        console2.log("guardian:     ", guardian);
        console2.log("next owner:   ", timelock);
        if (keccak256(bytes(mode)) == keccak256("plan")) {
            console2.log("multicall calldata (to = TRUST_REGISTRY, value 0):");
            console2.logBytes(abi.encodeCall(registry.multicall, (calls)));
            return;
        }
        require(keccak256(bytes(mode)) == keccak256("apply"), "MODE must be apply or plan");
        vm.startBroadcast();
        registry.multicall(calls);
        vm.stopBroadcast();
        require(registry.guardian() == guardian, "guardian not set");
        require(registry.pendingOwner() == timelock, "the Timelock is not the pending owner");
        console2.log("guardian set; the Timelock is the pending owner.");
        console2.log("NEXT: the Timelock accepts - TrustRegistryCalls with CALLS=acceptOwnership() calldata");
    }
}
