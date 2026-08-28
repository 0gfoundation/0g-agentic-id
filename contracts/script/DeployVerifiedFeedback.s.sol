// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {FeedbackBatcher} from "../src/FeedbackBatcher.sol";

/// @notice Incremental deploy: add a VerifiedFeedbackRegistry (impl + beacon +
///         proxy) to an EXISTING AgenticID environment (DEPLOYMENT.md §6),
///         without touching AgenticID / verifier / the deprecated fork
///         registry. Fresh full-stack deploys use `Deploy.s.sol` instead,
///         which already includes this contract.
///
///         Environment variables:
///           AGENTIC_ID                — existing AgenticID proxy (proof anchor)
///           TIMELOCK                  — existing TimelockController (beacon owner)
///           OWNER                     — admin role (setPauser / setMaxProofAge)
///           PAUSER                    — pause / unpause role
///           MAX_PROOF_AGE             — nonce GC horizon in seconds (default 86400)
///           CANONICAL_8004_REPUTATION — override the chainId default
contract DeployVerifiedFeedback is Script {
    function run() external returns (address impl, address beacon, address proxy, address batcher) {
        address agenticId   = vm.envAddress("AGENTIC_ID");
        address timelock    = vm.envAddress("TIMELOCK");
        address owner       = vm.envAddress("OWNER");
        address pauser      = vm.envAddress("PAUSER");
        uint256 maxProofAge = vm.envOr("MAX_PROOF_AGE", uint256(86400));
        address canonicalReputation =
            vm.envOr("CANONICAL_8004_REPUTATION", _defaultCanonicalReputation(block.chainid));

        // Fail fast — the anchoring checks live here, NOT in initialize
        // (see DEPLOYMENT.md §2.1: deploy through scripts only).
        require(
            keccak256(bytes(IVersioned(canonicalReputation).getVersion())) == keccak256(bytes("2.0.0")),
            "canonicalReputation is not ERC-8004 ReputationRegistry v2.0.0 on this chain"
        );
        require(
            ICanonicalReputationLike(canonicalReputation).getIdentityRegistry()
                == ICanonicalBoundLike(agenticId).canonical(),
            "canonicalReputation is not bound to AGENTIC_ID's canonical IdentityRegistry"
        );

        console2.log("=== DeployVerifiedFeedback config ===");
        console2.log("agenticId:            ", agenticId);
        console2.log("canonicalReputation:  ", canonicalReputation);
        console2.log("timelock (beacon own):", timelock);
        console2.log("owner:                ", owner);
        console2.log("pauser:               ", pauser);
        console2.log("maxProofAge:          ", maxProofAge);

        vm.startBroadcast();
        VerifiedFeedbackRegistry vfImpl = new VerifiedFeedbackRegistry();
        UpgradeableBeacon vfBeacon = new UpgradeableBeacon(address(vfImpl), timelock);
        BeaconProxy vfProxy = new BeaconProxy(
            address(vfBeacon),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (agenticId, canonicalReputation, owner, pauser, maxProofAge)
            )
        );
        // EIP-7702 delegate for the atomic feedback+attest flow (stateless,
        // no beacon — replace by deploying a new one and re-delegating).
        FeedbackBatcher fb = new FeedbackBatcher(canonicalReputation, address(vfProxy));
        vm.stopBroadcast();

        impl = address(vfImpl);
        beacon = address(vfBeacon);
        proxy = address(vfProxy);
        batcher = address(fb);

        console2.log("=== Deployed -- record in DEPLOYMENT.md section 6 ===");
        console2.log("VerifiedFeedback impl:  ", impl);
        console2.log("VerifiedFeedback beacon:", beacon);
        console2.log("VerifiedFeedback proxy: ", proxy);
        console2.log("FeedbackBatcher:        ", batcher);
    }

    /// @dev Same defaults as Deploy.s.sol — keep the two in sync.
    function _defaultCanonicalReputation(uint256 chainId) internal pure returns (address) {
        if (chainId == 16661 || chainId == 1) {
            return 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63; // 0G / Ethereum mainnet
        }
        if (chainId == 16602 || chainId == 11155111) {
            return 0x8004B663056A597Dffe9eCcC1965A193B7388713; // 0G Galileo / Ethereum Sepolia
        }
        revert("no known canonical ERC-8004 ReputationRegistry for this chainId; set CANONICAL_8004_REPUTATION");
    }
}

interface IVersioned {
    function getVersion() external view returns (string memory);
}

interface ICanonicalReputationLike {
    function getIdentityRegistry() external view returns (address);
}

interface ICanonicalBoundLike {
    function canonical() external view returns (address);
}
