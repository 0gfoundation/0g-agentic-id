// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";

/// @notice Deploy AgenticID stack behind BeaconProxy + TimelockController.
///
///         Environment variables:
///           OWNER             — EOA/multisig receiving TimelockController admin role
///           PAUSER            — address allowed to pause/unpause (not timelocked)
///           TEE_ORACLE        — signer address for TEEDataVerifier
///           TIMELOCK_DELAY    — seconds (dev: 0, prod: e.g. 172800 = 2 days)
///           PROPOSERS         — comma-separated addresses (defaults to OWNER)
///           EXECUTORS         — comma-separated addresses; pass 0x0 for open execution
///           NFT_NAME          — ERC-721 name   (default "AgenticID")
///           NFT_SYMBOL        — ERC-721 symbol (default "AID")
///           MAX_PROOF_AGE     — nonce GC horizon in seconds (default 86400)
contract Deploy is Script {
    struct Config {
        address   owner;
        address   pauser;
        address   teeOracle;
        uint256   timelockDelay;
        address[] proposers;
        address[] executors;
        string    nftName;
        string    nftSymbol;
        uint256   maxProofAge;
        // Fixed canonical ERC-8004 registry to custody-bind to.
        // 0G Galileo testnet: 0x8004a818bfb912233c491871b3d84c89a494bd9e
        address   canonical;
        // Fixed canonical ERC-8004 Reputation Registry the verified-feedback
        // layer anchors to. 0G Galileo testnet: 0x8004b663…8713
        address   canonicalReputation;
    }

    struct Deployed {
        address timelock;
        address verifierImpl;
        address verifierBeacon;
        address verifier;
        address agenticIdImpl;
        address agenticIdBeacon;
        address agenticId;
        address verifiedFeedbackImpl;
        address verifiedFeedbackBeacon;
        address verifiedFeedback;
    }

    function run() external returns (Deployed memory d) {
        Config memory c = _readConfig();
        _printConfig(c);

        // Fail fast if canonical points at the wrong contract (e.g. the testnet
        // address used on mainnet, which resolves to a different v0.0.1 contract).
        require(
            keccak256(bytes(ICanonical8004(c.canonical).getVersion())) == keccak256(bytes("2.0.0")),
            "canonical is not ERC-8004 IdentityRegistry v2.0.0 on this chain"
        );
        require(
            keccak256(bytes(ICanonical8004(c.canonicalReputation).getVersion())) == keccak256(bytes("2.0.0")),
            "canonicalReputation is not ERC-8004 ReputationRegistry v2.0.0 on this chain"
        );
        require(
            ICanonical8004Reputation(c.canonicalReputation).getIdentityRegistry() == c.canonical,
            "canonicalReputation is not bound to the canonical IdentityRegistry"
        );

        vm.startBroadcast();

        // 1. Timelock — owner of every beacon.
        TimelockController timelock = new TimelockController(
            c.timelockDelay, c.proposers, c.executors, c.owner
        );
        d.timelock = address(timelock);

        // 2. Verifier.
        TEEDataVerifier verifierImpl = new TEEDataVerifier();
        UpgradeableBeacon verifierBeacon = new UpgradeableBeacon(address(verifierImpl), address(timelock));
        BeaconProxy verifierProxy = new BeaconProxy(
            address(verifierBeacon),
            abi.encodeCall(TEEDataVerifier.initialize, (c.owner, c.pauser, c.teeOracle, c.maxProofAge))
        );
        d.verifierImpl = address(verifierImpl);
        d.verifierBeacon = address(verifierBeacon);
        d.verifier = address(verifierProxy);

        // 3. AgenticID.
        AgenticID agenticIdImpl = new AgenticID();
        UpgradeableBeacon agenticIdBeacon = new UpgradeableBeacon(address(agenticIdImpl), address(timelock));
        BeaconProxy agenticIdProxy = new BeaconProxy(
            address(agenticIdBeacon),
            abi.encodeCall(
                AgenticID.initialize,
                (c.nftName, c.nftSymbol, address(verifierProxy), c.owner, c.pauser, c.canonical)
            )
        );
        d.agenticIdImpl = address(agenticIdImpl);
        d.agenticIdBeacon = address(agenticIdBeacon);
        d.agenticId = address(agenticIdProxy);

        // 4. Verified-feedback registry (companion to the canonical ERC-8004
        //    Reputation Registry — feedback lives there, verification marks here).
        VerifiedFeedbackRegistry vfImpl = new VerifiedFeedbackRegistry();
        UpgradeableBeacon vfBeacon = new UpgradeableBeacon(address(vfImpl), address(timelock));
        BeaconProxy vfProxy = new BeaconProxy(
            address(vfBeacon),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(agenticIdProxy), c.canonicalReputation, c.owner, c.pauser, c.maxProofAge)
            )
        );
        d.verifiedFeedbackImpl = address(vfImpl);
        d.verifiedFeedbackBeacon = address(vfBeacon);
        d.verifiedFeedback = address(vfProxy);

        vm.stopBroadcast();

        _printDeployed(d);
    }

    function _readConfig() internal view returns (Config memory c) {
        c.owner         = vm.envAddress("OWNER");
        c.pauser        = vm.envAddress("PAUSER");
        c.teeOracle     = vm.envAddress("TEE_ORACLE");
        c.timelockDelay = vm.envOr("TIMELOCK_DELAY", uint256(0));
        c.nftName       = vm.envOr("NFT_NAME", string("AgenticID"));
        c.nftSymbol     = vm.envOr("NFT_SYMBOL", string("AID"));
        c.maxProofAge   = vm.envOr("MAX_PROOF_AGE", uint256(86400));
        // Canonical ERC-8004 registries, chosen by chainId (override via
        // CANONICAL_8004 / CANONICAL_8004_REPUTATION).
        c.canonical           = vm.envOr("CANONICAL_8004", _defaultCanonical(block.chainid));
        c.canonicalReputation = vm.envOr("CANONICAL_8004_REPUTATION", _defaultCanonicalReputation(block.chainid));

        address[] memory defaultProposers = new address[](1);
        defaultProposers[0] = c.owner;
        c.proposers = vm.envOr("PROPOSERS", ",", defaultProposers);

        address[] memory defaultExecutors = new address[](1);
        defaultExecutors[0] = address(0); // open execution by default
        c.executors = vm.envOr("EXECUTORS", ",", defaultExecutors);
    }

    function _printConfig(Config memory c) internal pure {
        console2.log("=== Deploy Config ===");
        console2.log("owner:         ", c.owner);
        console2.log("pauser:        ", c.pauser);
        console2.log("teeOracle:     ", c.teeOracle);
        console2.log("timelockDelay: ", c.timelockDelay);
        console2.log("maxProofAge:   ", c.maxProofAge);
        console2.log("canonical8004: ", c.canonical);
        console2.log("canonical8004Reputation: ", c.canonicalReputation);
    }

    function _printDeployed(Deployed memory d) internal pure {
        console2.log("=== Deployed ===");
        console2.log("TimelockController:         ", d.timelock);
        console2.log("TEEDataVerifier impl:       ", d.verifierImpl);
        console2.log("TEEDataVerifier beacon:     ", d.verifierBeacon);
        console2.log("TEEDataVerifier proxy:      ", d.verifier);
        console2.log("AgenticID impl:             ", d.agenticIdImpl);
        console2.log("AgenticID beacon:           ", d.agenticIdBeacon);
        console2.log("AgenticID proxy:            ", d.agenticId);
        console2.log("VerifiedFeedback impl:      ", d.verifiedFeedbackImpl);
        console2.log("VerifiedFeedback beacon:    ", d.verifiedFeedbackBeacon);
        console2.log("VerifiedFeedback proxy:     ", d.verifiedFeedback);
    }

    /// @dev Canonical ERC-8004 IdentityRegistry by chainId. ERC-8004 is deployed
    ///      via CREATE2: all mainnets share one address, all testnets another.
    function _defaultCanonical(uint256 chainId) internal pure returns (address) {
        if (chainId == 16661 || chainId == 1) {
            return 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432; // 0G / Ethereum mainnet
        }
        if (chainId == 16602 || chainId == 11155111) {
            return 0x8004A818BFB912233c491871b3d84c89A494BD9e; // 0G Galileo / Ethereum Sepolia
        }
        revert("no known canonical ERC-8004 for this chainId; set CANONICAL_8004");
    }

    /// @dev Canonical ERC-8004 ReputationRegistry by chainId — same CREATE2
    ///      vanity-address pattern as the identity registry.
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

interface ICanonical8004 {
    function getVersion() external view returns (string memory);
}

interface ICanonical8004Reputation {
    function getIdentityRegistry() external view returns (address);
}
