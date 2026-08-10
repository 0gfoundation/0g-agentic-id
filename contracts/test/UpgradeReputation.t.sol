// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticIDReputationRegistry} from "../src/AgenticIDReputationRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

/// @notice V2 impl proving the beacon code swap took effect.
contract ReputationRegistryV2 is AgenticIDReputationRegistry {
    function version2Tag() external pure returns (string memory) {
        return "v2";
    }
}

/// @notice The reputation registry is deployed behind the same
///         BeaconProxy + UpgradeableBeacon + Timelock topology as every other
///         AgenticID contract (`Deploy.s.sol`), so the generic
///         ScheduleUpgrade/ExecuteUpgrade path upgrades it exactly like the
///         AgenticID beacon (covered in Upgradeable.t.sol). This locks storage
///         preservation + post-upgrade behavior across a real beacon upgrade.
contract UpgradeReputationTest is AgenticIDTestBase {
    TimelockController internal timelock;
    UpgradeableBeacon  internal repBeacon;
    AgenticIDReputationRegistry internal reputation;

    Vm.Wallet internal sealWallet;
    address internal agentOwner = address(0xA1);
    address internal client = address(0xC1);

    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);
    uint256 internal constant DELAY = 2 days;

    bytes32 internal constant TASK_HASH = keccak256("task-1");
    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sealWallet = vm.createWallet("agent-seal");

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new TimelockController(DELAY, proposers, executors, owner);

        // Reputation registry behind a beacon owned by the timelock.
        AgenticIDReputationRegistry repImpl = new AgenticIDReputationRegistry();
        repBeacon = new UpgradeableBeacon(address(repImpl), address(timelock));
        BeaconProxy repProxy = new BeaconProxy(
            address(repBeacon),
            abi.encodeCall(
                AgenticIDReputationRegistry.initialize,
                (address(agenticId), owner, pauser, MAX_PROOF_AGE)
            )
        );
        reputation = AgenticIDReputationRegistry(address(repProxy));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    function _mintSealAgent() internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256("rep-data");
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            agentOwner, "", metadata, datas, sealedKeys, sealWallet.addr, SEAL_ID
        );
    }

    /// @dev ServeProof signed by the controlled seal wallet, bound to `client`
    ///      as the redeemer plus this chain and the identity registry.
    function _mkProof(uint256 agentId, bytes32[] memory dataHashes, uint256 deadline)
        internal view returns (ServeProof memory)
    {
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), client,
            agentId, block.timestamp, deadline, TASK_HASH,
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH
        ));
        return ServeProof({
            agentId: agentId,
            submitter: client,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: TASK_HASH,
            dataHashes: dataHashes,
            frameworkHash: FRAMEWORK_HASH,
            signature: _sign(sealWallet.privateKey, _eip191RawHash(inner))
        });
    }

    function _give(uint256 agentId, bytes32[] memory dataHashes) internal {
        // deadline computed inline (never reused across a vm.warp).
        ServeProof memory p = _mkProof(agentId, dataHashes, block.timestamp + 1 hours);
        vm.prank(client);
        reputation.giveFeedback(
            agentId, 5, 0, "quality", "e2e", "ep", "ipfs://f", keccak256("fh"), p
        );
    }

    function _upgradeBeacon(address newImpl) internal {
        bytes memory cd = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        vm.prank(proposer);
        timelock.schedule(address(repBeacon), 0, cd, bytes32(0), bytes32(0), DELAY);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(executor);
        timelock.execute(address(repBeacon), 0, cd, bytes32(0), bytes32(0));
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    function test_beaconOwnedByTimelock() public view {
        assertEq(repBeacon.owner(), address(timelock));
    }

    function test_upgrade_reputation_preservesFeedback() public {
        (uint256 agentId, bytes32 dataHash) = _mintSealAgent();
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        _give(agentId, dataHashes); // feedback at index 1

        // Sanity pre-upgrade.
        (int128 v0,,,,) = reputation.readFeedback(agentId, client, 1);
        assertEq(int256(v0), 5);

        // Upgrade the beacon impl through the timelock.
        _upgradeBeacon(address(new ReputationRegistryV2()));
        assertEq(repBeacon.implementation() != address(0), true);
        assertEq(ReputationRegistryV2(address(reputation)).version2Tag(), "v2");

        // Storage survived: the pre-upgrade feedback still reads back.
        (int128 v1, , string memory tag1, , bool revoked) =
            reputation.readFeedback(agentId, client, 1);
        assertEq(int256(v1), 5);
        assertEq(tag1, "quality");
        assertEq(revoked, false);
        assertEq(reputation.getLastIndex(agentId, client), 1);

        // Post-upgrade behavior: a fresh client-less giveFeedback still works.
        _give(agentId, dataHashes); // index 2
        assertEq(reputation.getLastIndex(agentId, client), 2);
    }
}
