// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {AgenticID, AgenticIDNotPauser} from "../src/AgenticID.sol";
import {CanonicalIdentityRegistryMock} from "./mocks/CanonicalIdentityRegistryMock.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

/// @notice Minimal v2 that adds a new view to prove code swap took effect.
contract AgenticIDV2 is AgenticID {
    function version2Tag() external pure returns (string memory) {
        return "v2";
    }
}

contract UpgradeableTest is Test {
    TimelockController internal timelock;
    UpgradeableBeacon  internal beacon;
    AgenticID          internal agenticId;
    TEEDataVerifier    internal verifier;

    address internal owner    = address(0xA11CE);
    address internal pauser   = address(0xBABE);
    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);
    address internal oracleAddr;

    uint256 internal constant DELAY         = 2 days;
    uint256 internal constant MAX_PROOF_AGE = 1 days;

    function setUp() public {
        (oracleAddr, ) = makeAddrAndKey("oracle");

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new TimelockController(DELAY, proposers, executors, owner);

        // Verifier behind its own beacon (owned by timelock).
        TEEDataVerifier verifierImpl = new TEEDataVerifier();
        UpgradeableBeacon verifierBeacon = new UpgradeableBeacon(address(verifierImpl), address(timelock));
        BeaconProxy verifierProxy = new BeaconProxy(
            address(verifierBeacon),
            abi.encodeCall(TEEDataVerifier.initialize, (owner, pauser, oracleAddr, MAX_PROOF_AGE))
        );
        verifier = TEEDataVerifier(address(verifierProxy));

        CanonicalIdentityRegistryMock canonical = new CanonicalIdentityRegistryMock();
        canonical.initialize();

        // AgenticID behind beacon (owned by timelock).
        AgenticID agenticIdImpl = new AgenticID();
        beacon = new UpgradeableBeacon(address(agenticIdImpl), address(timelock));
        BeaconProxy agenticIdProxy = new BeaconProxy(
            address(beacon),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(verifier), owner, pauser, address(canonical))
            )
        );
        agenticId = AgenticID(address(agenticIdProxy));
    }

    // ── Upgrade via Timelock ─────────────────────────────────────────────────

    function test_upgrade_nonTimelockCannotUpgradeBeacon() public {
        AgenticIDV2 v2 = new AgenticIDV2();

        vm.prank(owner);
        vm.expectRevert(); // Ownable: caller is not the owner (owner = timelock)
        beacon.upgradeTo(address(v2));
    }

    function test_upgrade_throughTimelock_beforeDelay_reverts() public {
        AgenticIDV2 v2 = new AgenticIDV2();
        bytes memory callData = abi.encodeCall(UpgradeableBeacon.upgradeTo, (address(v2)));

        vm.prank(proposer);
        timelock.schedule(address(beacon), 0, callData, bytes32(0), bytes32(0), DELAY);

        // Not yet ready — execute should revert.
        vm.prank(executor);
        vm.expectRevert();
        timelock.execute(address(beacon), 0, callData, bytes32(0), bytes32(0));
    }

    function test_upgrade_throughTimelock_afterDelay_succeeds() public {
        AgenticIDV2 v2 = new AgenticIDV2();
        bytes memory callData = abi.encodeCall(UpgradeableBeacon.upgradeTo, (address(v2)));

        vm.prank(proposer);
        timelock.schedule(address(beacon), 0, callData, bytes32(0), bytes32(0), DELAY);

        vm.warp(block.timestamp + DELAY + 1);

        vm.prank(executor);
        timelock.execute(address(beacon), 0, callData, bytes32(0), bytes32(0));

        assertEq(beacon.implementation(), address(v2));
        // New view callable through existing proxy → proves storage preserved and code swapped.
        assertEq(AgenticIDV2(address(agenticId)).version2Tag(), "v2");
        // Pre-existing state preserved (VERSION from the base impl).
        assertEq(agenticId.VERSION(), "1.0.0");
    }

    // ── Pause ────────────────────────────────────────────────────────────────

    function test_pause_nonPauserRejected() public {
        vm.prank(owner);
        vm.expectRevert(AgenticIDNotPauser.selector);
        agenticId.pause();
    }

    function test_pause_blocksSelfMint() public {
        vm.prank(pauser);
        agenticId.pause();

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("x")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(address(0x1234));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.register("", metadata, datas, sealedKeys);
    }

    function test_pause_viewsStillWork() public {
        vm.prank(pauser);
        agenticId.pause();

        // View functions should not revert.
        assertEq(agenticId.VERSION(), "1.0.0");
        assertEq(agenticId.pauser(), pauser);
        assertEq(agenticId.owner(), owner);
    }

    function test_unpause_restoresWrites() public {
        vm.prank(pauser);
        agenticId.pause();

        vm.prank(pauser);
        agenticId.unpause();

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("x")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(address(0x1234));
        uint256 id = agenticId.register("", metadata, datas, sealedKeys);
        assertEq(agenticId.ownerOf(id), address(0x1234));
    }

    function test_setPauser_onlyOwner() public {
        address newPauser = address(0xDEAD);

        vm.prank(address(0x9999));
        vm.expectRevert();
        agenticId.setPauser(newPauser);

        vm.prank(owner);
        agenticId.setPauser(newPauser);
        assertEq(agenticId.pauser(), newPauser);

        // Old pauser can no longer pause.
        vm.prank(pauser);
        vm.expectRevert(AgenticIDNotPauser.selector);
        agenticId.pause();

        vm.prank(newPauser);
        agenticId.pause();
        assertTrue(agenticId.paused());
    }
}
