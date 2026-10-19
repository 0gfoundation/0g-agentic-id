// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {VerifiedFeedbackRegistryV1_1_0} from "./mocks/VerifiedFeedbackRegistryV1_1_0.sol";
import {
    VerifiedFeedbackRegistry,
    VerifiedFeedbackInvalidProofSignature
} from "../src/VerifiedFeedbackRegistry.sol";
import {TaskReveal} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

/// @notice VerifiedFeedbackRegistry 1.1.0 → 1.2.0 across a real
///         BeaconProxy + UpgradeableBeacon + Timelock upgrade (the generic
///         ScheduleUpgrade/ExecuteUpgrade path). The pre-upgrade impl is the
///         frozen 1.1.0 source (test/mocks/VerifiedFeedbackRegistryV1_1_0.sol).
///         Locks storage survival (1.2.0 changes no storage) and the hard cut:
///         a proof under the legacy personal_sign wrap — what pre-1.2.0 sealed
///         images emit — stops verifying the moment the beacon flips, and a
///         registry-bound proof verifies. Also locks the two-step-ownership
///         swap (Ownable → Ownable2Step, FIND-16): owner preserved, the new
///         pendingOwner slot starts empty.
contract UpgradeVerifiedFeedbackTest is AgenticIDTestBase {
    TimelockController internal timelock;
    UpgradeableBeacon  internal vfBeacon;
    VerifiedFeedbackRegistry internal registry; // the proxy, typed as the new impl
    CanonicalReputationRegistryMock internal canonicalRep;

    Vm.Wallet internal sealWallet;
    address internal agentOwner = address(0xA1);
    address internal client = address(0xC1);

    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);
    /// @dev minDelay = 0, as on testnet / dev (mainnet is 1 day; the 1.2.0
    ///      rollout schedules ≥ 86400 s ahead, DEPLOYMENT.md §7 step 3): no
    ///      vm.warp, so an in-flight proof is still unexpired after the
    ///      upgrade and fails ONLY on its format.
    uint256 internal constant DELAY = 0;

    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");

    function setUp() public override {
        // A realistic clock, set once before anything reads it: forge starts
        // at block.timestamp == 1, and OZ TimelockController uses 1 as its
        // "Done" sentinel, so a zero-delay op scheduled then reads as executed.
        vm.warp(1_760_000_000);
        super.setUp();
        _whitelistAttestor();
        sealWallet = vm.createWallet("agent-seal");
        canonicalRep = new CanonicalReputationRegistryMock();

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new TimelockController(DELAY, proposers, executors, owner);

        VerifiedFeedbackRegistryV1_1_0 oldImpl = new VerifiedFeedbackRegistryV1_1_0();
        vfBeacon = new UpgradeableBeacon(address(oldImpl), address(timelock));
        BeaconProxy proxy = new BeaconProxy(
            address(vfBeacon),
            abi.encodeCall(
                VerifiedFeedbackRegistryV1_1_0.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        );
        registry = VerifiedFeedbackRegistry(address(proxy));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    function _mintSealAgent() internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256("vf-upgrade-data");
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

    function _canonicalFeedback(uint256 agentId) internal returns (uint64) {
        vm.prank(client);
        canonicalRep.giveFeedback(agentId, 90, 0, "quality", "", "ep", "", bytes32(0));
        return canonicalRep.getLastIndex(agentId, client);
    }

    /// @dev Seal-signed proof for `client`: `registryBound` picks the 1.2.0
    ///      digest (EIP-191 v0, validator = the proxy) over the legacy
    ///      personal_sign wrap 1.1.0 verified.
    function _proof(uint256 agentId, bytes32 dataHash, bytes32 taskHash, bool registryBound)
        internal view returns (ServeProof memory p)
    {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        p = ServeProof({
            agentId: agentId,
            submitter: client,
            timestamp: block.timestamp,
            deadline: block.timestamp + 1 hours,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: FRAMEWORK_HASH,
            signature: ""
        });
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), client, agentId,
            p.timestamp, p.deadline, taskHash,
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH
        ));
        p.signature = _sign(
            sealWallet.privateKey,
            registryBound ? _eip191ValidatorHash(address(registry), inner) : _eip191RawHash(inner)
        );
    }

    function _task(string memory uri) internal pure returns (TaskReveal memory t, bytes32 taskHash) {
        t = TaskReveal({
            method: "GET", uri: uri,
            reqBodyHash: keccak256(""), respBodyHash: keccak256("resp"), statusCode: 200
        });
        taskHash = keccak256(abi.encodePacked(
            bytes(t.method), bytes(t.uri), t.reqBodyHash, t.respBodyHash, bytes("200")
        ));
    }

    /// @dev Under 1.1.0: a plain mark (index 1, legacy proof) and a
    ///      receipt-opened mark (index 2, legacy proof, endpoint "/hello").
    function _seedUnderOldImpl() internal returns (uint256 agentId, bytes32 dataHash, bytes memory sig1) {
        (agentId, dataHash) = _mintSealAgent();
        uint64 i1 = _canonicalFeedback(agentId);
        uint64 i2 = _canonicalFeedback(agentId);

        ServeProof memory p1 = _proof(agentId, dataHash, keccak256("task-1"), false);
        vm.prank(client);
        registry.attestFeedback(agentId, i1, p1);
        sig1 = p1.signature;

        (TaskReveal memory t, bytes32 th) = _task("/hello");
        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, i2, _proof(agentId, dataHash, th, false), t);
    }

    function _upgradeBeacon(address newImpl) internal {
        bytes memory cd = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        vm.prank(proposer);
        timelock.schedule(address(vfBeacon), 0, cd, bytes32(0), bytes32(0), DELAY);
        vm.prank(executor);
        timelock.execute(address(vfBeacon), 0, cd, bytes32(0), bytes32(0));
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    function test_beaconOwnedByTimelock() public view {
        assertEq(vfBeacon.owner(), address(timelock));
        assertEq(registry.VERSION(), "1.1.0", "starts on the frozen 1.1.0 impl");
    }

    function test_upgrade_preservesMarksAndConfig() public {
        (uint256 agentId, bytes32 dataHash, bytes memory sig1) = _seedUnderOldImpl();
        bytes32 nonceKey1 = keccak256(abi.encode(keccak256("SERVEPROOF"), agentId, sig1));
        assertTrue(registry.isNonceConsumed(nonceKey1), "pre-upgrade nonce consumed");

        VerifiedFeedbackRegistry newImpl = new VerifiedFeedbackRegistry();
        _upgradeBeacon(address(newImpl));
        assertEq(vfBeacon.implementation(), address(newImpl), "beacon points at 1.2.0");
        assertEq(registry.VERSION(), "1.2.0", "post-upgrade VERSION");

        // Marks + audit data + endpoints survived (no storage change in 1.2.0).
        assertTrue(registry.isVerified(agentId, client, 1), "plain mark survived");
        assertTrue(registry.isVerified(agentId, client, 2), "receipt mark survived");
        (bytes32[] memory hashes, bytes32 fw) = registry.getServeData(agentId, client, 1);
        assertEq(hashes.length, 1, "serve data length");
        assertEq(hashes[0], dataHash, "serve data dataHash");
        assertEq(fw, FRAMEWORK_HASH, "serve data frameworkHash");
        assertEq(registry.getVerifiedEndpoint(agentId, client, 1), "", "plain mark has no endpoint");
        assertEq(registry.getVerifiedEndpoint(agentId, client, 2), "/hello", "endpoint survived");
        assertEq(registry.getVerifiedIndexes(agentId, client).length, 2, "indexes survived");
        assertEq(registry.getVerifiedClients(agentId).length, 1, "clients survived");

        // Config + nonce store survived.
        assertEq(registry.getIdentityRegistry(), address(agenticId), "identity registry");
        assertEq(registry.getCanonicalReputation(), address(canonicalRep), "canonical reputation");
        assertEq(registry.owner(), owner, "owner");
        assertEq(registry.pauser(), pauser, "pauser");
        assertEq(registry.nonceMaxAge(), MAX_PROOF_AGE, "maxProofAge");
        assertTrue(registry.isNonceConsumed(nonceKey1), "nonce store survived");
    }

    /// @dev 1.2.0 swaps OwnableUpgradeable for Ownable2StepUpgradeable. The
    ///      owner (OZ's Ownable slot) survives untouched, the pending-owner
    ///      slot (OZ's Ownable2Step namespace) starts empty, and a transfer
    ///      needs the new owner's acceptOwnership.
    function test_upgrade_ownershipBecomesTwoStep() public {
        bytes32 ownableSlot = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
        bytes32 pendingSlot = 0x237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00;
        _seedUnderOldImpl();
        bytes32 ownerWord = vm.load(address(registry), ownableSlot);
        assertEq(vm.load(address(registry), pendingSlot), bytes32(0), "pending slot unused by 1.1.0");

        _upgradeBeacon(address(new VerifiedFeedbackRegistry()));
        assertEq(vm.load(address(registry), ownableSlot), ownerWord, "Ownable slot untouched");
        assertEq(registry.owner(), owner, "owner preserved");
        assertEq(registry.pendingOwner(), address(0), "no pending owner after upgrade");

        address newOwner = address(0x0E1);
        vm.prank(owner);
        registry.transferOwnership(newOwner);
        assertEq(registry.owner(), owner, "propose leaves owner unchanged");
        assertEq(registry.pendingOwner(), newOwner, "pending owner recorded");

        vm.prank(address(0xB0B));
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xB0B))
        );
        registry.acceptOwnership();

        vm.prank(newOwner);
        registry.acceptOwnership();
        assertEq(registry.owner(), newOwner, "owner moves on accept");
        assertEq(registry.pendingOwner(), address(0), "pending cleared");
    }

    /// @dev The hard cut: no dual-accept window. A legacy-format proof issued
    ///      before the upgrade (an old sealed image) is rejected afterwards; a
    ///      registry-bound proof for the same entry is accepted.
    function test_upgrade_hardCutsLegacyProofFormat() public {
        (uint256 agentId, bytes32 dataHash, ) = _seedUnderOldImpl();
        uint64 i3 = _canonicalFeedback(agentId);
        ServeProof memory inFlight = _proof(agentId, dataHash, keccak256("task-3"), false);

        _upgradeBeacon(address(new VerifiedFeedbackRegistry()));

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, i3, inFlight);

        vm.prank(client);
        registry.attestFeedback(agentId, i3, _proof(agentId, dataHash, keccak256("task-3"), true));
        assertTrue(registry.isVerified(agentId, client, i3), "registry-bound proof accepted post-upgrade");
    }
}
