// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {VerifiedFeedbackRegistryV1_2_0} from "./mocks/VerifiedFeedbackRegistryV1_2_0.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {TaskReveal, VersionedServeProof} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

/// @notice VerifiedFeedbackRegistry 1.2.0 → 1.3.0, the upgrade test and
///         mainnet take (dev took it on 2026-11-12), across a real BeaconProxy
///         + UpgradeableBeacon + Timelock upgrade. The pre-upgrade impl is the
///         frozen 1.2.0 source (test/mocks/VerifiedFeedbackRegistryV1_2_0.sol).
///         Locks that 1.3.0 moves no storage: every word of the namespace's
///         fixed fields and of each mark's record reads the same after the
///         beacon flips, and the two fields 1.3.0 appends to ServeData read
///         zero for old marks. No hard cut: a v1 proof signed under 1.2.0
///         still verifies after the upgrade, and v2 proofs verify from then on.
contract UpgradeVerifiedFeedbackFrom1_2_0Test is AgenticIDTestBase {
    TimelockController internal timelock;
    UpgradeableBeacon internal vfBeacon;
    VerifiedFeedbackRegistry internal registry; // the proxy, typed as the new impl
    CanonicalReputationRegistryMock internal canonicalRep;

    Vm.Wallet internal sealWallet;
    address internal agentOwner = address(0xA1);
    address internal client = address(0xC1);

    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);
    uint256 internal constant DELAY = 0;

    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");

    /// @dev VerifiedFeedbackStorage's ERC-7201 slot (StorageLayout.t.sol pins
    ///      the derivation): identityRegistry at +0, canonicalReputation +1,
    ///      the `verified` mapping +2, pauser +6.
    bytes32 internal constant VF_SLOT = 0xa91e4c2ef61514299267811101bdc16c30719384e3b85c6fa8328f091e37e100;
    bytes32 internal constant OWNABLE_SLOT = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
    bytes32 internal constant OWNABLE2STEP_SLOT =
        0x237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00;

    function setUp() public override {
        // OZ TimelockController treats timestamp 1 as "done": start later.
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

        vfBeacon = new UpgradeableBeacon(address(new VerifiedFeedbackRegistryV1_2_0()), address(timelock));
        registry = VerifiedFeedbackRegistry(address(new BeaconProxy(
            address(vfBeacon),
            abi.encodeCall(
                VerifiedFeedbackRegistryV1_2_0.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        )));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _mintSealAgent() internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256("vf-1.2.0-data");
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(agentOwner, "", metadata, datas, sealedKeys, sealWallet.addr, SEAL_ID);
    }

    function _canonicalFeedback(uint256 agentId) internal returns (uint64) {
        vm.prank(client);
        canonicalRep.giveFeedback(agentId, 90, 0, "quality", "", "ep", "", bytes32(0));
        return canonicalRep.getLastIndex(agentId, client);
    }

    /// @dev A v1 proof as 1.2.0 verifies it: EIP-191 v0, validator = the proxy.
    function _proof(uint256 agentId, bytes32 dataHash, bytes32 taskHash)
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
            block.chainid, address(agenticId), client, agentId, p.timestamp, p.deadline, taskHash,
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH
        ));
        p.signature = _sign(sealWallet.privateKey, _eip191ValidatorHash(address(registry), inner));
    }

    function _proofV2(uint256 agentId, bytes32 dataHash, bytes32 taskHash)
        internal view returns (VersionedServeProof memory p)
    {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        p = VersionedServeProof({
            version: 2,
            agentId: agentId,
            submitter: client,
            timestamp: block.timestamp,
            deadline: block.timestamp + 1 hours,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: FRAMEWORK_HASH,
            sealedHash: keccak256("sealed-v1"),
            harnessHash: keccak256("harness-v1"),
            inferenceURL: "https://router.example/v1",
            model: "model-x",
            signature: ""
        });
        bytes32 inner = keccak256(abi.encode(
            keccak256("AgentDNA.ServeProof.v2"),
            block.chainid, address(agenticId), client, agentId, p.timestamp, p.deadline, taskHash,
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH,
            p.sealedHash, p.harnessHash, keccak256(bytes(p.inferenceURL)), keccak256(bytes(p.model))
        ));
        p.signature = _sign(sealWallet.privateKey, _eip191ValidatorHash(address(registry), inner));
    }

    function _task(string memory uri) internal pure returns (TaskReveal memory t, bytes32 taskHash) {
        t = TaskReveal({
            method: "GET", uri: uri, reqBodyHash: keccak256(""), respBodyHash: keccak256("resp"), statusCode: 200
        });
        taskHash = keccak256(abi.encodePacked(bytes(t.method), bytes(t.uri), t.reqBodyHash, t.respBodyHash, bytes("200")));
    }

    /// @dev Under 1.2.0: a plain mark (index 1) and a receipt-opened mark
    ///      (index 2, endpoint "/hello").
    function _seedUnder1_2_0() internal returns (uint256 agentId, bytes32 dataHash, bytes memory sig1) {
        (agentId, dataHash) = _mintSealAgent();
        uint64 i1 = _canonicalFeedback(agentId);
        uint64 i2 = _canonicalFeedback(agentId);
        ServeProof memory p1 = _proof(agentId, dataHash, keccak256("task-1"));
        vm.prank(client);
        registry.attestFeedback(agentId, i1, p1);
        sig1 = p1.signature;
        (TaskReveal memory t, bytes32 th) = _task("/hello");
        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, i2, _proof(agentId, dataHash, th), t);
    }

    /// @dev The record of mark (agentId, client, idx): ServeData's words are
    ///      exists +0, frameworkHash +1, dataHashes' length +2, uri +3, and
    ///      1.3.0's sealedHash +4 / harnessHash +5.
    function _markSlot(uint256 agentId, uint64 idx) internal view returns (uint256) {
        bytes32 byAgent = keccak256(abi.encode(agentId, uint256(VF_SLOT) + 2));
        bytes32 byClient = keccak256(abi.encode(client, byAgent));
        return uint256(keccak256(abi.encode(idx, byClient)));
    }

    /// @dev The words 1.2.0 writes: the namespace's fixed fields, the owner
    ///      slots and both marks' first four words.
    function _words(uint256 agentId) internal view returns (bytes32[13] memory w) {
        w[0] = vm.load(address(registry), VF_SLOT);
        w[1] = vm.load(address(registry), bytes32(uint256(VF_SLOT) + 1));
        w[2] = vm.load(address(registry), bytes32(uint256(VF_SLOT) + 6));
        w[3] = vm.load(address(registry), OWNABLE_SLOT);
        w[4] = vm.load(address(registry), OWNABLE2STEP_SLOT);
        for (uint64 idx = 1; idx <= 2; ++idx) {
            uint256 rec = _markSlot(agentId, idx);
            for (uint256 k; k < 4; ++k) w[5 + (idx - 1) * 4 + k] = vm.load(address(registry), bytes32(rec + k));
        }
    }

    function _upgradeBeacon(address newImpl) internal {
        bytes memory cd = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        vm.prank(proposer);
        timelock.schedule(address(vfBeacon), 0, cd, bytes32(0), bytes32(0), DELAY);
        vm.prank(executor);
        timelock.execute(address(vfBeacon), 0, cd, bytes32(0), bytes32(0));
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    function test_startsOnTheFrozen1_2_0() public view {
        assertEq(vfBeacon.owner(), address(timelock));
        assertEq(registry.VERSION(), "1.2.0", "starts on the frozen 1.2.0 impl");
    }

    function test_upgrade_preservesEveryStoredWord() public {
        (uint256 agentId, bytes32 dataHash, bytes memory sig1) = _seedUnder1_2_0();
        uint256 rec1 = _markSlot(agentId, 1);
        assertEq(vm.load(address(registry), bytes32(rec1)), bytes32(uint256(1)), "slot derivation: exists");
        assertEq(vm.load(address(registry), bytes32(rec1 + 1)), FRAMEWORK_HASH, "slot derivation: frameworkHash");
        bytes32[13] memory before = _words(agentId);

        VerifiedFeedbackRegistry newImpl = new VerifiedFeedbackRegistry();
        _upgradeBeacon(address(newImpl));
        assertEq(vfBeacon.implementation(), address(newImpl), "beacon points at the new impl");
        assertEq(registry.VERSION(), "1.3.0", "post-upgrade VERSION");

        bytes32[13] memory afterwards = _words(agentId);
        for (uint256 i; i < before.length; ++i) assertEq(afterwards[i], before[i], "a stored word moved");
        for (uint64 idx = 1; idx <= 2; ++idx) {
            uint256 rec = _markSlot(agentId, idx);
            assertEq(vm.load(address(registry), bytes32(rec + 4)), bytes32(0), "appended sealedHash reads zero");
            assertEq(vm.load(address(registry), bytes32(rec + 5)), bytes32(0), "appended harnessHash reads zero");
        }

        (bytes32[] memory hashes, bytes32 fw) = registry.getServeData(agentId, client, 1);
        assertEq(hashes.length, 1, "serve data length");
        assertEq(hashes[0], dataHash, "serve data dataHash");
        assertEq(fw, FRAMEWORK_HASH, "serve data frameworkHash");
        assertEq(registry.getVerifiedEndpoint(agentId, client, 2), "/hello", "endpoint survived");
        (bytes32 sealedHash, bytes32 harnessHash) = registry.getServeLayers(agentId, client, 2);
        assertEq(sealedHash, bytes32(0), "an old mark has no sealed hash");
        assertEq(harnessHash, bytes32(0), "an old mark has no harness hash");
        assertEq(registry.getVerifiedIndexes(agentId, client).length, 2, "indexes survived");
        assertEq(registry.getVerifiedClients(agentId).length, 1, "clients survived");
        assertEq(registry.getIdentityRegistry(), address(agenticId), "identity registry");
        assertEq(registry.getCanonicalReputation(), address(canonicalRep), "canonical reputation");
        assertEq(registry.owner(), owner, "owner");
        assertEq(registry.pendingOwner(), address(0), "no pending owner");
        assertEq(registry.pauser(), pauser, "pauser");
        assertEq(registry.nonceMaxAge(), MAX_PROOF_AGE, "maxProofAge");
        assertTrue(
            registry.isNonceConsumed(keccak256(abi.encode(keccak256("SERVEPROOF"), agentId, sig1))),
            "nonce store survived"
        );
    }

    /// @dev 1.3.0 leaves v1 as it was: a proof an image signed before the
    ///      upgrade is redeemed after it, and the versioned entry point
    ///      takes v2 proofs from then on.
    function test_upgrade_keepsV1AndAddsV2() public {
        (uint256 agentId, bytes32 dataHash,) = _seedUnder1_2_0();
        uint64 i3 = _canonicalFeedback(agentId);
        uint64 i4 = _canonicalFeedback(agentId);
        ServeProof memory inFlight = _proof(agentId, dataHash, keccak256("task-3"));

        _upgradeBeacon(address(new VerifiedFeedbackRegistry()));

        vm.prank(client);
        registry.attestFeedback(agentId, i3, inFlight);
        assertTrue(registry.isVerified(agentId, client, i3), "a v1 proof from before the upgrade verifies");

        TaskReveal memory none;
        VersionedServeProof memory v2 = _proofV2(agentId, dataHash, keccak256("task-4"));
        vm.prank(client);
        registry.attestVersionedFeedback(agentId, i4, v2, none);
        (bytes32 sealedHash, bytes32 harnessHash) = registry.getServeLayers(agentId, client, i4);
        assertEq(sealedHash, v2.sealedHash, "v2 mark records its sealed hash");
        assertEq(harnessHash, v2.harnessHash, "v2 mark records its harness hash");
    }
}
