// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {
    VerifiedFeedbackRegistry,
    VerifiedFeedbackInvalidProofSignature,
    VerifiedFeedbackProofAgentMismatch,
    VerifiedFeedbackProofSubmitterMismatch,
    VerifiedFeedbackSelfFeedback,
    VerifiedFeedbackAlreadyVerified,
    VerifiedFeedbackNotVerified,
    VerifiedFeedbackTaskMismatch,
    VerifiedFeedbackInvalidTaskReveal,
    VerifiedFeedbackUnsupportedVersion
} from "../src/VerifiedFeedbackRegistry.sol";
import {TaskReveal, VersionedServeProof} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {NonceAlreadyUsed} from "../src/utils/NonceRegistryUpgradeable.sol";

/// @notice Exposes the production v1 / v2 hashes and the wrap, so the
///         known-answer vector runs the registry's own code.
contract VersionedDigestHarness is VerifiedFeedbackRegistry {
    function exposedServeProofHashV2(uint256 chainId, address identityRegistry, VersionedServeProof calldata proof)
        external pure returns (bytes32)
    {
        return _serveProofHashV2(chainId, identityRegistry, proof);
    }

    function exposedServeProofHash(uint256 chainId, address identityRegistry, ServeProof calldata proof)
        external pure returns (bytes32)
    {
        return _serveProofHash(chainId, identityRegistry, proof);
    }

    function exposedServeProofDigest(address validator, bytes32 proofHash) external pure returns (bytes32) {
        return _serveProofDigest(validator, proofHash);
    }
}

/// @notice VerifiedFeedbackRegistry 1.3.0's versioned entry point
///         (attestVersionedFeedback, ServeProof v2). The v1 entry points keep
///         their own suite (VerifiedFeedback.t.sol), unchanged.
contract VersionedFeedbackTest is AgenticIDTestBase {
    VerifiedFeedbackRegistry internal registry;
    CanonicalReputationRegistryMock internal canonicalRep;
    Vm.Wallet internal sealWallet;

    address internal agentOwner = address(0xA1);
    address internal client = address(0xC1);

    bytes32 internal constant TASK_HASH = keccak256("task-1");
    bytes32 internal constant FRAMEWORK_HASH = keccak256("image-v1");
    bytes32 internal constant SEALED_HASH = keccak256("sealed-v1");
    bytes32 internal constant HARNESS_HASH = keccak256("harness-v1");
    string internal constant INFERENCE_URL = "https://router.example/v1";
    string internal constant MODEL = "model-x";

    event FeedbackVerified(
        uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex,
        bytes32[] dataHashes, bytes32 frameworkHash, bytes32 taskHash, string uri
    );
    event VersionedFeedbackVerified(
        uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex,
        uint16 version, bytes32 sealedHash, bytes32 harnessHash, string inferenceURL, string model
    );

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sealWallet = vm.createWallet("agent-seal");
        canonicalRep = new CanonicalReputationRegistryMock();
        registry = VerifiedFeedbackRegistry(address(new ERC1967Proxy(
            address(new VerifiedFeedbackRegistry()),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        )));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _mint() internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256("vf2-data");
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(agentOwner, "", metadata, datas, keys, sealWallet.addr, SEAL_ID);
    }

    function _feedback(uint256 agentId, address from) internal returns (uint64) {
        vm.prank(from);
        canonicalRep.giveFeedback(
            agentId, 90, 0, "quality", "latency", "https://api.example.com", "ipfs://fb", keccak256("fb")
        );
        return canonicalRep.getLastIndex(agentId, from);
    }

    /// @dev The v2 inner hash spelled out independently of the contract.
    function _innerV2(VersionedServeProof memory p) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("AgentDNA.ServeProof.v2"),
            block.chainid, address(agenticId), p.submitter, p.agentId, p.timestamp, p.deadline,
            p.taskHash, keccak256(abi.encodePacked(p.dataHashes)), p.frameworkHash,
            p.sealedHash, p.harnessHash, keccak256(bytes(p.inferenceURL)), keccak256(bytes(p.model))
        ));
    }

    function _unsigned(uint256 agentId, address submitter, bytes32 dataHash, bytes32 taskHash)
        internal view returns (VersionedServeProof memory p)
    {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        p = VersionedServeProof({
            version: 2,
            agentId: agentId,
            submitter: submitter,
            timestamp: block.timestamp,
            deadline: block.timestamp + 1 hours,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: FRAMEWORK_HASH,
            sealedHash: SEALED_HASH,
            harnessHash: HARNESS_HASH,
            inferenceURL: INFERENCE_URL,
            model: MODEL,
            signature: ""
        });
    }

    function _signed(uint256 agentId, address submitter, bytes32 dataHash, bytes32 taskHash)
        internal view returns (VersionedServeProof memory p)
    {
        p = _unsigned(agentId, submitter, dataHash, taskHash);
        p.signature = _sign(sealWallet.privateKey, _eip191ValidatorHash(address(registry), _innerV2(p)));
    }

    function _noTask() internal pure returns (TaskReveal memory task) {}

    function _attestAs(address from, uint256 agentId, uint64 idx, VersionedServeProof memory p) internal {
        vm.prank(from);
        registry.attestVersionedFeedback(agentId, idx, p, _noTask());
    }

    // ── Known-answer vector ───────────────────────────────────────────────────

    /// @dev The v2 vector sealed pins (sealed/internal/proxy/serveproof_v2_test.go,
    ///      LAYERS.md §7): v1's known-answer inputs plus the layer fields.
    function test_serveProofDigestV2_knownAnswerVector() public {
        VersionedDigestHarness h = new VersionedDigestHarness();
        bytes32[] memory dataHashes = new bytes32[](2);
        dataHashes[0] = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
        dataHashes[1] = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));
        VersionedServeProof memory p = VersionedServeProof({
            version: 2,
            agentId: 42,
            submitter: address(uint160(0xC1)),
            timestamp: 1700000000,
            deadline: 1700003600,
            taskHash: bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
            dataHashes: dataHashes,
            frameworkHash: bytes32(0x4444444444444444444444444444444444444444444444444444444444444444),
            sealedHash: bytes32(0x5555555555555555555555555555555555555555555555555555555555555555),
            harnessHash: bytes32(0x6666666666666666666666666666666666666666666666666666666666666666),
            inferenceURL: "https://router.example/v1",
            model: "model-x",
            signature: ""
        });

        bytes32 inner = h.exposedServeProofHashV2(16602, address(uint160(0xA9)), p);
        assertEq(inner, 0xdac99843c8993224fa49be6989ea6cb8fc3c5190e2d2e8be132e9d073ba73a73, "v2 proofHash drifted");
        assertEq(
            h.exposedServeProofDigest(address(uint160(0xB7)), inner),
            0x50f91a86a4e744dddd29bc16e936ab717a8c54074458e4332c5f43661538df4e,
            "v2 signed digest drifted"
        );

        // The same v1 fields hash to v1's vector, not v2's.
        ServeProof memory v1 = ServeProof({
            agentId: p.agentId, submitter: p.submitter, timestamp: p.timestamp, deadline: p.deadline,
            taskHash: p.taskHash, dataHashes: dataHashes, frameworkHash: p.frameworkHash, signature: ""
        });
        assertEq(
            h.exposedServeProofHash(16602, address(uint160(0xA9)), v1),
            0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b,
            "v1 vector"
        );
    }

    /// @dev The same inputs with a non-ASCII model, pinned by every copy: the
    ///      model hashes as its UTF-8 bytes (e6a8a1 e59e8b 2d c3a9).
    function test_serveProofDigestV2_utf8ModelVector() public {
        VersionedDigestHarness h = new VersionedDigestHarness();
        VersionedServeProof memory p = _vectorProof(unicode"模型-é");
        bytes32 inner = h.exposedServeProofHashV2(16602, address(uint160(0xA9)), p);
        assertEq(inner, 0x00dc0a9ba85191968c4bdcb00d11b4003216306420d80a6e68432fe01f24a977, "UTF-8 v2 proofHash drifted");
        assertEq(
            h.exposedServeProofDigest(address(uint160(0xB7)), inner),
            0xcab300c137d0d07deb4e73c3e027db4ff63df5045e0a95767519cce28ffbd963,
            "UTF-8 v2 signed digest drifted"
        );
    }

    /// @dev The known-answer inputs, with `model`.
    function _vectorProof(string memory model) internal pure returns (VersionedServeProof memory p) {
        bytes32[] memory dataHashes = new bytes32[](2);
        dataHashes[0] = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
        dataHashes[1] = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));
        p.version = 2;
        p.agentId = 42;
        p.submitter = address(uint160(0xC1));
        p.timestamp = 1700000000;
        p.deadline = 1700003600;
        p.taskHash = bytes32(0x1111111111111111111111111111111111111111111111111111111111111111);
        p.dataHashes = dataHashes;
        p.frameworkHash = bytes32(0x4444444444444444444444444444444444444444444444444444444444444444);
        p.sealedHash = bytes32(0x5555555555555555555555555555555555555555555555555555555555555555);
        p.harnessHash = bytes32(0x6666666666666666666666666666666666666666666666666666666666666666);
        p.inferenceURL = "https://router.example/v1";
        p.model = model;
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_attestVersioned_recordsTheLayersAndEmitsBothEvents() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);

        vm.expectEmit(true, true, true, true, address(registry));
        emit FeedbackVerified(agentId, client, idx, p.dataHashes, FRAMEWORK_HASH, TASK_HASH, "");
        vm.expectEmit(true, true, true, true, address(registry));
        emit VersionedFeedbackVerified(agentId, client, idx, 2, SEALED_HASH, HARNESS_HASH, INFERENCE_URL, MODEL);
        _attestAs(client, agentId, idx, p);

        assertTrue(registry.isVerified(agentId, client, idx));
        (bytes32[] memory hashes, bytes32 fw) = registry.getServeData(agentId, client, idx);
        assertEq(hashes.length, 1);
        assertEq(hashes[0], dataHash);
        assertEq(fw, FRAMEWORK_HASH);
        (bytes32 sealedHash, bytes32 harnessHash) = registry.getServeLayers(agentId, client, idx);
        assertEq(sealedHash, SEALED_HASH);
        assertEq(harnessHash, HARNESS_HASH);
        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "", "no reveal, no endpoint");
        assertEq(registry.getVerifiedIndexes(agentId, client).length, 1);
    }

    function test_attestVersioned_withTaskRecordsTheEndpoint() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        TaskReveal memory task = TaskReveal({
            method: "POST", uri: "/v1/chat", reqBodyHash: keccak256("req"), respBodyHash: keccak256("resp"),
            statusCode: 200
        });
        bytes32 taskHash = keccak256(abi.encodePacked(
            bytes(task.method), bytes(task.uri), task.reqBodyHash, task.respBodyHash, bytes("200")
        ));
        VersionedServeProof memory p = _signed(agentId, client, dataHash, taskHash);

        vm.prank(client);
        registry.attestVersionedFeedback(agentId, idx, p, task);
        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "/v1/chat");

        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count,,) = registry.getVerifiedSummaryForEndpoint(agentId, cs, "/v1/chat");
        assertEq(count, 1, "counts toward the endpoint summary like a v1 mark");
    }

    function test_attestVersioned_badRevealReverts() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);
        TaskReveal memory task = TaskReveal({
            method: "GET", uri: "/x", reqBodyHash: bytes32(0), respBodyHash: bytes32(0), statusCode: 200
        });
        vm.prank(client);
        vm.expectPartialRevert(VerifiedFeedbackTaskMismatch.selector);
        registry.attestVersionedFeedback(agentId, idx, p, task);

        task.method = "FETCH";
        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidTaskReveal.selector);
        registry.attestVersionedFeedback(agentId, idx, p, task);
    }

    // ── Versions ──────────────────────────────────────────────────────────────

    function test_attestVersioned_acceptsOnlyVersion2() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        uint16[3] memory others = [uint16(0), 1, 3];
        for (uint256 i; i < others.length; ++i) {
            VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);
            p.version = others[i];
            vm.prank(client);
            vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackUnsupportedVersion.selector, others[i]));
            registry.attestVersionedFeedback(agentId, idx, p, _noTask());
        }
    }

    /// @dev A v1 signature over the same fields does not pass as v2.
    function test_attestVersioned_rejectsAV1Signature() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        VersionedServeProof memory p = _unsigned(agentId, client, dataHash, TASK_HASH);
        bytes32 v1Inner = keccak256(abi.encode(
            block.chainid, address(agenticId), p.submitter, p.agentId, p.timestamp, p.deadline,
            p.taskHash, keccak256(abi.encodePacked(p.dataHashes)), p.frameworkHash
        ));
        p.signature = _sign(sealWallet.privateKey, _eip191ValidatorHash(address(registry), v1Inner));
        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestVersionedFeedback(agentId, idx, p, _noTask());
    }

    /// @dev …and a v2 signature does not pass the v1 entry point.
    function test_v1EntryRejectsAV2Signature() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);
        ServeProof memory v1 = ServeProof({
            agentId: p.agentId, submitter: p.submitter, timestamp: p.timestamp, deadline: p.deadline,
            taskHash: p.taskHash, dataHashes: p.dataHashes, frameworkHash: p.frameworkHash, signature: p.signature
        });
        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, idx, v1);
    }

    function test_attestVersioned_everyLayerFieldIsSigned() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        for (uint256 field; field < 4; ++field) {
            VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);
            if (field == 0) p.sealedHash = keccak256("other sealed");
            if (field == 1) p.harnessHash = keccak256("other harness");
            if (field == 2) p.inferenceURL = "https://elsewhere.example/v1";
            if (field == 3) p.model = "model-y";
            vm.prank(client);
            vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
            registry.attestVersionedFeedback(agentId, idx, p, _noTask());
        }
    }

    // ── The v1 checks apply unchanged ─────────────────────────────────────────

    function test_attestVersioned_keepsTheV1Checks() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 i1 = _feedback(agentId, client);
        uint64 i2 = _feedback(agentId, client);
        VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackProofAgentMismatch.selector, agentId + 1, agentId));
        registry.attestVersionedFeedback(agentId + 1, i1, p, _noTask());

        address other = address(0xC2);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackProofSubmitterMismatch.selector, client, other));
        registry.attestVersionedFeedback(agentId, i1, p, _noTask());

        _attestAs(client, agentId, i1, p);
        vm.prank(client);
        vm.expectPartialRevert(NonceAlreadyUsed.selector);
        registry.attestVersionedFeedback(agentId, i2, p, _noTask());

        VersionedServeProof memory fresh = _signed(agentId, client, dataHash, keccak256("task-2"));
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackAlreadyVerified.selector, agentId, client, i1));
        registry.attestVersionedFeedback(agentId, i1, fresh, _noTask());
    }

    function test_attestVersioned_refusesSelfFeedback() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, agentOwner);
        VersionedServeProof memory p = _signed(agentId, agentOwner, dataHash, TASK_HASH);
        vm.prank(agentOwner);
        vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackSelfFeedback.selector, agentId, agentOwner));
        registry.attestVersionedFeedback(agentId, idx, p, _noTask());
    }

    function test_attestVersioned_revertsWhenPaused() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        VersionedServeProof memory p = _signed(agentId, client, dataHash, TASK_HASH);
        vm.prank(pauser);
        registry.pause();
        vm.prank(client);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        registry.attestVersionedFeedback(agentId, idx, p, _noTask());
    }

    // ── getServeLayers ────────────────────────────────────────────────────────

    function test_getServeLayers_zeroForAV1MarkAndRevertsWhenUnverified() public {
        (uint256 agentId, bytes32 dataHash) = _mint();
        uint64 idx = _feedback(agentId, client);
        vm.expectRevert(abi.encodeWithSelector(VerifiedFeedbackNotVerified.selector, agentId, client, idx));
        registry.getServeLayers(agentId, client, idx);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        ServeProof memory v1 = ServeProof({
            agentId: agentId, submitter: client, timestamp: block.timestamp, deadline: block.timestamp + 1 hours,
            taskHash: TASK_HASH, dataHashes: dataHashes, frameworkHash: FRAMEWORK_HASH, signature: ""
        });
        bytes32 v1Inner = keccak256(abi.encode(
            block.chainid, address(agenticId), v1.submitter, v1.agentId, v1.timestamp, v1.deadline,
            v1.taskHash, keccak256(abi.encodePacked(v1.dataHashes)), v1.frameworkHash
        ));
        v1.signature = _sign(sealWallet.privateKey, _eip191ValidatorHash(address(registry), v1Inner));
        vm.prank(client);
        registry.attestFeedback(agentId, idx, v1);

        (bytes32 sealedHash, bytes32 harnessHash) = registry.getServeLayers(agentId, client, idx);
        assertEq(sealedHash, bytes32(0));
        assertEq(harnessHash, bytes32(0));
    }
}
