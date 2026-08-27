// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {
    VerifiedFeedbackRegistry,
    VerifiedFeedbackNoAgentSeal,
    VerifiedFeedbackInvalidProofSignature,
    VerifiedFeedbackProofAgentMismatch,
    VerifiedFeedbackProofSubmitterMismatch,
    VerifiedFeedbackSelfFeedback,
    VerifiedFeedbackNoSuchEntry,
    VerifiedFeedbackAlreadyVerified,
    VerifiedFeedbackNotVerified,
    VerifiedFeedbackClientsRequired
} from "../src/VerifiedFeedbackRegistry.sol";
import {IVerifiedFeedbackRegistry} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {NonceExpired, NonceAlreadyUsed, NonceDeadlineTooFar} from "../src/utils/NonceRegistryUpgradeable.sol";

contract VerifiedFeedbackTest is AgenticIDTestBase {
    VerifiedFeedbackRegistry internal registry;
    CanonicalReputationRegistryMock internal canonicalRep;

    Vm.Wallet internal sealWallet;   // holds agentSeal priv — signs ServeProofs
    address internal agentOwner = address(0xA1);
    address internal client = address(0xC1);
    address internal client2 = address(0xC2);

    bytes32 internal constant TASK_HASH = keccak256("task-1");
    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();

        sealWallet = vm.createWallet("agent-seal");
        canonicalRep = new CanonicalReputationRegistryMock();

        VerifiedFeedbackRegistry impl = new VerifiedFeedbackRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        );
        registry = VerifiedFeedbackRegistry(address(proxy));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev Like base's `_mintWithSeal` but the seal address comes from a real
    ///      wallet we control, so we can sign ServeProofs that recover to it.
    function _mintWithSealWallet(address to) internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256(abi.encode("vf-data", to));
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "", metadata, datas, sealedKeys, sealWallet.addr, SEAL_ID
        );
    }

    /// @dev Build + sign a ServeProof with the controlled sealWallet — same
    ///      digest as the fork registry (chainId ‖ identityRegistry ‖ submitter ‖ …).
    function _mkServeProof(
        uint256 agentId,
        address submitter,
        bytes32 taskHash,
        bytes32[] memory dataHashes,
        bytes32 frameworkHash,
        uint256 deadline,
        uint256 signerPk
    ) internal view returns (ServeProof memory) {
        bytes32 inner = keccak256(
            abi.encode(
                block.chainid,
                address(agenticId),
                submitter,
                agentId,
                block.timestamp,
                deadline,
                taskHash,
                keccak256(abi.encodePacked(dataHashes)),
                frameworkHash
            )
        );
        return ServeProof({
            agentId: agentId,
            submitter: submitter,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: frameworkHash,
            signature: _sign(signerPk, _eip191RawHash(inner))
        });
    }

    function _proofFor(uint256 agentId, address submitter, bytes32 dataHash, bytes32 taskHash)
        internal view returns (ServeProof memory)
    {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        return _mkServeProof(
            agentId, submitter, taskHash, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
    }

    /// @dev Client leaves a canonical feedback entry (attribution = msg.sender
    ///      on the canonical registry, exactly like the live 0x8004B… contract).
    function _canonicalFeedback(uint256 agentId, address client_, int128 value, uint8 dec) internal returns (uint64) {
        vm.prank(client_);
        canonicalRep.giveFeedback(
            agentId, value, dec, "quality", "latency",
            "https://api.example.com", "ipfs://feedback-uri", keccak256("feedback-hash")
        );
        return canonicalRep.getLastIndex(agentId, client_);
    }

    function _attest(uint256 agentId, address client_, uint64 index, ServeProof memory proof) internal {
        vm.prank(client_);
        registry.attestFeedback(agentId, index, proof);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_attestFeedback_happyPath() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);

        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        bytes32[] memory wantHashes = new bytes32[](1);
        wantHashes[0] = dataHash;
        vm.expectEmit(true, true, true, true, address(registry));
        emit IVerifiedFeedbackRegistry.FeedbackVerified(agentId, client, idx, wantHashes, FRAMEWORK_HASH);

        _attest(agentId, client, idx, proof);

        assertTrue(registry.isVerified(agentId, client, idx), "entry verified");
        (bytes32[] memory storedHashes, bytes32 storedFw) = registry.getServeData(agentId, client, idx);
        assertEq(storedHashes.length, 1, "serve data dataHashes length");
        assertEq(storedHashes[0], dataHash, "serve data dataHash");
        assertEq(storedFw, FRAMEWORK_HASH, "serve data frameworkHash");

        uint64[] memory indexes = registry.getVerifiedIndexes(agentId, client);
        assertEq(indexes.length, 1, "one verified index");
        assertEq(indexes[0], idx, "verified index recorded");

        address[] memory clients = registry.getVerifiedClients(agentId);
        assertEq(clients.length, 1, "one verified client");
        assertEq(clients[0], client, "client recorded");
    }

    function test_attestFeedback_twoEntriesTwoProofs() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 i1 = _canonicalFeedback(agentId, client, 90, 0);
        uint64 i2 = _canonicalFeedback(agentId, client, 70, 0);

        _attest(agentId, client, i1, _proofFor(agentId, client, dataHash, keccak256("task-a")));
        _attest(agentId, client, i2, _proofFor(agentId, client, dataHash, keccak256("task-b")));

        assertTrue(registry.isVerified(agentId, client, i1), "first verified");
        assertTrue(registry.isVerified(agentId, client, i2), "second verified");
        assertEq(registry.getVerifiedIndexes(agentId, client).length, 2, "two indexes");
        assertEq(registry.getVerifiedClients(agentId).length, 1, "client listed once");
    }

    // ── Proof rejection paths ─────────────────────────────────────────────────

    function test_attestFeedback_revertsOnAgentIdMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        uint256 otherId = agentId + 1;
        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackProofAgentMismatch.selector, otherId, agentId)
        );
        registry.attestFeedback(otherId, 1, proof);
    }

    function test_attestFeedback_revertsOnSubmitterMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        // Proof issued to `client`; attacker copies it and redeems from client2.
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client2);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackProofSubmitterMismatch.selector, client, client2)
        );
        registry.attestFeedback(agentId, 1, proof);

        // The declared client can still redeem it — nonce was never consumed.
        _attest(agentId, client, 1, proof);
        assertTrue(registry.isVerified(agentId, client, 1), "honest client's proof survived");
    }

    function test_attestFeedback_revertsOnInvalidSignature() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);

        (, uint256 fakePk) = makeAddrAndKey("not-the-seal");
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, fakePk
        );

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_attestFeedback_revertsWhenAgentHasNoSeal() public {
        (uint256 agentId, bytes32 dataHash) = _selfMint(agentOwner); // no seal
        _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackNoAgentSeal.selector);
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_attestFeedback_revertsOnExpiredDeadline() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        // Absolute, NOT derived from block.timestamp: via_ir rematerializes
        // timestamp-derived locals across vm.warp (see QUIRKS.md).
        uint256 deadline = 3601;
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH, deadline, sealWallet.privateKey
        );

        vm.warp(deadline + 1);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(NonceExpired.selector, deadline, block.timestamp));
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_attestFeedback_revertsOnDeadlineBeyondMaxAge() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        uint256 tooFar = block.timestamp + MAX_PROOF_AGE + 1;
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH, tooFar, sealWallet.privateKey
        );

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(NonceDeadlineTooFar.selector, tooFar, block.timestamp + MAX_PROOF_AGE)
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    /// @dev One proof marks at most one entry — replaying it on a second
    ///      canonical entry fails on the signature-derived nonce.
    function test_attestFeedback_revertsOnProofReplay() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 i1 = _canonicalFeedback(agentId, client, 90, 0);
        uint64 i2 = _canonicalFeedback(agentId, client, 70, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        _attest(agentId, client, i1, proof);

        vm.prank(client);
        vm.expectPartialRevert(NonceAlreadyUsed.selector);
        registry.attestFeedback(agentId, i2, proof);
    }

    // ── Canonical-entry binding ───────────────────────────────────────────────

    function test_attestFeedback_revertsWhenNoCanonicalEntry() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        // client has left NO canonical feedback.
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackNoSuchEntry.selector, agentId, client, uint64(1), uint64(0))
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_attestFeedback_revertsOnIndexZero() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackNoSuchEntry.selector, agentId, client, uint64(0), uint64(1))
        );
        registry.attestFeedback(agentId, 0, proof);
    }

    /// @dev Canonical attribution is per-client: another client's entry index
    ///      is out of range for the caller, even if it exists for them.
    function test_attestFeedback_cannotAttestAnotherClientsEntry() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client2, 90, 0); // entry belongs to client2
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackNoSuchEntry.selector, agentId, client, uint64(1), uint64(0))
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    /// @dev Two DIFFERENT proofs must not stack marks on one entry.
    function test_attestFeedback_revertsOnAlreadyVerified() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);

        _attest(agentId, client, idx, _proofFor(agentId, client, dataHash, keccak256("task-a")));

        ServeProof memory second = _proofFor(agentId, client, dataHash, keccak256("task-b"));
        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackAlreadyVerified.selector, agentId, client, idx)
        );
        registry.attestFeedback(agentId, idx, second);
    }

    // ── Self-feedback conformance ─────────────────────────────────────────────

    function test_attestFeedback_revertsWhenOwnerSelfAttests() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, agentOwner, 100, 0);
        ServeProof memory proof = _proofFor(agentId, agentOwner, dataHash, TASK_HASH);

        vm.prank(agentOwner);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackSelfFeedback.selector, agentId, agentOwner)
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_attestFeedback_revertsWhenApprovedOperatorAttests() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        address operator = makeAddr("operator");
        vm.prank(agentOwner);
        agenticId.setApprovalForAll(operator, true);

        _canonicalFeedback(agentId, operator, 100, 0);
        ServeProof memory proof = _proofFor(agentId, operator, dataHash, TASK_HASH);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackSelfFeedback.selector, agentId, operator)
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    // ── Reads ─────────────────────────────────────────────────────────────────

    function test_getServeData_revertsWhenNotVerified() public {
        (uint256 agentId, ) = _mintWithSealWallet(agentOwner);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackNotVerified.selector, agentId, client, uint64(1))
        );
        registry.getServeData(agentId, client, 1);
    }

    function test_getVerifiedSummary_aggregatesOnlyVerified() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 i1 = _canonicalFeedback(agentId, client, 90, 0);
        _canonicalFeedback(agentId, client, 10, 0); // unverified — must not count

        _attest(agentId, client, i1, _proofFor(agentId, client, dataHash, TASK_HASH));

        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count, int128 summaryValue, uint8 dec) =
            registry.getVerifiedSummary(agentId, cs, "quality", "latency");
        assertEq(count, 1, "only the verified entry counted");
        assertEq(summaryValue, int128(90) * int128(1e18), "normalized to 18 decimals");
        assertEq(dec, 18, "summary decimals 18");
    }

    function test_getVerifiedSummary_skipsCanonicallyRevoked() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        _attest(agentId, client, idx, _proofFor(agentId, client, dataHash, TASK_HASH));

        // Revocation lives on the canonical registry; the mark stays but the
        // summary must follow the canonical revoked flag.
        vm.prank(client);
        canonicalRep.revokeFeedback(agentId, idx);

        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count, int128 summaryValue, ) =
            registry.getVerifiedSummary(agentId, cs, "", "");
        assertEq(count, 0, "revoked entry skipped");
        assertEq(summaryValue, 0, "no value aggregated");
        assertTrue(registry.isVerified(agentId, client, idx), "verification mark itself remains");
    }

    function test_getVerifiedSummary_revertsOnEmptyClients() public {
        (uint256 agentId, ) = _mintWithSealWallet(agentOwner);
        address[] memory empty = new address[](0);
        vm.expectRevert(VerifiedFeedbackClientsRequired.selector);
        registry.getVerifiedSummary(agentId, empty, "", "");
    }

    // ── Pause / initializer guards ────────────────────────────────────────────

    function test_attestFeedback_revertsWhenPaused() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(pauser);
        registry.pause();

        vm.prank(client);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        registry.attestFeedback(agentId, 1, proof);
    }

    function test_implementation_initializeDisabled() public {
        VerifiedFeedbackRegistry impl = new VerifiedFeedbackRegistry();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE);
    }
}
