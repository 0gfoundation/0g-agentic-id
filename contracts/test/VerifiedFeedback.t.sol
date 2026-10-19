// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

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
    VerifiedFeedbackClientsRequired,
    VerifiedFeedbackTaskMismatch,
    VerifiedFeedbackInvalidTaskReveal
} from "../src/VerifiedFeedbackRegistry.sol";
import {IVerifiedFeedbackRegistry, TaskReveal} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {AgenticIDReputationRegistry, ReputationInvalidProofSignature} from "../src/AgenticIDReputationRegistry.sol";
import {NonceExpired, NonceAlreadyUsed, NonceDeadlineTooFar} from "../src/utils/NonceRegistryUpgradeable.sol";

/// @notice Exposes the production ServeProof hash + wrap, so the known-answer
///         vector runs the registry's own code path, not a re-implementation.
contract VerifiedFeedbackDigestHarness is VerifiedFeedbackRegistry {
    function exposedServeProofHash(uint256 chainId, address identityRegistry, ServeProof calldata proof)
        external pure returns (bytes32)
    {
        return _serveProofHash(chainId, identityRegistry, proof);
    }

    function exposedServeProofDigest(address validator, bytes32 proofHash) external pure returns (bytes32) {
        return _serveProofDigest(validator, proofHash);
    }
}

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
        registry = _deployRegistry();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev A VerifiedFeedbackRegistry proxy anchored to this suite's
    ///      (identity, canonical) pair — a second call yields a second
    ///      instance over the SAME pair (the FIND-16 setting).
    function _deployRegistry() internal returns (VerifiedFeedbackRegistry) {
        VerifiedFeedbackRegistry impl = new VerifiedFeedbackRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        );
        return VerifiedFeedbackRegistry(address(proxy));
    }

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

    /// @dev Build + sign a ServeProof with the controlled sealWallet: inner hash
    ///      (chainId ‖ identityRegistry ‖ submitter ‖ …) wrapped as EIP-191
    ///      version 0x00 with the registry proxy as the intended validator.
    function _mkServeProof(
        uint256 agentId,
        address submitter,
        bytes32 taskHash,
        bytes32[] memory dataHashes,
        bytes32 frameworkHash,
        uint256 deadline,
        uint256 signerPk
    ) internal view returns (ServeProof memory proof) {
        proof = ServeProof({
            agentId: agentId,
            submitter: submitter,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: frameworkHash,
            signature: ""
        });
        proof.signature = _sign(signerPk, _eip191ValidatorHash(address(registry), _innerOf(proof)));
    }

    /// @dev The proof's inner hash (pre-wrap): chainId ‖ identityRegistry ‖
    ///      submitter ‖ agentId ‖ timestamp ‖ deadline ‖ taskHash ‖
    ///      keccak(dataHashes) ‖ frameworkHash.
    function _innerOf(ServeProof memory p) internal view returns (bytes32) {
        return keccak256(abi.encode(
            block.chainid, address(agenticId), p.submitter, p.agentId,
            p.timestamp, p.deadline, p.taskHash,
            keccak256(abi.encodePacked(p.dataHashes)), p.frameworkHash
        ));
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
        emit IVerifiedFeedbackRegistry.FeedbackVerified(
            agentId, client, idx, wantHashes, FRAMEWORK_HASH, proof.taskHash, ""
        );

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

    /// @dev The agent's own agentSeal must not attest its own agent (1.2.0).
    ///      Conformance only — a fresh wallet the seal funds still passes (the
    ///      documented sybil class).
    function test_attestFeedback_revertsWhenAgentSealSelfAttests() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, sealWallet.addr, 100, 0);
        ServeProof memory proof = _proofFor(agentId, sealWallet.addr, dataHash, TASK_HASH);

        vm.prank(sealWallet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiedFeedbackSelfFeedback.selector, agentId, sealWallet.addr)
        );
        registry.attestFeedback(agentId, 1, proof);
    }

    // ── Registry-bound digest (1.2.0: FIND-01 / FIND-16) ──────────────────────

    /// @dev Cross-implementation known-answer vector for the ServeProof digest
    ///      — the anchor the sealed proxy and the SDK pin the same constants
    ///      against. Runs the PRODUCTION hash + wrap (via the harness); the
    ///      library call and the byte-wise test helper are cross-checked
    ///      against the same constant. The legacy personal_sign digest of the
    ///      same inner hash (pre-1.2.0, now rejected) is pinned as the shared
    ///      negative vector.
    function test_serveProofDigest_knownAnswerVector() public {
        VerifiedFeedbackDigestHarness h = new VerifiedFeedbackDigestHarness();
        bytes32[] memory dataHashes = new bytes32[](2);
        dataHashes[0] = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
        dataHashes[1] = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));
        ServeProof memory p = ServeProof({
            agentId: 42,
            submitter: address(uint160(0xC1)),
            timestamp: 1700000000,
            deadline: 1700003600,
            taskHash: bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
            dataHashes: dataHashes,
            frameworkHash: bytes32(0x4444444444444444444444444444444444444444444444444444444444444444),
            signature: ""
        });

        bytes32 inner = h.exposedServeProofHash(16602, address(uint160(0xA9)), p);
        assertEq(
            inner,
            0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b,
            "inner proofHash drifted from the cross-impl known-answer vector"
        );

        address validator = address(uint160(0xB7));
        bytes32 signed = h.exposedServeProofDigest(validator, inner);
        assertEq(
            signed,
            0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b,
            "signed (EIP-191 v0) digest drifted from the cross-impl known-answer vector"
        );
        assertEq(
            MessageHashUtils.toDataWithIntendedValidatorHash(validator, abi.encodePacked(inner)),
            signed, "MessageHashUtils v0 wrap disagrees"
        );
        assertEq(_eip191ValidatorHash(validator, inner), signed, "byte-wise v0 wrap disagrees");

        bytes32 legacy = MessageHashUtils.toEthSignedMessageHash(inner);
        assertEq(
            legacy,
            0x6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf,
            "legacy personal_sign vector drifted"
        );
        assertTrue(legacy != signed, "legacy and v0 digests must differ");
    }

    /// @dev FIND-01 regression. The sealed sign socket's /sign/personal_sign
    ///      signs ANY agent-chosen message; for a 32-byte proofHash that is
    ///      toEthSignedMessageHash(proofHash) — the pre-1.2.0 ServeProof format.
    ///      Signed by the REAL seal key it must not verify; the same fields
    ///      under the registry-bound digest must.
    function test_attestFeedback_rejectsLegacyPersonalSignProof() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);
        bytes memory registryBoundSig = proof.signature;

        proof.signature = _sign(sealWallet.privateKey, _eip191RawHash(_innerOf(proof)));
        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, idx, proof);

        proof.signature = registryBoundSig;
        _attest(agentId, client, idx, proof);
        assertTrue(registry.isVerified(agentId, client, idx), "registry-bound proof accepted");
    }

    /// @dev The socket's /sign/typed_data signs 0x19 0x01 ‖ domainSeparator ‖
    ///      structHash. An EIP-712-wrapped signature over the proofHash — even
    ///      under a domain naming this registry — must not verify.
    function test_attestFeedback_rejectsEip712WrappedProof() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("VerifiedFeedbackRegistry"), keccak256("1"), block.chainid, address(registry)
        ));
        proof.signature = _sign(
            sealWallet.privateKey, MessageHashUtils.toTypedDataHash(domainSeparator, _innerOf(proof))
        );

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, idx, proof);
    }

    /// @dev FIND-16: a proof binds to ONE registry. A second instance over the
    ///      same (identity, canonical) pair rejects a proof bound to the first
    ///      and vice versa; each redeems only at its own validator.
    function test_attestFeedback_rejectsProofBoundToOtherValidator() public {
        VerifiedFeedbackRegistry other = _deployRegistry();
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);

        ServeProof memory forRegistry = _proofFor(agentId, client, dataHash, TASK_HASH);
        ServeProof memory forOther = _proofFor(agentId, client, dataHash, keccak256("task-2"));
        forOther.signature = _sign(
            sealWallet.privateKey, _eip191ValidatorHash(address(other), _innerOf(forOther))
        );

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        other.attestFeedback(agentId, idx, forRegistry);

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidProofSignature.selector);
        registry.attestFeedback(agentId, idx, forOther);

        _attest(agentId, client, idx, forRegistry);
        vm.prank(client);
        other.attestFeedback(agentId, idx, forOther);
        assertTrue(registry.isVerified(agentId, client, idx), "bound proof redeemed at its registry");
        assertTrue(other.isVerified(agentId, client, idx), "other's proof redeemed at other");
    }

    /// @dev FIND-16, fork direction: a registry-bound proof does not verify on
    ///      the deprecated fork (legacy personal_sign wrap), so one proof can no
    ///      longer be redeemed on both. The fork still accepts legacy-format
    ///      proofs — which is why live fork instances must be paused.
    function test_registryBoundProof_rejectedByDeprecatedFork() public {
        AgenticIDReputationRegistry forkImpl = new AgenticIDReputationRegistry();
        AgenticIDReputationRegistry fork = AgenticIDReputationRegistry(address(new ERC1967Proxy(
            address(forkImpl),
            abi.encodeCall(AgenticIDReputationRegistry.initialize, (address(agenticId), owner, pauser, MAX_PROOF_AGE))
        )));
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, TASK_HASH);

        vm.prank(client);
        vm.expectRevert(ReputationInvalidProofSignature.selector);
        fork.giveFeedback(agentId, 90, 0, "q", "l", "ep", "", bytes32(0), proof);
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

    // ── Task-receipt opening (attestFeedbackWithTask) ─────────────────────────

    /// @dev Cross-implementation known-answer vector for the taskHash
    ///      reconstruction. Generated from the sealed proxy's Go code
    ///      (crypto.Keccak256(method, uri, keccak(reqBody), respBodyHash,
    ///      itoa(status))) — if the Solidity reconstruction or the Go
    ///      composition drifts, this fails.
    function test_taskHash_crossImplVector() public pure {
        bytes32 recomputed = keccak256(abi.encodePacked(
            bytes("GET"), bytes("/hello"),
            keccak256(""), // empty request body
            bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
            bytes("200")
        ));
        assertEq(
            recomputed,
            0x2f9ed03f9562ed3d04171edfc8690f42c817e3ae99745799da3c108ab32122c3,
            "taskHash reconstruction drifted from the sealed proxy's composition"
        );
    }

    /// @dev The taskHash known-answer vector the sealed proxy pins by driving
    ///      writeServeProof (sealed/internal/proxy/serveproof_test.go,
    ///      katTaskHash): POST /api/x?q=1 (RequestURI, query included),
    ///      request body {"q":"in"}, response body {"a":"out"}, status 201.
    ///      Recomputed exactly as attestFeedbackWithTask does, then redeemed
    ///      with a proof committing to the pinned constant — a receipt the
    ///      runtime signs must open on chain.
    bytes32 private constant SEALED_KAT_TASK_HASH =
        0x6c37771076037daf6053adca6126264030e249e0c9a6fc0cc238c56509f842db;

    function test_taskHash_sealedProxyVector_redeems() public {
        TaskReveal memory task = TaskReveal({
            method: "POST",
            uri: "/api/x?q=1",
            reqBodyHash: keccak256('{"q":"in"}'),
            respBodyHash: keccak256('{"a":"out"}'),
            statusCode: 201
        });
        bytes32 recomputed = keccak256(abi.encodePacked(
            bytes(task.method), bytes(task.uri), task.reqBodyHash, task.respBodyHash,
            bytes(Strings.toString(uint256(task.statusCode)))
        ));
        assertEq(recomputed, SEALED_KAT_TASK_HASH, "taskHash drifted from the sealed proxy's pinned vector");

        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        ServeProof memory proof = _proofFor(agentId, client, dataHash, SEALED_KAT_TASK_HASH);
        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, idx, proof, task);

        assertTrue(registry.isVerified(agentId, client, idx), "verified");
        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "/api/x?q=1", "endpoint recorded verbatim");
    }

    function _taskAndProof(uint256 agentId, address submitter, bytes32 dataHash, string memory uri)
        internal view returns (TaskReveal memory task, ServeProof memory proof)
    {
        return _taskAndProofWithStatus(agentId, submitter, dataHash, uri, 200);
    }

    /// @dev Reveal + a proof whose taskHash genuinely commits to `statusCode`
    ///      (its decimal form, as the sealed proxy composes it).
    function _taskAndProofWithStatus(
        uint256 agentId,
        address submitter,
        bytes32 dataHash,
        string memory uri,
        uint16 statusCode
    ) internal view returns (TaskReveal memory task, ServeProof memory proof) {
        task = TaskReveal({
            method: "GET",
            uri: uri,
            reqBodyHash: keccak256(""),
            respBodyHash: keccak256("resp-body"),
            statusCode: statusCode
        });
        bytes32 taskHash = keccak256(abi.encodePacked(
            bytes(task.method), bytes(task.uri), task.reqBodyHash, task.respBodyHash,
            bytes(Strings.toString(uint256(statusCode)))
        ));
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        proof = _mkServeProof(
            agentId, submitter, taskHash, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
    }

    function test_attestWithTask_recordsVerifiedEndpoint() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        (TaskReveal memory task, ServeProof memory proof) = _taskAndProof(agentId, client, dataHash, "/hello");

        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, idx, proof, task);

        assertTrue(registry.isVerified(agentId, client, idx), "verified");
        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "/hello", "TEE-verified endpoint recorded");

        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count, int128 sum, uint8 dec) = registry.getVerifiedSummaryForEndpoint(agentId, cs, "/hello");
        assertEq(count, 1, "endpoint summary counts the entry");
        assertEq(sum, int128(90) * int128(1e18), "value aggregated");
        assertEq(dec, 18, "18 decimals");
        (count, , ) = registry.getVerifiedSummaryForEndpoint(agentId, cs, "/other");
        assertEq(count, 0, "other endpoint counts nothing");
    }

    /// @dev A plain attest leaves the endpoint unproven — it never matches an
    ///      endpoint-scoped summary and reads back as "".
    function test_plainAttest_hasNoVerifiedEndpoint() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        _attest(agentId, client, idx, _proofFor(agentId, client, dataHash, TASK_HASH));

        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "", "no endpoint without a reveal");
        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count, , ) = registry.getVerifiedSummaryForEndpoint(agentId, cs, "");
        // "" is the sentinel for "unproven", not a queryable endpoint — but even
        // querying it aggregates only entries that genuinely stored "".
        assertEq(count, 1, "unrevealed entries group under the empty sentinel");
    }

    function test_attestWithTask_revertsOnTaskMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        // Proof commits to /hello; the reveal claims /evil.
        (, ServeProof memory proof) = _taskAndProof(agentId, client, dataHash, "/hello");
        (TaskReveal memory lie, ) = _taskAndProof(agentId, client, dataHash, "/evil");

        vm.prank(client);
        vm.expectPartialRevert(VerifiedFeedbackTaskMismatch.selector);
        registry.attestFeedbackWithTask(agentId, 1, proof, lie);
    }

    function test_attestWithTask_revertsOnUnknownMethod() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        (TaskReveal memory task, ServeProof memory proof) = _taskAndProof(agentId, client, dataHash, "/hello");
        task.method = "FETCH";

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidTaskReveal.selector);
        registry.attestFeedbackWithTask(agentId, 1, proof, task);
    }

    function test_attestWithTask_revertsOnUriWithoutSlash() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _canonicalFeedback(agentId, client, 90, 0);
        (TaskReveal memory task, ServeProof memory proof) = _taskAndProof(agentId, client, dataHash, "/hello");
        task.uri = "hello"; // no leading slash

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidTaskReveal.selector);
        registry.attestFeedbackWithTask(agentId, 1, proof, task);
    }

    /// @dev FIND-02: statusCode must be exactly three digits. Each proof here
    ///      genuinely commits to its out-of-range status, so without the bound
    ///      the recompute would MATCH — the revert is the range check, not a
    ///      TaskMismatch.
    function test_attestWithTask_revertsOnStatusCodeOutOfRange() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        uint16[3] memory bad = [uint16(0), uint16(99), uint16(1000)];
        for (uint256 i = 0; i < bad.length; i++) {
            (TaskReveal memory task, ServeProof memory proof) =
                _taskAndProofWithStatus(agentId, client, dataHash, "/hello", bad[i]);
            vm.prank(client);
            vm.expectRevert(VerifiedFeedbackInvalidTaskReveal.selector);
            registry.attestFeedbackWithTask(agentId, idx, proof, task);
        }
    }

    /// @dev The bound's edges are legitimate statuses (Go's net/http emits
    ///      100..999) — both verify.
    function test_attestWithTask_acceptsStatusCodeBounds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 i1 = _canonicalFeedback(agentId, client, 90, 0);
        uint64 i2 = _canonicalFeedback(agentId, client, 70, 0);

        (TaskReveal memory t100, ServeProof memory p100) =
            _taskAndProofWithStatus(agentId, client, dataHash, "/hello", 100);
        (TaskReveal memory t999, ServeProof memory p999) =
            _taskAndProofWithStatus(agentId, client, dataHash, "/hello", 999);
        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, i1, p100, t100);
        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, i2, p999, t999);

        assertEq(registry.getVerifiedEndpoint(agentId, client, i1), "/hello", "status 100 accepted");
        assertEq(registry.getVerifiedEndpoint(agentId, client, i2), "/hello", "status 999 accepted");
    }

    /// @dev FIND-02, the concrete forgery: a genuine GET /hello → 200 receipt
    ///      re-split with status "0" — two body-hash bytes shift into the URI
    ///      and "20" into the response-hash slot — hashes identically, so
    ///      pre-1.2.0 the client could record "/hello" + 2 junk bytes as its
    ///      TEE-verified endpoint. The 3-digit bound rejects it; the genuine
    ///      reveal still verifies.
    function test_attestWithTask_rejectsStatusZeroShiftedSplit() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        uint64 idx = _canonicalFeedback(agentId, client, 90, 0);
        (TaskReveal memory genuine, ServeProof memory proof) =
            _taskAndProof(agentId, client, dataHash, "/hello");

        TaskReveal memory forged = TaskReveal({
            method: genuine.method,
            uri: string(abi.encodePacked(genuine.uri, bytes2(genuine.reqBodyHash))),
            reqBodyHash: (genuine.reqBodyHash << 16) | (genuine.respBodyHash >> 240),
            respBodyHash: (genuine.respBodyHash << 16) | bytes32(uint256(uint16(bytes2("20")))),
            statusCode: 0
        });
        // The collision is real: the forged split hashes to the signed taskHash.
        assertEq(
            keccak256(abi.encodePacked(
                bytes(forged.method), bytes(forged.uri), forged.reqBodyHash, forged.respBodyHash, bytes("0")
            )),
            proof.taskHash,
            "shifted split collides with the genuine receipt"
        );

        vm.prank(client);
        vm.expectRevert(VerifiedFeedbackInvalidTaskReveal.selector);
        registry.attestFeedbackWithTask(agentId, idx, proof, forged);

        vm.prank(client);
        registry.attestFeedbackWithTask(agentId, idx, proof, genuine);
        assertEq(registry.getVerifiedEndpoint(agentId, client, idx), "/hello", "genuine endpoint recorded");
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
