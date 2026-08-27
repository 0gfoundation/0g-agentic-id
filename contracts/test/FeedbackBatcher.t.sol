// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {FeedbackBatcher, BatcherNotSelf} from "../src/FeedbackBatcher.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";

/// @notice The batcher runs AS the client's EOA via an EIP-7702 delegation.
///         These tests exercise it with forge's 7702 cheatcodes
///         (signDelegation/attachDelegation): the client EOA gets the
///         batcher's code attached and self-calls, exactly like a live
///         type-4 transaction.
contract FeedbackBatcherTest is AgenticIDTestBase {
    VerifiedFeedbackRegistry internal registry;
    CanonicalReputationRegistryMock internal canonicalRep;
    FeedbackBatcher internal batcher;

    Vm.Wallet internal sealWallet;   // agentSeal — signs ServeProofs
    Vm.Wallet internal clientWallet; // the delegating client EOA
    address internal agentOwner = address(0xA1);

    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();

        sealWallet = vm.createWallet("agent-seal");
        clientWallet = vm.createWallet("delegating-client");
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
        batcher = new FeedbackBatcher(address(canonicalRep), address(registry));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _mintWithSealWallet(address to) internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256(abi.encode("batch-data", to));
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

    function _mkProof(uint256 agentId, address submitter, bytes32 dataHash, uint256 signerPk)
        internal view returns (ServeProof memory)
    {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), submitter, agentId,
            block.timestamp, deadline, keccak256("task"),
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH
        ));
        return ServeProof({
            agentId: agentId,
            submitter: submitter,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: keccak256("task"),
            dataHashes: dataHashes,
            frameworkHash: FRAMEWORK_HASH,
            signature: _sign(signerPk, _eip191RawHash(inner))
        });
    }

    /// @dev Attach the batcher's code to the client EOA (7702) and self-call
    ///      giveFeedbackAndAttest with the given proof.
    function _delegatedCall(uint256 agentId, ServeProof memory proof) internal returns (uint64) {
        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        vm.prank(clientWallet.addr);
        return FeedbackBatcher(clientWallet.addr).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof
        );
    }

    // ── Atomic happy path ─────────────────────────────────────────────────────

    function test_delegatedBatch_writesAndAttestsAtomically() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        ServeProof memory proof = _mkProof(agentId, clientWallet.addr, dataHash, sealWallet.privateKey);

        uint64 idx = _delegatedCall(agentId, proof);

        assertEq(idx, 1, "entry landed at canonical index 1");
        // Canonical entry attributed to the CLIENT EOA (not the batcher).
        assertEq(canonicalRep.getLastIndex(agentId, clientWallet.addr), 1, "canonical attribution = client EOA");
        assertEq(canonicalRep.getLastIndex(agentId, address(batcher)), 0, "nothing attributed to the batcher");
        // Mark landed for the same (agentId, client, index).
        assertTrue(registry.isVerified(agentId, clientWallet.addr, 1), "verified mark set");
    }

    // ── Atomicity: failed attest rolls back the canonical write ──────────────

    function test_delegatedBatch_badProofRollsBackCanonicalWrite() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        // Signed by the wrong key — canonical write would succeed, attest reverts.
        (, uint256 fakePk) = makeAddrAndKey("not-the-seal");
        ServeProof memory proof = _mkProof(agentId, clientWallet.addr, dataHash, fakePk);

        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        vm.prank(clientWallet.addr);
        vm.expectRevert(); // VerifiedFeedbackInvalidProofSignature, bubbled through the batch
        FeedbackBatcher(clientWallet.addr).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof
        );

        // The whole batch reverted: no orphan canonical entry, no mark.
        assertEq(canonicalRep.getLastIndex(agentId, clientWallet.addr), 0, "canonical write rolled back");
        assertFalse(registry.isVerified(agentId, clientWallet.addr, 1), "no mark");
    }

    // ── Self-call guard ───────────────────────────────────────────────────────

    /// @dev Calling the batcher contract directly (not as a delegated
    ///      self-call) must be rejected — msg.sender != address(this).
    function test_directCall_reverts() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        ServeProof memory proof = _mkProof(agentId, clientWallet.addr, dataHash, sealWallet.privateKey);

        vm.prank(clientWallet.addr);
        vm.expectRevert(BatcherNotSelf.selector);
        batcher.giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof
        );
    }

    /// @dev An outsider calling a DELEGATED EOA must be rejected too —
    ///      otherwise anyone could submit feedback in the delegated user's name.
    function test_outsiderCallingDelegatedEOA_reverts() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        ServeProof memory proof = _mkProof(agentId, clientWallet.addr, dataHash, sealWallet.privateKey);

        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert(BatcherNotSelf.selector);
        FeedbackBatcher(clientWallet.addr).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof
        );
    }

    // ── Constructor guards ────────────────────────────────────────────────────

    function test_constructor_rejectsZeroAddresses() public {
        vm.expectRevert(bytes("canonicalReputation=0"));
        new FeedbackBatcher(address(0), address(registry));
        vm.expectRevert(bytes("verifiedFeedback=0"));
        new FeedbackBatcher(address(canonicalRep), address(0));
    }
}
