// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {FeedbackBatcher, BatcherNotSelf} from "../src/FeedbackBatcher.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {TaskReveal} from "../src/interfaces/IVerifiedFeedbackRegistry.sol";

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

    function _emptyTask() internal pure returns (TaskReveal memory) {
        return TaskReveal({method: "", uri: "", reqBodyHash: 0, respBodyHash: 0, statusCode: 0});
    }

    /// @dev Attach the batcher's code to the client EOA (7702) and self-call
    ///      giveFeedbackAndAttest with the given proof.
    function _delegatedCall(uint256 agentId, ServeProof memory proof) internal returns (uint64) {
        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        vm.prank(clientWallet.addr);
        return FeedbackBatcher(payable(clientWallet.addr)).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof, _emptyTask()
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

    /// @dev With a task reveal, the batch also records the TEE-verified endpoint.
    function test_delegatedBatch_withTaskRecordsEndpoint() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        TaskReveal memory task = TaskReveal({
            method: "GET", uri: "/hello",
            reqBodyHash: keccak256(""), respBodyHash: keccak256("resp"), statusCode: 200
        });
        bytes32 taskHash = keccak256(abi.encodePacked(
            bytes(task.method), bytes(task.uri), task.reqBodyHash, task.respBodyHash, bytes("200")
        ));
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), clientWallet.addr, agentId,
            block.timestamp, deadline, taskHash,
            keccak256(abi.encodePacked(dataHashes)), FRAMEWORK_HASH
        ));
        ServeProof memory proof = ServeProof({
            agentId: agentId, submitter: clientWallet.addr,
            timestamp: block.timestamp, deadline: deadline,
            taskHash: taskHash, dataHashes: dataHashes, frameworkHash: FRAMEWORK_HASH,
            signature: _sign(sealWallet.privateKey, _eip191RawHash(inner))
        });

        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        vm.prank(clientWallet.addr);
        uint64 idx = FeedbackBatcher(payable(clientWallet.addr)).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof, task
        );

        assertEq(registry.getVerifiedEndpoint(agentId, clientWallet.addr, idx), "/hello", "endpoint recorded through the batch");
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
        FeedbackBatcher(payable(clientWallet.addr)).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof, _emptyTask()
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
            "https://api.example.com", "", bytes32(0), proof, _emptyTask()
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
        FeedbackBatcher(payable(clientWallet.addr)).giveFeedbackAndAttest(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "", bytes32(0), proof, _emptyTask()
        );
    }

    /// @dev Delegation persists between feedback calls — a plain ETH transfer
    ///      to the delegated EOA must still land (empty calldata resolves to
    ///      the delegate code's receive()).
    function test_delegatedEOA_stillReceivesPlainETH() public {
        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        address sender = makeAddr("faucet");
        vm.deal(sender, 1 ether);
        uint256 before = clientWallet.addr.balance;
        vm.prank(sender);
        (bool ok, ) = clientWallet.addr.call{value: 0.5 ether}("");
        assertTrue(ok, "plain transfer to a delegated EOA must not revert");
        assertEq(clientWallet.addr.balance, before + 0.5 ether, "value lands in the EOA's own balance");
        assertEq(address(batcher).balance, 0, "the batcher contract itself holds nothing");
    }

    function test_delegatedEOA_stillReceivesSafeMintedNFTs() public {
        // Regression: a wallet that ever used the atomic feedback path keeps
        // the delegation designator; ERC-721 safeMint/safeTransfer probe any
        // code-bearing receiver via onERC721Received. v3 lacked the hook, so
        // clone mints to such wallets reverted ERC721InvalidReceiver.
        vm.signAndAttachDelegation(address(batcher), clientWallet.privateKey);
        MinimalERC721 nft = new MinimalERC721();
        nft.safeMint(clientWallet.addr, 1);
        assertEq(nft.ownerOf(1), clientWallet.addr, "safeMint lands on the delegated EOA");
    }

    // ── Constructor guards ────────────────────────────────────────────────────

    function test_constructor_rejectsZeroAddresses() public {
        vm.expectRevert(bytes("canonicalReputation=0"));
        new FeedbackBatcher(address(0), address(registry));
        vm.expectRevert(bytes("verifiedFeedback=0"));
        new FeedbackBatcher(address(canonicalRep), address(0));
    }
}

/// @dev Just enough ERC-721 to exercise the safeMint receiver probe.
contract MinimalERC721 is ERC721 {
    constructor() ERC721("T", "T") {}

    function safeMint(address to, uint256 id) external {
        _safeMint(to, id);
    }
}
