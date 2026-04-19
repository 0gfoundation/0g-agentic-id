// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    AgenticIDReputationRegistry,
    ReputationClientMismatch,
    ReputationNoAgentSeal,
    ReputationInvalidProofSignature,
    ReputationInvalidIndex,
    ReputationAlreadyRevoked,
    ReputationNotAgentOwner,
    ReputationAlreadyResponded
} from "../contracts/AgenticIDReputationRegistry.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof, AgenticIDProofRequired} from "../contracts/interfaces/IAgenticIDReputationRegistry.sol";
import {NonceExpired, NonceAlreadyUsed} from "../contracts/utils/NonceRegistryUpgradeable.sol";

contract ReputationTest is AgenticIDTestBase {
    AgenticIDReputationRegistry internal reputation;

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

        AgenticIDReputationRegistry repImpl = new AgenticIDReputationRegistry();
        ERC1967Proxy repProxy = new ERC1967Proxy(
            address(repImpl),
            abi.encodeCall(
                AgenticIDReputationRegistry.initialize,
                (address(agenticId), owner, MAX_PROOF_AGE)
            )
        );
        reputation = AgenticIDReputationRegistry(address(repProxy));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev Like base's `_mintWithSeal` but the seal address comes from a real
    ///      wallet we control, so we can sign ServeProofs that recover to it.
    function _mintWithSealWallet(address to) internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256(abi.encode("rep-data", to));
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

    /// @dev Build + sign a ServeProof with the controlled sealWallet.
    function _mkServeProof(
        uint256 agentId,
        address client_,
        bytes32 taskHash,
        bytes32[] memory dataHashes,
        bytes32 frameworkHash,
        uint256 deadline,
        uint256 signerPk
    ) internal view returns (ServeProof memory) {
        bytes32 inner = keccak256(
            abi.encode(
                agentId,
                client_,
                block.timestamp,
                deadline,
                taskHash,
                keccak256(abi.encodePacked(dataHashes)),
                frameworkHash
            )
        );
        return ServeProof({
            agentId: agentId,
            client: client_,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: taskHash,
            dataHashes: dataHashes,
            frameworkHash: frameworkHash,
            signature: _sign(signerPk, _eip191RawHash(inner))
        });
    }

    function _submitFeedback(
        uint256 agentId,
        address client_,
        int128 value,
        ServeProof memory proof
    ) internal {
        vm.prank(client_);
        reputation.giveFeedback(
            agentId, value, 0,
            "quality", "latency",
            "https://api.example.com",
            "ipfs://feedback-uri",
            keccak256("feedback-hash"),
            proof
        );
    }

    // ── Disabled base giveFeedback ────────────────────────────────────────────

    function test_giveFeedback_noProof_reverts() public {
        vm.prank(client);
        vm.expectRevert(AgenticIDProofRequired.selector);
        reputation.giveFeedback(
            1, 100, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f")
        );
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_giveFeedback_happyPath() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        _submitFeedback(agentId, client, 90, proof);

        (int128 value, uint8 decimals, string memory tag1, string memory tag2, bool revoked) =
            reputation.readFeedback(agentId, client, 0);
        assertEq(value, 90, "feedback value stored");
        assertEq(decimals, 0, "decimals stored");
        assertEq(tag1, "quality", "tag1 stored");
        assertEq(tag2, "latency", "tag2 stored");
        assertTrue(!revoked, "not revoked");

        (bytes32[] memory storedHashes, bytes32 storedFw) =
            reputation.getServeData(agentId, client, 0);
        assertEq(storedHashes.length, 1, "serve data dataHashes length");
        assertEq(storedHashes[0], dataHash, "serve data dataHash");
        assertEq(storedFw, FRAMEWORK_HASH, "serve data frameworkHash");

        address[] memory clients = reputation.getClients(agentId);
        assertEq(clients.length, 1, "one client recorded");
        assertEq(clients[0], client, "client recorded");
    }

    // ── No-seal rejection ─────────────────────────────────────────────────────

    function test_giveFeedback_revertsWhenAgentHasNoSeal() public {
        // Self-mint → no seal → ServeProof verification must bail early.
        (uint256 agentId, bytes32 dataHash) = _selfMint(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        vm.prank(client);
        vm.expectRevert(ReputationNoAgentSeal.selector);
        reputation.giveFeedback(
            agentId, 90, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proof
        );
    }

    // ── Client / caller mismatch ──────────────────────────────────────────────

    function test_giveFeedback_revertsOnClientMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        // proof.client says `client`, but `client2` calls giveFeedback.
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        vm.prank(client2);
        vm.expectRevert(ReputationClientMismatch.selector);
        reputation.giveFeedback(
            agentId, 90, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proof
        );
    }

    // ── Forged signature rejection ────────────────────────────────────────────

    function test_giveFeedback_revertsOnInvalidSignature() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        // Signed by a random wallet, not the agent's seal.
        (, uint256 fakePk) = makeAddrAndKey("not-the-seal");
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, fakePk
        );

        vm.prank(client);
        vm.expectRevert(ReputationInvalidProofSignature.selector);
        reputation.giveFeedback(
            agentId, 90, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proof
        );
    }

    // ── Expired deadline rejection ────────────────────────────────────────────

    function test_giveFeedback_revertsOnExpiredDeadline() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        uint256 deadline = block.timestamp + 1 hours;
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            deadline, sealWallet.privateKey
        );

        vm.warp(deadline + 1);

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(NonceExpired.selector, deadline, block.timestamp)
        );
        reputation.giveFeedback(
            agentId, 90, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proof
        );
    }

    // ── Replay rejection ──────────────────────────────────────────────────────

    function test_giveFeedback_revertsOnReplay() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        _submitFeedback(agentId, client, 90, proof);

        // Resubmit identical ServeProof — signature-derived nonce already consumed.
        vm.prank(client);
        vm.expectPartialRevert(NonceAlreadyUsed.selector);
        reputation.giveFeedback(
            agentId, 80, 0, "q", "l",
            "https://api.example.com", "ipfs://f2", keccak256("f2"),
            proof
        );
    }

    // ── Revoke feedback ───────────────────────────────────────────────────────

    function test_revokeFeedback_byClient_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
        _submitFeedback(agentId, client, 90, proof);

        vm.prank(client);
        reputation.revokeFeedback(agentId, 0);

        (, , , , bool revoked) = reputation.readFeedback(agentId, client, 0);
        assertTrue(revoked, "feedback revoked");
    }

    function test_revokeFeedback_revertsOnAlreadyRevoked() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
        _submitFeedback(agentId, client, 90, proof);

        vm.prank(client);
        reputation.revokeFeedback(agentId, 0);

        vm.prank(client);
        vm.expectRevert(ReputationAlreadyRevoked.selector);
        reputation.revokeFeedback(agentId, 0);
    }

    function test_revokeFeedback_revertsOnInvalidIndex() public {
        (uint256 agentId, ) = _mintWithSealWallet(agentOwner);

        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationInvalidIndex.selector, uint256(5), uint256(0))
        );
        reputation.revokeFeedback(agentId, 5);
    }

    // ── Append response by agent owner ────────────────────────────────────────

    function test_appendResponse_byAgentOwner_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
        _submitFeedback(agentId, client, 90, proof);

        vm.prank(agentOwner);
        reputation.appendResponse(agentId, client, 0, "ipfs://reply", keccak256("reply"));

        address[] memory none = new address[](0);
        uint64 count = reputation.getResponseCount(agentId, client, 0, none);
        assertEq(count, 1, "one response recorded");
    }

    function test_appendResponse_revertsOnDuplicateByResponder() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
        _submitFeedback(agentId, client, 90, proof);

        vm.startPrank(agentOwner);
        reputation.appendResponse(agentId, client, 0, "ipfs://r1", keccak256("r1"));
        vm.expectRevert(ReputationAlreadyResponded.selector);
        reputation.appendResponse(agentId, client, 0, "ipfs://r2", keccak256("r2"));
        vm.stopPrank();
    }

    function test_appendResponse_revertsWhenNotAgentOwner() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
        _submitFeedback(agentId, client, 90, proof);

        vm.prank(client);
        vm.expectRevert(ReputationNotAgentOwner.selector);
        reputation.appendResponse(agentId, client, 0, "ipfs://r", keccak256("r"));
    }
}
