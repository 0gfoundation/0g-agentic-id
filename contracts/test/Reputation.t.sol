// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    AgenticIDReputationRegistry,
    ReputationNoAgentSeal,
    ReputationInvalidProofSignature,
    ReputationInvalidIndex,
    ReputationAlreadyRevoked,
    ReputationNotAgentOwner,
    ReputationAlreadyResponded,
    ReputationProofAgentMismatch,
    ReputationValueOutOfRange,
    ReputationValueDecimalsTooLarge,
    ReputationClientsRequired,
    ReputationProofSubmitterMismatch
} from "../src/AgenticIDReputationRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ServeProof, AgenticIDProofRequired} from "../src/interfaces/IAgenticIDReputationRegistry.sol";
import {NonceExpired, NonceAlreadyUsed, NonceDeadlineTooFar} from "../src/utils/NonceRegistryUpgradeable.sol";

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
                (address(agenticId), owner, pauser, MAX_PROOF_AGE)
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

    /// @dev Build + sign a ServeProof with the controlled sealWallet. The proof
    ///      is bound to `submitter` (the address that will redeem it) plus this
    ///      chain and the reputation contract's identity registry.
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
            reputation.readFeedback(agentId, client, 1);
        assertEq(value, 90, "feedback value stored");
        assertEq(decimals, 0, "decimals stored");
        assertEq(tag1, "quality", "tag1 stored");
        assertEq(tag2, "latency", "tag2 stored");
        assertTrue(!revoked, "not revoked");

        (bytes32[] memory storedHashes, bytes32 storedFw) =
            reputation.getServeData(agentId, client, 1);
        assertEq(storedHashes.length, 1, "serve data dataHashes length");
        assertEq(storedHashes[0], dataHash, "serve data dataHash");
        assertEq(storedFw, FRAMEWORK_HASH, "serve data frameworkHash");

        address[] memory clients = reputation.getClients(agentId);
        assertEq(clients.length, 1, "one client recorded");
        assertEq(clients[0], client, "client recorded");
    }

    // ── Cross-agent proof rejection ───────────────────────────────────────────

    /// @dev A valid ServeProof for agent A must not write feedback under a
    ///      different outer agentId.
    function test_giveFeedback_revertsOnAgentIdMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        ServeProof memory proofForA = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        uint256 otherId = agentId + 1; // a different id — need not even exist
        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationProofAgentMismatch.selector, otherId, agentId)
        );
        reputation.giveFeedback(
            otherId, -100, 0, "quality", "latency",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proofForA
        );

        // nothing landed on the targeted id
        assertEq(reputation.getClients(otherId).length, 0, "no client recorded on mismatched id");
    }

    // ── Feedback value bounds ─────────────────────────────────────────────────

    function _proofFor(uint256 agentId, bytes32 dataHash) internal view returns (ServeProof memory) {
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        return _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );
    }

    function test_giveFeedback_revertsOnValueTooLarge() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        int128 tooBig = int128(1e9) + 1; // above MAX_ABS_VALUE
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(ReputationValueOutOfRange.selector, tooBig));
        reputation.giveFeedback(
            agentId, tooBig, 0, "quality", "latency",
            "https://api.example.com", "ipfs://f", keccak256("f"), _proofFor(agentId, dataHash)
        );
    }

    function test_giveFeedback_revertsOnDecimalsTooLarge() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(ReputationValueDecimalsTooLarge.selector, uint8(19)));
        reputation.giveFeedback(
            agentId, 5, 19, "quality", "latency",
            "https://api.example.com", "ipfs://f", keccak256("f"), _proofFor(agentId, dataHash)
        );
    }

    function test_getSummary_aggregatesBoundedValue() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _submitFeedback(agentId, client, 90, _proofFor(agentId, dataHash)); // value 90, decimals 0

        address[] memory cs = new address[](1);
        cs[0] = client;
        (uint64 count, int128 summaryValue, uint8 dec) = reputation.getSummary(agentId, cs, "quality", "latency");
        assertEq(count, 1, "one entry counted");
        assertEq(summaryValue, int128(90) * int128(1e18), "normalized to 18 decimals");
        assertEq(dec, 18, "summary decimals 18");
    }

    // ── ERC-8004 read-surface conformance ─────────────────────────────────────

    /// @dev feedbackIndex is 1-based (ERC-8004): the first feedback is index 1,
    ///      and index 0 is never a valid handle.
    function test_feedbackIndex_isOneBased() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _submitFeedback(agentId, client, 90, _proofFor(agentId, dataHash));

        // index 1 reads the first entry…
        (int128 value,,,,) = reputation.readFeedback(agentId, client, 1);
        assertEq(int256(value), 90, "first feedback lives at index 1");

        // …and index 0 is out of range.
        vm.expectRevert(
            abi.encodeWithSelector(ReputationInvalidIndex.selector, uint256(0), uint256(1))
        );
        reputation.readFeedback(agentId, client, 0);
    }

    /// @dev getLastIndex returns the count (== the last 1-based index), not
    ///      length-1. Zero when the client has left no feedback.
    function test_getLastIndex_returnsCount() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        assertEq(reputation.getLastIndex(agentId, client), 0, "no feedback -> 0");
        _submitFeedback(agentId, client, 90, _proofFor(agentId, dataHash));
        assertEq(reputation.getLastIndex(agentId, client), 1, "one feedback -> last index 1");
    }

    /// @dev ERC-8004 getSummary requires an explicit, non-empty clientAddresses;
    ///      an empty set reverts rather than silently aggregating all clients.
    function test_getSummary_revertsOnEmptyClients() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        _submitFeedback(agentId, client, 90, _proofFor(agentId, dataHash));

        address[] memory empty = new address[](0);
        vm.expectRevert(ReputationClientsRequired.selector);
        reputation.getSummary(agentId, empty, "quality", "latency");
    }

    // ── Deadline within nonce retention ───────────────────────────────────────

    /// @dev A proof whose deadline outlives the nonce retention (maxAge) is
    ///      rejected, so its consumption record can't be GC'd while still valid.
    function test_giveFeedback_revertsOnDeadlineBeyondMaxAge() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        uint256 tooFar = block.timestamp + MAX_PROOF_AGE + 1; // beyond retention
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH, tooFar, sealWallet.privateKey
        );
        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(NonceDeadlineTooFar.selector, tooFar, block.timestamp + MAX_PROOF_AGE)
        );
        reputation.giveFeedback(
            agentId, 90, 0, "quality", "latency",
            "https://api.example.com", "ipfs://f", keccak256("f"), proof
        );
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

    // ── Submitter binding / front-running ─────────────────────────────────────

    /// @dev Cross-implementation known-answer vector. The ServeProof digest for a
    ///      fixed input set must equal this exact constant here, in the sealed Go
    ///      runtime (writeServeProof), and in the TypeScript SDK
    ///      (buildServeProofMessageHash). The constant was generated from the SDK;
    ///      if any implementation's field order or encoding drifts, its assertion
    ///      against this value fails. Keep the three in lockstep.
    function test_serveProofDigest_knownAnswerVector() public pure {
        bytes32[] memory dataHashes = new bytes32[](2);
        dataHashes[0] = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
        dataHashes[1] = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));

        bytes32 digest = keccak256(abi.encode(
            uint256(16602),                                   // chainId
            address(0x00000000000000000000000000000000000000A9), // identityRegistry
            address(0x00000000000000000000000000000000000000C1), // submitter
            uint256(42),                                      // agentId
            uint256(1700000000),                              // timestamp
            uint256(1700003600),                              // deadline
            bytes32(0x1111111111111111111111111111111111111111111111111111111111111111), // taskHash
            keccak256(abi.encodePacked(dataHashes)),
            bytes32(0x4444444444444444444444444444444444444444444444444444444444444444)  // frameworkHash
        ));

        assertEq(
            digest,
            0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b,
            "ServeProof digest drifted from the cross-impl known-answer vector"
        );
    }

    /// @dev A proof is bound to the declared submitter: only that address may
    ///      redeem it. An attacker who copies a pending proof from the mempool
    ///      cannot submit it from their own address — the honest client's proof
    ///      stays theirs to spend.
    function test_giveFeedback_revertsOnSubmitterMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealWallet(agentOwner);

        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;

        // Proof issued to `client` (declared submitter).
        ServeProof memory proof = _mkServeProof(
            agentId, client, TASK_HASH, dataHashes, FRAMEWORK_HASH,
            block.timestamp + 1 hours, sealWallet.privateKey
        );

        // Attacker copies it and tries to front-run from their own address.
        vm.prank(client2);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationProofSubmitterMismatch.selector, client, client2)
        );
        reputation.giveFeedback(
            agentId, -100, 0, "q", "l",
            "https://api.example.com", "ipfs://f", keccak256("f"),
            proof
        );

        // The declared client can still redeem it — nonce was never consumed.
        _submitFeedback(agentId, client, 90, proof);
        (int128 value,,,,) = reputation.readFeedback(agentId, client, 1);
        assertEq(value, 90, "honest client's proof survived the front-run attempt");
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
        reputation.revokeFeedback(agentId, 1);

        (, , , , bool revoked) = reputation.readFeedback(agentId, client, 1);
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
        reputation.revokeFeedback(agentId, 1);

        vm.prank(client);
        vm.expectRevert(ReputationAlreadyRevoked.selector);
        reputation.revokeFeedback(agentId, 1);
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
        reputation.appendResponse(agentId, client, 1, "ipfs://reply", keccak256("reply"));

        address[] memory none = new address[](0);
        uint64 count = reputation.getResponseCount(agentId, client, 1, none);
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
        reputation.appendResponse(agentId, client, 1, "ipfs://r1", keccak256("r1"));
        vm.expectRevert(ReputationAlreadyResponded.selector);
        reputation.appendResponse(agentId, client, 1, "ipfs://r2", keccak256("r2"));
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
        reputation.appendResponse(agentId, client, 1, "ipfs://r", keccak256("r"));
    }
}
