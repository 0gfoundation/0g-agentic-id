// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticIDSealIdTaken} from "../src/AgenticID.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

/// @notice Locks in the custody-binding invariants between AgenticID and the
///         fixed canonical ERC-8004 registry: the canonical token is held by the
///         AgenticID contract, agentIds come from the canonical global counter,
///         the canonical record is the source of truth ecosystem tools read, and
///         agentId 0 is handled safely.
contract CanonicalBindingTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");
    }

    // ── Custody: canonical token owned by the contract, local token by the user ─

    function test_custody_canonicalTokenHeldByContract() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        assertEq(agenticId.ownerOf(agentId), alice, "local owner is the user");
        assertEq(canonical.ownerOf(agentId), address(agenticId), "canonical token in custody");
        assertEq(agenticId.canonical(), address(canonical), "canonical address wired");
    }

    function test_custody_survivesLocalTransfer() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);
        _transfer(agentId, dataHash);

        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "local owner moved");
        assertEq(canonical.ownerOf(agentId), address(agenticId), "canonical token still in custody");
    }

    // ── agentId comes from the canonical global counter ────────────────────────

    function test_agentId_fromGlobalCanonicalCounter() public {
        // Three third-party agents register directly on the canonical registry first.
        address thirdParty = address(0xDEAD);
        vm.startPrank(thirdParty);
        canonical.register();
        canonical.register();
        canonical.register();
        vm.stopPrank();

        // AgenticID's first agent therefore gets the next global id, not a clean 0.
        (uint256 agentId, ) = _mintWithSeal(alice);
        assertEq(agentId, 3, "agentId continues the shared global counter");
        assertEq(canonical.ownerOf(agentId), address(agenticId), "custodied at global id");
    }

    // ── Canonical record is the ecosystem-visible source of truth ──────────────

    function test_canonicalVisibility_uriAndMetadata() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("vis")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](1);
        metadata[0] = MetadataEntry({metadataKey: "category", metadataValue: bytes("inference")});

        vm.prank(attestor);
        uint256 agentId = agenticId.registerWithSeal(
            alice, "ipfs://card", metadata, datas, sealedKeys, SEAL_ADDR, SEAL_ID
        );

        // A tool that only knows the canonical registry sees the agent natively.
        assertEq(canonical.tokenURI(agentId), "ipfs://card", "URI readable on canonical");
        assertEq(canonical.getMetadata(agentId, "category"), bytes("inference"), "metadata on canonical");
        // And the same values surface through AgenticID's read-through.
        assertEq(agenticId.tokenURI(agentId), "ipfs://card", "URI read-through matches");
    }

    function test_agentWallet_clearedAtMint() public {
        // Canonical register() seeds agentWallet = msg.sender (the AgenticID
        // contract); the binding must clear it so the agent starts empty.
        (uint256 agentId, ) = _mintWithSeal(alice);
        assertEq(canonical.getAgentWallet(agentId), address(0), "agentWallet empty at mint");
    }

    // ── agentId 0 sentinel safety ──────────────────────────────────────────────

    function test_sentinel_agentZeroSealBindingIsSafe() public {
        // Fresh deployment: the first agent is canonical id 0.
        (uint256 agentId, ) = _mintWithSeal(alice);
        assertEq(agentId, 0, "first agent is id 0");

        // Seal bookkeeping must not confuse "agent 0" with "unbound".
        assertEq(agenticId.getAgentSeal(0), SEAL_ADDR, "seal bound to agent 0");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID), 0, "reverse map returns 0 (the real agent)");
        assertTrue(agenticId.isSealIdBound(SEAL_ID), "existence flag distinguishes from unbound");

        // Minting another agent with the same sealId must still be rejected,
        // even though sealIdToAgentId[SEAL_ID] == 0 would look "empty" without
        // the explicit existence flag.
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("cb-dup")});
        bytes[] memory keys = new bytes[](1);
        keys[0] = hex"cafe";
        MetadataEntry[] memory meta = new MetadataEntry[](0);
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID, uint256(0)));
        agenticId.registerWithSeal(alice, "", meta, datas, keys, address(0xB1), SEAL_ID);
    }

    // ── Clone also registers a fresh canonical identity ────────────────────────

    function test_clone_registersNewCanonicalId() public {
        // Clone is allowed for non-seal sources only (seal-bound clone reverts).
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;
        AccessProof memory ap = _mkAccessProof(dataHash, "", bytes("ap-c"), deadline, buyerWallet.privateKey);
        OwnershipProof memory op = _mkOwnershipProof(dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-c"), deadline);
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        uint256 cloneId = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        assertTrue(cloneId != srcId, "clone gets a distinct id");
        assertEq(agenticId.ownerOf(cloneId), buyerWallet.addr, "clone local owner");
        assertEq(canonical.ownerOf(cloneId), address(agenticId), "clone canonical token custodied");
        // Clone path must also clear the canonical agentWallet (not leave it as
        // the wrapper address) — same cleanup as register/registerWithSeal.
        assertEq(canonical.getAgentWallet(cloneId), address(0), "clone agentWallet cleared");
        // Source canonical identity untouched.
        assertEq(canonical.ownerOf(srcId), address(agenticId), "source still custodied");
    }

    // ── Stray canonical deposits are rejected (no permanent lock) ─────────────

    function test_strayCanonicalDepositRejected() public {
        address stranger = address(0x5747);
        vm.prank(stranger);
        uint256 strayId = canonical.register();

        // Pushing an already-existing canonical token into custody must revert —
        // there is no withdrawal path, so accepting it would lock it forever.
        vm.prank(stranger);
        vm.expectRevert();
        canonical.safeTransferFrom(stranger, address(agenticId), strayId);

        assertEq(canonical.ownerOf(strayId), stranger, "stray token stays with its owner");
    }

    // ── setAgentURI requires a local token even for an attestor ───────────────

    function test_setAgentURI_revertsOnNonexistentTokenEvenForAttestor() public {
        uint256 ghostId = 999_999;
        vm.prank(attestor);
        vm.expectRevert();
        agenticId.setAgentURI(ghostId, "ipfs://attacker-controlled");
    }

    // ── helper ──────────────────────────────────────────────────────────────────

    /// @dev test_custody_survivesLocalTransfer uses a seal-bound agent, which now
    ///      transfers ownership-only via standard transferFrom.
    function _transfer(uint256 agentId, bytes32 /*dataHash*/) internal {
        vm.prank(sellerWallet.addr);
        agenticId.transferFrom(sellerWallet.addr, buyerWallet.addr, agentId);
    }
}
