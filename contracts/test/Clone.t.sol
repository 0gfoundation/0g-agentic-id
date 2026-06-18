// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticIDCannotCloneSealedAgent} from "../src/AgenticID.sol";
import {IERC7857} from "../src/interfaces/IERC7857.sol";
import {IERC7857Cloneable} from "../src/interfaces/IERC7857Cloneable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {DataVerifierDataHashMismatch} from "../src/verifiers/BaseDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

contract CloneTest is AgenticIDTestBase {
    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");
    }

    function _buildCloneProofs(bytes32 dataHash, bytes memory nonceSuffix)
        internal
        view
        returns (TransferValidityProof[] memory proofs)
    {
        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash,
            "",
            abi.encodePacked("ap-", nonceSuffix),
            deadline,
            buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash,
            SEALED_KEY_NEW,
            buyerPubkey,
            abi.encodePacked("op-", nonceSuffix),
            deadline
        );
        proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_iCloneFrom_succeeds() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-1");

        vm.prank(sellerWallet.addr);
        uint256 newId = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        assertTrue(newId != srcId, "clone must be a distinct tokenId");
        assertEq(agenticId.ownerOf(srcId), sellerWallet.addr, "source owner unchanged");
        assertEq(agenticId.ownerOf(newId), buyerWallet.addr, "clone goes to buyer");
    }

    // ── Source fully preserved ────────────────────────────────────────────────

    function test_iCloneFrom_sourceDataUnchanged() public {
        // Clone is only allowed for non-seal sources (seal-bound clone reverts —
        // see test_iCloneFrom_sealBoundSource_reverts). Source data is preserved.
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-src");

        vm.prank(sellerWallet.addr);
        agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        assertEq(agenticId.getAgentSeal(srcId), address(0), "non-seal source still seal-less");
        IntelligentData[] memory srcDatas = agenticId.intelligentDatasOf(srcId);
        assertEq(srcDatas.length, 1, "source data length unchanged");
        assertEq(srcDatas[0].dataHash, dataHash, "source dataHash unchanged");
    }

    // ── Seal-bound source cannot be cloned ────────────────────────────────────

    function test_iCloneFrom_sealBoundSource_reverts() public {
        (uint256 srcId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-sb");

        vm.prank(sellerWallet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDCannotCloneSealedAgent.selector, srcId)
        );
        agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);
    }

    // ── Clone inherits IntelligentData ────────────────────────────────────────

    function test_iCloneFrom_newTokenInheritsData() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-data");

        vm.prank(sellerWallet.addr);
        uint256 newId = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        IntelligentData[] memory newDatas = agenticId.intelligentDatasOf(newId);
        assertEq(newDatas.length, 1, "clone has one data entry");
        assertEq(newDatas[0].dataHash, dataHash, "clone inherits source dataHash");
    }

    // ── Clone has no seal — must be set separately to sign ServeProofs ────────

    function test_iCloneFrom_newTokenHasNoSeal() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-seal");

        vm.prank(sellerWallet.addr);
        uint256 newId = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        assertEq(agenticId.getAgentSeal(newId), address(0), "clone has no seal");
        assertEq(agenticId.getSealId(newId), bytes32(0), "clone has no sealId");
    }

    // ── Event: emits Cloned, not ITransferred ─────────────────────────────────

    function test_iCloneFrom_emitsCloned() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-evt");

        vm.recordLogs();
        vm.prank(sellerWallet.addr);
        uint256 newId = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 clonedSig = IERC7857Cloneable.Cloned.selector;
        bytes32 transferredSig = IERC7857.ITransferred.selector;

        bool sawCloned;
        bool sawITransferred;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] == clonedSig) {
                sawCloned = true;
                assertEq(uint256(logs[i].topics[1]), srcId, "Cloned.tokenId indexed == srcId");
                assertEq(uint256(logs[i].topics[2]), newId, "Cloned.newTokenId indexed == newId");
            } else if (logs[i].topics[0] == transferredSig) {
                sawITransferred = true;
            }
        }
        assertTrue(sawCloned, "Cloned event must be emitted");
        assertTrue(!sawITransferred, "ITransferred must NOT be emitted for a clone");
    }

    // ── Bad proof rejected same as iTransferFrom ──────────────────────────────

    function test_iCloneFrom_revertsOnDataHashMismatch() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            keccak256("wrong-hash"), SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(DataVerifierDataHashMismatch.selector);
        agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, srcId, proofs);
    }

    // ── Shared tokenId counter between register and iCloneFrom ────────────────
    //
    // AgenticID overrides `_incrementTokenId` via C3 MRO to point at ERC-8004's
    // counter, so register and iCloneFrom share it. If the override ever gets
    // reshuffled, clones could collide with subsequent registrations — this
    // invariant is critical but otherwise invisible from the rest of the suite.

    function test_tokenIdCounter_sharedBetweenRegisterAndClone() public {
        // agentIds come from the canonical registry's global counter, which
        // starts at 0 in this test deployment. What matters is that register
        // and iCloneFrom share one counter so ids stay sequential and distinct.
        (uint256 id1, bytes32 dh1) = _selfMintData(sellerWallet.addr, 0);
        assertEq(id1, 0, "first register mints canonical id 0");

        TransferValidityProof[] memory proofs = _buildCloneProofs(dh1, "counter");
        vm.prank(sellerWallet.addr);
        uint256 id2 = agenticId.iCloneFrom(sellerWallet.addr, buyerWallet.addr, id1, proofs);
        assertEq(id2, 1, "clone must take next sequential tokenId");

        // A fresh register after the clone should NOT collide with id2.
        (uint256 id3, ) = _selfMintData(sellerWallet.addr, 42);
        assertEq(id3, 2, "register after clone continues counter");
        assertTrue(id3 != id2, "no tokenId collision");
    }

    // ── Source must be owned by `from` ────────────────────────────────────────

    function test_iCloneFrom_revertsWhenFromDoesNotOwnSource() public {
        (uint256 srcId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);
        TransferValidityProof[] memory proofs = _buildCloneProofs(dataHash, "clone-bad-from");

        address stranger = address(0xDEADBEEF);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721InvalidSender.selector, stranger)
        );
        agenticId.iCloneFrom(stranger, buyerWallet.addr, srcId, proofs);
    }
}
