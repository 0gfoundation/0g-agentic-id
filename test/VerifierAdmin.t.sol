// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {TEEDataVerifierInvalidSignature} from "../contracts/verifiers/TEEDataVerifier.sol";
import {DataVerifierNotPauser} from "../contracts/verifiers/BaseDataVerifier.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../contracts/interfaces/IERC7857DataVerifier.sol";

contract VerifierAdminTest is AgenticIDTestBase {
    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");
    }

    // ── setTeeOracleAddress: rotation ─────────────────────────────────────────

    function test_setTeeOracleAddress_rotatesActiveOracle() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        // Rotate to a new oracle key.
        (address newOracleAddr, uint256 newOraclePk) = makeAddrAndKey("new-oracle");
        vm.prank(owner);
        verifier.setTeeOracleAddress(newOracleAddr);
        assertEq(verifier.teeOracleAddress(), newOracleAddr, "new oracle registered");

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        // Sig by OLD oracle must now fail.
        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory opOld = _mkOwnershipProofSignedBy(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-old"), deadline, oraclePk
        );
        TransferValidityProof[] memory proofsOld = new TransferValidityProof[](1);
        proofsOld[0] = TransferValidityProof({accessProof: ap, ownershipProof: opOld});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierInvalidSignature.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofsOld);

        // Sig by NEW oracle must succeed (with fresh ap nonce — the old ap was never
        // consumed, so we can reuse it as long as the ownership proof is fresh).
        OwnershipProof memory opNew = _mkOwnershipProofSignedBy(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-new"), deadline, newOraclePk
        );
        TransferValidityProof[] memory proofsNew = new TransferValidityProof[](1);
        proofsNew[0] = TransferValidityProof({accessProof: ap, ownershipProof: opNew});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofsNew);
        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "transfer after rotation works");
    }

    function test_setTeeOracleAddress_revertsWhenNotOwner() public {
        vm.prank(address(0xB0B));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xB0B)
            )
        );
        verifier.setTeeOracleAddress(address(0xBEEF));
    }

    // ── pause / unpause ───────────────────────────────────────────────────────

    function test_pause_blocksVerifyTransferValidity() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        vm.prank(pauser);
        verifier.pause();

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_unpause_restoresVerifyTransferValidity() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        vm.startPrank(pauser);
        verifier.pause();
        verifier.unpause();
        vm.stopPrank();

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "transfer works after unpause");
    }

    function test_pause_revertsWhenNotPauser() public {
        vm.prank(address(0xB0B));
        vm.expectRevert(DataVerifierNotPauser.selector);
        verifier.pause();
    }

    // ── setMaxProofAge ────────────────────────────────────────────────────────

    function test_setMaxProofAge_updatesValue() public {
        vm.prank(owner);
        verifier.setMaxProofAge(2 days);
        assertEq(verifier.maxProofAge(), 2 days, "maxProofAge updated");
    }

    function test_setMaxProofAge_revertsWhenNotOwner() public {
        vm.prank(address(0xB0B));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xB0B)
            )
        );
        verifier.setMaxProofAge(2 days);
    }
}
