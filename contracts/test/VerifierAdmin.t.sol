// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    TEEDataVerifier,
    TEEDataVerifierInvalidSignature,
    TEEDataVerifierZeroAddress
} from "../src/verifiers/TEEDataVerifier.sol";
import {DataVerifierNotPauser} from "../src/verifiers/BaseDataVerifier.sol";
import {NonceMaxAgeDecrease, NonceMaxAgeOutOfRange} from "../src/utils/NonceRegistryUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        // Rotate to a new oracle key.
        (address newOracleAddr, uint256 newOraclePk) = makeAddrAndKey("new-oracle");
        vm.prank(owner);
        verifier.setTeeOracleAddress(newOracleAddr);
        assertEq(verifier.teeOracleAddress(), newOracleAddr, "new oracle registered");

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        // Sig by OLD oracle must now fail.
        AccessProof memory ap = _mkAccessProof(
            agentId, sellerWallet.addr, dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory opOld = _mkOwnershipProofSignedBy(
            agentId, sellerWallet.addr, dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-old"), deadline, oraclePk
        );
        TransferValidityProof[] memory proofsOld = new TransferValidityProof[](1);
        proofsOld[0] = TransferValidityProof({accessProof: ap, ownershipProof: opOld});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierInvalidSignature.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofsOld);

        // Sig by NEW oracle must succeed (with fresh ap nonce — the old ap was never
        // consumed, so we can reuse it as long as the ownership proof is fresh).
        OwnershipProof memory opNew = _mkOwnershipProofSignedBy(
            agentId, sellerWallet.addr, dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-new"), deadline, newOraclePk
        );
        TransferValidityProof[] memory proofsNew = new TransferValidityProof[](1);
        proofsNew[0] = TransferValidityProof({accessProof: ap, ownershipProof: opNew});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofsNew);
        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "transfer after rotation works");
    }

    /// @dev FIND-12: no signature recovers to address(0), so a zero oracle
    ///      would make every ownership proof fail — 1.2.0 refuses it and the
    ///      current oracle stays active.
    function test_setTeeOracleAddress_revertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TEEDataVerifierZeroAddress.selector);
        verifier.setTeeOracleAddress(address(0));
        assertEq(verifier.teeOracleAddress(), oracleAddr, "oracle unchanged");
    }

    /// @dev FIND-12: the rotation is observable on chain — old and new address.
    function test_setTeeOracleAddress_emitsTeeOracleUpdated() public {
        address newOracle = makeAddr("rotated-oracle");
        vm.expectEmit(true, true, false, false, address(verifier));
        emit TEEDataVerifier.TeeOracleUpdated(oracleAddr, newOracle);
        vm.prank(owner);
        verifier.setTeeOracleAddress(newOracle);
        assertEq(verifier.teeOracleAddress(), newOracle, "oracle rotated");
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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        vm.prank(pauser);
        verifier.pause();

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            agentId, sellerWallet.addr, dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            agentId, sellerWallet.addr, dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_unpause_restoresVerifyTransferValidity() public {
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        vm.startPrank(pauser);
        verifier.pause();
        verifier.unpause();
        vm.stopPrank();

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            agentId, sellerWallet.addr, dataHash, "", bytes("ap"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            agentId, sellerWallet.addr, dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op"), deadline
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

    // ── maxProofAge bounds (1.2.0: FIND-07) ──────────────────────────────────

    function test_setMaxProofAge_revertsOnDecrease() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(NonceMaxAgeDecrease.selector, MAX_PROOF_AGE, MAX_PROOF_AGE - 1));
        verifier.setMaxProofAge(MAX_PROOF_AGE - 1);
    }

    /// @dev 0 rejected every proof not expiring in the current second; a value
    ///      near 2^256 overflowed `now + maxAge` and halted every verification.
    function test_initialize_rejectsOutOfRangeMaxProofAge() public {
        address impl = address(new TEEDataVerifier());
        vm.expectRevert(abi.encodeWithSelector(NonceMaxAgeOutOfRange.selector, uint256(0)));
        new ERC1967Proxy(impl, abi.encodeCall(TEEDataVerifier.initialize, (owner, pauser, oracleAddr, 0)));
        vm.expectRevert(abi.encodeWithSelector(NonceMaxAgeOutOfRange.selector, type(uint256).max));
        new ERC1967Proxy(
            impl, abi.encodeCall(TEEDataVerifier.initialize, (owner, pauser, oracleAddr, type(uint256).max))
        );
    }
}
