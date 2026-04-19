// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    TEEDataVerifierInvalidSignature,
    TEEDataVerifierWrongOracleType
} from "../contracts/verifiers/TEEDataVerifier.sol";
import {DataVerifierDataHashMismatch} from "../contracts/verifiers/BaseDataVerifier.sol";
import {NonceExpired, NonceAlreadyUsed} from "../contracts/utils/NonceRegistryUpgradeable.sol";
import {IERC7857, SealedKeyEntry} from "../contracts/interfaces/IERC7857.sol";
import {
    OracleType,
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../contracts/interfaces/IERC7857DataVerifier.sol";

contract TransferFlowTest is AgenticIDTestBase {
    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");
    }

    // ── Ethereum-mode happy path ──────────────────────────────────────────────

    function test_iTransferFrom_ethMode_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        assertEq(
            address(uint160(uint256(keccak256(buyerPubkey)))),
            buyerWallet.addr,
            "pubkey derivation must match buyer addr"
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory apNonce = bytes("ap-nonce-1");
        bytes memory opNonce = bytes("op-nonce-1");

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", apNonce, deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, opNonce, deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);

        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "ownership moved");
        assertEq(agenticId.getAgentSeal(agentId), SEAL_ADDR, "seal preserved across transfer");
        assertEq(agenticId.getSealId(agentId), SEAL_ID, "sealId preserved across transfer");
    }

    // ── ITransferred emitted on successful iTransferFrom ─────────────────────
    //
    // Canonical ERC-7857 transfer event — indexers rely on this over plain
    // ERC-721 Transfer to pick up sealedKey payloads.

    function test_iTransferFrom_emitsITransferredEvent() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-emit"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-emit"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        SealedKeyEntry[] memory expectedEntries = new SealedKeyEntry[](1);
        expectedEntries[0] = SealedKeyEntry({dataHash: dataHash, sealedKey: SEALED_KEY_NEW});

        vm.expectEmit(true, true, true, true);
        emit IERC7857.ITransferred(sellerWallet.addr, buyerWallet.addr, agentId, expectedEntries);

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── dataHash mismatch rejection ───────────────────────────────────────────

    function test_iTransferFrom_revertsOnDataHashMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            keccak256("wrong-hash"),
            SEALED_KEY_NEW,
            buyerPubkey,
            bytes("op-nonce"),
            deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(DataVerifierDataHashMismatch.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Delegate-signed AccessProof ───────────────────────────────────────────

    function test_iTransferFrom_ethMode_signedByDelegate_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        Vm.Wallet memory delegateWallet = vm.createWallet("delegate");
        vm.prank(buyerWallet.addr);
        agenticId.setAccessDelegate(delegateWallet.addr);
        assertEq(
            agenticId.getAccessDelegate(buyerWallet.addr),
            delegateWallet.addr,
            "delegate registered"
        );

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, delegateWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);

        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "ownership moved to buyer");
    }

    function test_iTransferFrom_revertsWhenSignedByUnregisteredDelegate() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        Vm.Wallet memory strangerWallet = vm.createWallet("stranger");

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, strangerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Expired deadline ──────────────────────────────────────────────────────

    function test_iTransferFrom_revertsOnExpiredAccessDeadline() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory buyerPubkey = _pubkey(buyerWallet);

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.warp(deadline + 1);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(NonceExpired.selector, deadline, block.timestamp)
        );
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Nonce replay ──────────────────────────────────────────────────────────

    function test_iTransferFrom_revertsOnAccessNonceReplay() public {
        (uint256 agentId1, bytes32 dataHash1) = _mintWithSealSalt(sellerWallet.addr, 0);
        (uint256 agentId2, bytes32 dataHash2) = _mintWithSealSalt(sellerWallet.addr, 1);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory buyerPubkey = _pubkey(buyerWallet);
        bytes memory sharedNonce = bytes("replay-nonce");

        AccessProof memory ap1 = _mkAccessProof(
            dataHash1, "", sharedNonce, deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op1 = _mkOwnershipProof(
            dataHash1, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce-1"), deadline
        );
        TransferValidityProof[] memory proofs1 = new TransferValidityProof[](1);
        proofs1[0] = TransferValidityProof({accessProof: ap1, ownershipProof: op1});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId1, proofs1);

        AccessProof memory ap2 = _mkAccessProof(
            dataHash2, "", sharedNonce, deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op2 = _mkOwnershipProof(
            dataHash2, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce-2"), deadline
        );
        TransferValidityProof[] memory proofs2 = new TransferValidityProof[](1);
        proofs2[0] = TransferValidityProof({accessProof: ap2, ownershipProof: op2});

        vm.prank(sellerWallet.addr);
        // Partial match: NonceAlreadyUsed(bytes32 key) carries the specific key,
        // but the selector alone is enough to prove we hit the replay guard.
        vm.expectPartialRevert(NonceAlreadyUsed.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId2, proofs2);
    }

    // ── Oracle signature attacks ──────────────────────────────────────────────

    function test_iTransferFrom_revertsOnNonOracleSigner() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        (, uint256 imposterPk) = makeAddrAndKey("imposter-oracle");
        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProofSignedBy(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline, imposterPk
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierInvalidSignature.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_iTransferFrom_revertsOnWrongOracleType() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );
        op.oracleType = OracleType.ZKP;

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierWrongOracleType.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Custom-pubkey mode ────────────────────────────────────────────────────

    function test_iTransferFrom_customMode_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory customPubkey = hex"01020304050607080910111213141516";
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, customPubkey, bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, customPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);

        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "custom mode transfer worked");
    }

    function test_iTransferFrom_revertsOnCustomModeKeyMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory apCustomKey = hex"01020304";
        bytes memory opCustomKey = hex"deadbeef";
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, apCustomKey, bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, opCustomKey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Ethereum-mode pubkey validation ───────────────────────────────────────

    function test_iTransferFrom_revertsOnShortTargetPubkey() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory shortPubkey = new bytes(63);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, shortPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_iTransferFrom_revertsOnPubkeyNotMatchingTo() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        Vm.Wallet memory otherReceiver = vm.createWallet("other-receiver");

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, otherReceiver.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, otherReceiver.addr, agentId, proofs);
    }

    // ── Proof array shape validation ──────────────────────────────────────────

    function test_iTransferFrom_revertsOnEmptyProofs() public {
        (uint256 agentId, ) = _mintWithSeal(sellerWallet.addr);

        TransferValidityProof[] memory proofs = new TransferValidityProof[](0);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_iTransferFrom_revertsOnProofsLengthMismatch() public {
        (uint256 agentId, bytes32[] memory dataHashes) = _mintWithNDatas(sellerWallet.addr, 2);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHashes[0], "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHashes[0], SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Disabled ERC-721 transfers ────────────────────────────────────────────

    function test_transferFrom_disabled_reverts() public {
        (uint256 agentId, ) = _mintWithSeal(sellerWallet.addr);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857UseITransferFrom.selector);
        agenticId.transferFrom(sellerWallet.addr, buyerWallet.addr, agentId);
    }

    function test_safeTransferFrom_disabled_reverts() public {
        (uint256 agentId, ) = _mintWithSeal(sellerWallet.addr);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857UseITransferFrom.selector);
        agenticId.safeTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId);
    }
}
