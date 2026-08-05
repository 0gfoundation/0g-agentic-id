// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticIDSealedAgentUseTransfer} from "../src/AgenticID.sol";
import {
    TEEDataVerifierInvalidSignature,
    TEEDataVerifierWrongOracleType
} from "../src/verifiers/TEEDataVerifier.sol";
import {DataVerifierDataHashMismatch} from "../src/verifiers/BaseDataVerifier.sol";
import {NonceExpired, NonceAlreadyUsed} from "../src/utils/NonceRegistryUpgradeable.sol";
import {IERC7857, SealedKeyEntry} from "../src/interfaces/IERC7857.sol";
import {
    OracleType,
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        // Non-seal agent: the proof-gated path is for seal-less data agents.
        assertEq(agenticId.getAgentSeal(agentId), address(0), "non-seal agent has no seal");
        // sealedKeys are re-wrapped to the new owner and persisted to storage.
        // V2 invariant: post-transfer `sealedKeysOf` returns the NEW wraps,
        // not whatever the prior owner saw. Without this assertion, a regression
        // that drops the _updateSealedKeys hook from iTransferFrom would still
        // pass the event-emit test (events fire from the entries array) while
        // leaving stale wraps in storage — exactly the bug class V2 was meant
        // to eliminate.
        bytes[] memory keysAfter = agenticId.sealedKeysOf(agentId);
        assertEq(keysAfter.length, 1, "one wrap per dim");
        assertEq(keysAfter[0], SEALED_KEY_NEW, "wrap rotated to new owner");
    }

    // ── ITransferred emitted on successful iTransferFrom ─────────────────────
    //
    // Canonical ERC-7857 transfer event — indexers rely on this over plain
    // ERC-721 Transfer to pick up sealedKey payloads.

    function test_iTransferFrom_emitsITransferredEvent() public {
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId1, bytes32 dataHash1) = _selfMintData(sellerWallet.addr, 0);
        (uint256 agentId2, bytes32 dataHash2) = _selfMintData(sellerWallet.addr, 1);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

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
        (uint256 agentId, ) = _selfMintData(sellerWallet.addr, 0);

        TransferValidityProof[] memory proofs = new TransferValidityProof[](0);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857InvalidProof.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    function test_iTransferFrom_revertsOnProofsLengthMismatch() public {
        (uint256 agentId, bytes32[] memory dataHashes) = _selfMintNDatas(sellerWallet.addr, 2);

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

    // ── Plain ERC-721 transfers disabled for NON-SEAL agents ──────────────────

    function test_transferFrom_nonSeal_reverts() public {
        (uint256 agentId, ) = _selfMintData(sellerWallet.addr, 0);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857UseITransferFrom.selector);
        agenticId.transferFrom(sellerWallet.addr, buyerWallet.addr, agentId);
    }

    function test_safeTransferFrom_nonSeal_reverts() public {
        (uint256 agentId, ) = _selfMintData(sellerWallet.addr, 0);

        vm.prank(sellerWallet.addr);
        vm.expectRevert(IERC7857.ERC7857UseITransferFrom.selector);
        agenticId.safeTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId);
    }

    // ── Seal-bound agents: ownership-only transfer; proof path disabled ───────

    function test_sealBound_transferFrom_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(sellerWallet.addr);

        vm.prank(sellerWallet.addr);
        agenticId.transferFrom(sellerWallet.addr, buyerWallet.addr, agentId);

        assertEq(agenticId.ownerOf(agentId), buyerWallet.addr, "seal-bound ownership moved");
        assertEq(agenticId.getAgentSeal(agentId), SEAL_ADDR, "seal retained across transfer");
    }

    function test_sealBound_iTransferFrom_reverts() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;
        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-sb"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-sb"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDSealedAgentUseTransfer.selector, agentId)
        );
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Dynamic-field boundary re-split (encode, not packed) ──────────────────

    /// @dev A buyer signature over one (targetPubkey, nonce) split must NOT be
    ///      valid for a different split. The exploit: the buyer signs an honest
    ///      empty-target proof whose nonce embeds the attacker's pubkey; the
    ///      seller re-splits the identical bytes so targetPubkey becomes the
    ///      attacker's key and the data would seal to the attacker while the
    ///      buyer takes the token. Under packed encoding both splits hashed
    ///      identically and the re-split was honored; under abi.encode the
    ///      length prefix makes the two splits distinct digests, so the buyer's
    ///      signature no longer recovers to the buyer and the transfer reverts.
    function test_iTransferFrom_revertsOnAccessProofBoundaryReSplit() public {
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        Vm.Wallet memory attacker = vm.createWallet("attacker");
        bytes memory kAtt = _pubkey(attacker); // 64-byte pubkey
        bytes memory apTail = hex"42";
        uint256 deadline = block.timestamp + 1 hours;

        // Buyer signs the HONEST split: targetPubkey = "", nonce = kAtt ‖ apTail.
        // (In Ethereum mode the empty target means "seal to my own key".)
        bytes32 innerHonest = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash,
            bytes(""), abi.encodePacked(kAtt, apTail), deadline
        ));
        bytes memory buyerSig = _sign(buyerWallet.privateKey, _eip191HexHash(innerHonest));

        // Seller re-splits the identical bytes and presents targetPubkey = kAtt.
        AccessProof memory apReSplit = AccessProof({
            dataHash: dataHash,
            targetPubkey: kAtt,     // moved boundary (was "")
            nonce: apTail,          // moved boundary (was kAtt ‖ apTail)
            deadline: deadline,
            proof: buyerSig         // unchanged buyer signature
        });
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, kAtt, bytes("op-resplit"), deadline
        );
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: apReSplit, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(); // buyer sig recovers to a non-buyer address → rejected
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);

        assertEq(agenticId.ownerOf(agentId), sellerWallet.addr, "token stayed with seller");
    }

    /// @dev Same class on the oracle side: re-splitting the (sealedKey,
    ///      targetPubkey, nonce) run of the ownership proof must invalidate the
    ///      oracle signature rather than let the stored sealedKey differ from
    ///      what was signed.
    function test_iTransferFrom_revertsOnOwnershipProofBoundaryReSplit() public {
        (uint256 agentId, bytes32 dataHash) = _selfMintData(sellerWallet.addr, 0);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-osplit"), deadline, buyerWallet.privateKey
        );

        // Oracle signs sealedKey = A ‖ B (concatenated); attacker re-splits so
        // the stored sealedKey is just A. abi.encode makes these distinct digests.
        bytes memory keyHead = hex"aaaa";
        bytes memory keyTail = hex"bbbb";
        bytes memory opNonce = bytes("op-osplit");
        bytes32 innerHonest = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash,
            abi.encodePacked(keyHead, keyTail), buyerPubkey, opNonce, deadline
        ));
        bytes memory oracleSig = _sign(oraclePk, _eip191HexHash(innerHonest));

        OwnershipProof memory opReSplit = OwnershipProof({
            oracleType: OracleType.TEE,
            dataHash: dataHash,
            sealedKey: keyHead,   // moved boundary (was keyHead ‖ keyTail)
            targetPubkey: buyerPubkey,
            nonce: opNonce,
            deadline: deadline,
            proof: oracleSig
        });
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: opReSplit});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierInvalidSignature.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    /// @dev Known-answer vector for the AccessProof digest, computed with fixed
    ///      inputs (chain/contract/fields as literals, independent of the test
    ///      chain). This is the canonical reference any off-chain buyer signer —
    ///      which lives outside this repo — must reproduce. If the on-chain
    ///      encoding drifts, this constant changes and the assertion fails.
    function test_accessProofDigest_knownAnswerVector() public pure {
        bytes memory targetPubkey = new bytes(64);
        for (uint256 i = 0; i < 64; i++) targetPubkey[i] = 0x22;
        bytes memory nonce = hex"3333";

        bytes32 digest = keccak256(abi.encode(
            uint256(16602),                                   // chainId
            address(0x00000000000000000000000000000000000000A9), // erc7857
            bytes32(0x1111111111111111111111111111111111111111111111111111111111111111), // dataHash
            targetPubkey,
            nonce,
            uint256(1700003600)                               // deadline
        ));

        assertEq(
            digest,
            0x23cf25e6103163928e91c5c7a4efe48f9a4405856f1b236f15beb4c5d754b0ff,
            "AccessProof digest drifted from the cross-component known-answer vector"
        );
    }
}
