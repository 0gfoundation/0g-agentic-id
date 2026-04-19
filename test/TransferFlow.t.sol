// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {AgenticID} from "../contracts/AgenticID.sol";
import {
    TEEDataVerifier,
    TEEDataVerifierInvalidSignature,
    TEEDataVerifierWrongOracleType
} from "../contracts/verifiers/TEEDataVerifier.sol";
import {DataVerifierDataHashMismatch} from "../contracts/verifiers/BaseDataVerifier.sol";
import {NonceExpired, NonceAlreadyUsed} from "../contracts/utils/NonceRegistryUpgradeable.sol";
import {IERC7857} from "../contracts/interfaces/IERC7857.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";
import {
    OracleType,
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../contracts/interfaces/IERC7857DataVerifier.sol";

contract TransferFlowTest is Test {
    AgenticID internal agenticId;
    TEEDataVerifier internal verifier;

    address internal owner = address(0xA11CE);
    address internal attestor = address(0xA77E57);
    address internal oracleAddr;
    uint256 internal oraclePk;

    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    uint256 internal constant MAX_PROOF_AGE = 1 days;
    bytes32 internal constant SEAL_ID = bytes32(uint256(0xBEEF));
    address internal constant SEAL_ADDR = address(0xAA);

    bytes internal constant SEALED_KEY_ORIGINAL = hex"cafe";
    bytes internal constant SEALED_KEY_NEW = hex"deadbeef";

    function setUp() public {
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");

        TEEDataVerifier verifierImpl = new TEEDataVerifier();
        ERC1967Proxy verifierProxy = new ERC1967Proxy(
            address(verifierImpl),
            abi.encodeCall(TEEDataVerifier.initialize, (owner, oracleAddr, MAX_PROOF_AGE))
        );
        verifier = TEEDataVerifier(address(verifierProxy));

        AgenticID agenticIdImpl = new AgenticID();
        ERC1967Proxy agenticIdProxy = new ERC1967Proxy(
            address(agenticIdImpl),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(verifier), owner, MAX_PROOF_AGE)
            )
        );
        agenticId = AgenticID(address(agenticIdProxy));

        vm.prank(owner);
        agenticId.addTrustedAttestor(attestor);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev 64-byte uncompressed secp256k1 pubkey (publicKeyX ‖ publicKeyY).
    function _pubkey(Vm.Wallet memory wallet) internal pure returns (bytes memory) {
        return abi.encodePacked(wallet.publicKeyX, wallet.publicKeyY);
    }

    /// @dev Replicates BaseDataVerifier._eip191Hash — hex-encodes the inner hash
    ///      so the message is human-readable in wallet prompts.
    function _eip191Hex(bytes32 inner) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n66",
                Strings.toHexString(uint256(inner), 32)
            )
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _mkAccessProof(
        bytes32 dataHash,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline,
        uint256 signerPk
    ) internal pure returns (AccessProof memory) {
        bytes32 inner = keccak256(abi.encodePacked(dataHash, targetPubkey, nonce, deadline));
        return AccessProof({
            dataHash: dataHash,
            targetPubkey: targetPubkey,
            nonce: nonce,
            deadline: deadline,
            proof: _sign(signerPk, _eip191Hex(inner))
        });
    }

    function _mkOwnershipProof(
        bytes32 dataHash,
        bytes memory sealedKey,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline
    ) internal view returns (OwnershipProof memory) {
        bytes32 inner =
            keccak256(abi.encodePacked(dataHash, sealedKey, targetPubkey, nonce, deadline));
        return OwnershipProof({
            oracleType: OracleType.TEE,
            dataHash: dataHash,
            sealedKey: sealedKey,
            targetPubkey: targetPubkey,
            nonce: nonce,
            deadline: deadline,
            proof: _sign(oraclePk, _eip191Hex(inner))
        });
    }

    function _mintWithSeal(address to) internal returns (uint256 agentId, bytes32 dataHash) {
        return _mintWithSealSalt(to, 0);
    }

    /// @dev Salt disambiguates sealId/sealAddr so multiple agents can coexist.
    function _mintWithSealSalt(address to, uint256 salt)
        internal
        returns (uint256 agentId, bytes32 dataHash)
    {
        bytes32 sealId = bytes32(uint256(SEAL_ID) + salt);
        address sealAddr = address(uint160(uint160(SEAL_ADDR) + salt));
        dataHash = keccak256(abi.encode("data", to, salt));

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "", metadata, datas, sealedKeys, sealAddr, sealId
        );
    }

    function _mintWithNDatas(address to, uint256 n)
        internal
        returns (uint256 agentId, bytes32[] memory dataHashes)
    {
        dataHashes = new bytes32[](n);
        IntelligentData[] memory datas = new IntelligentData[](n);
        bytes[] memory sealedKeys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            dataHashes[i] = keccak256(abi.encode("data-multi", to, i));
            datas[i] = IntelligentData({dataDescription: "d", dataHash: dataHashes[i]});
            sealedKeys[i] = abi.encodePacked(hex"cafe", bytes32(i));
        }
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "", metadata, datas, sealedKeys, SEAL_ADDR, SEAL_ID
        );
    }

    function _mkOwnershipProofSignedBy(
        bytes32 dataHash,
        bytes memory sealedKey,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline,
        uint256 signerPk
    ) internal pure returns (OwnershipProof memory) {
        bytes32 inner =
            keccak256(abi.encodePacked(dataHash, sealedKey, targetPubkey, nonce, deadline));
        return OwnershipProof({
            oracleType: OracleType.TEE,
            dataHash: dataHash,
            sealedKey: sealedKey,
            targetPubkey: targetPubkey,
            nonce: nonce,
            deadline: deadline,
            proof: _sign(signerPk, _eip191Hex(inner))
        });
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

        // Ethereum mode: AccessProof.targetPubkey is empty.
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

    // ── dataHash mismatch rejection ───────────────────────────────────────────

    function test_iTransferFrom_revertsOnDataHashMismatch() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            keccak256("wrong-hash"), // mismatch
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

        // AccessProof signed by delegate, not buyer — but wantedKey/targetPubkey
        // still target buyer so sealedKey is re-encrypted to buyer's key.
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

        // Random wallet that is neither `to` nor buyer's delegate.
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

        // Advance time past the 1-hour deadline before submitting.
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
        // Two independent agents so the second transfer has a live target token.
        (uint256 agentId1, bytes32 dataHash1) = _mintWithSealSalt(sellerWallet.addr, 0);
        (uint256 agentId2, bytes32 dataHash2) = _mintWithSealSalt(sellerWallet.addr, 1);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory buyerPubkey = _pubkey(buyerWallet);
        bytes memory sharedNonce = bytes("replay-nonce");

        // First transfer consumes the nonce.
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

        // Second transfer reuses sharedNonce for AccessProof — must fail.
        AccessProof memory ap2 = _mkAccessProof(
            dataHash2, "", sharedNonce, deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op2 = _mkOwnershipProof(
            dataHash2, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce-2"), deadline
        );
        TransferValidityProof[] memory proofs2 = new TransferValidityProof[](1);
        proofs2[0] = TransferValidityProof({accessProof: ap2, ownershipProof: op2});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(); // NonceAlreadyUsed(key) — key depends on msg.sender + nonce
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
        // Signed by a key that isn't `teeOracleAddress`.
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
        op.oracleType = OracleType.ZKP; // TEE verifier rejects non-TEE

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        vm.expectRevert(TEEDataVerifierWrongOracleType.selector);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── Custom-pubkey mode ────────────────────────────────────────────────────

    function test_iTransferFrom_customMode_succeeds() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSeal(sellerWallet.addr);

        // Arbitrary non-empty custom pubkey (e.g. an ECIES x25519 pubkey).
        bytes memory customPubkey = hex"01020304050607080910111213141516";
        uint256 deadline = block.timestamp + 1 hours;

        // Custom mode: AccessProof.targetPubkey == OwnershipProof.targetPubkey != "".
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
        bytes memory opCustomKey = hex"deadbeef"; // mismatch
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

        // 63-byte pubkey — wantedKey is empty so eth mode kicks in, length check fails.
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

        // Transfer to a different address than the one the pubkey derives to.
        Vm.Wallet memory otherReceiver = vm.createWallet("other-receiver");

        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        // AccessProof must be signed by `to` (otherReceiver), not buyer.
        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, otherReceiver.privateKey
        );
        // OwnershipProof targets buyerPubkey (derives to buyerWallet.addr, NOT otherReceiver.addr).
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
        // Agent has 2 IntelligentData entries; submit only 1 proof.
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
