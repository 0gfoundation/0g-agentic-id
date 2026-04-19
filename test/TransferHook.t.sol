// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../contracts/interfaces/IERC7857DataVerifier.sol";

/// @notice Verifies the side-effects of iTransferFrom's _update hook chain:
///           • agentWallet is cleared
///           • authorizedUsers is cleared
///           • agentSeal / sealId / IntelligentData / metadata / URI are preserved
contract TransferHookTest is AgenticIDTestBase {
    Vm.Wallet internal sellerWallet;
    Vm.Wallet internal buyerWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        sellerWallet = vm.createWallet("seller");
        buyerWallet = vm.createWallet("buyer");
    }

    /// @dev Like base's `_mintWithSeal` but adds URI + metadata so we can
    ///      check that those survive transfer.
    function _mintWithSealAndMetadata(address to)
        internal
        returns (uint256 agentId, bytes32 dataHash)
    {
        dataHash = keccak256(abi.encode("data", to));
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;

        MetadataEntry[] memory metadata = new MetadataEntry[](1);
        metadata[0] = MetadataEntry({metadataKey: "category", metadataValue: bytes("inference")});

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "ipfs://agent-uri", metadata, datas, sealedKeys, SEAL_ADDR, SEAL_ID
        );
    }

    function _performTransfer(uint256 agentId, bytes32 dataHash) internal {
        bytes memory buyerPubkey = _pubkey(buyerWallet);
        uint256 deadline = block.timestamp + 1 hours;

        AccessProof memory ap = _mkAccessProof(
            dataHash, "", bytes("ap-nonce"), deadline, buyerWallet.privateKey
        );
        OwnershipProof memory op = _mkOwnershipProof(
            dataHash, SEALED_KEY_NEW, buyerPubkey, bytes("op-nonce"), deadline
        );

        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});

        vm.prank(sellerWallet.addr);
        agenticId.iTransferFrom(sellerWallet.addr, buyerWallet.addr, agentId, proofs);
    }

    // ── agentWallet cleared on transfer ───────────────────────────────────────

    function test_transfer_clearsAgentWallet() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealAndMetadata(sellerWallet.addr);

        Vm.Wallet memory paymentWallet = vm.createWallet("payment");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("wallet-nonce");

        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);
        vm.prank(sellerWallet.addr);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);
        assertEq(agenticId.getAgentWallet(agentId), paymentWallet.addr, "wallet set pre-transfer");

        _performTransfer(agentId, dataHash);

        assertEq(agenticId.getAgentWallet(agentId), address(0), "agentWallet cleared");
    }

    // ── authorizedUsers cleared on transfer ───────────────────────────────────

    function test_transfer_clearsAuthorizedUsers() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealAndMetadata(sellerWallet.addr);

        address userA = address(0xA1);
        address userB = address(0xB2);
        vm.startPrank(sellerWallet.addr);
        agenticId.authorizeUsage(agentId, userA);
        agenticId.authorizeUsage(agentId, userB);
        vm.stopPrank();

        address[] memory before_ = agenticId.authorizedUsersOf(agentId);
        assertEq(before_.length, 2, "two users authorized pre-transfer");

        _performTransfer(agentId, dataHash);

        address[] memory after_ = agenticId.authorizedUsersOf(agentId);
        assertEq(after_.length, 0, "authorizedUsers cleared post-transfer");
    }

    // ── seal / sealId preserved across transfer ───────────────────────────────

    function test_transfer_preservesSealAndSealId() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealAndMetadata(sellerWallet.addr);

        _performTransfer(agentId, dataHash);

        assertEq(agenticId.getAgentSeal(agentId), SEAL_ADDR, "seal preserved");
        assertEq(agenticId.getSealId(agentId), SEAL_ID, "sealId preserved");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID), agentId, "reverse mapping intact");
    }

    // ── IntelligentData / agentURI / metadata preserved ───────────────────────

    function test_transfer_preservesDataUriAndMetadata() public {
        (uint256 agentId, bytes32 dataHash) = _mintWithSealAndMetadata(sellerWallet.addr);

        _performTransfer(agentId, dataHash);

        IntelligentData[] memory datas = agenticId.intelligentDatasOf(agentId);
        assertEq(datas.length, 1, "IntelligentData preserved");
        assertEq(datas[0].dataHash, dataHash, "dataHash preserved");

        assertEq(agenticId.tokenURI(agentId), "ipfs://agent-uri", "agentURI preserved");
        assertEq(
            agenticId.getMetadata(agentId, "category"),
            bytes("inference"),
            "metadata preserved"
        );
    }
}
