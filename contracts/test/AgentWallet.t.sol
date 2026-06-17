// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice setAgentWallet is forwarded to the canonical ERC-8004 registry, which
///         enforces the official consent scheme: a 4-arg EIP-712 signature from
///         newWallet over AgentWalletSet(agentId,newWallet,owner,deadline) with
///         owner = the AgenticID contract (canonical token holder), and a
///         deadline capped at now + 5 minutes. There is no nonce; the canonical
///         contract simply overwrites the stored wallet idempotently.
contract AgentWalletTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    Vm.Wallet internal paymentWallet;

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        paymentWallet = vm.createWallet("payment");
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_setAgentWallet_succeedsWithValidSig() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);

        assertEq(agenticId.getAgentWallet(agentId), paymentWallet.addr, "wallet registered");
    }

    // ── Signature authenticity ────────────────────────────────────────────────

    function test_setAgentWallet_revertsOnWrongSigner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        Vm.Wallet memory stranger = vm.createWallet("stranger");
        uint256 deadline = block.timestamp + 4 minutes;

        // Signature made by `stranger` but wallet target is `paymentWallet.addr`
        // → recovered signer ≠ newWallet, ERC1271 fallback fails → canonical reverts.
        bytes memory sig = _signSetAgentWallet(stranger, agentId, deadline);

        vm.prank(alice);
        vm.expectRevert(bytes("invalid wallet sig"));
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);
    }

    // ── Deadline ──────────────────────────────────────────────────────────────

    function test_setAgentWallet_revertsOnExpiredDeadline() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.warp(deadline + 1);

        vm.prank(alice);
        vm.expectRevert(bytes("expired"));
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);
    }

    function test_setAgentWallet_revertsOnDeadlineTooFar() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        // Official contract caps deadline at now + 5 minutes.
        uint256 deadline = block.timestamp + 6 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.prank(alice);
        vm.expectRevert(bytes("deadline too far"));
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);
    }

    // ── Idempotent overwrite (no nonce in the official scheme) ─────────────────

    function test_setAgentWallet_overwritesOnSecondCall() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);

        Vm.Wallet memory wallet2 = vm.createWallet("payment2");
        bytes memory sig2 = _signSetAgentWallet(wallet2, agentId, deadline);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, wallet2.addr, deadline, sig2);

        assertEq(agenticId.getAgentWallet(agentId), wallet2.addr, "wallet overwritten");
    }

    // ── Non-owner rejected (local check in AgenticID, before forwarding) ───────

    function test_setAgentWallet_revertsWhenNotAgentOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);
    }

    // ── unsetAgentWallet by owner ─────────────────────────────────────────────

    function test_unsetAgentWallet_byOwner_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, sig);

        vm.prank(alice);
        agenticId.unsetAgentWallet(agentId);

        assertEq(agenticId.getAgentWallet(agentId), address(0), "wallet unset");
    }

    function test_unsetAgentWallet_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.unsetAgentWallet(agentId);
    }
}
