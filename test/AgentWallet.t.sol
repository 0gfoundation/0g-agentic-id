// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {ERC8004InvalidWalletSignature} from "../contracts/ERC8004IdentityRegistryUpgradeable.sol";
import {NonceExpired, NonceAlreadyUsed} from "../contracts/utils/NonceRegistryUpgradeable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

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

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("wallet-nonce");
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);

        assertEq(agenticId.getAgentWallet(agentId), paymentWallet.addr, "wallet registered");
    }

    // ── Signature authenticity ────────────────────────────────────────────────

    function test_setAgentWallet_revertsOnWrongSigner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        Vm.Wallet memory stranger = vm.createWallet("stranger");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n");

        // Signature made by `stranger` but wallet target is `paymentWallet.addr`
        // → recovered signer ≠ newWallet → revert.
        bytes memory sig = _signSetAgentWallet(stranger, agentId, deadline, nonce);

        vm.prank(alice);
        vm.expectRevert(ERC8004InvalidWalletSignature.selector);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);
    }

    // ── Deadline ──────────────────────────────────────────────────────────────

    function test_setAgentWallet_revertsOnExpiredDeadline() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = 3601;                       // literal, opt-proof
        bytes32 nonce = keccak256("n");
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);

        vm.warp(deadline + 1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(NonceExpired.selector, deadline, block.timestamp)
        );
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);
    }

    // ── Replay ────────────────────────────────────────────────────────────────

    function test_setAgentWallet_revertsOnReplayedNonce() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n");
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);

        vm.prank(alice);
        vm.expectRevert();
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);
    }

    // ── Non-owner rejected ────────────────────────────────────────────────────

    function test_setAgentWallet_revertsWhenNotAgentOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n");
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);
    }

    // ── unsetAgentWallet by owner ─────────────────────────────────────────────

    function test_unsetAgentWallet_byOwner_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n");
        bytes memory sig = _signSetAgentWallet(paymentWallet, agentId, deadline, nonce);

        vm.prank(alice);
        agenticId.setAgentWallet(agentId, paymentWallet.addr, deadline, nonce, sig);

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
