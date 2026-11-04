// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticID, AgenticIDNotTrustedAttestor, AgenticIDZeroAddress} from "../src/AgenticID.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Vm} from "forge-std/Vm.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

contract AgenticIDAdminTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal stranger = address(0xB0B);

    // ── Trusted attestor lifecycle ────────────────────────────────────────────

    function test_addTrustedAttestor_enablesRegisterWithSeal() public {
        assertTrue(!agenticId.isTrustedAttestor(attestor), "not whitelisted initially");
        _whitelistAttestor();
        assertTrue(agenticId.isTrustedAttestor(attestor), "whitelisted");
    }

    function test_removeTrustedAttestor_disablesRegisterWithSeal() public {
        _whitelistAttestor();

        vm.prank(owner);
        agenticId.removeTrustedAttestor(attestor);
        assertTrue(!agenticId.isTrustedAttestor(attestor), "attestor removed");

        // Subsequent registerWithSeal from (now-former) attestor must revert.
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("d")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(alice, "", metadata, datas, sealedKeys, address(0xAA), SEAL_ID);
    }

    function test_addTrustedAttestor_revertsWhenNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger
            )
        );
        agenticId.addTrustedAttestor(attestor);
    }

    // ── validFrameworkHashes lifecycle ────────────────────────────────────────

    function test_frameworkHashes_addRemoveAndQuery() public {
        bytes32 frameworkHashA = keccak256("framework-A");
        bytes32 frameworkHashB = keccak256("framework-B");

        assertTrue(!agenticId.isValidFrameworkHash(frameworkHashA), "initially unknown");

        vm.startPrank(owner);
        agenticId.addValidFrameworkHash(frameworkHashA);
        agenticId.addValidFrameworkHash(frameworkHashB);
        vm.stopPrank();

        assertTrue(agenticId.isValidFrameworkHash(frameworkHashA), "A added");
        assertTrue(agenticId.isValidFrameworkHash(frameworkHashB), "B added");

        vm.prank(owner);
        agenticId.removeValidFrameworkHash(frameworkHashA);
        assertTrue(!agenticId.isValidFrameworkHash(frameworkHashA), "A removed");
        assertTrue(agenticId.isValidFrameworkHash(frameworkHashB), "B still there");
    }

    function test_addValidFrameworkHash_revertsWhenNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger
            )
        );
        agenticId.addValidFrameworkHash(keccak256("fw"));
    }

    // ── setVerifier ───────────────────────────────────────────────────────────

    function test_setVerifier_updatesAddress() public {
        address newVerifier = address(0xDEAD);

        vm.prank(owner);
        agenticId.setVerifier(newVerifier);

        assertEq(address(agenticId.verifier()), newVerifier, "verifier updated");
    }

    function test_setVerifier_revertsWhenNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger
            )
        );
        agenticId.setVerifier(address(0xDEAD));
    }

    /// @dev FIND-12: a zero verifier would brick every proof-gated
    ///      iTransferFrom / iCloneFrom (the call into address(0) fails), so
    ///      1.2.0 refuses it outright and the old verifier stays in place.
    function test_setVerifier_revertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(AgenticIDZeroAddress.selector);
        agenticId.setVerifier(address(0));
        assertEq(address(agenticId.verifier()), address(verifier), "verifier unchanged");
    }

    /// @dev FIND-12: the swap is observable on chain — old and new address.
    function test_setVerifier_emitsVerifierUpdated() public {
        address newVerifier = address(0xDEAD);
        vm.expectEmit(true, true, false, false, address(agenticId));
        emit AgenticID.VerifierUpdated(address(verifier), newVerifier);
        vm.prank(owner);
        agenticId.setVerifier(newVerifier);
    }

    // ── What a pause covers (1.2.0: FIND-11) ─────────────────────────────────

    /// @dev Writes that add or change an agent's canonical record stop while
    ///      paused — including a trusted attestor's URI rewrite, so pausing
    ///      contains a compromised attestor.
    function test_pause_blocksUriMetadataAndWalletWrites() public {
        _whitelistAttestor();
        (uint256 agentId, ) = _mintWithSeal(alice);
        Vm.Wallet memory payment = vm.createWallet("payment");
        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(payment, agentId, deadline);

        vm.prank(pauser);
        agenticId.pause();

        vm.prank(alice);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.setAgentURI(agentId, "ipfs://owner");
        vm.prank(attestor);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.setAgentURI(agentId, "ipfs://attestor");
        vm.prank(alice);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.setMetadata(agentId, "k", bytes("v"));
        vm.prank(alice);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.setAgentWallet(agentId, payment.addr, deadline, sig);
        vm.prank(alice);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        agenticId.authorizeUsage(agentId, stranger);

        vm.prank(pauser);
        agenticId.unpause();
        vm.prank(alice);
        agenticId.setAgentWallet(agentId, payment.addr, deadline, sig);
        assertEq(agenticId.getAgentWallet(agentId), payment.addr, "writes resume after unpause");
    }

    /// @dev Actions that only take a privilege away stay open while paused, so
    ///      an owner can still defend during an incident.
    function test_pause_allowsRevocations() public {
        _whitelistAttestor();
        (uint256 agentId, ) = _mintWithSeal(alice);
        Vm.Wallet memory payment = vm.createWallet("payment");
        uint256 deadline = block.timestamp + 4 minutes;
        bytes memory sig = _signSetAgentWallet(payment, agentId, deadline);
        address userA = address(0xA10);
        address userB = address(0xB20);
        vm.startPrank(alice);
        agenticId.setAgentWallet(agentId, payment.addr, deadline, sig);
        agenticId.authorizeUsage(agentId, userA);
        agenticId.authorizeUsage(agentId, userB);
        vm.stopPrank();

        vm.prank(pauser);
        agenticId.pause();

        vm.startPrank(alice);
        agenticId.revokeAuthorization(agentId, userA);
        agenticId.clearAuthorizedUsers(agentId);
        agenticId.unsetAgentWallet(agentId);
        vm.stopPrank();

        assertEq(agenticId.authorizedUsersOf(agentId).length, 0, "authorizations cleared while paused");
        assertEq(agenticId.getAgentWallet(agentId), address(0), "wallet unset while paused");
    }
}
