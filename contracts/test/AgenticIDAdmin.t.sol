// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticIDNotTrustedAttestor} from "../src/AgenticID.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
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
}
