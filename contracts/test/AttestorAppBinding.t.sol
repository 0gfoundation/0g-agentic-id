// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IAttestorAppRegistry, AgenticIDNotTrustedAttestor} from "../src/AgenticID.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

contract AttestorRegistryMock is IAttestorAppRegistry {
    uint256 public epoch = 100;
    bool public failing;
    address public appOwner = address(1);

    function setEpoch(uint256 value) external {
        epoch = value;
    }

    function setOwner(address value) external {
        appOwner = value;
    }

    function setFailing(bool value) external {
        failing = value;
    }

    function getAppInfo(string calldata) external view returns (AppInfo memory info) {
        require(!failing, "registry unavailable");
        info.owner = epoch == 0 ? address(0) : appOwner;
        info.registeredAt = epoch;
    }
}

contract AttestorAppBindingTest is AgenticIDTestBase {
    AttestorRegistryMock internal registry;

    function setUp() public override {
        super.setUp();
        registry = new AttestorRegistryMock();
    }

    function bind() internal {
        vm.prank(owner);
        agenticId.bindTrustedAttestorApp(attestor, address(registry), "attestor", 100);
    }

    function test_recycledAppDoesNotInheritStableKeyAuthorization() public {
        bind();
        assertTrue(agenticId.isTrustedAttestor(attestor));
        registry.setEpoch(101);
        assertFalse(agenticId.isTrustedAttestor(attestor));
        IntelligentData[] memory datas = new IntelligentData[](0);
        bytes[] memory keys = new bytes[](0);
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(owner, "", metadata, datas, keys, SEAL_ADDR, SEAL_ID);
    }

    function test_registryFailureAndUnregistrationDeny() public {
        bind();
        registry.setFailing(true);
        assertFalse(agenticId.isTrustedAttestor(attestor));
        registry.setFailing(false);
        registry.setEpoch(0);
        assertFalse(agenticId.isTrustedAttestor(attestor));
    }

    function test_sameTimestampDifferentOwnerDoesNotInheritAuthorization() public {
        bind();
        registry.setOwner(address(2));
        assertFalse(agenticId.isTrustedAttestor(attestor));
    }

    function test_migrationRequiresBindingsAndCannotReenableLegacyWithAdd() public {
        _whitelistAttestor();
        assertTrue(agenticId.isTrustedAttestor(attestor));
        vm.prank(owner);
        agenticId.requireInstanceBoundAttestors();
        assertFalse(agenticId.isTrustedAttestor(attestor));
        _whitelistAttestor();
        assertFalse(agenticId.isTrustedAttestor(attestor));
        bind();
        assertTrue(agenticId.isTrustedAttestor(attestor));
    }

    function test_removeClearsBindingAndWrongEpochCannotBind() public {
        vm.prank(owner);
        vm.expectRevert("app instance mismatch");
        agenticId.bindTrustedAttestorApp(attestor, address(registry), "attestor", 99);
        bind();
        vm.prank(owner);
        agenticId.removeTrustedAttestor(attestor);
        (address addr,, uint256 epoch,) = agenticId.trustedAttestorAppBinding(attestor);
        assertEq(addr, address(0));
        assertEq(epoch, 0);
        assertFalse(agenticId.isTrustedAttestor(attestor));
    }
}
