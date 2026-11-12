// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {
    TrustRegistry,
    TrustRegistryZeroValue,
    TrustRegistryAlreadyListed,
    TrustRegistryNotListed
} from "../src/TrustRegistry.sol";

/// @notice The TrustRegistry's code lists and its owner surface. Attestor
///         trust and app bindings are covered in AttestorAppBinding.t.sol.
contract TrustRegistryTest is Test {
    TrustRegistry internal reg;
    address internal owner = address(0xA11CE);
    address internal stranger = address(0xB0B);

    bytes32 internal imageKind;
    bytes32 internal sealedKind;
    bytes32 internal harnessKind;

    event Listed(bytes32 indexed kind, bytes32 indexed hash);
    event Delisted(bytes32 indexed kind, bytes32 indexed hash);

    function setUp() public {
        reg = TrustRegistry(address(new ERC1967Proxy(
            address(new TrustRegistry()), abi.encodeCall(TrustRegistry.initialize, (owner))
        )));
        imageKind = reg.IMAGE();
        sealedKind = reg.SEALED();
        harnessKind = reg.HARNESS();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _h(uint256 i) internal pure returns (bytes32) {
        return bytes32(i);
    }

    function _list(bytes32 kind, bytes32 hash) internal {
        vm.prank(owner);
        reg.list(kind, hash);
    }

    function _delist(bytes32 kind, bytes32 hash) internal {
        vm.prank(owner);
        reg.delist(kind, hash);
    }

    function _hashes(uint256 a, uint256 b, uint256 c) internal pure returns (bytes32[] memory out) {
        uint256 n = (a == 0 ? 0 : 1) + (b == 0 ? 0 : 1) + (c == 0 ? 0 : 1);
        out = new bytes32[](n);
        uint256 i;
        if (a != 0) out[i++] = bytes32(a);
        if (b != 0) out[i++] = bytes32(b);
        if (c != 0) out[i++] = bytes32(c);
    }

    /// @dev The whole list in order, its latest entry, and isListed agree.
    function _assertList(bytes32 kind, bytes32[] memory want) internal view {
        bytes32[] memory got = reg.listed(kind);
        assertEq(got.length, want.length, "length");
        for (uint256 i; i < want.length; ++i) {
            assertEq(got[i], want[i], "listing order");
            assertTrue(reg.isListed(kind, want[i]), "isListed");
        }
        assertEq(reg.latest(kind), want.length == 0 ? bytes32(0) : want[want.length - 1], "latest");
    }

    // ── Basics ────────────────────────────────────────────────────────────────

    function test_kindsAndVersion() public view {
        assertEq(imageKind, keccak256("image"));
        assertEq(sealedKind, keccak256("sealed"));
        assertEq(harnessKind, keccak256("harness"));
        assertEq(reg.VERSION(), "1.0.0");
        assertEq(reg.owner(), owner);
    }

    function test_emptyList() public view {
        _assertList(sealedKind, new bytes32[](0));
        assertFalse(reg.isListed(sealedKind, _h(1)));
    }

    // ── Listing order and latest ──────────────────────────────────────────────

    function test_list_keepsListingOrderAndLatest() public {
        _list(sealedKind, _h(1));
        _list(sealedKind, _h(2));
        _list(sealedKind, _h(3));
        _assertList(sealedKind, _hashes(1, 2, 3));
        assertFalse(reg.isListed(harnessKind, _h(2)), "kinds are separate lists");
        assertEq(reg.latest(harnessKind), bytes32(0));
    }

    function test_delist_middleTailAndHeadKeepTheRestInOrder() public {
        _list(sealedKind, _h(1));
        _list(sealedKind, _h(2));
        _list(sealedKind, _h(3));
        _list(sealedKind, _h(4));

        _delist(sealedKind, _h(2)); // middle
        bytes32[] memory a = new bytes32[](3);
        (a[0], a[1], a[2]) = (_h(1), _h(3), _h(4));
        _assertList(sealedKind, a);
        assertFalse(reg.isListed(sealedKind, _h(2)));

        _delist(sealedKind, _h(4)); // the latest: the one before takes over
        _assertList(sealedKind, _hashes(1, 3, 0));

        _delist(sealedKind, _h(1)); // head
        _assertList(sealedKind, _hashes(3, 0, 0));

        _delist(sealedKind, _h(3)); // the last one
        _assertList(sealedKind, new bytes32[](0));
    }

    function test_relist_becomesTheLatest() public {
        _list(harnessKind, _h(1));
        _list(harnessKind, _h(2));
        _delist(harnessKind, _h(1));
        _list(harnessKind, _h(1));
        _assertList(harnessKind, _hashes(2, 1, 0));
    }

    function test_anyKindWorks() public {
        bytes32 policy = keccak256("policy");
        _list(policy, _h(9));
        _assertList(policy, _hashes(9, 0, 0));
    }

    // ── Errors and access ─────────────────────────────────────────────────────

    function test_list_rejectsZeroAndDuplicates_delistRejectsUnlisted() public {
        vm.startPrank(owner);
        vm.expectRevert(TrustRegistryZeroValue.selector);
        reg.list(sealedKind, bytes32(0));
        vm.expectRevert(TrustRegistryZeroValue.selector);
        reg.list(bytes32(0), _h(1));
        reg.list(sealedKind, _h(1));
        vm.expectRevert(abi.encodeWithSelector(TrustRegistryAlreadyListed.selector, sealedKind, _h(1)));
        reg.list(sealedKind, _h(1));
        vm.expectRevert(abi.encodeWithSelector(TrustRegistryNotListed.selector, sealedKind, _h(2)));
        reg.delist(sealedKind, _h(2));
        vm.expectRevert(abi.encodeWithSelector(TrustRegistryNotListed.selector, harnessKind, _h(1)));
        reg.delist(harnessKind, _h(1));
        vm.stopPrank();
    }

    function test_ownerOnly() public {
        bytes memory unauthorized =
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger);
        vm.startPrank(stranger);
        vm.expectRevert(unauthorized);
        reg.list(sealedKind, _h(1));
        vm.expectRevert(unauthorized);
        reg.delist(sealedKind, _h(1));
        vm.expectRevert(unauthorized);
        reg.addTrustedAttestor(stranger);
        vm.expectRevert(unauthorized);
        reg.removeTrustedAttestor(stranger);
        vm.expectRevert(unauthorized);
        reg.requireInstanceBoundAttestors();
        vm.stopPrank();
    }

    function test_listAndDelistEmit() public {
        vm.expectEmit(true, true, false, false, address(reg));
        emit Listed(sealedKind, _h(7));
        _list(sealedKind, _h(7));
        vm.expectEmit(true, true, false, false, address(reg));
        emit Delisted(sealedKind, _h(7));
        _delist(sealedKind, _h(7));
    }

    // ── multicall ─────────────────────────────────────────────────────────────

    function test_multicall_batchesOwnerCalls() public {
        bytes[] memory calls = new bytes[](3);
        calls[0] = abi.encodeCall(TrustRegistry.addTrustedAttestor, (address(0xA77)));
        calls[1] = abi.encodeCall(TrustRegistry.list, (imageKind, _h(1)));
        calls[2] = abi.encodeCall(TrustRegistry.list, (imageKind, _h(2)));
        vm.prank(owner);
        reg.multicall(calls);
        assertTrue(reg.isTrustedAttestor(address(0xA77)));
        _assertList(imageKind, _hashes(1, 2, 0));

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger));
        reg.multicall(calls);
    }

    function test_multicall_isAllOrNothing() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(TrustRegistry.list, (imageKind, _h(1)));
        calls[1] = abi.encodeCall(TrustRegistry.list, (imageKind, _h(1)));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(TrustRegistryAlreadyListed.selector, imageKind, _h(1)));
        reg.multicall(calls);
        assertFalse(reg.isListed(imageKind, _h(1)), "nothing applied");
    }

    // ── Initialization, ownership, upgrade ────────────────────────────────────

    function test_implementation_initializeDisabled() public {
        TrustRegistry impl = new TrustRegistry();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(owner);
    }

    function test_proxy_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        reg.initialize(stranger);
    }

    function test_ownershipIsTwoStep() public {
        vm.prank(owner);
        reg.transferOwnership(stranger);
        assertEq(reg.owner(), owner, "proposal does not move ownership");
        assertEq(reg.pendingOwner(), stranger);
        vm.prank(stranger);
        reg.acceptOwnership();
        assertEq(reg.owner(), stranger);
    }

    function test_beaconUpgrade_keepsListsAndAttestors() public {
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(new TrustRegistry()), address(this));
        TrustRegistry b = TrustRegistry(address(new BeaconProxy(
            address(beacon), abi.encodeCall(TrustRegistry.initialize, (owner))
        )));
        vm.startPrank(owner);
        b.addTrustedAttestor(address(0xA77));
        b.list(sealedKind, _h(1));
        b.list(sealedKind, _h(2));
        b.requireInstanceBoundAttestors();
        vm.stopPrank();

        beacon.upgradeTo(address(new TrustRegistry()));
        assertTrue(b.instanceBoundAttestorsRequired());
        assertFalse(b.isTrustedAttestor(address(0xA77)), "unbound, and binding is required");
        assertEq(b.latest(sealedKind), _h(2));
        assertEq(b.listed(sealedKind).length, 2);
        assertEq(b.owner(), owner);
    }
}
