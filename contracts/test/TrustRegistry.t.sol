// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {
    TrustRegistry,
    TrustRegistryZeroValue,
    TrustRegistryAlreadyListed,
    TrustRegistryNotListed,
    TrustRegistryNotOwnerOrGuardian
} from "../src/TrustRegistry.sol";
import {TrustRegistryV1_0_0} from "./mocks/TrustRegistryV1_0_0.sol";
import {AttestorRegistryMock} from "./AttestorAppBinding.t.sol";
import {HandOver} from "../script/HandOverTrustRegistry.s.sol";
import {RegistryCalls} from "../script/TrustRegistryCalls.s.sol";

/// @dev External wrappers so the script libraries' reverts can be asserted
///      with vm.expectRevert (which needs a call boundary).
contract RegistryScriptsHarness {
    function handOver(address registry, address guardian, address timelock, uint256 chainId)
        external
        view
        returns (bytes[] memory)
    {
        return HandOver.calls(registry, guardian, timelock, chainId);
    }

    function describe(bytes memory data) external pure returns (string memory) {
        return RegistryCalls.describe(data);
    }
}

/// @notice The TrustRegistry's code lists, its owner and guardian surface, the
///         1.0.0 → 1.1.0 beacon upgrade from the frozen 1.0.0 source, and the
///         operating model: the owner moved to a TimelockController adds trust
///         through scheduled operations while the guardian removes it at once.
///         Attestor trust and app bindings are covered in
///         AttestorAppBinding.t.sol.
contract TrustRegistryTest is Test {
    TrustRegistry internal reg;
    address internal owner = address(0xA11CE);
    address internal stranger = address(0xB0B);
    address internal guardian = address(0x6A2D);

    bytes32 internal imageKind;
    bytes32 internal sealedKind;
    bytes32 internal harnessKind;

    event Listed(bytes32 indexed kind, bytes32 indexed hash);
    event Delisted(bytes32 indexed kind, bytes32 indexed hash);
    event GuardianSet(address indexed previous, address indexed guardian);

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
        assertEq(reg.VERSION(), "1.1.0");
        assertEq(reg.owner(), owner);
        assertEq(reg.guardian(), address(0), "no guardian until set");
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
        bytes memory notOwnerOrGuardian = abi.encodeWithSelector(TrustRegistryNotOwnerOrGuardian.selector, stranger);
        vm.startPrank(stranger);
        vm.expectRevert(unauthorized);
        reg.list(sealedKind, _h(1));
        vm.expectRevert(notOwnerOrGuardian);
        reg.delist(sealedKind, _h(1));
        vm.expectRevert(unauthorized);
        reg.addTrustedAttestor(stranger);
        vm.expectRevert(notOwnerOrGuardian);
        reg.removeTrustedAttestor(stranger);
        vm.expectRevert(unauthorized);
        reg.bindTrustedAttestorApp(stranger, address(0xA99), "app", 1);
        vm.expectRevert(unauthorized);
        reg.requireInstanceBoundAttestors();
        vm.expectRevert(unauthorized);
        reg.setGuardian(stranger);
        vm.stopPrank();
    }

    // ── Guardian ──────────────────────────────────────────────────────────────

    function test_guardian_setByTheOwner() public {
        vm.expectEmit(true, true, false, false, address(reg));
        emit GuardianSet(address(0), guardian);
        vm.prank(owner);
        reg.setGuardian(guardian);
        assertEq(reg.guardian(), guardian);

        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, guardian));
        reg.setGuardian(stranger);

        vm.expectEmit(true, true, false, false, address(reg));
        emit GuardianSet(guardian, address(0));
        vm.prank(owner);
        reg.setGuardian(address(0));
        _list(sealedKind, _h(1));
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(TrustRegistryNotOwnerOrGuardian.selector, guardian));
        reg.delist(sealedKind, _h(1));
    }

    /// @dev The guardian removes trust — one call at a time or batched through
    ///      multicall — and adds none; the owner keeps every call.
    function test_guardian_removesTrustOnly() public {
        vm.startPrank(owner);
        reg.setGuardian(guardian);
        reg.list(sealedKind, _h(1));
        reg.list(sealedKind, _h(2));
        reg.list(harnessKind, _h(3));
        reg.addTrustedAttestor(address(0xA77));
        reg.addTrustedAttestor(address(0xA78));
        vm.stopPrank();

        vm.startPrank(guardian);
        reg.delist(sealedKind, _h(2));
        reg.removeTrustedAttestor(address(0xA77));
        bytes[] memory removals = new bytes[](2);
        removals[0] = abi.encodeCall(TrustRegistry.delist, (harnessKind, _h(3)));
        removals[1] = abi.encodeCall(TrustRegistry.removeTrustedAttestor, (address(0xA78)));
        reg.multicall(removals);

        bytes memory unauthorized =
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, guardian);
        vm.expectRevert(unauthorized);
        reg.list(sealedKind, _h(9));
        vm.expectRevert(unauthorized);
        reg.addTrustedAttestor(guardian);
        vm.expectRevert(unauthorized);
        reg.bindTrustedAttestorApp(guardian, address(0xA99), "app", 1);
        vm.expectRevert(unauthorized);
        reg.requireInstanceBoundAttestors();
        bytes[] memory adds = new bytes[](2);
        adds[0] = abi.encodeCall(TrustRegistry.delist, (sealedKind, _h(1)));
        adds[1] = abi.encodeCall(TrustRegistry.list, (sealedKind, _h(9)));
        vm.expectRevert(unauthorized);
        reg.multicall(adds);
        vm.stopPrank();

        _assertList(sealedKind, _hashes(1, 0, 0));
        _assertList(harnessKind, new bytes32[](0));
        assertFalse(reg.isTrustedAttestor(address(0xA77)), "untrusted by the guardian");
        assertFalse(reg.isTrustedAttestor(address(0xA78)), "untrusted in the batch");

        vm.startPrank(owner);
        reg.delist(sealedKind, _h(1));
        reg.list(sealedKind, _h(9));
        vm.stopPrank();
        _assertList(sealedKind, _hashes(9, 0, 0));
    }

    /// @dev The operating model: the governance key, owner after deploy and
    ///      migration, sets itself as guardian and hands ownership to the
    ///      Timelock, which accepts through a scheduled operation. From then on
    ///      a listing is a Timelock operation — not before its delay, and
    ///      cancellable until it runs — while the guardian delists at once.
    function test_ownerMovesToATimelock_listsWaitDelistsDoNot() public {
        vm.warp(1_760_000_000); // TimelockController reads timestamp 1 as "done"
        address[] memory proposers = new address[](1);
        proposers[0] = owner;
        address[] memory executors = new address[](1);
        executors[0] = address(0);
        TimelockController timelock = new TimelockController(1 days, proposers, executors, address(0));

        bytes[] memory handOver = new bytes[](2);
        handOver[0] = abi.encodeCall(TrustRegistry.setGuardian, (owner));
        handOver[1] = abi.encodeWithSignature("transferOwnership(address)", address(timelock));
        vm.prank(owner);
        reg.multicall(handOver);
        assertEq(reg.pendingOwner(), address(timelock));
        _timelockRun(timelock, abi.encodeWithSignature("acceptOwnership()"), bytes32("accept"));
        assertEq(reg.owner(), address(timelock), "the Timelock owns the registry");
        assertEq(reg.guardian(), owner, "the governance key guards it");

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, owner));
        reg.list(sealedKind, _h(1));

        _timelockRun(timelock, abi.encodeCall(TrustRegistry.list, (sealedKind, _h(1))), bytes32("list-1"));
        _assertList(sealedKind, _hashes(1, 0, 0));

        bytes memory listTwo = abi.encodeCall(TrustRegistry.list, (sealedKind, _h(2)));
        vm.prank(owner);
        timelock.schedule(address(reg), 0, listTwo, bytes32(0), bytes32("list-2"), 1 days);
        bytes32 op = timelock.hashOperation(address(reg), 0, listTwo, bytes32(0), bytes32("list-2"));
        uint256 wouldBeReady = vm.getBlockTimestamp() + 1 days;
        vm.prank(owner);
        timelock.cancel(op);
        vm.warp(wouldBeReady);
        vm.expectRevert();
        timelock.execute(address(reg), 0, listTwo, bytes32(0), bytes32("list-2"));
        assertFalse(reg.isListed(sealedKind, _h(2)), "a cancelled listing never runs");

        vm.prank(owner);
        reg.delist(sealedKind, _h(1));
        _assertList(sealedKind, new bytes32[](0));
    }

    /// @dev HandOverTrustRegistry's calls: guardian set and the Timelock
    ///      proposed, in one multicall by the owner; refused for a registry
    ///      without a guardian (1.0.0), a zero guardian, a TIMELOCK that is no
    ///      Timelock, and on 0G mainnet a Timelock under one day.
    function test_handOverScript_setsTheGuardianAndProposesTheTimelock() public {
        RegistryScriptsHarness h = new RegistryScriptsHarness();
        address[] memory none = new address[](0);
        TimelockController timelock = new TimelockController(1 days, none, none, address(0));
        bytes[] memory calls = h.handOver(address(reg), guardian, address(timelock), 16661);
        vm.prank(owner);
        reg.multicall(calls);
        assertEq(reg.guardian(), guardian, "guardian set");
        assertEq(reg.pendingOwner(), address(timelock), "the Timelock proposed");
        assertEq(reg.owner(), owner, "the owner stays until the Timelock accepts");

        TrustRegistryV1_0_0 old = TrustRegistryV1_0_0(address(new ERC1967Proxy(
            address(new TrustRegistryV1_0_0()), abi.encodeCall(TrustRegistryV1_0_0.initialize, (owner))
        )));
        vm.expectRevert(bytes("TRUST_REGISTRY has no guardian(): upgrade it to 1.1.0 first"));
        h.handOver(address(old), guardian, address(timelock), 16602);
        vm.expectRevert(bytes("GUARDIAN is zero"));
        h.handOver(address(reg), address(0), address(timelock), 16602);
        vm.expectRevert(bytes("TIMELOCK has no code"));
        h.handOver(address(reg), guardian, makeAddr("not-a-timelock"), 16602);
        TimelockController weak = new TimelockController(0, none, none, address(0));
        h.handOver(address(reg), guardian, address(weak), 16602);
        vm.expectRevert(bytes("TIMELOCK minDelay below 86400 (1 day) on 0G mainnet (chain 16661)"));
        h.handOver(address(reg), guardian, address(weak), 16661);
    }

    /// @dev TrustRegistryCalls shows each call before scheduling it, and
    ///      schedules only the registry's owner calls.
    function test_registryCallsScript_describesOwnerCallsOnly() public {
        RegistryScriptsHarness h = new RegistryScriptsHarness();
        assertEq(
            h.describe(abi.encodeCall(TrustRegistry.list, (sealedKind, bytes32(uint256(0xAB))))),
            "list SEALED 0x00000000000000000000000000000000000000000000000000000000000000ab"
        );
        assertEq(
            h.describe(abi.encodeCall(TrustRegistry.delist, (harnessKind, bytes32(uint256(1))))),
            "delist HARNESS 0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assertEq(
            h.describe(abi.encodeCall(TrustRegistry.setGuardian, (address(0xBEEF)))),
            "set guardian 0x000000000000000000000000000000000000beef"
        );
        assertEq(h.describe(abi.encodeWithSignature("acceptOwnership()")), "accept ownership");
        vm.expectRevert(bytes("not a TrustRegistry owner call this script schedules"));
        h.describe(abi.encodeWithSignature("renounceOwnership()"));
        vm.expectRevert(bytes("not a TrustRegistry owner call this script schedules"));
        h.describe(abi.encodeWithSignature("multicall(bytes[])", new bytes[](0)));
    }

    /// @dev Schedule `data` on the registry, check it cannot run before the
    ///      delay, then run it as any account (open execution). The clock is
    ///      read with vm.getBlockTimestamp(): under via-IR, block.timestamp
    ///      read again after a vm.warp in the same test can return the value
    ///      from before it.
    function _timelockRun(TimelockController timelock, bytes memory data, bytes32 salt) internal {
        uint256 ready = vm.getBlockTimestamp() + 1 days;
        vm.prank(owner);
        timelock.schedule(address(reg), 0, data, bytes32(0), salt, 1 days);
        vm.warp(ready - 1);
        vm.expectRevert();
        timelock.execute(address(reg), 0, data, bytes32(0), salt);
        vm.warp(ready);
        vm.prank(address(0xE4EC));
        timelock.execute(address(reg), 0, data, bytes32(0), salt);
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

    /// @dev 1.0.0 → 1.1.0 from the frozen 1.0.0 source (what dev runs): the
    ///      lists, attestors, bindings, instance mode and owner carry over,
    ///      and the appended guardian reads zero until the owner sets one.
    function test_beaconUpgrade_from1_0_0_keepsEverythingGuardianZero() public {
        AttestorRegistryMock tapp = new AttestorRegistryMock();
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(new TrustRegistryV1_0_0()), address(this));
        TrustRegistry b = TrustRegistry(address(new BeaconProxy(
            address(beacon), abi.encodeCall(TrustRegistryV1_0_0.initialize, (owner))
        )));
        assertEq(b.VERSION(), "1.0.0", "starts on the frozen 1.0.0 impl");
        vm.startPrank(owner);
        b.bindTrustedAttestorApp(address(0xA77), address(tapp), "0g-agentic-id", 100);
        b.addTrustedAttestor(address(0xA78));
        b.list(imageKind, _h(1));
        b.list(sealedKind, _h(2));
        b.list(sealedKind, _h(3));
        b.list(harnessKind, _h(4));
        b.delist(sealedKind, _h(2));
        b.transferOwnership(stranger);
        vm.stopPrank();
        (address r0, string memory id0, uint256 at0, address o0) = b.trustedAttestorAppBinding(address(0xA77));

        beacon.upgradeTo(address(new TrustRegistry()));
        assertEq(b.VERSION(), "1.1.0");
        assertEq(b.guardian(), address(0), "guardian starts zero");
        assertEq(b.owner(), owner, "owner");
        assertEq(b.pendingOwner(), stranger, "pending owner");
        assertTrue(b.isTrustedAttestor(address(0xA77)), "bound attestor");
        assertTrue(b.isTrustedAttestor(address(0xA78)), "unbound attestor");
        (address r1, string memory id1, uint256 at1, address o1) = b.trustedAttestorAppBinding(address(0xA77));
        assertEq(r1, r0, "binding registry");
        assertEq(id1, id0, "binding appId");
        assertEq(at1, at0, "binding registeredAt");
        assertEq(o1, o0, "binding app owner");
        assertFalse(b.instanceBoundAttestorsRequired(), "instance mode");
        assertEq(b.listed(imageKind).length, 1, "image list");
        bytes32[] memory sealedList = b.listed(sealedKind);
        assertEq(sealedList.length, 1, "sealed list");
        assertEq(sealedList[0], _h(3));
        assertEq(b.latest(harnessKind), _h(4), "harness list");

        vm.prank(owner);
        b.setGuardian(guardian);
        vm.prank(guardian);
        b.delist(sealedKind, _h(3));
        assertFalse(b.isListed(sealedKind, _h(3)), "the new guardian delists");
    }
}
