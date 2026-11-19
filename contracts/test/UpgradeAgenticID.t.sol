// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalIdentityRegistryMock} from "./mocks/CanonicalIdentityRegistryMock.sol";
import {AgenticIDV1_3_0} from "./mocks/AgenticIDV1_3_0.sol";
import {AttestorRegistryMock} from "./AttestorAppBinding.t.sol";
import {AgenticID, AgenticIDNotTrustedAttestor, AgenticIDAgentSealTaken} from "../src/AgenticID.sol";
import {TrustRegistry} from "../src/TrustRegistry.sol";
import {CloneGate} from "../src/CloneGate.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {TrustMigration, ILegacyTrust} from "../script/TrustMigration.sol";
import {TrustRegistryCheck} from "../script/ScheduleUpgrade.s.sol";

/// @dev External wrapper so the library's reverts can be asserted with
///      vm.expectRevert (which needs a call boundary).
contract TrustRegistryCheckHarness {
    function registryOf(address impl) external view returns (address) {
        return TrustRegistryCheck.registryOf(impl);
    }

    function check(address named, address expected, address expectedOwner) external view {
        TrustRegistryCheck.check(named, expected, expectedOwner);
    }
}

/// @notice AgenticID 1.3.0 → 1.4.0 as UPGRADING.md runs it: TrustMigration,
///         fed the events 1.3.0 emitted, copies AgenticID's lists into a
///         TrustRegistry; the copy is checked; ScheduleUpgrade checks the
///         registry the new implementation reads; the beacon upgrade then
///         switches every trust read at once. Starts from the frozen 1.3.0
///         source in the shape test, dev and mainnet have: instance binding
///         required, the attestor and the CloneGate bound to the attestor app,
///         image hashes added and removed, an address-only attestor removed,
///         plus one left in place (inert once binding is required) and one
///         whose app was re-registered (a stale binding).
contract UpgradeAgenticIDTest is AgenticIDTestBase {
    UpgradeableBeacon internal beacon;
    AgenticIDV1_3_0 internal old;
    AttestorRegistryMock internal tapp;
    AttestorRegistryMock internal otherTapp;
    CloneGate internal gate;

    address internal removedAttestor = address(0x1E6A);
    address internal inertAttestor = address(0x1AE7);
    address internal staleAttestor = address(0x57A1E);
    address internal agentOwner = address(0xA1);

    bytes32 internal constant FW_A = keccak256("image-a");
    bytes32 internal constant FW_B = keccak256("image-b");
    bytes32 internal constant FW_C = keccak256("image-c");
    string internal constant APP = "0g-agentic-id";

    address[] internal candidateAttestors;
    bytes32[] internal candidateImages;
    uint256 internal sealedId;

    function setUp() public override {
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");
        verifier = TEEDataVerifier(address(new ERC1967Proxy(
            address(new TEEDataVerifier()),
            abi.encodeCall(TEEDataVerifier.initialize, (owner, pauser, oracleAddr, MAX_PROOF_AGE))
        )));
        canonical = new CanonicalIdentityRegistryMock();
        canonical.initialize();

        beacon = new UpgradeableBeacon(address(new AgenticIDV1_3_0()), address(this));
        BeaconProxy proxy = new BeaconProxy(address(beacon), abi.encodeCall(
            AgenticIDV1_3_0.initialize, ("AgenticID", "AID", address(verifier), owner, pauser, address(canonical))
        ));
        old = AgenticIDV1_3_0(address(proxy));
        agenticId = AgenticID(address(proxy));
        assertEq(old.VERSION(), "1.3.0", "starts on the frozen 1.3.0 impl");

        tapp = new AttestorRegistryMock();
        otherTapp = new AttestorRegistryMock();
        gate = CloneGate(address(new ERC1967Proxy(
            address(new CloneGate()), abi.encodeCall(CloneGate.initialize, (address(agenticId)))
        )));

        vm.recordLogs();
        vm.startPrank(owner);
        old.addTrustedAttestor(removedAttestor);
        old.addTrustedAttestor(inertAttestor);
        old.addValidFrameworkHash(FW_A);
        old.addValidFrameworkHash(FW_B);
        old.addValidFrameworkHash(FW_C);
        old.removeValidFrameworkHash(FW_B);
        old.bindTrustedAttestorApp(attestor, address(tapp), APP, 100);
        old.bindTrustedAttestorApp(address(gate), address(tapp), APP, 100);
        old.bindTrustedAttestorApp(staleAttestor, address(otherTapp), "other-app", 100);
        old.requireInstanceBoundAttestors();
        old.removeTrustedAttestor(removedAttestor);
        vm.stopPrank();
        otherTapp.setEpoch(101); // the other app was re-registered

        TrustMigration.Candidates memory c;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(proxy)) TrustMigration.collect(c, logs[i].topics);
        }
        candidateAttestors = c.attestors;
        candidateImages = c.images;

        sealedId = _mint(attestor, SEAL_ADDR, SEAL_ID);
        vm.prank(attestor);
        agenticId.setAgentURI(sealedId, "ipfs://sealed-agent");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _candidates() internal view returns (TrustMigration.Candidates memory c) {
        c.attestors = candidateAttestors;
        c.images = candidateImages;
    }

    function _mint(address by, address seal, bytes32 sealId) internal returns (uint256) {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "persona", dataHash: keccak256(abi.encode(sealId))});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(by);
        return agenticId.registerWithSeal(agentOwner, "", metadata, datas, keys, seal, sealId);
    }

    function _all() internal pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    /// @dev A TrustRegistry holding the migration's calls, applied by its owner.
    function _migrated() internal returns (TrustRegistry reg) {
        return _migratedKeeping(_all());
    }

    function _migratedKeeping(bytes32[] memory keep) internal returns (TrustRegistry reg) {
        reg = _deployTrustRegistry(owner);
        bytes[] memory calls = TrustMigration.calls(ILegacyTrust(address(old)), _candidates(), reg.IMAGE(), keep);
        vm.prank(owner);
        reg.multicall(calls);
    }

    function _upgradeTo(TrustRegistry reg) internal {
        beacon.upgradeTo(address(new AgenticID(address(reg))));
        assertEq(agenticId.VERSION(), "1.4.0", "post-upgrade VERSION");
    }

    // ── The migration ─────────────────────────────────────────────────────────

    function test_candidatesComeFromTheEvents() public view {
        assertEq(candidateAttestors.length, 5, "every attestor ever named");
        assertEq(candidateImages.length, 3, "every image hash ever named");
        assertEq(candidateImages[0], FW_A, "first-named order");
        assertEq(candidateImages[1], FW_B);
        assertEq(candidateImages[2], FW_C);
    }

    function test_calls_copyOnlyWhatIsTrustedNow() public view {
        bytes[] memory calls =
            TrustMigration.calls(ILegacyTrust(address(old)), _candidates(), keccak256("image"), _all());
        assertEq(calls.length, 5, "two binds, the mode, two image hashes");
        assertEq(calls[0], abi.encodeCall(TrustRegistry.bindTrustedAttestorApp, (attestor, address(tapp), APP, 100)));
        assertEq(calls[1], abi.encodeCall(TrustRegistry.bindTrustedAttestorApp, (address(gate), address(tapp), APP, 100)));
        assertEq(calls[2], abi.encodeCall(TrustRegistry.requireInstanceBoundAttestors, ()));
        assertEq(calls[3], abi.encodeCall(TrustRegistry.list, (keccak256("image"), FW_A)));
        assertEq(calls[4], abi.encodeCall(TrustRegistry.list, (keccak256("image"), FW_C)));
    }

    function test_check_passesOnTheCopyAndCatchesAGap() public {
        TrustRegistry reg = _migrated();
        (bool ok,) = TrustMigration.check(ILegacyTrust(address(old)), reg, _candidates(), _all());
        assertTrue(ok, "the copy reads the same");

        bytes32 imageKind = reg.IMAGE();
        vm.prank(owner);
        reg.delist(imageKind, FW_C);
        (bool ok2, string memory why) = TrustMigration.check(ILegacyTrust(address(old)), reg, _candidates(), _all());
        assertFalse(ok2, "a missing image hash is caught");
        assertEq(why, "image hash");
    }

    /// @dev The check reads the registry's image list whole, and every
    ///      attestor the logs of either contract name: an image hash or an
    ///      attestor the registry has beyond the copy is caught, the attestor
    ///      only once the registry's own logs are among the candidates.
    function test_check_catchesWhatTheRegistryHasBeyondTheCopy() public {
        vm.recordLogs();
        TrustRegistry reg = _migrated();
        bytes32 imageKind = reg.IMAGE();
        vm.prank(owner);
        reg.list(imageKind, keccak256("image-extra"));
        (bool ok, string memory why) = TrustMigration.check(ILegacyTrust(address(old)), reg, _candidates(), _all());
        assertFalse(ok, "an image hash beyond the copy is caught");
        assertEq(why, "extra image hash");

        vm.startPrank(owner);
        reg.delist(imageKind, keccak256("image-extra"));
        reg.bindTrustedAttestorApp(address(0xE77A), address(tapp), APP, 100);
        vm.stopPrank();
        TrustMigration.Candidates memory c = _candidates();
        (ok,) = TrustMigration.check(ILegacyTrust(address(old)), reg, c, _all());
        assertTrue(ok, "AgenticID's logs alone do not name the extra attestor");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(reg)) TrustMigration.collect(c, logs[i].topics);
        }
        (ok, why) = TrustMigration.check(ILegacyTrust(address(old)), reg, c, _all());
        assertFalse(ok, "with the registry's logs it is caught");
        assertEq(why, "attestor trust");
    }

    /// @dev IMAGES: carry over only the named image hashes; the other listed
    ///      ones are reported, and the upgrade delists them.
    function test_keep_carriesOnlyTheNamedImages() public {
        bytes32[] memory keep = new bytes32[](1);
        keep[0] = FW_C;
        bytes32[] memory gone = TrustMigration.dropped(ILegacyTrust(address(old)), _candidates(), keep);
        assertEq(gone.length, 1, "one listed hash left out");
        assertEq(gone[0], FW_A);

        TrustRegistry reg = _migratedKeeping(keep);
        (bool ok,) = TrustMigration.check(ILegacyTrust(address(old)), reg, _candidates(), keep);
        assertTrue(ok, "reads as intended: FW_C kept, FW_A delisted");
        (bool okAll, string memory why) = TrustMigration.check(ILegacyTrust(address(old)), reg, _candidates(), _all());
        assertFalse(okAll, "a full-copy check sees the delisting");
        assertEq(why, "image hash");

        _upgradeTo(reg);
        assertTrue(agenticId.isValidFrameworkHash(FW_C), "kept");
        assertFalse(agenticId.isValidFrameworkHash(FW_A), "delisted by the upgrade");
        assertTrue(agenticId.isTrustedAttestor(attestor), "attestors are not filtered");
    }

    function test_keep_rejectsAHashAgenticIDDoesNotList() public {
        bytes32[] memory keep = new bytes32[](1);
        keep[0] = FW_B; // removed on 1.3.0
        vm.expectRevert(bytes("keep names an image hash AgenticID does not list"));
        this.callsFor(keep);
    }

    /// @dev External so expectRevert sees the library's revert.
    function callsFor(bytes32[] memory keep) external view returns (bytes[] memory) {
        return TrustMigration.calls(ILegacyTrust(address(old)), _candidates(), keccak256("image"), keep);
    }

    // ── Scheduling ────────────────────────────────────────────────────────────

    /// @dev ScheduleUpgrade refuses an AgenticID implementation that reads
    ///      another registry than the environment's, a registry with no code,
    ///      or one under another owner — e.g. test's 1.4.0 built with dev's
    ///      registry, both on chain 16602.
    function test_schedule_checksTheRegistryTheImplementationReads() public {
        TrustRegistryCheckHarness h = new TrustRegistryCheckHarness();
        TrustRegistry reg = _migrated();
        assertEq(h.registryOf(address(new AgenticID(address(reg)))), address(reg), "1.4.0 names its registry");
        assertEq(h.registryOf(beacon.implementation()), address(0), "1.3.0 names none");
        assertEq(h.registryOf(address(new TrustRegistry())), address(0), "other contracts name none");
        h.check(address(reg), address(reg), owner);

        TrustRegistry other = _deployTrustRegistry(owner);
        vm.expectRevert(bytes("NEW_IMPL reads another TrustRegistry than TRUST_REGISTRY"));
        h.check(address(reg), address(other), owner);
        vm.expectRevert(bytes("TRUST_REGISTRY's owner is not TRUST_REGISTRY_OWNER"));
        h.check(address(reg), address(reg), address(0xD0E));
        address codeless = makeAddr("codeless");
        vm.expectRevert(bytes("TRUST_REGISTRY has no code"));
        h.check(codeless, codeless, owner);
    }

    // ── The upgrade ───────────────────────────────────────────────────────────

    function test_upgrade_switchesEveryTrustReadAtOnce() public {
        (address r0, string memory id0, uint256 at0, address o0) = old.trustedAttestorAppBinding(attestor);
        TrustRegistry reg = _migrated();
        _upgradeTo(reg);

        assertEq(agenticId.trustRegistry(), address(reg));
        assertTrue(agenticId.instanceBoundAttestorsRequired(), "mode carried over");
        assertTrue(agenticId.isTrustedAttestor(attestor), "bound attestor");
        assertTrue(agenticId.isTrustedAttestor(address(gate)), "bound CloneGate");
        assertFalse(agenticId.isTrustedAttestor(removedAttestor), "removed stays removed");
        assertFalse(agenticId.isTrustedAttestor(inertAttestor), "unbound stays inert");
        assertFalse(agenticId.isTrustedAttestor(staleAttestor), "stale binding stays stale");
        (address r1, string memory id1, uint256 at1, address o1) = agenticId.trustedAttestorAppBinding(attestor);
        assertEq(r1, r0, "binding registry");
        assertEq(id1, id0, "binding appId");
        assertEq(at1, at0, "binding registeredAt");
        assertEq(o1, o0, "binding app owner");
        assertTrue(agenticId.isValidFrameworkHash(FW_A));
        assertFalse(agenticId.isValidFrameworkHash(FW_B), "removed hash stays removed");
        assertTrue(agenticId.isValidFrameworkHash(FW_C));
        (bool ok,) = TrustMigration.check(ILegacyTrust(address(agenticId)), reg, _candidates(), _all());
        assertTrue(ok, "AgenticID 1.4.0 forwards: the comparison is now the registry against itself");
    }

    /// @dev What a check after the upgrade can still prove: the kept image
    ///      hashes are on the registry's list.
    function test_checkKept_afterTheUpgrade() public {
        bytes32[] memory keep = new bytes32[](1);
        keep[0] = FW_C;
        TrustRegistry reg = _migratedKeeping(keep);
        _upgradeTo(reg);
        (bool ok,) = TrustMigration.checkKept(reg, keep);
        assertTrue(ok, "the kept hash is listed");

        bytes32 imageKind = reg.IMAGE();
        vm.prank(owner);
        reg.delist(imageKind, FW_C);
        (bool ok2, string memory why) = TrustMigration.checkKept(reg, keep);
        assertFalse(ok2, "a kept hash gone from the list is caught");
        assertEq(why, "kept image hash");
    }

    function test_upgrade_keepsAgentsAndGatesNewWritesOnTheRegistry() public {
        TrustRegistry reg = _migrated();
        _upgradeTo(reg);

        assertEq(agenticId.ownerOf(sealedId), agentOwner, "owner");
        assertEq(agenticId.getAgentSeal(sealedId), SEAL_ADDR, "seal");
        assertEq(agenticId.getSealId(sealedId), SEAL_ID, "sealId");
        assertEq(agenticId.tokenURI(sealedId), "ipfs://sealed-agent", "URI");
        assertEq(agenticId.owner(), owner, "AgenticID owner");

        uint256 next = _mint(attestor, address(0xBB), bytes32(uint256(0xB2)));
        assertEq(agenticId.getAgentSeal(next), address(0xBB), "a migrated attestor mints");
        vm.prank(attestor);
        agenticId.setAgentURI(next, "ipfs://next");

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("d")});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(inertAttestor);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(agentOwner, "", metadata, datas, keys, address(0xCC), bytes32(uint256(0xC3)));
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDAgentSealTaken.selector, SEAL_ADDR));
        agenticId.registerWithSeal(agentOwner, "", metadata, datas, keys, SEAL_ADDR, bytes32(uint256(0xC4)));

        // Trust changes now land in the registry only.
        vm.prank(owner);
        reg.removeTrustedAttestor(attestor);
        assertFalse(agenticId.isTrustedAttestor(attestor));
    }

    /// @dev Why the copy goes first: an upgrade onto an empty registry trusts
    ///      no attestor and no image.
    function test_upgrade_ontoAnEmptyRegistryTrustsNothing() public {
        _upgradeTo(_deployTrustRegistry(owner));
        assertFalse(agenticId.isTrustedAttestor(attestor));
        assertFalse(agenticId.isValidFrameworkHash(FW_A));
    }

    /// @dev 1.4.0 never writes the retired fields, so rolling the beacon back
    ///      to 1.3.0 restores 1.3.0's lists as they were.
    function test_rollbackTo1_3_0_restoresTheOldLists() public {
        address oldImpl = beacon.implementation();
        TrustRegistry reg = _migrated();
        _upgradeTo(reg);
        vm.prank(owner);
        reg.removeTrustedAttestor(attestor);

        beacon.upgradeTo(oldImpl);
        assertEq(old.VERSION(), "1.3.0");
        assertTrue(old.isTrustedAttestor(attestor), "1.3.0's own list is back");
        assertTrue(old.isValidFrameworkHash(FW_A));
        assertFalse(old.isValidFrameworkHash(FW_B));
        assertTrue(old.instanceBoundAttestorsRequired());
    }
}
