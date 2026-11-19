// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticID, AgenticIDNotTrustedAttestor, AgenticIDAgentSealTaken} from "../src/AgenticID.sol";
import {
    IAttestorAppRegistry, AgenticIDInvalidAttestorBinding, AgenticIDAppInstanceMismatch
} from "../src/AttestorAppBindingLib.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
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

contract AttestorRawRegistryMock {
    bytes private response;
    bool private failing;

    function setResponse(bytes memory value, bool shouldFail) external {
        response = value;
        failing = shouldFail;
    }

    fallback() external {
        require(!failing);
        bytes memory data = response;
        assembly ("memory-safe") { return(add(data, 0x20), mload(data)) }
    }
}

/// @notice Attestor trust and Tapp app bindings. The TrustRegistry holds them
///         (1.4.0); AgenticID's mint and URI gates and its trust reads follow
///         the registry.
contract AttestorAppBindingTest is AgenticIDTestBase {
    AttestorRegistryMock internal registry;

    event TrustedAttestorAppBound(
        address indexed attestor, address indexed registry, string appId, uint256 registeredAt
    );
    event TrustedAttestorRemoved(address indexed attestor);

    function setUp() public override {
        super.setUp();
        registry = new AttestorRegistryMock();
    }

    function bind() internal {
        vm.prank(owner);
        trustRegistry.bindTrustedAttestorApp(attestor, address(registry), "attestor", 100);
    }

    function test_bindingAdministrationRemainsOwnerOnly() public {
        vm.startPrank(attestor);
        vm.expectRevert();
        trustRegistry.bindTrustedAttestorApp(attestor, address(registry), "attestor", 100);
        vm.expectRevert();
        trustRegistry.removeTrustedAttestor(attestor);
        vm.expectRevert();
        trustRegistry.requireInstanceBoundAttestors();
        vm.stopPrank();
        assertFalse(agenticId.isTrustedAttestor(attestor));
        assertFalse(agenticId.instanceBoundAttestorsRequired());
    }

    function test_bindingEmitsFromRegistryAndClearsLongAppId() public {
        string memory appId = "attestor-app-id-longer-than-one-solidity-storage-word";
        vm.expectEmit(true, true, false, true, address(trustRegistry));
        emit TrustedAttestorAppBound(attestor, address(registry), appId, 100);
        vm.prank(owner);
        trustRegistry.bindTrustedAttestorApp(attestor, address(registry), appId, 100);
        (, string memory stored,,) = agenticId.trustedAttestorAppBinding(attestor);
        assertEq(stored, appId, "AgenticID forwards the binding read");
        vm.expectEmit(true, false, false, true, address(trustRegistry));
        emit TrustedAttestorRemoved(attestor);
        vm.prank(owner);
        trustRegistry.removeTrustedAttestor(attestor);
        (address boundRegistry, string memory cleared, uint256 epoch, address boundOwner) =
            trustRegistry.trustedAttestorAppBinding(attestor);
        assertEq(boundRegistry, address(0));
        assertEq(cleared, "");
        assertEq(epoch, 0);
        assertEq(boundOwner, address(0));
        assertFalse(agenticId.isTrustedAttestor(attestor));
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
        trustRegistry.requireInstanceBoundAttestors();
        assertTrue(agenticId.instanceBoundAttestorsRequired(), "AgenticID forwards the mode");
        assertFalse(agenticId.isTrustedAttestor(attestor));
        _whitelistAttestor();
        assertFalse(agenticId.isTrustedAttestor(attestor));
        bind();
        assertTrue(agenticId.isTrustedAttestor(attestor));
    }

    function test_removeClearsBindingAndWrongEpochCannotBind() public {
        vm.prank(owner);
        vm.expectRevert(AgenticIDAppInstanceMismatch.selector);
        trustRegistry.bindTrustedAttestorApp(attestor, address(registry), "attestor", 99);
        bind();
        vm.prank(owner);
        trustRegistry.removeTrustedAttestor(attestor);
        (address addr,, uint256 epoch,) = trustRegistry.trustedAttestorAppBinding(attestor);
        assertEq(addr, address(0));
        assertEq(epoch, 0);
        assertFalse(agenticId.isTrustedAttestor(attestor));
    }

    function test_instanceReaderRejectsMalformedHeadsAndReverts() public {
        AttestorRawRegistryMock raw = new AttestorRawRegistryMock();
        bytes[] memory images = new bytes[](1);
        images[0] = hex"1234";
        bytes memory valid = abi.encode(IAttestorAppRegistry.AppInfo({
            composeHash: hex"ab", volumesHash: hex"cd", imageHashes: images,
            owner: address(1), registeredAt: 100
        }));
        raw.setResponse(valid, false);
        vm.prank(owner);
        trustRegistry.bindTrustedAttestorApp(attestor, address(raw), "attestor", 100);
        assertTrue(trustRegistry.isTrustedAttestor(attestor));

        bytes[] memory malformed = new bytes[](6);
        malformed[0] = new bytes(0);
        malformed[1] = new bytes(31);
        malformed[2] = new bytes(191);
        for (uint256 i = 3; i < malformed.length; i++) malformed[i] = bytes.concat(valid);
        bytes memory zeroOffset = malformed[3];
        bytes memory shiftedOffset = malformed[4];
        bytes memory dirtyOwner = malformed[5];
        assembly ("memory-safe") {
            mstore(add(zeroOffset, 0x20), 0)
            mstore(add(shiftedOffset, 0x20), 64)
            mstore(add(dirtyOwner, 0xa0), or(shl(160, 1), 1))
        }
        for (uint256 i = 0; i < malformed.length; i++) {
            raw.setResponse(malformed[i], false);
            assertFalse(trustRegistry.isTrustedAttestor(attestor), "malformed live response must deny");
            vm.prank(owner);
            vm.expectRevert(AgenticIDAppInstanceMismatch.selector);
            trustRegistry.bindTrustedAttestorApp(attestor, address(raw), "attestor", 100);
        }
        raw.setResponse(valid, true);
        assertFalse(trustRegistry.isTrustedAttestor(attestor), "reverting registry must deny");
        vm.prank(owner);
        vm.expectRevert(AgenticIDAppInstanceMismatch.selector);
        trustRegistry.bindTrustedAttestorApp(attestor, address(raw), "attestor", 100);
        raw.setResponse(valid, false);
        assertTrue(trustRegistry.isTrustedAttestor(attestor));
    }

    function test_invalidBindingInputsRevertWithCustomError() public {
        vm.startPrank(owner);
        vm.expectRevert(AgenticIDInvalidAttestorBinding.selector);
        trustRegistry.bindTrustedAttestorApp(address(0), address(registry), "attestor", 100);
        vm.expectRevert(AgenticIDInvalidAttestorBinding.selector);
        trustRegistry.bindTrustedAttestorApp(attestor, address(0), "attestor", 100);
        vm.expectRevert(AgenticIDInvalidAttestorBinding.selector);
        trustRegistry.bindTrustedAttestorApp(attestor, address(registry), "", 100);
        vm.stopPrank();
    }

    function test_beaconProxySelfChecksPreserveTheOriginalAttestor() public {
        AgenticID implementation = new AgenticID(address(trustRegistry));
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(implementation), address(this));
        BeaconProxy proxy = new BeaconProxy(address(beacon), abi.encodeCall(
            AgenticID.initialize, ("AgenticID", "AID", address(verifier), owner, pauser, address(canonical))
        ));
        agenticId = AgenticID(address(proxy));
        bind();
        vm.prank(owner);
        trustRegistry.requireInstanceBoundAttestors();
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("data")});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        uint256 id = agenticId.registerWithSeal(owner, "", metadata, datas, keys, SEAL_ADDR, SEAL_ID);
        vm.prank(attestor);
        agenticId.setAgentURI(id, "https://example/card.json");
        assertEq(agenticId.tokenURI(id), "https://example/card.json");

        registry.setEpoch(101);
        vm.prank(attestor);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(owner, "", metadata, datas, keys, address(2), bytes32(uint256(2)));
        vm.prank(attestor);
        vm.expectRevert();
        agenticId.setAgentURI(id, "https://example/unauthorized.json");
        assertEq(agenticId.tokenURI(id), "https://example/card.json");
    }

    /// @dev 1.4.0 keeps AgenticID's storage struct as 1.3.0 left it: the seal
    ///      map stays at base+7 and still binds, while the retired trust fields
    ///      (trustedAttestors base+3, attestorAppBindings base+8,
    ///      instanceBoundAttestorsRequired base+9) are never written — trust
    ///      changes land in the registry only.
    function test_trustStateLivesInTheRegistryNotInAgenticIDStorage() public {
        uint256 base = uint256(0xaa0e3d57ddf5d2f322a098202cb27f2804b292978acf041b4edd6beb821d4000);
        bytes32 sealSlot = keccak256(abi.encode(SEAL_ADDR, base + 7));
        // This entry already exists on a pre-1.4.0 proxy before a beacon upgrade.
        vm.store(address(agenticId), sealSlot, bytes32(uint256(1)));
        bind();
        vm.prank(owner);
        trustRegistry.requireInstanceBoundAttestors();
        assertTrue(agenticId.isTrustedAttestor(attestor));
        assertEq(vm.load(address(agenticId), keccak256(abi.encode(attestor, base + 3))), bytes32(0));
        assertEq(vm.load(address(agenticId), keccak256(abi.encode(attestor, base + 8))), bytes32(0));
        assertEq(vm.load(address(agenticId), bytes32(base + 9)), bytes32(0));

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("data")});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDAgentSealTaken.selector, SEAL_ADDR));
        agenticId.registerWithSeal(owner, "", metadata, datas, keys, SEAL_ADDR, SEAL_ID);
    }
}
