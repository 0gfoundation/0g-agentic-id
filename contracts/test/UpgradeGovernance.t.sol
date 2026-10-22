// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalIdentityRegistryMock} from "./mocks/CanonicalIdentityRegistryMock.sol";
import {AgenticIDV1_1_0} from "./mocks/AgenticIDV1_1_0.sol";
import {TEEDataVerifierV1_1_0} from "./mocks/TEEDataVerifierV1_1_0.sol";
import {AgenticID, AgenticIDZeroAddress, AgenticIDSealIdTaken} from "../src/AgenticID.sol";
import {TEEDataVerifier, TEEDataVerifierZeroAddress} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

/// @notice AgenticID 1.1.0 → 1.2.0 and TEEDataVerifier 1.1.0 → 1.2.0 across a
///         real BeaconProxy + UpgradeableBeacon + TimelockController upgrade,
///         starting from the frozen 1.1.0 sources (test/mocks/*V1_1_0.sol) —
///         the code every environment runs today. The Timelock has 0G
///         mainnet's delay and role shape (DEPLOYMENT.md §6.2m): minDelay 1
///         day, the owner as sole proposer/canceller, open execution — with
///         admin = address(0) as Deploy.s.sol now produces on 0G mainnet
///         (on the existing mainnet Timelock the vault still holds the admin
///         role; DEPLOYMENT.md §8).
///
///         Locks the 1.2.0 upgrade-safety claims:
///           - every pre-upgrade value survives (the Ownable2Step swap only
///             adds OZ's namespaced pendingOwner slot, which starts at zero);
///           - the owner survives, and ownership is two-step afterwards;
///           - the FIND-12 setter guards are live through the existing proxy.
contract UpgradeGovernanceTest is AgenticIDTestBase {
    TimelockController internal timelock;
    UpgradeableBeacon internal agenticIdBeacon;
    UpgradeableBeacon internal verifierBeacon;

    uint256 internal constant DELAY = 1 days;

    /// @dev OZ ERC-7201 slots (pinned in StorageLayout.t.sol).
    bytes32 internal constant OWNABLE_SLOT =
        0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
    bytes32 internal constant OWNABLE2STEP_SLOT =
        0x237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00;

    bytes32 internal constant FRAMEWORK_HASH = keccak256("framework-v1");
    string internal constant SEALED_URI = "ipfs://sealed-agent";

    address internal agentOwner = address(0xA1);
    address internal newOwner = address(0x0E1);
    Vm.Wallet internal seller;
    Vm.Wallet internal buyer;

    // Seeded under 1.1.0.
    uint256 internal sealedId;
    bytes32 internal sealedHash;
    uint256 internal soldId;
    bytes32 internal soldHash;

    /// @dev Deploys both proxies on the FROZEN 1.1.0 impls. Does not call
    ///      super.setUp(): the base deploys plain ERC1967 proxies on the
    ///      current source; this suite needs beacons on the old code. The
    ///      base's state vars (agenticId / verifier / canonical / oracle*) are
    ///      filled here so its proof builders work unchanged.
    function setUp() public override {
        // Realistic clock: OZ TimelockController treats timestamp 1 as "done".
        vm.warp(1_760_000_000);
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");
        seller = vm.createWallet("seller");
        buyer = vm.createWallet("buyer");

        address[] memory proposers = new address[](1);
        proposers[0] = owner;
        address[] memory executors = new address[](1);
        executors[0] = address(0);
        timelock = new TimelockController(DELAY, proposers, executors, address(0));

        canonical = new CanonicalIdentityRegistryMock();
        canonical.initialize();

        verifierBeacon = new UpgradeableBeacon(address(new TEEDataVerifierV1_1_0()), address(timelock));
        verifier = TEEDataVerifier(address(new BeaconProxy(
            address(verifierBeacon),
            abi.encodeCall(TEEDataVerifierV1_1_0.initialize, (owner, pauser, oracleAddr, MAX_PROOF_AGE))
        )));

        agenticIdBeacon = new UpgradeableBeacon(address(new AgenticIDV1_1_0()), address(timelock));
        agenticId = AgenticID(address(new BeaconProxy(
            address(agenticIdBeacon),
            abi.encodeCall(
                AgenticIDV1_1_0.initialize,
                ("AgenticID", "AID", address(verifier), owner, pauser, address(canonical))
            )
        )));

        assertEq(agenticId.VERSION(), "1.1.0", "AgenticID starts on the frozen 1.1.0 impl");
        assertEq(verifier.VERSION(), "1.1.0", "TEEDataVerifier starts on the frozen 1.1.0 impl");
        _seedUnderOldImpls();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev Under 1.1.0: allowlists, a seal-bound agent with URI + metadata,
    ///      and a non-seal agent sold through a proof-gated iTransferFrom (so
    ///      the verifier's nonce store holds consumed entries).
    function _seedUnderOldImpls() internal {
        vm.startPrank(owner);
        agenticId.addTrustedAttestor(attestor);
        agenticId.addValidFrameworkHash(FRAMEWORK_HASH);
        vm.stopPrank();

        sealedHash = keccak256("sealed-agent-data");
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "persona", dataHash: sealedHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](1);
        metadata[0] = MetadataEntry({metadataKey: "category", metadataValue: bytes("inference")});
        vm.prank(attestor);
        sealedId = agenticId.registerWithSeal(
            agentOwner, SEALED_URI, metadata, datas, sealedKeys, SEAL_ADDR, SEAL_ID
        );

        (soldId, soldHash) = _selfMintData(seller.addr, 0);
        _sell(soldId, soldHash, seller.addr, buyer, "ap-1", "op-1");
    }

    /// @dev Proof-gated iTransferFrom of a non-seal agent to `to`.
    function _sell(
        uint256 agentId,
        bytes32 dataHash,
        address from,
        Vm.Wallet memory to,
        bytes memory apNonce,
        bytes memory opNonce
    ) internal {
        uint256 deadline = block.timestamp + 1 hours;
        AccessProof memory ap = _mkAccessProof(dataHash, "", apNonce, deadline, to.privateKey);
        OwnershipProof memory op = _mkOwnershipProof(dataHash, SEALED_KEY_NEW, _pubkey(to), opNonce, deadline);
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});
        vm.prank(from);
        agenticId.iTransferFrom(from, to.addr, agentId, proofs);
    }

    /// @dev The verifier's nonce key for a proof nonce (BaseDataVerifier:
    ///      keccak256(abi.encode(tag, msg.sender = AgenticID, nonce))).
    function _nonceKey(string memory tag, bytes memory nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(tag)), address(agenticId), nonce));
    }

    /// @dev Mainnet-shaped upgrade: the owner schedules, the op is NOT ready
    ///      before minDelay, then any account executes (open execution).
    function _upgrade(UpgradeableBeacon beacon, address newImpl) internal {
        bytes memory cd = abi.encodeCall(UpgradeableBeacon.upgradeTo, (newImpl));
        vm.prank(owner);
        timelock.schedule(address(beacon), 0, cd, bytes32(0), bytes32(0), DELAY);

        vm.warp(block.timestamp + DELAY - 1);
        vm.expectRevert();
        timelock.execute(address(beacon), 0, cd, bytes32(0), bytes32(0));

        vm.warp(block.timestamp + 1);
        vm.prank(address(0xE4EC));
        timelock.execute(address(beacon), 0, cd, bytes32(0), bytes32(0));
        assertEq(beacon.implementation(), newImpl, "beacon points at the new impl");
    }

    // ── AgenticID 1.1.0 → 1.2.0 ───────────────────────────────────────────────

    function test_agenticID_upgrade_preservesState() public {
        assertEq(vm.load(address(agenticId), OWNABLE2STEP_SLOT), bytes32(0), "pending slot unused by 1.1.0");
        bytes32 ownerWord = vm.load(address(agenticId), OWNABLE_SLOT);
        assertEq(address(uint160(uint256(ownerWord))), owner, "owner lives in OZ's Ownable slot");

        _upgrade(agenticIdBeacon, address(new AgenticID()));
        assertEq(agenticId.VERSION(), "1.2.0", "post-upgrade VERSION");

        // Governance config.
        assertEq(vm.load(address(agenticId), OWNABLE_SLOT), ownerWord, "Ownable slot untouched");
        assertEq(agenticId.owner(), owner, "owner preserved");
        assertEq(agenticId.pendingOwner(), address(0), "no pending owner after upgrade");
        assertEq(agenticId.pauser(), pauser, "pauser preserved");
        assertFalse(agenticId.paused(), "not paused");
        assertEq(address(agenticId.verifier()), address(verifier), "verifier preserved");
        assertEq(agenticId.canonical(), address(canonical), "canonical binding preserved");
        assertTrue(agenticId.isTrustedAttestor(attestor), "attestor allowlist preserved");
        assertTrue(agenticId.isValidFrameworkHash(FRAMEWORK_HASH), "framework hash preserved");
        assertEq(agenticId.name(), "AgenticID", "name preserved");
        assertEq(agenticId.symbol(), "AID", "symbol preserved");

        // Seal binding + iData of the seal-bound agent.
        assertEq(agenticId.ownerOf(sealedId), agentOwner, "seal-bound agent owner");
        assertEq(agenticId.getAgentSeal(sealedId), SEAL_ADDR, "agentSeal preserved");
        assertEq(agenticId.getSealId(sealedId), SEAL_ID, "sealId preserved");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID), sealedId, "sealId -> agentId preserved");
        assertTrue(agenticId.isSealIdBound(SEAL_ID), "sealIdBound preserved");
        IntelligentData[] memory datas = agenticId.intelligentDatasOf(sealedId);
        assertEq(datas.length, 1, "iData length");
        assertEq(datas[0].dataHash, sealedHash, "iData hash preserved");
        assertEq(agenticId.sealedKeysOf(sealedId)[0], SEALED_KEY_ORIGINAL, "sealedKey preserved");
        assertEq(agenticId.tokenURI(sealedId), SEALED_URI, "URI preserved");
        assertEq(agenticId.getMetadata(sealedId, "category"), bytes("inference"), "metadata preserved");

        // The agent sold under 1.1.0.
        assertEq(agenticId.ownerOf(soldId), buyer.addr, "sold agent owner");
        assertEq(agenticId.getAgentSeal(soldId), address(0), "sold agent is non-seal");
        assertEq(agenticId.sealedKeysOf(soldId)[0], SEALED_KEY_NEW, "re-sealed key preserved");

        // Behavior on the preserved state, through the refactored mint path:
        // the seal uniqueness set survived, so re-binding SEAL_ID fails...
        IntelligentData[] memory more = new IntelligentData[](1);
        more[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("post-upgrade")});
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory none = new MetadataEntry[](0);
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID, sealedId));
        agenticId.registerWithSeal(agentOwner, "", none, more, keys, address(0xAB), SEAL_ID);
        // ...and a fresh seal mints right after the pre-upgrade agents.
        vm.prank(attestor);
        uint256 nextId = agenticId.registerWithSeal(
            agentOwner, "", none, more, keys, address(0xAB), bytes32(uint256(SEAL_ID) + 1)
        );
        assertEq(nextId, soldId + 1, "canonical counter continues");
        assertEq(agenticId.getAgentSeal(nextId), address(0xAB), "new seal bound");
    }

    function test_agenticID_upgrade_ownershipBecomesTwoStep() public {
        // 1.1.0 is one-step Ownable: no pendingOwner on the old impl.
        vm.expectRevert();
        agenticId.pendingOwner();

        _upgrade(agenticIdBeacon, address(new AgenticID()));

        vm.prank(owner);
        agenticId.transferOwnership(newOwner);
        assertEq(agenticId.owner(), owner, "propose leaves owner unchanged");
        assertEq(agenticId.pendingOwner(), newOwner, "pending owner recorded");
        assertEq(
            address(uint160(uint256(vm.load(address(agenticId), OWNABLE2STEP_SLOT)))),
            newOwner,
            "pending owner lives in OZ's Ownable2Step slot"
        );

        vm.prank(address(0xB0B));
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xB0B))
        );
        agenticId.acceptOwnership();

        vm.prank(newOwner);
        agenticId.acceptOwnership();
        assertEq(agenticId.owner(), newOwner, "owner moves on accept");
        assertEq(agenticId.pendingOwner(), address(0), "pending cleared");
    }

    function test_agenticID_upgrade_closesZeroVerifier() public {
        // FIND-12 as shipped in 1.1.0: a zero verifier was accepted silently.
        uint256 snap = vm.snapshotState();
        vm.prank(owner);
        agenticId.setVerifier(address(0));
        assertEq(address(agenticId.verifier()), address(0), "1.1.0 accepted a zero verifier");
        vm.revertToState(snap);

        _upgrade(agenticIdBeacon, address(new AgenticID()));

        vm.prank(owner);
        vm.expectRevert(AgenticIDZeroAddress.selector);
        agenticId.setVerifier(address(0));

        vm.expectEmit(true, true, false, false, address(agenticId));
        emit AgenticID.VerifierUpdated(address(verifier), address(0xDEAD));
        vm.prank(owner);
        agenticId.setVerifier(address(0xDEAD));
    }

    // ── TEEDataVerifier 1.1.0 → 1.2.0 ─────────────────────────────────────────

    function test_verifier_upgrade_preservesState() public {
        bytes32 apKey = _nonceKey("ERC7857_TRANSFER_ACCESS", "ap-1");
        bytes32 opKey = _nonceKey("ERC7857_TRANSFER_OWNERSHIP", "op-1");
        assertTrue(verifier.isNonceConsumed(apKey), "pre-upgrade access nonce consumed");
        assertTrue(verifier.isNonceConsumed(opKey), "pre-upgrade ownership nonce consumed");
        uint256 apAt = verifier.nonceConsumedAt(apKey);
        assertEq(vm.load(address(verifier), OWNABLE2STEP_SLOT), bytes32(0), "pending slot unused by 1.1.0");

        _upgrade(verifierBeacon, address(new TEEDataVerifier()));
        assertEq(verifier.VERSION(), "1.2.0", "post-upgrade VERSION");

        assertEq(verifier.owner(), owner, "owner preserved");
        assertEq(verifier.pendingOwner(), address(0), "no pending owner after upgrade");
        assertEq(verifier.pauser(), pauser, "pauser preserved");
        assertEq(verifier.teeOracleAddress(), oracleAddr, "oracle preserved");
        assertEq(verifier.maxProofAge(), MAX_PROOF_AGE, "maxProofAge preserved");
        assertTrue(verifier.isNonceConsumed(apKey), "access nonce store preserved");
        assertTrue(verifier.isNonceConsumed(opKey), "ownership nonce store preserved");
        assertEq(verifier.nonceConsumedAt(apKey), apAt, "nonce timestamp preserved");

        // The upgraded verifier still verifies (proof encoding unchanged):
        // the buyer resells to the original seller with fresh proofs.
        _sell(soldId, soldHash, buyer.addr, seller, "ap-2", "op-2");
        assertEq(agenticId.ownerOf(soldId), seller.addr, "post-upgrade transfer verified");
    }

    function test_verifier_upgrade_ownershipBecomesTwoStepAndClosesZeroOracle() public {
        // FIND-12 as shipped in 1.1.0: a zero oracle was accepted silently.
        uint256 snap = vm.snapshotState();
        vm.prank(owner);
        verifier.setTeeOracleAddress(address(0));
        assertEq(verifier.teeOracleAddress(), address(0), "1.1.0 accepted a zero oracle");
        vm.revertToState(snap);

        _upgrade(verifierBeacon, address(new TEEDataVerifier()));

        vm.prank(owner);
        vm.expectRevert(TEEDataVerifierZeroAddress.selector);
        verifier.setTeeOracleAddress(address(0));

        address rotated = makeAddr("rotated-oracle");
        vm.expectEmit(true, true, false, false, address(verifier));
        emit TEEDataVerifier.TeeOracleUpdated(oracleAddr, rotated);
        vm.prank(owner);
        verifier.setTeeOracleAddress(rotated);

        vm.prank(owner);
        verifier.transferOwnership(newOwner);
        assertEq(verifier.owner(), owner, "propose leaves owner unchanged");
        assertEq(verifier.pendingOwner(), newOwner, "pending owner recorded");
        vm.prank(newOwner);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), newOwner, "owner moves on accept");
    }
}
