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
import {AgenticID, AgenticIDZeroAddress, AgenticIDSealIdTaken, AgenticIDAgentSealTaken} from "../src/AgenticID.sol";
import {
    TEEDataVerifier,
    TEEDataVerifierZeroAddress,
    TEEDataVerifierInvalidSignature
} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CloneGate, CloneGateSourceSealReused} from "../src/CloneGate.sol";
import {ICloneAuthorizer} from "../src/interfaces/ICloneAuthorizer.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {
    AccessProof,
    OracleType,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

/// @notice AgenticID 1.1.0 → 1.3.0 and TEEDataVerifier 1.1.0 → 1.2.0 across a
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
///           - the FIND-12 setter guards are live through the existing proxy;
///           - transfer proofs become token-bound (FIND-05), which changes
///             the AgenticID → verifier call, so the two impls must land in
///             the same window: either one alone breaks non-seal transfers.
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
        _sellV1_1_0(soldId, soldHash, seller.addr, buyer, "ap-1", "op-1");
    }

    /// @dev Proof-gated iTransferFrom under the 1.1.0 impls: the 1.1.0 proof
    ///      preimages, abi.encode(chainId, erc7857, <fields>) — no tokenId /
    ///      from.
    function _sellV1_1_0(
        uint256 agentId,
        bytes32 dataHash,
        address from,
        Vm.Wallet memory to,
        bytes memory apNonce,
        bytes memory opNonce
    ) internal {
        vm.prank(from);
        agenticId.iTransferFrom(from, to.addr, agentId, _proofsV1_1_0(dataHash, to, apNonce, opNonce));
    }

    function _proofsV1_1_0(bytes32 dataHash, Vm.Wallet memory to, bytes memory apNonce, bytes memory opNonce)
        internal view returns (TransferValidityProof[] memory proofs)
    {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory toPubkey = _pubkey(to);
        bytes32 apInner = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash, bytes(""), apNonce, deadline
        ));
        bytes32 opInner = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash, SEALED_KEY_NEW, toPubkey, opNonce, deadline
        ));
        proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({
            accessProof: AccessProof({
                dataHash: dataHash, targetPubkey: "", nonce: apNonce, deadline: deadline,
                proof: _sign(to.privateKey, _eip191HexHash(apInner))
            }),
            ownershipProof: OwnershipProof({
                oracleType: OracleType.TEE, dataHash: dataHash, sealedKey: SEALED_KEY_NEW,
                targetPubkey: toPubkey, nonce: opNonce, deadline: deadline,
                proof: _sign(oraclePk, _eip191HexHash(opInner))
            })
        });
    }

    /// @dev Proof-gated iTransferFrom of a non-seal agent to `to` (1.2.0
    ///      token-bound proofs).
    function _sell(
        uint256 agentId,
        bytes32 dataHash,
        address from,
        Vm.Wallet memory to,
        bytes memory apNonce,
        bytes memory opNonce
    ) internal {
        uint256 deadline = block.timestamp + 1 hours;
        AccessProof memory ap = _mkAccessProof(agentId, from, dataHash, "", apNonce, deadline, to.privateKey);
        OwnershipProof memory op = _mkOwnershipProof(agentId, from, dataHash, SEALED_KEY_NEW, _pubkey(to), opNonce, deadline);
        TransferValidityProof[] memory proofs = new TransferValidityProof[](1);
        proofs[0] = TransferValidityProof({accessProof: ap, ownershipProof: op});
        vm.prank(from);
        agenticId.iTransferFrom(from, to.addr, agentId, proofs);
    }

    /// @dev The 1.1.0 verifier's nonce key for a proof nonce
    ///      (keccak256(abi.encode(tag, msg.sender = AgenticID, nonce)); 1.2.0
    ///      adds the signer to the access key — FIND-06 — and the tokenId to
    ///      the ownership key).
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

    // ── AgenticID 1.1.0 → 1.3.0 ───────────────────────────────────────────────

    function test_agenticID_upgrade_preservesState() public {
        assertEq(vm.load(address(agenticId), OWNABLE2STEP_SLOT), bytes32(0), "pending slot unused by 1.1.0");
        bytes32 ownerWord = vm.load(address(agenticId), OWNABLE_SLOT);
        assertEq(address(uint160(uint256(ownerWord))), owner, "owner lives in OZ's Ownable slot");

        _upgrade(agenticIdBeacon, address(new AgenticID()));
        assertEq(agenticId.VERSION(), "1.3.0", "post-upgrade VERSION");

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
        // ...and a seal address bound after the upgrade cannot be bound again (FIND-08).
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDAgentSealTaken.selector, address(0xAB)));
        agenticId.registerWithSeal(agentOwner, "", none, more, keys, address(0xAB), bytes32(uint256(SEAL_ID) + 2));
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
        // Token-bound proofs change the AgenticID → verifier call: AgenticID
        // ships in the same window.
        _upgrade(agenticIdBeacon, address(new AgenticID()));

        assertEq(verifier.owner(), owner, "owner preserved");
        assertEq(verifier.pendingOwner(), address(0), "no pending owner after upgrade");
        assertEq(verifier.pauser(), pauser, "pauser preserved");
        assertEq(verifier.teeOracleAddress(), oracleAddr, "oracle preserved");
        assertEq(verifier.maxProofAge(), MAX_PROOF_AGE, "maxProofAge preserved");
        assertTrue(verifier.isNonceConsumed(apKey), "access nonce store preserved");
        assertTrue(verifier.isNonceConsumed(opKey), "ownership nonce store preserved");
        assertEq(verifier.nonceConsumedAt(apKey), apAt, "nonce timestamp preserved");

        // 1.1.0-format proofs (no tokenId / from) no longer verify...
        TransferValidityProof[] memory legacy = _proofsV1_1_0(soldHash, seller, "ap-legacy", "op-legacy");
        vm.prank(buyer.addr);
        vm.expectRevert(TEEDataVerifierInvalidSignature.selector);
        agenticId.iTransferFrom(buyer.addr, seller.addr, soldId, legacy);
        // ...token-bound ones do: the buyer resells to the original seller.
        _sell(soldId, soldHash, buyer.addr, seller, "ap-2", "op-2");
        assertEq(agenticId.ownerOf(soldId), seller.addr, "post-upgrade transfer verified");
    }

    /// @dev The rollout constraint behind "same window": with only one of the
    ///      two impls upgraded, the AgenticID → verifier call has no matching
    ///      entrypoint and every non-seal transfer reverts (none happen today:
    ///      no oracle signs ownership proofs yet).
    function test_verifierAndAgenticID_mustUpgradeTogether() public {
        uint256 snap = vm.snapshotState();

        // No matching selector and no fallback: an empty revert, bubbled up.
        _upgrade(verifierBeacon, address(new TEEDataVerifier()));
        TransferValidityProof[] memory legacy = _proofsV1_1_0(soldHash, seller, "ap-v", "op-v");
        vm.prank(buyer.addr);
        vm.expectRevert(bytes(""));
        agenticId.iTransferFrom(buyer.addr, seller.addr, soldId, legacy);

        vm.revertToState(snap);
        _upgrade(agenticIdBeacon, address(new AgenticID()));
        vm.expectRevert(bytes(""));
        _sell(soldId, soldHash, buyer.addr, seller, "ap-a", "op-a");

        _upgrade(verifierBeacon, address(new TEEDataVerifier()));
        _sell(soldId, soldHash, buyer.addr, seller, "ap-a", "op-a");
        assertEq(agenticId.ownerOf(soldId), seller.addr, "both upgraded: transfer verifies");
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

    /// @dev FIND-08 on the deployed state. AgenticID 1.2.0 tracks only seals
    ///      bound after its upgrade, so a pre-upgrade seal is not refused by
    ///      registerWithSeal itself (the documented limit — the attestor
    ///      derives every seal from a fresh sealId). CloneGate 1.1.0 still
    ///      refuses that seal for a clone of its own source.
    function test_legacySeal_cloneGateRejectsItAsTheCloneSeal() public {
        _upgrade(agenticIdBeacon, address(new AgenticID()));
        CloneGate gate = CloneGate(address(new ERC1967Proxy(
            address(new CloneGate()), abi.encodeCall(CloneGate.initialize, (address(agenticId)))
        )));
        vm.prank(owner);
        agenticId.addTrustedAttestor(address(gate));
        AllowAllAuthorizer allow = new AllowAllAuthorizer();
        vm.prank(agentOwner);
        gate.setCloneAuthorizer(sealedId, address(allow));

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = sealedHash;
        bytes[] memory keys = new bytes[](1);
        keys[0] = SEALED_KEY_NEW;
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(CloneGateSourceSealReused.selector, SEAL_ADDR));
        gate.cloneFrom(sealedId, buyer.addr, hashes, keys, SEAL_ADDR, bytes32(uint256(SEAL_ID) + 9), buyer.addr, "");

        // A fresh seal clones fine.
        vm.prank(attestor);
        uint256 cloneId = gate.cloneFrom(
            sealedId, buyer.addr, hashes, keys, address(0xC10E), bytes32(uint256(SEAL_ID) + 9), buyer.addr, ""
        );
        assertEq(agenticId.getAgentSeal(cloneId), address(0xC10E), "clone bound to its own seal");
    }
}

contract AllowAllAuthorizer is ICloneAuthorizer {
    function canClone(uint256, address, address, bytes calldata) external pure returns (bool) {
        return true;
    }
}
