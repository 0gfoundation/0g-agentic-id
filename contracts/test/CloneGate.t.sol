// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AgenticID, AgenticIDNotTrustedAttestor, AgenticIDSealIdTaken} from "../src/AgenticID.sol";
import {
    CloneGate,
    CloneGateNotTrustedAttestor,
    CloneGateNotTokenOwner,
    CloneGateDenied,
    CloneGateDataHashMismatch,
    CloneGateArityMismatch
} from "../src/CloneGate.sol";
import {IERC7857Updatable} from "../src/interfaces/IERC7857Updatable.sol";
import {ICloneAuthorizer} from "../src/interfaces/ICloneAuthorizer.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";

/// @dev Configurable verdict — for deny / allow toggling.
contract ToggleAuthorizer {
    bool public allow = true;

    function setAllow(bool a) external {
        allow = a;
    }

    function canClone(uint256, address, address, bytes calldata) external view returns (bool) {
        return allow;
    }
}

/// @dev An authorizer that REVERTS (a failed require) rather than returning
///      false — pins the documented bubbling semantics: the authorizer's own
///      revert data surfaces from cloneFrom unchanged, NOT
///      CloneGateDenied (which is reserved for unconfigured/declined).
contract RevertingAuthorizer {
    error PurchaseExpired(uint256 purchaseId);

    function canClone(uint256, address, address, bytes calldata) external pure returns (bool) {
        revert PurchaseExpired(42);
    }
}

/// @dev Args-binding authorizer: returns true only when called with the EXACT
///      (source, target, caller, data) it was constructed with. Asserts the
///      policy receives correctly-bound arguments (canClone is view — no
///      mock-side recording possible).
contract BoundAuthorizer {
    uint256 internal immutable _source;
    address internal immutable _target;
    address internal immutable _caller;
    bytes internal _data;

    constructor(uint256 s, address t, address c, bytes memory d) {
        _source = s;
        _target = t;
        _caller = c;
        _data = d;
    }

    function canClone(uint256 s, address t, address c, bytes calldata d)
        external view returns (bool)
    {
        return s == _source && t == _target && c == _caller && keccak256(d) == keccak256(_data);
    }
}

/// @notice Policy-mode cloning (issue #133): setCloneAuthorizer / cloneFrom /
///         transfer-clearing semantics, against controllable authorizer mocks.
contract CloneGateTest is AgenticIDTestBase {
    CloneGate internal gate;

    ToggleAuthorizer internal toggle;
    address internal buyer = address(0xB0B);
    address internal attacker = address(0xEA11);

    // Fresh seal material for clones — must not collide with the base's
    // SEAL_ID / SEAL_ADDR (base mints with those).
    address internal constant CLONE_SEAL = address(0x5EA1);
    bytes32 internal constant CLONE_SEAL_ID = bytes32(uint256(0xF00D));
    bytes internal constant CLONE_SEALED_KEY = hex"beef";
    bytes internal constant AUTH_DATA = hex"0123";

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        toggle = new ToggleAuthorizer();

        CloneGate impl = new CloneGate();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(CloneGate.initialize, (address(agenticId)))
        );
        gate = CloneGate(address(proxy));
        // The gate mints through registerWithSeal, so it must be allowlisted.
        vm.prank(owner);
        agenticId.addTrustedAttestor(address(gate));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _mintSealedSource() internal returns (uint256 sourceId, bytes32 dataHash) {
        (sourceId, dataHash) = _mintWithSeal(owner);
    }

    function _cloneArgs(bytes32 dataHash)
        internal pure returns (bytes32[] memory hashes, bytes[] memory keys)
    {
        hashes = new bytes32[](1);
        hashes[0] = dataHash;
        keys = new bytes[](1);
        keys[0] = CLONE_SEALED_KEY;
    }

    function _cloneFrom(uint256 sourceId, bytes32 dataHash) internal returns (uint256 cloneId) {
        (bytes32[] memory hashes, bytes[] memory keys) = _cloneArgs(dataHash);
        vm.prank(attestor);
        cloneId = gate.cloneFrom(
            sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, AUTH_DATA
        );
    }

    function _cloneFromExpectRevert(uint256 sourceId, bytes32 dataHash, bytes memory revertData)
        internal
    {
        (bytes32[] memory hashes, bytes[] memory keys) = _cloneArgs(dataHash);
        vm.prank(attestor);
        vm.expectRevert(revertData);
        gate.cloneFrom(
            sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, AUTH_DATA
        );
    }

    // ── setCloneAuthorizer ────────────────────────────────────────────────────

    function test_setCloneAuthorizer_ownerSets() public {
        (uint256 sourceId,) = _mintSealedSource();
        vm.expectEmit(true, true, true, true, address(gate));
        emit CloneGate.CloneAuthorizerSet(sourceId, address(toggle), owner);
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));
        assertEq(gate.cloneAuthorizerOf(sourceId), address(toggle), "authorizer set");
    }

    function test_setCloneAuthorizer_revertsForNonOwner() public {
        (uint256 sourceId,) = _mintSealedSource();
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(CloneGateNotTokenOwner.selector, attacker, sourceId, owner)
        );
        gate.setCloneAuthorizer(sourceId, address(toggle));
    }

    function test_setCloneAuthorizer_revertsForNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(999)));
        gate.setCloneAuthorizer(999, address(toggle));
    }

    function test_setCloneAuthorizer_clearWithZero() public {
        (uint256 sourceId,) = _mintSealedSource();
        vm.startPrank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));
        gate.setCloneAuthorizer(sourceId, address(0));
        vm.stopPrank();
        assertEq(gate.cloneAuthorizerOf(sourceId), address(0), "authorizer cleared");
    }

    // ── cloneFrom — happy paths ───────────────────────────────────────────────

    function test_cloneFrom_happyPath() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        uint256 cloneId = _cloneFrom(sourceId, dataHash);

        assertEq(agenticId.ownerOf(cloneId), buyer, "clone minted to buyer");
        assertEq(gate.cloneSourceOf(cloneId), sourceId, "lineage recorded");
        assertEq(agenticId.getAgentSeal(cloneId), CLONE_SEAL, "clone seal bound");
        assertEq(agenticId.getSealId(cloneId), CLONE_SEAL_ID, "clone sealId bound");

        // iData copied from the LIVE source storage (description + hash).
        IntelligentData[] memory datas = agenticId.intelligentDatasOf(cloneId);
        assertEq(datas.length, 1, "one data entry");
        assertEq(datas[0].dataHash, dataHash, "dataHash copied from source");
        assertEq(datas[0].dataDescription, "d", "description copied from source");

        // Source untouched: still owned by the owner, seal unchanged.
        assertEq(agenticId.ownerOf(sourceId), owner, "source owner unchanged");
    }

    /// @dev The policy must be consulted with the EXACT bound arguments — a
    ///      mismatched call makes BoundAuthorizer return false → clone denied.
    function test_cloneFrom_policySeesBoundArguments() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        BoundAuthorizer bound = new BoundAuthorizer(sourceId, buyer, buyer, AUTH_DATA);
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(bound));

        uint256 cloneId = _cloneFrom(sourceId, dataHash);
        assertEq(gate.cloneSourceOf(cloneId), sourceId, "bound policy allowed the clone");
    }

    /// @dev Sequential ids: no other mints between source and clone, so the
    ///      clone takes the next canonical id — pinned here for the event test.
    function test_cloneFrom_emitsClonedFrom() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        uint256 expectedCloneId = sourceId + 1;
        vm.expectEmit(true, true, true, true, address(gate));
        emit CloneGate.ClonedFrom(sourceId, expectedCloneId, buyer, buyer);

        uint256 cloneId = _cloneFrom(sourceId, dataHash);
        assertEq(cloneId, expectedCloneId, "clone took the next canonical id");
    }

    // ── cloneFrom — rejections ────────────────────────────────────────────────

    function test_cloneFrom_revertsForNonAttestor() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        (bytes32[] memory hashes, bytes[] memory keys) = _cloneArgs(dataHash);
        vm.prank(attacker);
        vm.expectRevert(CloneGateNotTrustedAttestor.selector);
        gate.cloneFrom(
            sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, attacker, AUTH_DATA
        );
    }

    function test_cloneFrom_revertsWhenNoAuthorizer() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        // NOTE: no setCloneAuthorizer — fail closed.
        _cloneFromExpectRevert(
            sourceId,
            dataHash,
            abi.encodeWithSelector(CloneGateDenied.selector, sourceId, address(0))
        );
    }

    function test_cloneFrom_revertsWhenPolicyDenies() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));
        toggle.setAllow(false);

        _cloneFromExpectRevert(
            sourceId,
            dataHash,
            abi.encodeWithSelector(CloneGateDenied.selector, sourceId, address(toggle))
        );
    }

    /// @dev A REVERTING authorizer bubbles its own revert data (documented in
    ///      ICloneAuthorizer): the clone still fails closed, but the error is
    ///      the authorizer's — CloneGateDenied is reserved for
    ///      unconfigured/declined, and the bubbled reason is the diagnostic
    ///      the tx submitter (the attestor worker) reports.
    function test_cloneFrom_revertingAuthorizerBubblesOwnData() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        RevertingAuthorizer reverting = new RevertingAuthorizer();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(reverting));

        _cloneFromExpectRevert(
            sourceId, dataHash, abi.encodeWithSelector(RevertingAuthorizer.PurchaseExpired.selector, 42)
        );
    }

    function test_cloneFrom_revertsOnDataHashMismatch() public {
        (uint256 sourceId, bytes32 liveHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        // The attestor re-sealed against a stale snapshot (source evolved).
        bytes32 staleHash = keccak256("stale");
        _cloneFromExpectRevert(
            sourceId,
            staleHash,
            abi.encodeWithSelector(
                CloneGateDataHashMismatch.selector, 0, liveHash, staleHash
            )
        );
    }

    function test_cloneFrom_revertsOnNonexistentSource() public {
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(999)));
        (bytes32[] memory hashes, bytes[] memory keys) = _cloneArgs(keccak256("x"));
        gate.cloneFrom(999, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, AUTH_DATA);
    }

    function test_cloneFrom_revertsOnArityMismatch() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = dataHash;
        hashes[1] = dataHash;
        bytes[] memory keys = new bytes[](2); // source carries 1 entry
        keys[0] = hex"aa"; keys[1] = hex"bb";
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(CloneGateArityMismatch.selector, 1, 2));
        gate.cloneFrom(sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, AUTH_DATA);
    }

    function test_cloneFrom_revertsOnSealIdCollision() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        // Reuse the SOURCE's sealId (base mints with SEAL_ID) — already taken.
        (bytes32[] memory hashes, bytes[] memory keys) = _cloneArgs(dataHash);
        vm.prank(attestor);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID, sourceId)
        );
        gate.cloneFrom(sourceId, buyer, hashes, keys, CLONE_SEAL, SEAL_ID, buyer, AUTH_DATA);
    }

    function test_cloneFrom_revertsWhenPaused() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));

        vm.prank(pauser);
        agenticId.pause();

        _cloneFromExpectRevert(sourceId, dataHash, abi.encodePacked(PausableUpgradeable.EnforcedPause.selector));
    }

    // ── Transfer semantics ────────────────────────────────────────────────────

    function test_authorizerClearedOnTransfer() public {
        (uint256 sourceId,) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));
        assertTrue(gate.cloneAuthorizerOf(sourceId) != address(0), "precondition: set");

        // Sealed agents transfer via plain transferFrom (ownership-only path).
        vm.prank(owner);
        agenticId.transferFrom(owner, buyer, sourceId);

        assertEq(gate.cloneAuthorizerOf(sourceId), address(0), "authorizer cleared on transfer");
    }

    function test_lineageSurvivesTransfer() public {
        (uint256 sourceId, bytes32 dataHash) = _mintSealedSource();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(toggle));
        uint256 cloneId = _cloneFrom(sourceId, dataHash);

        vm.prank(buyer);
        agenticId.transferFrom(buyer, attacker, cloneId);

        assertEq(gate.cloneSourceOf(cloneId), sourceId, "lineage survives transfer");
    }
}
