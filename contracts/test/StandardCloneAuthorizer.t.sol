// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CloneGate, CloneGateDenied} from "../src/CloneGate.sol";
import {StandardCloneAuthorizer, StdCloneAuthNotSeller} from "../src/StandardCloneAuthorizer.sol";

/// @notice StandardCloneAuthorizer — the official stock policy: a per-buyer
///         permission switch keyed (sourceAgentId, buyer), seller-managed,
///         owner-at-grant lazy invalidation, full consult path through
///         CloneGate. authData is ignored by design.
contract StandardCloneAuthorizerTest is AgenticIDTestBase {
    CloneGate internal gate;
    StandardCloneAuthorizer internal std;

    address internal buyer = address(0xB0B);
    address internal attacker = address(0xEA11);

    address internal constant CLONE_SEAL = address(0x5EA1);
    bytes32 internal constant CLONE_SEAL_ID = bytes32(uint256(0xF00D));

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
        std = new StandardCloneAuthorizer(address(agenticId));

        CloneGate impl = new CloneGate();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(CloneGate.initialize, (address(agenticId)))
        );
        gate = CloneGate(address(proxy));
        vm.prank(owner);
        agenticId.addTrustedAttestor(address(gate));
    }

    function _source() internal returns (uint256 sourceId, bytes32 dataHash) {
        (sourceId, dataHash) = _mintWithSeal(owner);
    }

    // ── grant / revoke authorization ──────────────────────────────────────────

    function test_grant_sellerOnly() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        vm.expectEmit(true, true, false, true, address(std));
        emit StandardCloneAuthorizer.CloneGranted(sourceId, buyer, owner);
        std.grant(sourceId, buyer);

        (address grantor, bool effective) = std.grantOf(sourceId, buyer);
        assertEq(grantor, owner);
        assertTrue(effective);
    }

    function test_grant_revertsForNonSeller() public {
        (uint256 sourceId,) = _source();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(StdCloneAuthNotSeller.selector, attacker, sourceId, owner));
        std.grant(sourceId, buyer);
    }

    function test_grant_revertsForNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 999));
        std.grant(999, buyer);
    }

    function test_grant_revertsForZeroBuyer() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        vm.expectRevert(bytes("buyer=0"));
        std.grant(sourceId, address(0));
    }

    function test_revoke_sellerOnly_closesTheDoor() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, buyer);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(StdCloneAuthNotSeller.selector, attacker, sourceId, owner));
        std.revoke(sourceId, buyer);

        vm.prank(owner);
        vm.expectEmit(true, true, false, true, address(std));
        emit StandardCloneAuthorizer.CloneRevoked(sourceId, buyer, owner);
        std.revoke(sourceId, buyer);
        assertFalse(std.canClone(sourceId, buyer, buyer, ""));
        (address grantor, bool effective) = std.grantOf(sourceId, buyer);
        assertEq(grantor, address(0));
        assertFalse(effective);
    }

    // ── canClone verdict matrix ───────────────────────────────────────────────

    function test_canClone_matrix() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, buyer);

        assertTrue(std.canClone(sourceId, buyer, buyer, ""), "happy path");
        assertTrue(std.canClone(sourceId, buyer, buyer, hex"deadbeef"), "authData ignored by design");
        assertFalse(std.canClone(sourceId, attacker, attacker, ""), "ungranted buyer");
        assertFalse(std.canClone(sourceId, buyer, attacker, ""), "relayed by non-buyer");
    }

    function test_canClone_grantsScopedPerAgent() public {
        (uint256 a,) = _source();
        (uint256 b,) = _mintWithSealSalt(owner, 1);
        vm.prank(owner);
        std.grant(a, buyer);
        assertTrue(std.canClone(a, buyer, buyer, ""), "granted agent unlocks");
        assertFalse(std.canClone(b, buyer, buyer, ""), "same buyer, other agent stays locked");
    }

    // ── lazy owner-at-grant invalidation (same semantics as the gate config) ──

    function test_canClone_grantDiesOnTransfer_revivesOnReacquire() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, buyer);

        vm.prank(owner);
        agenticId.transferFrom(owner, attacker, sourceId);
        assertFalse(std.canClone(sourceId, buyer, buyer, ""), "dormant under new owner");
        (, bool effective) = std.grantOf(sourceId, buyer);
        assertFalse(effective);

        vm.prank(attacker);
        agenticId.transferFrom(attacker, owner, sourceId);
        assertTrue(std.canClone(sourceId, buyer, buyer, ""), "revives when grantor re-acquires");
    }

    function test_newOwnerGrantsFresh_overwritingStaleGrant() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, buyer);
        vm.prank(owner);
        agenticId.transferFrom(owner, attacker, sourceId);

        vm.prank(attacker); // now the seller
        std.grant(sourceId, buyer);
        assertTrue(std.canClone(sourceId, buyer, buyer, ""), "new owner's own grant is live");
    }

    // ── end-to-end through the gate ───────────────────────────────────────────

    function test_cloneFrom_throughGate_withStandardPolicy() public {
        (uint256 sourceId, bytes32 dataHash) = _source();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(std));
        vm.prank(owner);
        std.grant(sourceId, buyer);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = dataHash;
        bytes[] memory keys = new bytes[](1);
        keys[0] = hex"beef";

        vm.prank(attestor);
        uint256 cloneId = gate.cloneFrom(
            sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, ""
        );
        assertEq(gate.cloneSourceOf(cloneId), sourceId);
        assertEq(agenticId.ownerOf(cloneId), buyer);

        // Manual one-shot: seller revokes after the mint — next attempt denies.
        vm.prank(owner);
        std.revoke(sourceId, buyer);
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(CloneGateDenied.selector, sourceId, address(std)));
        gate.cloneFrom(
            sourceId, buyer, hashes, keys, address(0x5EA2), bytes32(uint256(0xF00E)), buyer, ""
        );
    }
}
