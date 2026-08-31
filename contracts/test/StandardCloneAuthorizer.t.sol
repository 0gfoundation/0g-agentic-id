// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CloneGate, CloneGateDenied} from "../src/CloneGate.sol";
import {StandardCloneAuthorizer, StdCloneAuthNotSeller} from "../src/StandardCloneAuthorizer.sol";

/// @notice StandardCloneAuthorizer — the official stock policy: per-agent
///         purchase scoping, seller-managed grants, owner-at-grant lazy
///         invalidation, and the full consult path through CloneGate.
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

    function _auth(uint256 purchaseId) internal pure returns (bytes memory) {
        return abi.encode(purchaseId);
    }

    // ── grant / revoke authorization ──────────────────────────────────────────

    function test_grant_sellerOnly() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        vm.expectEmit(true, true, true, true, address(std));
        emit StandardCloneAuthorizer.PurchaseGranted(sourceId, 1, buyer, owner);
        std.grant(sourceId, 1, buyer);

        (address b, address g, bool effective) = std.purchaseOf(sourceId, 1);
        assertEq(b, buyer);
        assertEq(g, owner);
        assertTrue(effective);
    }

    function test_grant_revertsForNonSeller() public {
        (uint256 sourceId,) = _source();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(StdCloneAuthNotSeller.selector, attacker, sourceId, owner));
        std.grant(sourceId, 1, buyer);
    }

    function test_grant_revertsForNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 999));
        std.grant(999, 1, buyer);
    }

    function test_grant_revertsForZeroBuyer() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        vm.expectRevert(bytes("buyer=0"));
        std.grant(sourceId, 1, address(0));
    }

    function test_grant_overwriteRedirectsBuyer() public {
        (uint256 sourceId,) = _source();
        vm.startPrank(owner);
        std.grant(sourceId, 1, attacker); // fat-fingered
        std.grant(sourceId, 1, buyer);    // corrected
        vm.stopPrank();
        assertFalse(std.canClone(sourceId, attacker, attacker, _auth(1)));
        assertTrue(std.canClone(sourceId, buyer, buyer, _auth(1)));
    }

    function test_revoke_sellerOnly_deletesPurchase() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, 1, buyer);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(StdCloneAuthNotSeller.selector, attacker, sourceId, owner));
        std.revoke(sourceId, 1);

        vm.prank(owner);
        vm.expectEmit(true, true, false, true, address(std));
        emit StandardCloneAuthorizer.PurchaseRevoked(sourceId, 1, owner);
        std.revoke(sourceId, 1);
        assertFalse(std.canClone(sourceId, buyer, buyer, _auth(1)));
    }

    // ── canClone verdict matrix ───────────────────────────────────────────────

    function test_canClone_matrix() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, 7, buyer);

        assertTrue(std.canClone(sourceId, buyer, buyer, _auth(7)), "happy path");
        assertFalse(std.canClone(sourceId, buyer, buyer, _auth(8)), "unknown purchase");
        assertFalse(std.canClone(sourceId, attacker, attacker, _auth(7)), "wrong buyer");
        assertFalse(std.canClone(sourceId, buyer, attacker, _auth(7)), "relayed by non-buyer");
        assertFalse(std.canClone(sourceId, buyer, buyer, hex"0102"), "malformed data");
    }

    function test_canClone_purchasesScopedPerAgent() public {
        (uint256 a,) = _source();
        (uint256 b,) = _mintWithSealSalt(owner, 1);
        vm.prank(owner);
        std.grant(a, 1, buyer);
        assertTrue(std.canClone(a, buyer, buyer, _auth(1)), "granted agent unlocks");
        assertFalse(std.canClone(b, buyer, buyer, _auth(1)), "same purchase id, other agent stays locked");
    }

    // ── lazy owner-at-grant invalidation (same semantics as the gate config) ──

    function test_canClone_grantDiesOnTransfer_revivesOnReacquire() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, 1, buyer);

        vm.prank(owner);
        agenticId.transferFrom(owner, attacker, sourceId);
        assertFalse(std.canClone(sourceId, buyer, buyer, _auth(1)), "dormant under new owner");
        (,, bool effective) = std.purchaseOf(sourceId, 1);
        assertFalse(effective);

        vm.prank(attacker);
        agenticId.transferFrom(attacker, owner, sourceId);
        assertTrue(std.canClone(sourceId, buyer, buyer, _auth(1)), "revives when grantor re-acquires");
    }

    function test_newOwnerGrantsFresh_overwritingStaleGrant() public {
        (uint256 sourceId,) = _source();
        vm.prank(owner);
        std.grant(sourceId, 1, buyer);
        vm.prank(owner);
        agenticId.transferFrom(owner, attacker, sourceId);

        vm.prank(attacker); // now the seller
        std.grant(sourceId, 1, buyer);
        assertTrue(std.canClone(sourceId, buyer, buyer, _auth(1)), "new owner's own grant is live");
    }

    // ── end-to-end through the gate ───────────────────────────────────────────

    function test_cloneFrom_throughGate_withStandardPolicy() public {
        (uint256 sourceId, bytes32 dataHash) = _source();
        vm.prank(owner);
        gate.setCloneAuthorizer(sourceId, address(std));
        vm.prank(owner);
        std.grant(sourceId, 7, buyer);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = dataHash;
        bytes[] memory keys = new bytes[](1);
        keys[0] = hex"beef";

        vm.prank(attestor);
        uint256 cloneId = gate.cloneFrom(
            sourceId, buyer, hashes, keys, CLONE_SEAL, CLONE_SEAL_ID, buyer, _auth(7)
        );
        assertEq(gate.cloneSourceOf(cloneId), sourceId);
        assertEq(agenticId.ownerOf(cloneId), buyer);

        // Manual one-shot: seller revokes after the mint — next attempt denies.
        vm.prank(owner);
        std.revoke(sourceId, 7);
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(CloneGateDenied.selector, sourceId, address(std)));
        gate.cloneFrom(
            sourceId, buyer, hashes, keys, address(0x5EA2), bytes32(uint256(0xF00E)), buyer, _auth(7)
        );
    }
}
