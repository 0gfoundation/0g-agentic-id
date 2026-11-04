// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {CanonicalReputationRegistryMock} from "./mocks/CanonicalReputationRegistryMock.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";

/// @dev The owner-only setter all three contracts share — used to show who
///      holds owner rights at each step.
interface IPauserAdmin {
    function pauser() external view returns (address);
    function setPauser(address newPauser) external;
}

/// @notice FIND-16 (governance part): AgenticID, TEEDataVerifier and
///         VerifiedFeedbackRegistry are Ownable2Step (AgenticID / TEEDataVerifier
///         1.2.0, VerifiedFeedbackRegistry 1.2.0). transferOwnership only
///         records a pending owner; ownership — and with it every onlyOwner
///         admin call — moves only when that pending owner calls
///         acceptOwnership, so a mistyped or unreachable address can't strand
///         the admin surface. Each flow runs against all three contracts.
contract TwoStepOwnershipTest is AgenticIDTestBase {
    VerifiedFeedbackRegistry internal registry;

    address internal newOwner = address(0x0E1);
    address internal otherCandidate = address(0x0E2);
    address internal stranger = address(0xB0B);

    function setUp() public override {
        super.setUp();
        CanonicalReputationRegistryMock canonicalRep = new CanonicalReputationRegistryMock();
        VerifiedFeedbackRegistry impl = new VerifiedFeedbackRegistry();
        registry = VerifiedFeedbackRegistry(address(new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(agenticId), address(canonicalRep), owner, pauser, MAX_PROOF_AGE)
            )
        )));
    }

    function _unauthorized(address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, who);
    }

    /// @dev propose → (owner unchanged, pending set) → only the pending owner
    ///      can accept → owner moves, pending cleared, old owner locked out.
    function _assertTwoStepTransfer(address target) internal {
        Ownable2StepUpgradeable o = Ownable2StepUpgradeable(target);
        IPauserAdmin admin = IPauserAdmin(target);
        assertEq(o.owner(), owner, "initial owner");
        assertEq(o.pendingOwner(), address(0), "no pending owner initially");

        // Only the owner may propose.
        vm.prank(stranger);
        vm.expectRevert(_unauthorized(stranger));
        o.transferOwnership(newOwner);

        // Step 1: propose. Nothing moves yet.
        vm.expectEmit(true, true, false, false, target);
        emit Ownable2StepUpgradeable.OwnershipTransferStarted(owner, newOwner);
        vm.prank(owner);
        o.transferOwnership(newOwner);
        assertEq(o.owner(), owner, "owner unchanged after transferOwnership");
        assertEq(o.pendingOwner(), newOwner, "pendingOwner set");

        // The pending owner has no owner rights yet; the current owner keeps them.
        vm.prank(newOwner);
        vm.expectRevert(_unauthorized(newOwner));
        admin.setPauser(address(0xD1));
        vm.prank(owner);
        admin.setPauser(address(0xD1));
        assertEq(admin.pauser(), address(0xD1), "current owner still administers");

        // Nobody but the pending owner can accept — not a stranger, not the
        // current owner.
        vm.prank(stranger);
        vm.expectRevert(_unauthorized(stranger));
        o.acceptOwnership();
        vm.prank(owner);
        vm.expectRevert(_unauthorized(owner));
        o.acceptOwnership();

        // Step 2: accept.
        vm.expectEmit(true, true, false, false, target);
        emit OwnableUpgradeable.OwnershipTransferred(owner, newOwner);
        vm.prank(newOwner);
        o.acceptOwnership();
        assertEq(o.owner(), newOwner, "owner moved on accept");
        assertEq(o.pendingOwner(), address(0), "pending cleared on accept");

        // Rights moved with it.
        vm.prank(owner);
        vm.expectRevert(_unauthorized(owner));
        admin.setPauser(address(0xD2));
        vm.prank(newOwner);
        admin.setPauser(address(0xD2));
        assertEq(admin.pauser(), address(0xD2), "new owner administers");
    }

    /// @dev A second proposal replaces the first; proposing address(0)
    ///      cancels. A superseded candidate can never accept.
    function _assertOverwriteAndCancel(address target) internal {
        Ownable2StepUpgradeable o = Ownable2StepUpgradeable(target);

        vm.prank(owner);
        o.transferOwnership(otherCandidate);
        vm.prank(owner);
        o.transferOwnership(newOwner);
        assertEq(o.pendingOwner(), newOwner, "second proposal replaces the first");

        vm.prank(otherCandidate);
        vm.expectRevert(_unauthorized(otherCandidate));
        o.acceptOwnership();

        vm.prank(owner);
        o.transferOwnership(address(0));
        assertEq(o.pendingOwner(), address(0), "proposal cancelled");
        vm.prank(newOwner);
        vm.expectRevert(_unauthorized(newOwner));
        o.acceptOwnership();
        assertEq(o.owner(), owner, "owner never moved");
    }

    function test_twoStep_AgenticID() public {
        _assertTwoStepTransfer(address(agenticId));
    }

    function test_twoStep_TEEDataVerifier() public {
        _assertTwoStepTransfer(address(verifier));
    }

    function test_twoStep_VerifiedFeedbackRegistry() public {
        _assertTwoStepTransfer(address(registry));
    }

    function test_overwriteAndCancel_AgenticID() public {
        _assertOverwriteAndCancel(address(agenticId));
    }

    function test_overwriteAndCancel_TEEDataVerifier() public {
        _assertOverwriteAndCancel(address(verifier));
    }

    function test_overwriteAndCancel_VerifiedFeedbackRegistry() public {
        _assertOverwriteAndCancel(address(registry));
    }
}
