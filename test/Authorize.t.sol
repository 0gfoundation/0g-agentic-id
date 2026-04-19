// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IERC7857Authorize} from "../contracts/interfaces/IERC7857Authorize.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract AuthorizeTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);
    address internal userA = address(0xA10);
    address internal userB = address(0xB20);
    address internal userC = address(0xC30);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── authorizeUsage ────────────────────────────────────────────────────────

    function test_authorizeUsage_happyPath() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(alice);
        agenticId.authorizeUsage(agentId, userA);

        address[] memory users = agenticId.authorizedUsersOf(agentId);
        assertEq(users.length, 1, "one user authorized");
        assertEq(users[0], userA, "userA is in the set");
    }

    function test_authorizeUsage_revertsOnZeroAddress() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Authorize.ERC7857InvalidAuthorizedUser.selector, address(0)
            )
        );
        agenticId.authorizeUsage(agentId, address(0));
    }

    function test_authorizeUsage_revertsOnDuplicate() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.startPrank(alice);
        agenticId.authorizeUsage(agentId, userA);
        vm.expectRevert(IERC7857Authorize.ERC7857AlreadyAuthorized.selector);
        agenticId.authorizeUsage(agentId, userA);
        vm.stopPrank();
    }

    function test_authorizeUsage_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.authorizeUsage(agentId, userA);
    }

    // ── batchAuthorizeUsage ───────────────────────────────────────────────────

    function test_batchAuthorizeUsage_addsAll() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        address[] memory batch = new address[](3);
        batch[0] = userA;
        batch[1] = userB;
        batch[2] = userC;

        vm.prank(alice);
        agenticId.batchAuthorizeUsage(agentId, batch);

        address[] memory stored = agenticId.authorizedUsersOf(agentId);
        assertEq(stored.length, 3, "three users authorized");
    }

    function test_batchAuthorizeUsage_revertsOnZeroInBatch() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        address[] memory batch = new address[](2);
        batch[0] = userA;
        batch[1] = address(0);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Authorize.ERC7857InvalidAuthorizedUser.selector, address(0)
            )
        );
        agenticId.batchAuthorizeUsage(agentId, batch);
    }

    // ── revokeAuthorization ───────────────────────────────────────────────────

    function test_revokeAuthorization_removesUser() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.startPrank(alice);
        agenticId.authorizeUsage(agentId, userA);
        agenticId.authorizeUsage(agentId, userB);
        agenticId.revokeAuthorization(agentId, userA);
        vm.stopPrank();

        address[] memory stored = agenticId.authorizedUsersOf(agentId);
        assertEq(stored.length, 1, "one remaining");
        assertEq(stored[0], userB, "only userB remains");
    }

    function test_revokeAuthorization_revertsWhenUserNotAuthorized() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(alice);
        vm.expectRevert(IERC7857Authorize.ERC7857NotAuthorized.selector);
        agenticId.revokeAuthorization(agentId, userA);
    }

    // ── clearAuthorizedUsers ──────────────────────────────────────────────────

    function test_clearAuthorizedUsers_emptiesSet() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.startPrank(alice);
        agenticId.authorizeUsage(agentId, userA);
        agenticId.authorizeUsage(agentId, userB);
        agenticId.clearAuthorizedUsers(agentId);
        vm.stopPrank();

        address[] memory stored = agenticId.authorizedUsersOf(agentId);
        assertEq(stored.length, 0, "cleared");
    }
}
