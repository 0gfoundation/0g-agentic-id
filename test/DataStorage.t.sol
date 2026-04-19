// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {IERC7857Updatable} from "../contracts/interfaces/IERC7857Updatable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract DataStorageTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── update(): full replacement by owner ───────────────────────────────────

    function test_update_replacesAllEntries() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        IntelligentData[] memory newDatas = new IntelligentData[](2);
        newDatas[0] = IntelligentData({dataDescription: "replaced-1", dataHash: keccak256("r1")});
        newDatas[1] = IntelligentData({dataDescription: "replaced-2", dataHash: keccak256("r2")});

        vm.prank(alice);
        agenticId.update(agentId, newDatas);

        IntelligentData[] memory stored = agenticId.intelligentDatasOf(agentId);
        assertEq(stored.length, 2, "stored length matches new");
        assertEq(stored[0].dataHash, newDatas[0].dataHash, "entry 0 replaced");
        assertEq(stored[1].dataHash, newDatas[1].dataHash, "entry 1 replaced");
    }

    function test_update_revertsOnEmpty() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory empty = new IntelligentData[](0);

        vm.prank(alice);
        vm.expectRevert(IERC7857Updatable.ERC7857EmptyData.selector);
        agenticId.update(agentId, empty);
    }

    function test_update_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "n", dataHash: keccak256("n")});

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.update(agentId, newDatas);
    }

    // ── updateAt(): single-entry edit ─────────────────────────────────────────

    function test_updateAt_replacesOneEntry() public {
        (uint256 agentId, ) = _mintWithNDatas(alice, 3);

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "new",
            dataHash: keccak256("new-hash")
        });

        vm.prank(alice);
        agenticId.updateAt(agentId, 1, replacement);

        IntelligentData[] memory stored = agenticId.intelligentDatasOf(agentId);
        assertEq(stored.length, 3, "length unchanged");
        assertEq(stored[1].dataHash, replacement.dataHash, "entry 1 replaced");
        // Entries 0 and 2 should be the originally-minted hashes.
        assertTrue(stored[0].dataHash != replacement.dataHash, "entry 0 untouched");
        assertTrue(stored[2].dataHash != replacement.dataHash, "entry 2 untouched");
    }

    function test_updateAt_revertsOnOutOfBounds() public {
        (uint256 agentId, ) = _mintWithSeal(alice); // length = 1

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "x",
            dataHash: keccak256("x")
        });

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Updatable.ERC7857IndexOutOfBounds.selector, uint256(5), uint256(1)
            )
        );
        agenticId.updateAt(agentId, 5, replacement);
    }

    function test_updateAt_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData memory replacement = IntelligentData({
            dataDescription: "x",
            dataHash: keccak256("x")
        });

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.updateAt(agentId, 0, replacement);
    }
}
