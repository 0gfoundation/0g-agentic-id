// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDNotAgentSeal} from "../src/AgenticID.sol";
import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {IERC7857Updatable} from "../src/interfaces/IERC7857Updatable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract DataStorageTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── update(): full replacement by agentSeal ───────────────────────────────
    //
    // AgenticID gates update/updateAt on the bound agentSeal (not the
    // NFT owner). Tests prank as SEAL_ADDR — the address bound by
    // _mintWithSeal — to reflect the agent-runtime path (TEE holds
    // agentSeal_priv and signs txs with it).

    function test_update_replacesAllEntries() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        IntelligentData[] memory newDatas = new IntelligentData[](2);
        newDatas[0] = IntelligentData({dataDescription: "replaced-1", dataHash: keccak256("r1")});
        newDatas[1] = IntelligentData({dataDescription: "replaced-2", dataHash: keccak256("r2")});

        vm.prank(SEAL_ADDR);
        agenticId.update(agentId, newDatas);

        IntelligentData[] memory stored = agenticId.intelligentDatasOf(agentId);
        assertEq(stored.length, 2, "stored length matches new");
        assertEq(stored[0].dataHash, newDatas[0].dataHash, "entry 0 replaced");
        assertEq(stored[1].dataHash, newDatas[1].dataHash, "entry 1 replaced");
    }

    function test_update_revertsOnEmpty() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory empty = new IntelligentData[](0);

        vm.prank(SEAL_ADDR);
        vm.expectRevert(IERC7857Updatable.ERC7857EmptyData.selector);
        agenticId.update(agentId, empty);
    }

    function test_update_emitsUpdatedEventWithOldAndNewDatas() public {
        (uint256 agentId, bytes32 originalDataHash) = _mintWithSeal(alice);

        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "replaced", dataHash: keccak256("new-dh")});

        IntelligentData[] memory oldDatas = new IntelligentData[](1);
        oldDatas[0] = IntelligentData({dataDescription: "d", dataHash: originalDataHash});

        vm.expectEmit(true, false, false, true);
        emit IERC7857Updatable.Updated(agentId, oldDatas, newDatas);

        vm.prank(SEAL_ADDR);
        agenticId.update(agentId, newDatas);
    }

    function test_updateAt_emitsEntryUpdatedEvent() public {
        (uint256 agentId, bytes32 originalDataHash) = _mintWithSeal(alice);

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "at-replaced",
            dataHash: keccak256("at-new-dh")
        });
        IntelligentData memory original = IntelligentData({dataDescription: "d", dataHash: originalDataHash});

        vm.expectEmit(true, true, false, true);
        emit IERC7857Updatable.EntryUpdated(agentId, 0, original, replacement);

        vm.prank(SEAL_ADDR);
        agenticId.updateAt(agentId, 0, replacement);
    }

    function test_update_revertsWhenNotAgentSeal() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "n", dataHash: keccak256("n")});

        // bob is neither owner nor agentSeal.
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgenticIDNotAgentSeal.selector, agentId, bob, SEAL_ADDR
            )
        );
        agenticId.update(agentId, newDatas);
    }

    function test_update_revertsWhenOwnerCallsButSealIsBound() public {
        // Owner-only path is the legacy ERC-7857 default; AgenticID
        // overrides to agentSeal-only ONCE A SEAL IS BOUND. The owner
        // alice can no longer update — must use the agentSeal.
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "n", dataHash: keccak256("n")});

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgenticIDNotAgentSeal.selector, agentId, alice, SEAL_ADDR
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

        vm.prank(SEAL_ADDR);
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

        vm.prank(SEAL_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Updatable.ERC7857IndexOutOfBounds.selector, uint256(5), uint256(1)
            )
        );
        agenticId.updateAt(agentId, 5, replacement);
    }

    function test_updateAt_revertsWhenNotAgentSeal() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData memory replacement = IntelligentData({
            dataDescription: "x",
            dataHash: keccak256("x")
        });

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgenticIDNotAgentSeal.selector, agentId, bob, SEAL_ADDR
            )
        );
        agenticId.updateAt(agentId, 0, replacement);
    }
}
