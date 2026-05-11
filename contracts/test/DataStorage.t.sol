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
        bytes[] memory sealedKeys = _sealedKeys(2);

        vm.prank(SEAL_ADDR);
        agenticId.update(agentId, newDatas, sealedKeys);

        IntelligentData[] memory stored = agenticId.intelligentDatasOf(agentId);
        assertEq(stored.length, 2, "stored length matches new");
        assertEq(stored[0].dataHash, newDatas[0].dataHash, "entry 0 replaced");
        assertEq(stored[1].dataHash, newDatas[1].dataHash, "entry 1 replaced");
    }

    function test_update_revertsOnEmpty() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory empty = new IntelligentData[](0);
        bytes[] memory emptyKeys = new bytes[](0);

        vm.prank(SEAL_ADDR);
        vm.expectRevert(IERC7857Updatable.ERC7857EmptyData.selector);
        agenticId.update(agentId, empty, emptyKeys);
    }

    function test_update_revertsOnSealedKeyArityMismatch() public {
        // newDatas and sealedKeys must be 1:1 — caller can't sneak in a
        // mismatched-length pair and produce an event where some entries
        // have no key (or extras have no entry). Catches the bug class
        // where someone updates the data array without re-wrapping every
        // dim's key.
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](2);
        newDatas[0] = IntelligentData({dataDescription: "a", dataHash: keccak256("a")});
        newDatas[1] = IntelligentData({dataDescription: "b", dataHash: keccak256("b")});
        bytes[] memory wrongLen = _sealedKeys(1);

        vm.prank(SEAL_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Updatable.ERC7857SealedKeyArityMismatch.selector,
                uint256(2),
                uint256(1)
            )
        );
        agenticId.update(agentId, newDatas, wrongLen);
    }

    function test_update_emitsUpdatedEventWithOldAndNewDatas() public {
        (uint256 agentId, bytes32 originalDataHash) = _mintWithSeal(alice);

        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "replaced", dataHash: keccak256("new-dh")});
        bytes[] memory sealedKeys = _sealedKeys(1);

        IntelligentData[] memory oldDatas = new IntelligentData[](1);
        oldDatas[0] = IntelligentData({dataDescription: "d", dataHash: originalDataHash});

        vm.expectEmit(true, false, false, true);
        emit IERC7857Updatable.Updated(agentId, oldDatas, newDatas, sealedKeys);

        vm.prank(SEAL_ADDR);
        agenticId.update(agentId, newDatas, sealedKeys);
    }

    function test_updateAt_emitsEntryUpdatedEvent() public {
        (uint256 agentId, bytes32 originalDataHash) = _mintWithSeal(alice);

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "at-replaced",
            dataHash: keccak256("at-new-dh")
        });
        IntelligentData memory original = IntelligentData({dataDescription: "d", dataHash: originalDataHash});
        bytes memory sealedKey = bytes("sk-at-0");

        vm.expectEmit(true, true, false, true);
        emit IERC7857Updatable.EntryUpdated(agentId, 0, original, replacement, sealedKey);

        vm.prank(SEAL_ADDR);
        agenticId.updateAt(agentId, 0, replacement, sealedKey);
    }

    function test_update_revertsWhenNotAgentSeal() public {
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "n", dataHash: keccak256("n")});
        bytes[] memory sealedKeys = _sealedKeys(1);

        // bob is neither owner nor agentSeal.
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgenticIDNotAgentSeal.selector, agentId, bob, SEAL_ADDR
            )
        );
        agenticId.update(agentId, newDatas, sealedKeys);
    }

    function test_update_revertsWhenOwnerCallsButSealIsBound() public {
        // Owner-only path is the legacy ERC-7857 default; AgenticID
        // overrides to agentSeal-only ONCE A SEAL IS BOUND. The owner
        // alice can no longer update — must use the agentSeal.
        (uint256 agentId, ) = _mintWithSeal(alice);
        IntelligentData[] memory newDatas = new IntelligentData[](1);
        newDatas[0] = IntelligentData({dataDescription: "n", dataHash: keccak256("n")});
        bytes[] memory sealedKeys = _sealedKeys(1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgenticIDNotAgentSeal.selector, agentId, alice, SEAL_ADDR
            )
        );
        agenticId.update(agentId, newDatas, sealedKeys);
    }

    // ── updateAt(): single-entry edit ─────────────────────────────────────────

    function test_updateAt_replacesOneEntry() public {
        (uint256 agentId, ) = _mintWithNDatas(alice, 3);

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "new",
            dataHash: keccak256("new-hash")
        });

        vm.prank(SEAL_ADDR);
        agenticId.updateAt(agentId, 1, replacement, bytes("sk-1"));

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
        agenticId.updateAt(agentId, 5, replacement, bytes("sk"));
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
        agenticId.updateAt(agentId, 0, replacement, bytes("sk"));
    }

    // ── On-chain sealedKey storage (V2) ──────────────────────────────────────
    //
    // sealedKeys now live in contract state, parallel to iDatas[]. Tests
    // below cover the four entry points that mutate that state plus the
    // two read views.

    function test_mint_storesSealedKeysParallelToIDatas() public {
        // _mintWithSeal goes through registerWithSeal, which now writes
        // sealedKeys into storage. View must reflect what was minted.
        (uint256 agentId, ) = _mintWithSeal(alice);
        bytes[] memory keys = agenticId.sealedKeysOf(agentId);
        IntelligentData[] memory datas = agenticId.intelligentDatasOf(agentId);
        assertEq(keys.length, datas.length, "sealedKeys length == iDatas length");
        assertGt(keys.length, 0, "mint produced at least one entry");
    }

    function test_update_overwritesAllSealedKeys() public {
        // update() does delete+push for BOTH iDatas and sealedKeys.
        // Verifies no carry-over of stale wraps from the previous set.
        (uint256 agentId, ) = _mintWithSeal(alice);

        IntelligentData[] memory newDatas = new IntelligentData[](2);
        newDatas[0] = IntelligentData({dataDescription: "a", dataHash: keccak256("a")});
        newDatas[1] = IntelligentData({dataDescription: "b", dataHash: keccak256("b")});
        bytes[] memory sealedKeys = new bytes[](2);
        sealedKeys[0] = bytes("sk-after-update-0");
        sealedKeys[1] = bytes("sk-after-update-1");

        vm.prank(SEAL_ADDR);
        agenticId.update(agentId, newDatas, sealedKeys);

        bytes[] memory stored = agenticId.sealedKeysOf(agentId);
        assertEq(stored.length, 2);
        assertEq(stored[0], sealedKeys[0]);
        assertEq(stored[1], sealedKeys[1]);
    }

    function test_updateAt_overwritesOnlyOneSealedKey() public {
        (uint256 agentId, ) = _mintWithNDatas(alice, 3);
        // Mint baseline used opaque test fixture; record what survives.
        bytes[] memory before_ = agenticId.sealedKeysOf(agentId);
        assertEq(before_.length, 3, "pre-update length");

        IntelligentData memory replacement = IntelligentData({
            dataDescription: "new",
            dataHash: keccak256("at-r")
        });
        bytes memory newKey = bytes("sk-at-replaced");

        vm.prank(SEAL_ADDR);
        agenticId.updateAt(agentId, 1, replacement, newKey);

        bytes[] memory after_ = agenticId.sealedKeysOf(agentId);
        assertEq(after_.length, 3, "length unchanged");
        assertEq(after_[1], newKey, "index 1 wrap rotated");
        assertEq(after_[0], before_[0], "index 0 wrap untouched");
        assertEq(after_[2], before_[2], "index 2 wrap untouched");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build `n` placeholder sealedKeys. Tests don't decrypt — the
    /// contract only checks arity + emits — so opaque distinct bytes are
    /// enough to verify routing through the event without faking a real
    /// ECIES wrap.
    function _sealedKeys(uint256 n) internal pure returns (bytes[] memory keys) {
        keys = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            keys[i] = abi.encodePacked("sk-", i);
        }
    }
}
