// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    AgenticIDNotTrustedAttestor,
    AgenticIDUseRegisterWithData
} from "../src/AgenticID.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {IERC7857Updatable} from "../src/interfaces/IERC7857Updatable.sol";
import {IERC7857, SealedKeyEntry} from "../src/interfaces/IERC7857.sol";

contract AgenticIDTest is AgenticIDTestBase {
    address internal alice = address(0xA1);

    // ── Self-mint ─────────────────────────────────────────────────────────────

    function test_register_selfMint_succeeds() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "test-data", dataHash: keccak256("data-1")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(alice);
        uint256 agentId = agenticId.register("ipfs://foo", metadata, datas, sealedKeys);

        assertEq(agentId, 0, "first agentId is canonical id 0");
        assertEq(agenticId.ownerOf(agentId), alice, "owner should be minter");
        assertEq(agenticId.tokenURI(agentId), "ipfs://foo", "URI should match");
        assertEq(agenticId.getAgentSeal(agentId), address(0), "self-mint has no seal");

        IntelligentData[] memory stored = agenticId.intelligentDatasOf(agentId);
        assertEq(stored.length, 1, "one data entry");
        assertEq(stored[0].dataHash, datas[0].dataHash, "dataHash persisted");
    }

    // ── Empty data rejection ──────────────────────────────────────────────────

    function test_register_revertsOnEmptyData() public {
        IntelligentData[] memory datas = new IntelligentData[](0);
        bytes[] memory sealedKeys = new bytes[](0);
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(alice);
        vm.expectRevert(IERC7857Updatable.ERC7857EmptyData.selector);
        agenticId.register("", metadata, datas, sealedKeys);
    }

    // ── SealedKey length validation ───────────────────────────────────────────

    function test_register_revertsOnSealedKeyLengthMismatch() public {
        IntelligentData[] memory datas = new IntelligentData[](2);
        datas[0] = IntelligentData({dataDescription: "a", dataHash: keccak256("a")});
        datas[1] = IntelligentData({dataDescription: "b", dataHash: keccak256("b")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7857Updatable.ERC7857SealedKeyArityMismatch.selector,
                uint256(2),
                uint256(1)
            )
        );
        agenticId.register("", metadata, datas, sealedKeys);
    }

    // ── Disabled ERC-8004 register overloads ──────────────────────────────────

    function test_register_noArg_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgenticIDUseRegisterWithData.selector);
        agenticId.register();
    }

    function test_register_uriOnly_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgenticIDUseRegisterWithData.selector);
        agenticId.register("ipfs://foo");
    }

    function test_register_uriAndMetadata_reverts() public {
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(alice);
        vm.expectRevert(AgenticIDUseRegisterWithData.selector);
        agenticId.register("ipfs://foo", metadata);
    }

    // ── registerWithSeal: trusted-attestor gating ─────────────────────────────

    function test_registerWithSeal_revertsWhenCallerNotTrusted() public {
        // NB: base setUp does NOT whitelist attestor — that's exactly what's under test.
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("d")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(
            alice, "", metadata, datas, sealedKeys, address(0xAA), SEAL_ID
        );
    }

    function test_registerWithSeal_succeedsAfterAttestorWhitelisted() public {
        _whitelistAttestor();
        assertTrue(agenticId.isTrustedAttestor(attestor), "attestor should be whitelisted");

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("d")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        address agentSeal = address(0xAA);

        vm.prank(attestor);
        uint256 agentId = agenticId.registerWithSeal(
            alice, "ipfs://bar", metadata, datas, sealedKeys, agentSeal, SEAL_ID
        );

        assertEq(agenticId.ownerOf(agentId), alice, "alice should own the token");
        assertEq(agenticId.getAgentSeal(agentId), agentSeal, "seal should be set");
        assertEq(agenticId.getSealId(agentId), SEAL_ID, "sealId should be bound");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID), agentId, "reverse mapping set");
    }

    // ── ITransferred emitted on mint (indexer contract) ───────────────────────
    //
    // README §2 says indexers detect mint via ITransferred(from=0, ...). Both
    // register and registerWithSeal must emit this — verify both paths.

    function test_register_emitsITransferredMintEvent() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("dh-register")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"c0ffee";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        SealedKeyEntry[] memory expectedEntries = new SealedKeyEntry[](1);
        expectedEntries[0] = SealedKeyEntry({dataHash: datas[0].dataHash, sealedKey: sealedKeys[0]});

        // Canonical registry numbers agentIds from 0, so the first mint is id 0.
        vm.expectEmit(true, true, true, true);
        emit IERC7857.ITransferred(address(0), alice, 0, expectedEntries);

        vm.prank(alice);
        agenticId.register("", metadata, datas, sealedKeys);
    }

    function test_registerWithSeal_emitsITransferredMintEvent() public {
        _whitelistAttestor();

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256("dh-rws")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"feedface";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        SealedKeyEntry[] memory expectedEntries = new SealedKeyEntry[](1);
        expectedEntries[0] = SealedKeyEntry({dataHash: datas[0].dataHash, sealedKey: sealedKeys[0]});

        vm.expectEmit(true, true, true, true);
        emit IERC7857.ITransferred(address(0), alice, 0, expectedEntries);

        vm.prank(attestor);
        agenticId.registerWithSeal(alice, "", metadata, datas, sealedKeys, address(0xAA), SEAL_ID);
    }
}
