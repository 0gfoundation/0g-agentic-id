// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    AgenticIDNotTrustedAttestor,
    AgenticIDZeroSeal,
    AgenticIDSealAlreadySet,
    AgenticIDSealIdTaken
} from "../src/AgenticID.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

contract AgentSealTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    // Distinct from base's SEAL_ID/SEAL_ADDR so we can test sealId-collision cases.
    bytes32 internal constant SEAL_ID_A = bytes32(uint256(0xBEEF));
    bytes32 internal constant SEAL_ID_B = bytes32(uint256(0xCAFE));
    address internal constant SEAL_ADDR_A = address(0xAA);
    address internal constant SEAL_ADDR_B = address(0xBB);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── Helper: explicit (seal, sealId) mint so conflict tests can drive inputs ──

    function _mintWithSealCustom(address to, address agentSeal, bytes32 sealId)
        internal
        returns (uint256 agentId)
    {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256(abi.encode(to, sealId))});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(to, "", metadata, datas, sealedKeys, agentSeal, sealId);
    }

    // ── Zero-value rejection ──────────────────────────────────────────────────

    function test_setAgentSeal_rejectsZeroAgentSealAddress() public {
        (uint256 agentId, ) = _selfMint(alice);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.setAgentSeal(agentId, address(0), SEAL_ID_A);
    }

    function test_setAgentSeal_rejectsZeroSealId() public {
        (uint256 agentId, ) = _selfMint(alice);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.setAgentSeal(agentId, SEAL_ADDR_A, bytes32(0));
    }

    // ── Duplicate seal on same agentId ────────────────────────────────────────

    function test_setAgentSeal_rejectsDuplicateOnSameAgent() public {
        uint256 agentId = _mintWithSealCustom(alice, SEAL_ADDR_A, SEAL_ID_A);

        // Second attempt must revert even with a different (seal, sealId) pair.
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDSealAlreadySet.selector, agentId));
        agenticId.setAgentSeal(agentId, SEAL_ADDR_B, SEAL_ID_B);
    }

    // ── Reused sealId across different agents ─────────────────────────────────

    function test_setAgentSeal_rejectsReusedSealId() public {
        uint256 firstAgentId = _mintWithSealCustom(alice, SEAL_ADDR_A, SEAL_ID_A);
        (uint256 secondAgentId, ) = _selfMint(bob);

        // SEAL_ID_A is already bound to firstAgentId — rebinding to second should revert.
        vm.prank(attestor);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID_A, firstAgentId)
        );
        agenticId.setAgentSeal(secondAgentId, SEAL_ADDR_B, SEAL_ID_A);
    }

    // ── Post-mint sealing on a self-minted agent ──────────────────────────────

    function test_setAgentSeal_postMint_onSelfMintedAgent() public {
        (uint256 agentId, ) = _selfMint(alice);
        assertEq(agenticId.getAgentSeal(agentId), address(0), "no seal after self-mint");
        assertEq(agenticId.getSealId(agentId), bytes32(0), "no sealId after self-mint");

        vm.prank(attestor);
        agenticId.setAgentSeal(agentId, SEAL_ADDR_A, SEAL_ID_A);

        assertEq(agenticId.getAgentSeal(agentId), SEAL_ADDR_A, "seal should be set");
        assertEq(agenticId.getSealId(agentId), SEAL_ID_A, "sealId should be bound");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID_A), agentId, "reverse mapping set");
    }

    // ── Non-attestor cannot set seal ──────────────────────────────────────────

    function test_setAgentSeal_rejectsUntrustedCaller() public {
        (uint256 agentId, ) = _selfMint(alice);

        // Owner of the token is not a trusted attestor — must still revert.
        vm.prank(alice);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.setAgentSeal(agentId, SEAL_ADDR_A, SEAL_ID_A);
    }
}
