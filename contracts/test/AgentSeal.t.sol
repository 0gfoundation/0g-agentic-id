// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {
    AgenticIDNotTrustedAttestor,
    AgenticIDZeroSeal,
    AgenticIDSealIdTaken
} from "../src/AgenticID.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

// A seal is bound ONLY at mint time via registerWithSeal — there is no external
// setAgentSeal entrypoint (removed: sealId asserts TEE-confined data provenance
// that can't be granted retroactively, and a standalone binder let an attestor
// seize any agent without owner consent). These tests exercise the binding and
// its guards through the mint path.
contract AgentSealTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    bytes32 internal constant SEAL_ID_A = bytes32(uint256(0xBEEF));
    bytes32 internal constant SEAL_ID_B = bytes32(uint256(0xCAFE));
    address internal constant SEAL_ADDR_A = address(0xAA);
    address internal constant SEAL_ADDR_B = address(0xBB);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    function _mintArgs(address to, bytes32 salt)
        internal
        pure
        returns (IntelligentData[] memory datas, bytes[] memory keys, MetadataEntry[] memory meta)
    {
        datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256(abi.encode(to, salt))});
        keys = new bytes[](1);
        keys[0] = hex"cafe";
        meta = new MetadataEntry[](0);
    }

    function _mintWithSealCustom(address to, address agentSeal, bytes32 sealId)
        internal
        returns (uint256 agentId)
    {
        (IntelligentData[] memory datas, bytes[] memory keys, MetadataEntry[] memory meta) =
            _mintArgs(to, sealId);
        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(to, "", meta, datas, keys, agentSeal, sealId);
    }

    // ── Binding at mint ─────────────────────────────────────────────────────────

    function test_registerWithSeal_bindsSealAtMint() public {
        uint256 agentId = _mintWithSealCustom(alice, SEAL_ADDR_A, SEAL_ID_A);
        assertEq(agenticId.getAgentSeal(agentId), SEAL_ADDR_A, "seal set at mint");
        assertEq(agenticId.getSealId(agentId), SEAL_ID_A, "sealId bound at mint");
        assertEq(agenticId.getAgentIdBySealId(SEAL_ID_A), agentId, "reverse mapping set");
    }

    // ── Zero-value rejection ──────────────────────────────────────────────────

    function test_registerWithSeal_rejectsZeroAgentSealAddress() public {
        (IntelligentData[] memory d, bytes[] memory k, MetadataEntry[] memory m) = _mintArgs(alice, SEAL_ID_A);
        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.registerWithSeal(alice, "", m, d, k, address(0), SEAL_ID_A);
    }

    function test_registerWithSeal_rejectsZeroSealId() public {
        (IntelligentData[] memory d, bytes[] memory k, MetadataEntry[] memory m) = _mintArgs(alice, SEAL_ID_A);
        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.registerWithSeal(alice, "", m, d, k, SEAL_ADDR_A, bytes32(0));
    }

    // ── Reused sealId across different agents ─────────────────────────────────

    function test_registerWithSeal_rejectsReusedSealId() public {
        uint256 firstAgentId = _mintWithSealCustom(alice, SEAL_ADDR_A, SEAL_ID_A);

        // SEAL_ID_A is already bound to firstAgentId — a second mint reusing it reverts.
        (IntelligentData[] memory d, bytes[] memory k, MetadataEntry[] memory m) = _mintArgs(bob, SEAL_ID_B);
        vm.prank(attestor);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID_A, firstAgentId)
        );
        agenticId.registerWithSeal(bob, "", m, d, k, SEAL_ADDR_B, SEAL_ID_A);
    }

    // ── Only a trusted attestor can mint a sealed agent ───────────────────────

    function test_registerWithSeal_rejectsUntrustedCaller() public {
        (IntelligentData[] memory d, bytes[] memory k, MetadataEntry[] memory m) = _mintArgs(alice, SEAL_ID_A);
        vm.prank(alice);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.registerWithSeal(alice, "", m, d, k, SEAL_ADDR_A, SEAL_ID_A);
    }
}
