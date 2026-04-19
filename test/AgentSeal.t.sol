// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {
    AgenticID,
    AgenticIDNotTrustedAttestor,
    AgenticIDZeroSeal,
    AgenticIDSealAlreadySet,
    AgenticIDSealIdTaken
} from "../contracts/AgenticID.sol";
import {TEEDataVerifier} from "../contracts/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";

contract AgentSealTest is Test {
    AgenticID internal agenticId;
    TEEDataVerifier internal verifier;

    address internal owner = address(0xA11CE);
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);
    address internal attestor = address(0xA77E57);
    address internal oracleAddr;
    uint256 internal oraclePk;

    uint256 internal constant MAX_PROOF_AGE = 1 days;
    bytes32 internal constant SEAL_ID_A = bytes32(uint256(0xBEEF));
    bytes32 internal constant SEAL_ID_B = bytes32(uint256(0xCAFE));
    address internal constant SEAL_ADDR_A = address(0xAA);
    address internal constant SEAL_ADDR_B = address(0xBB);

    function setUp() public {
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");

        TEEDataVerifier verifierImpl = new TEEDataVerifier();
        ERC1967Proxy verifierProxy = new ERC1967Proxy(
            address(verifierImpl),
            abi.encodeCall(TEEDataVerifier.initialize, (owner, oracleAddr, MAX_PROOF_AGE))
        );
        verifier = TEEDataVerifier(address(verifierProxy));

        AgenticID agenticIdImpl = new AgenticID();
        ERC1967Proxy agenticIdProxy = new ERC1967Proxy(
            address(agenticIdImpl),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(verifier), owner, MAX_PROOF_AGE)
            )
        );
        agenticId = AgenticID(address(agenticIdProxy));

        vm.prank(owner);
        agenticId.addTrustedAttestor(attestor);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _selfMint(address who) internal returns (uint256 agentId) {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: keccak256(abi.encode(who))});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(who);
        agentId = agenticId.register("", metadata, datas, sealedKeys);
    }

    function _mintWithSeal(address to, address agentSeal, bytes32 sealId) internal returns (uint256 agentId) {
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
        uint256 agentId = _selfMint(alice);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.setAgentSeal(agentId, address(0), SEAL_ID_A);
    }

    function test_setAgentSeal_rejectsZeroSealId() public {
        uint256 agentId = _selfMint(alice);

        vm.prank(attestor);
        vm.expectRevert(AgenticIDZeroSeal.selector);
        agenticId.setAgentSeal(agentId, SEAL_ADDR_A, bytes32(0));
    }

    // ── Duplicate seal on same agentId ────────────────────────────────────────

    function test_setAgentSeal_rejectsDuplicateOnSameAgent() public {
        uint256 agentId = _mintWithSeal(alice, SEAL_ADDR_A, SEAL_ID_A);

        // Second attempt must revert even with a different (seal, sealId) pair.
        vm.prank(attestor);
        vm.expectRevert(abi.encodeWithSelector(AgenticIDSealAlreadySet.selector, agentId));
        agenticId.setAgentSeal(agentId, SEAL_ADDR_B, SEAL_ID_B);
    }

    // ── Reused sealId across different agents ─────────────────────────────────

    function test_setAgentSeal_rejectsReusedSealId() public {
        uint256 firstAgentId = _mintWithSeal(alice, SEAL_ADDR_A, SEAL_ID_A);
        uint256 secondAgentId = _selfMint(bob);

        // SEAL_ID_A is already bound to firstAgentId — rebinding to second should revert.
        vm.prank(attestor);
        vm.expectRevert(
            abi.encodeWithSelector(AgenticIDSealIdTaken.selector, SEAL_ID_A, firstAgentId)
        );
        agenticId.setAgentSeal(secondAgentId, SEAL_ADDR_B, SEAL_ID_A);
    }

    // ── Post-mint sealing on a self-minted agent ──────────────────────────────

    function test_setAgentSeal_postMint_onSelfMintedAgent() public {
        uint256 agentId = _selfMint(alice);
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
        uint256 agentId = _selfMint(alice);

        // Owner of the token is not a trusted attestor — must still revert.
        vm.prank(alice);
        vm.expectRevert(AgenticIDNotTrustedAttestor.selector);
        agenticId.setAgentSeal(agentId, SEAL_ADDR_A, SEAL_ID_A);
    }
}
