// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticID} from "../contracts/AgenticID.sol";
import {TEEDataVerifier} from "../contracts/verifiers/TEEDataVerifier.sol";
import {AgenticIDNotTrustedAttestor, AgenticIDSealedKeyLengthMismatch, AgenticIDUseRegisterWithData} from "../contracts/AgenticID.sol";
import {IntelligentData} from "../contracts/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";
import {IERC7857Updatable} from "../contracts/interfaces/IERC7857Updatable.sol";
import {IAgenticID} from "../contracts/interfaces/IAgenticID.sol";

contract AgenticIDTest is Test {
    AgenticID internal agenticId;
    TEEDataVerifier internal verifier;

    address internal owner = address(0xA11CE);
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);
    address internal attestor = address(0xA77E57);
    address internal oracleAddr;
    uint256 internal oraclePk;

    bytes32 internal constant SEAL_ID = bytes32(uint256(0xBEEF));

    uint256 internal constant MAX_PROOF_AGE = 1 days;

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
    }

    function test_register_selfMint_succeeds() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "test-data", dataHash: keccak256("data-1")});

        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";

        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(alice);
        uint256 agentId = agenticId.register("ipfs://foo", metadata, datas, sealedKeys);

        assertEq(agentId, 1, "first agentId should be 1");
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
            abi.encodeWithSelector(AgenticIDSealedKeyLengthMismatch.selector, uint256(2), uint256(1))
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
        vm.prank(owner);
        agenticId.addTrustedAttestor(attestor);
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
}
