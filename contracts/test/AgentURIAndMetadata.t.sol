// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract AgentURIAndMetadataTest is AgenticIDTestBase {
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);

    function setUp() public override {
        super.setUp();
        _whitelistAttestor();
    }

    // ── agentURI ──────────────────────────────────────────────────────────────

    function test_setAgentURI_byOwner_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(alice);
        agenticId.setAgentURI(agentId, "ipfs://new-uri");

        assertEq(agenticId.tokenURI(agentId), "ipfs://new-uri", "URI updated");
    }

    function test_setAgentURI_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.setAgentURI(agentId, "ipfs://hijack");
    }

    function test_setAgentURI_byTrustedAttestor_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(attestor);
        agenticId.setAgentURI(agentId, "https://dev-agent-market.oss-cn-beijing.aliyuncs.com/card.json");

        assertEq(
            agenticId.tokenURI(agentId),
            "https://dev-agent-market.oss-cn-beijing.aliyuncs.com/card.json",
            "attestor-written URI persisted"
        );
    }

    function test_setAgentURI_revertsForUntrustedAttestor() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        address rogue = address(0xDEAD);
        vm.prank(rogue);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, rogue, agentId, alice
            )
        );
        agenticId.setAgentURI(agentId, "ipfs://hijack");
    }

    function test_tokenURI_revertsOnNonexistentToken() public {
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(999))
        );
        agenticId.tokenURI(999);
    }

    // ── metadata ──────────────────────────────────────────────────────────────

    function test_setMetadata_byOwner_succeeds() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(alice);
        agenticId.setMetadata(agentId, "category", bytes("inference"));

        assertEq(
            agenticId.getMetadata(agentId, "category"),
            bytes("inference"),
            "metadata stored"
        );
    }

    function test_setMetadata_overwritesExistingKey() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.startPrank(alice);
        agenticId.setMetadata(agentId, "version", bytes("v1"));
        agenticId.setMetadata(agentId, "version", bytes("v2"));
        vm.stopPrank();

        assertEq(
            agenticId.getMetadata(agentId, "version"),
            bytes("v2"),
            "second write wins"
        );
    }

    function test_setMetadata_revertsWhenNotOwner() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721IncorrectOwner.selector, bob, agentId, alice
            )
        );
        agenticId.setMetadata(agentId, "k", bytes("v"));
    }

    function test_getMetadata_returnsEmptyForUnknownKey() public {
        (uint256 agentId, ) = _mintWithSeal(alice);

        bytes memory v = agenticId.getMetadata(agentId, "nonexistent");
        assertEq(v.length, 0, "unknown key returns empty bytes");
    }
}
