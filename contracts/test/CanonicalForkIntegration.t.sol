// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

interface ICanonicalRead {
    function ownerOf(uint256) external view returns (address);
    function tokenURI(uint256) external view returns (string memory);
    function getVersion() external view returns (string memory);
}

/// @notice Integration test against the REAL canonical ERC-8004 registry on 0G
///         Galileo testnet (0x8004…), to confirm the custody binding works
///         against the live contract — not just the local mock.
///
///         Opt-in: set FORK_RPC to a 0G Galileo RPC, e.g.
///           FORK_RPC=https://evmrpc-testnet.0g.ai forge test --match-path test/CanonicalForkIntegration.t.sol
///         Without FORK_RPC the suite skips (so normal `forge test` stays offline).
contract CanonicalForkIntegrationTest is Test {
    address constant CANONICAL_8004 = 0x8004A818BFB912233c491871b3d84c89A494BD9e;

    AgenticID internal agenticId;
    bool internal active;

    address internal deployer = address(0xD3);
    address internal alice    = address(0xA11CE);

    function setUp() public {
        string memory rpc = vm.envOr("FORK_RPC", string(""));
        if (bytes(rpc).length == 0) return; // skipped unless FORK_RPC is set
        vm.createSelectFork(rpc);
        active = true;

        // Sanity: confirm we're really pointed at the official v2 registry.
        assertEq(ICanonicalRead(CANONICAL_8004).getVersion(), "2.0.0", "canonical is 8004 v2");

        vm.startPrank(deployer);
        TEEDataVerifier vImpl = new TEEDataVerifier();
        ERC1967Proxy vProxy = new ERC1967Proxy(
            address(vImpl),
            abi.encodeCall(TEEDataVerifier.initialize, (deployer, deployer, deployer, 1 days))
        );
        AgenticID impl = new AgenticID();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(vProxy), deployer, deployer, 1 days, CANONICAL_8004)
            )
        );
        agenticId = AgenticID(address(proxy));
        vm.stopPrank();
    }

    function test_fork_selfMintBindsToLiveCanonical() public {
        if (!active) { vm.skip(true); return; }

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "persona", dataHash: keccak256("fork-data")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(alice);
        uint256 agentId = agenticId.register("ipfs://fork-card", metadata, datas, sealedKeys);

        // Custody + visibility against the live contract.
        assertEq(agenticId.ownerOf(agentId), alice, "local owner is the user");
        assertEq(ICanonicalRead(CANONICAL_8004).ownerOf(agentId), address(agenticId), "custodied on live 8004");
        assertEq(ICanonicalRead(CANONICAL_8004).tokenURI(agentId), "ipfs://fork-card", "URI visible on live 8004");
        assertEq(agenticId.getAgentWallet(agentId), address(0), "agentWallet cleared at mint");
        // Global counter: the live registry already has agents, so our id is well past 0.
        assertGe(agentId, 10, "agentId from live global counter");
    }
}
