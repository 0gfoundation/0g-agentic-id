// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";

/// @notice Real testnet deploy of AgenticID (UUPS proxy) bound to the live
///         canonical 8004, plus one self-mint. Owner/pauser/oracle = deployer.
///
///   PRIVATE_KEY=0x.. forge script script/DeployAndMint.s.sol \
///     --rpc-url https://evmrpc-testnet.0g.ai --broadcast
contract DeployAndMint is Script {
    address constant CANONICAL_8004 = 0x8004A818BFB912233c491871b3d84c89A494BD9e;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address me = vm.addr(pk);

        vm.startBroadcast(pk);

        TEEDataVerifier vImpl = new TEEDataVerifier();
        ERC1967Proxy vProxy = new ERC1967Proxy(
            address(vImpl),
            abi.encodeCall(TEEDataVerifier.initialize, (me, me, me, 1 days))
        );

        AgenticID impl = new AgenticID();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(vProxy), me, me, 1 days, CANONICAL_8004)
            )
        );
        AgenticID agenticId = AgenticID(address(proxy));

        // Self-mint one agent to the deployer.
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "persona-v1", dataHash: keccak256("first-real-agent")});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";
        MetadataEntry[] memory metadata = new MetadataEntry[](1);
        metadata[0] = MetadataEntry({metadataKey: "category", metadataValue: bytes("inference")});

        uint256 agentId = agenticId.register("ipfs://first-real-agent", metadata, datas, sealedKeys);

        vm.stopBroadcast();

        console2.log("deployer      :", me);
        console2.log("verifier proxy:", address(vProxy));
        console2.log("AgenticID     :", address(agenticId));
        console2.log("minted agentId:", agentId);
    }
}
