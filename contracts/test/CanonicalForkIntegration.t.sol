// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {ICanonicalReputationRegistry} from "../src/interfaces/ICanonicalReputationRegistry.sol";
import {ServeProof} from "../src/interfaces/IAgenticIDReputationRegistry.sol";

interface ICanonicalRead {
    function ownerOf(uint256) external view returns (address);
    function tokenURI(uint256) external view returns (string memory);
    function getVersion() external view returns (string memory);
}

interface ICanonicalReputationWrite {
    function giveFeedback(
        uint256 agentId, int128 value, uint8 valueDecimals,
        string calldata tag1, string calldata tag2,
        string calldata endpoint, string calldata feedbackURI, bytes32 feedbackHash
    ) external;
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
    address constant CANONICAL_8004_REPUTATION = 0x8004B663056A597Dffe9eCcC1965A193B7388713;

    AgenticID internal agenticId;
    VerifiedFeedbackRegistry internal verifiedFeedback;
    bool internal active;

    address internal deployer = address(0xD3);
    address internal alice    = address(0xA11CE);

    function setUp() public {
        string memory rpc = vm.envOr("FORK_RPC", string(""));
        if (bytes(rpc).length == 0) return; // skipped unless FORK_RPC is set
        vm.createSelectFork(rpc);
        active = true;

        // Sanity: confirm we're really pointed at the official v2 registries,
        // and that the live reputation registry anchors to the same identity
        // registry we custody-bind to.
        assertEq(ICanonicalRead(CANONICAL_8004).getVersion(), "2.0.0", "canonical is 8004 v2");
        assertEq(
            ICanonicalReputationRegistry(CANONICAL_8004_REPUTATION).getVersion(),
            "2.0.0", "canonical reputation is 8004 v2"
        );
        assertEq(
            ICanonicalReputationRegistry(CANONICAL_8004_REPUTATION).getIdentityRegistry(),
            CANONICAL_8004, "canonical reputation bound to canonical identity"
        );

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
                ("AgenticID", "AID", address(vProxy), deployer, deployer, CANONICAL_8004)
            )
        );
        agenticId = AgenticID(address(proxy));

        VerifiedFeedbackRegistry vfImpl = new VerifiedFeedbackRegistry();
        ERC1967Proxy vfProxy = new ERC1967Proxy(
            address(vfImpl),
            abi.encodeCall(
                VerifiedFeedbackRegistry.initialize,
                (address(proxy), CANONICAL_8004_REPUTATION, deployer, deployer, 1 days)
            )
        );
        verifiedFeedback = VerifiedFeedbackRegistry(address(vfProxy));
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

    /// @dev End-to-end against the LIVE canonical reputation registry: a client
    ///      submits feedback there directly (native attribution), then attests
    ///      it here with a seal-signed ServeProof.
    function test_fork_attestFeedbackOnLiveCanonicalReputation() public {
        if (!active) { vm.skip(true); return; }

        Vm.Wallet memory sealWallet = vm.createWallet("fork-agent-seal");
        address client = address(0xC1);

        // Seal-mint through the trusted-attestor path.
        vm.prank(deployer);
        agenticId.addTrustedAttestor(deployer);
        bytes32 dataHash = keccak256("fork-vf-data");
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "persona", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"cafe";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);
        vm.prank(deployer);
        uint256 agentId = agenticId.registerWithSeal(
            deployer, "", metadata, datas, sealedKeys, sealWallet.addr, bytes32(uint256(0xF0F0))
        );

        // 1. Client → live canonical registry (feedback attributed to the client).
        vm.prank(client);
        ICanonicalReputationWrite(CANONICAL_8004_REPUTATION).giveFeedback(
            agentId, 90, 0, "quality", "", "https://api.example.com", "", bytes32(0)
        );
        uint64 idx = ICanonicalReputationRegistry(CANONICAL_8004_REPUTATION).getLastIndex(agentId, client);
        assertEq(idx, 1, "live canonical recorded the client's entry");

        // 2. Client → verification layer, with a seal-signed ServeProof.
        bytes32[] memory dataHashes = new bytes32[](1);
        dataHashes[0] = dataHash;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), client, agentId,
            block.timestamp, deadline, keccak256("fork-task"),
            keccak256(abi.encodePacked(dataHashes)), keccak256("fw")
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            sealWallet.privateKey,
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner))
        );
        ServeProof memory proof = ServeProof({
            agentId: agentId,
            submitter: client,
            timestamp: block.timestamp,
            deadline: deadline,
            taskHash: keccak256("fork-task"),
            dataHashes: dataHashes,
            frameworkHash: keccak256("fw"),
            signature: abi.encodePacked(r, s, v)
        });
        vm.prank(client);
        verifiedFeedback.attestFeedback(agentId, idx, proof);

        assertTrue(verifiedFeedback.isVerified(agentId, client, idx), "entry verified on fork");
        (uint64 count, int128 sum, ) = _summaryOf(agentId, client);
        assertEq(count, 1, "verified summary counts the live entry");
        assertEq(sum, int128(90) * int128(1e18), "live value aggregated");
    }

    function _summaryOf(uint256 agentId, address client)
        internal view returns (uint64 count, int128 sum, uint8 dec)
    {
        address[] memory cs = new address[](1);
        cs[0] = client;
        return verifiedFeedback.getVerifiedSummary(agentId, cs, "", "");
    }
}
