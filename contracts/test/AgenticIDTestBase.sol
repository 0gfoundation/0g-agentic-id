// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {AgenticID} from "../src/AgenticID.sol";
import {CanonicalIdentityRegistryMock} from "./mocks/CanonicalIdentityRegistryMock.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {IntelligentData} from "../src/interfaces/IERC7857Metadata.sol";
import {MetadataEntry} from "../src/interfaces/IERC8004IdentityRegistry.sol";
import {
    OracleType,
    AccessProof,
    OwnershipProof,
    TransferValidityProof
} from "../src/interfaces/IERC7857DataVerifier.sol";

/// @notice Shared test scaffold for AgenticID test suites.
/// @dev The base does NOT whitelist the attestor — each suite opts in via
///      `_whitelistAttestor()`. This keeps `AgenticIDTest` able to cover the
///      pre-whitelist revert path cleanly.
abstract contract AgenticIDTestBase is Test {
    AgenticID internal agenticId;
    CanonicalIdentityRegistryMock internal canonical;
    TEEDataVerifier internal verifier;

    address internal owner = address(0xA11CE);
    address internal pauser = address(0xBABE);
    address internal attestor = address(0xA77E57);
    address internal oracleAddr;
    uint256 internal oraclePk;

    uint256 internal constant MAX_PROOF_AGE = 1 days;
    bytes32 internal constant SEAL_ID = bytes32(uint256(0xBEEF));
    address internal constant SEAL_ADDR = address(0xAA);
    bytes internal constant SEALED_KEY_ORIGINAL = hex"cafe";
    bytes internal constant SEALED_KEY_NEW = hex"deadbeef";

    function setUp() public virtual {
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");

        TEEDataVerifier verifierImpl = new TEEDataVerifier();
        ERC1967Proxy verifierProxy = new ERC1967Proxy(
            address(verifierImpl),
            abi.encodeCall(TEEDataVerifier.initialize, (owner, pauser, oracleAddr, MAX_PROOF_AGE))
        );
        verifier = TEEDataVerifier(address(verifierProxy));

        // Stand-in for the fixed canonical ERC-8004 registry (0x8004… on 0G).
        // Deployed standalone; agentIds start at 0, matching the live contract.
        canonical = new CanonicalIdentityRegistryMock();
        canonical.initialize();

        AgenticID agenticIdImpl = new AgenticID();
        ERC1967Proxy agenticIdProxy = new ERC1967Proxy(
            address(agenticIdImpl),
            abi.encodeCall(
                AgenticID.initialize,
                ("AgenticID", "AID", address(verifier), owner, pauser, address(canonical))
            )
        );
        agenticId = AgenticID(address(agenticIdProxy));
    }

    function _whitelistAttestor() internal {
        vm.prank(owner);
        agenticId.addTrustedAttestor(attestor);
    }

    // ── Signing primitives ────────────────────────────────────────────────────

    /// @dev 64-byte uncompressed secp256k1 pubkey (publicKeyX ‖ publicKeyY).
    function _pubkey(Vm.Wallet memory wallet) internal pure returns (bytes memory) {
        return abi.encodePacked(wallet.publicKeyX, wallet.publicKeyY);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev EIP-191 hex-encoded variant used by AccessProof / OwnershipProof.
    ///      Matches BaseDataVerifier._eip191Hash (displays as human-readable hex
    ///      string in wallet signing prompts).
    function _eip191HexHash(bytes32 inner) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n66",
                Strings.toHexString(uint256(inner), 32)
            )
        );
    }

    /// @dev EIP-191 raw-32-byte variant used by ServeProof / setAgentWallet.
    ///      Matches MessageHashUtils.toEthSignedMessageHash(bytes32).
    function _eip191RawHash(bytes32 inner) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
    }

    // ── Transfer proof builders ───────────────────────────────────────────────

    function _mkAccessProof(
        bytes32 dataHash,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline,
        uint256 signerPk
    ) internal view returns (AccessProof memory) {
        // Mirror the verifier's domain-separated preimage: abi.encode(chainId, erc7857, <fields>).
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash, targetPubkey, nonce, deadline
        ));
        return AccessProof({
            dataHash: dataHash,
            targetPubkey: targetPubkey,
            nonce: nonce,
            deadline: deadline,
            proof: _sign(signerPk, _eip191HexHash(inner))
        });
    }

    function _mkOwnershipProof(
        bytes32 dataHash,
        bytes memory sealedKey,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline
    ) internal view returns (OwnershipProof memory) {
        return _mkOwnershipProofSignedBy(
            dataHash, sealedKey, targetPubkey, nonce, deadline, oraclePk
        );
    }

    function _mkOwnershipProofSignedBy(
        bytes32 dataHash,
        bytes memory sealedKey,
        bytes memory targetPubkey,
        bytes memory nonce,
        uint256 deadline,
        uint256 signerPk
    ) internal view returns (OwnershipProof memory) {
        // Mirror the verifier's domain-separated preimage: abi.encode(chainId, erc7857, <fields>).
        bytes32 inner = keccak256(abi.encode(
            block.chainid, address(agenticId), dataHash, sealedKey, targetPubkey, nonce, deadline
        ));
        return OwnershipProof({
            oracleType: OracleType.TEE,
            dataHash: dataHash,
            sealedKey: sealedKey,
            targetPubkey: targetPubkey,
            nonce: nonce,
            deadline: deadline,
            proof: _sign(signerPk, _eip191HexHash(inner))
        });
    }

    // ── Mint helpers (require _whitelistAttestor first where noted) ───────────

    /// @dev Attestor-mint with a single IntelligentData entry, no metadata, no URI.
    ///      Requires attestor whitelisted.
    function _mintWithSeal(address to) internal returns (uint256 agentId, bytes32 dataHash) {
        return _mintWithSealSalt(to, 0);
    }

    /// @dev Like `_mintWithSeal` but a `salt` disambiguates sealId/sealAddr so
    ///      the same receiver can hold multiple agents.
    function _mintWithSealSalt(address to, uint256 salt)
        internal
        returns (uint256 agentId, bytes32 dataHash)
    {
        bytes32 sealId = bytes32(uint256(SEAL_ID) + salt);
        address sealAddr = address(uint160(uint160(SEAL_ADDR) + salt));
        dataHash = keccak256(abi.encode("data", to, salt));

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "", metadata, datas, sealedKeys, sealAddr, sealId
        );
    }

    /// @dev Attestor-mint with N IntelligentData entries (distinct dataHashes).
    function _mintWithNDatas(address to, uint256 n)
        internal
        returns (uint256 agentId, bytes32[] memory dataHashes)
    {
        dataHashes = new bytes32[](n);
        IntelligentData[] memory datas = new IntelligentData[](n);
        bytes[] memory sealedKeys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            dataHashes[i] = keccak256(abi.encode("data-multi", to, i));
            datas[i] = IntelligentData({dataDescription: "d", dataHash: dataHashes[i]});
            sealedKeys[i] = abi.encodePacked(hex"cafe", bytes32(i));
        }
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(attestor);
        agentId = agenticId.registerWithSeal(
            to, "", metadata, datas, sealedKeys, SEAL_ADDR, SEAL_ID
        );
    }

    /// @dev Self-mint (no seal, no metadata, no URI).
    function _selfMint(address who) internal returns (uint256 agentId, bytes32 dataHash) {
        dataHash = keccak256(abi.encode("self-data", who));
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = hex"deadbeef";
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(who);
        agentId = agenticId.register("", metadata, datas, sealedKeys);
    }

    /// @dev Self-mint (no seal) with a salt so the same owner can hold several,
    ///      each with a distinct dataHash. Used by the proof-gated transfer/clone
    ///      tests, which only apply to non-seal agents after the seal-bound split.
    function _selfMintData(address who, uint256 salt)
        internal
        returns (uint256 agentId, bytes32 dataHash)
    {
        dataHash = keccak256(abi.encode("self-data", who, salt));
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: "d", dataHash: dataHash});
        bytes[] memory sealedKeys = new bytes[](1);
        sealedKeys[0] = SEALED_KEY_ORIGINAL;
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(who);
        agentId = agenticId.register("", metadata, datas, sealedKeys);
    }

    /// @dev Self-mint (no seal) with N IntelligentData entries.
    function _selfMintNDatas(address who, uint256 n)
        internal
        returns (uint256 agentId, bytes32[] memory dataHashes)
    {
        dataHashes = new bytes32[](n);
        IntelligentData[] memory datas = new IntelligentData[](n);
        bytes[] memory sealedKeys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            dataHashes[i] = keccak256(abi.encode("self-multi", who, i));
            datas[i] = IntelligentData({dataDescription: "d", dataHash: dataHashes[i]});
            sealedKeys[i] = abi.encodePacked(hex"cafe", bytes32(i));
        }
        MetadataEntry[] memory metadata = new MetadataEntry[](0);

        vm.prank(who);
        agentId = agenticId.register("", metadata, datas, sealedKeys);
    }

    // ── setAgentWallet EIP-712 helper ─────────────────────────────────────────

    /// @dev Builds the official ERC-8004 EIP-712 signature for setAgentWallet.
    ///      The domain comes from the CANONICAL registry (where the signature is
    ///      verified), and the struct uses the official 4-field form whose `owner`
    ///      is the canonical token holder — i.e. the AgenticID contract.
    function _signSetAgentWallet(
        Vm.Wallet memory walletToSign,
        uint256 agentId,
        uint256 deadline
    ) internal view returns (bytes memory) {
        (, string memory name_, string memory version_, uint256 chainId_, address verifyingContract_, , )
            = canonical.eip712Domain();

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name_)),
                keccak256(bytes(version_)),
                chainId_,
                verifyingContract_
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)"
                ),
                agentId,
                walletToSign.addr,
                address(agenticId),
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return _sign(walletToSign.privateKey, digest);
    }
}
