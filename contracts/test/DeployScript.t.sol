// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {MainnetGovernance} from "../script/MainnetGovernance.sol";
import {AgenticID} from "../src/AgenticID.sol";
import {TEEDataVerifier} from "../src/verifiers/TEEDataVerifier.sol";
import {VerifiedFeedbackRegistry} from "../src/VerifiedFeedbackRegistry.sol";

/// @dev Canonical ERC-8004 stand-in: Deploy.s.sol only probes getVersion()
///      on both registries and getIdentityRegistry() on the reputation one.
contract Canonical8004Stub {
    address private immutable IDENTITY_REGISTRY;

    constructor(address identityRegistry_) {
        IDENTITY_REGISTRY = identityRegistry_;
    }

    function getVersion() external pure returns (string memory) {
        return "2.0.0";
    }

    function getIdentityRegistry() external view returns (address) {
        return IDENTITY_REGISTRY;
    }
}

/// @dev External wrapper so the library's reverts can be asserted with
///      vm.expectRevert (which needs a call boundary).
contract MainnetGovernanceHarness {
    function timelockDelay(uint256 chainId, bool overridden, uint256 requested)
        external pure returns (uint256)
    {
        return MainnetGovernance.timelockDelay(chainId, overridden, requested);
    }

    function timelockAdmin(uint256 chainId, address owner) external pure returns (address) {
        return MainnetGovernance.timelockAdmin(chainId, owner);
    }

    function requireMainnetTimelock(uint256 chainId, address timelock) external view {
        MainnetGovernance.requireMainnetTimelock(chainId, timelock);
    }
}

/// @notice Deploy-script governance rules (script/MainnetGovernance.sol):
///         0G mainnet (16661) defaults TIMELOCK_DELAY to 1 day, refuses less,
///         and gives a fresh Timelock no external admin; every other chain
///         stays lightweight (delay defaults to 0, OWNER is the Timelock
///         admin); incremental deploys refuse a weak beacon owner on mainnet.
contract DeployScriptTest is Test {
    MainnetGovernanceHarness internal h;

    bytes internal constant DELAY_TOO_SHORT =
        bytes("TIMELOCK_DELAY below 86400 (1 day) is not allowed on 0G mainnet (chain 16661)");

    function setUp() public {
        h = new MainnetGovernanceHarness();
    }

    // ── Delay rule ────────────────────────────────────────────────────────────

    function test_delay_mainnetDefaultsToOneDay() public view {
        assertEq(h.timelockDelay(16661, false, 0), 86400);
    }

    function test_delay_mainnetOverrideAtOrAboveMinimumKept() public view {
        assertEq(h.timelockDelay(16661, true, 86400), 86400);
        assertEq(h.timelockDelay(16661, true, 172800), 172800);
    }

    function test_delay_mainnetOverrideBelowMinimumReverts() public {
        vm.expectRevert(DELAY_TOO_SHORT);
        h.timelockDelay(16661, true, 86399);
        vm.expectRevert(DELAY_TOO_SHORT);
        h.timelockDelay(16661, true, 0);
    }

    function test_delay_otherChainsStayLightweight() public view {
        assertEq(h.timelockDelay(16602, false, 0), 0, "Galileo default");
        assertEq(h.timelockDelay(31337, false, 0), 0, "local default");
        assertEq(h.timelockDelay(16602, true, 0), 0, "Galileo explicit 0");
        assertEq(h.timelockDelay(16602, true, 3600), 3600, "Galileo override kept");
    }

    // ── Incremental deploys: existing beacon owner on mainnet ─────────────────

    function test_requireMainnetTimelock() public {
        address[] memory proposers = new address[](1);
        proposers[0] = address(this);
        address[] memory executors = new address[](1);
        TimelockController weak = new TimelockController(3600, proposers, executors, address(0));
        TimelockController strong = new TimelockController(1 days, proposers, executors, address(0));
        address eoa = makeAddr("not-a-timelock");

        vm.expectRevert(bytes("TIMELOCK minDelay below 86400 (1 day) on 0G mainnet (chain 16661)"));
        h.requireMainnetTimelock(16661, address(weak));
        vm.expectRevert(bytes("TIMELOCK has no code (0G mainnet needs a TimelockController)"));
        h.requireMainnetTimelock(16661, eoa);
        h.requireMainnetTimelock(16661, address(strong));

        // Off mainnet: no constraint.
        h.requireMainnetTimelock(16602, address(weak));
        h.requireMainnetTimelock(16602, eoa);
    }

    // ── End to end: Deploy.run() ──────────────────────────────────────────────

    /// @param ownerIsAdmin false on 0G mainnet (no external Timelock admin),
    ///        true elsewhere (OWNER admin, as on the testnet / dev Timelocks).
    function _assertGovernance(Deploy.Deployed memory d, address owner, uint256 delay, bool ownerIsAdmin)
        internal view
    {
        TimelockController t = TimelockController(payable(d.timelock));
        assertEq(t.getMinDelay(), delay, "minDelay");

        bytes32 adminRole = t.DEFAULT_ADMIN_ROLE();
        assertTrue(t.hasRole(adminRole, d.timelock), "Timelock self-administers");
        assertEq(t.hasRole(adminRole, owner), ownerIsAdmin, "OWNER Timelock admin iff not mainnet");
        assertFalse(t.hasRole(adminRole, DEFAULT_SENDER), "deployer is not a Timelock admin");
        assertTrue(t.hasRole(t.PROPOSER_ROLE(), owner), "OWNER proposes");
        assertTrue(t.hasRole(t.CANCELLER_ROLE(), owner), "OWNER cancels");
        assertTrue(t.hasRole(t.EXECUTOR_ROLE(), address(0)), "open execution");

        assertEq(UpgradeableBeacon(d.agenticIdBeacon).owner(), d.timelock, "AgenticID beacon owner");
        assertEq(UpgradeableBeacon(d.verifierBeacon).owner(), d.timelock, "verifier beacon owner");
        assertEq(UpgradeableBeacon(d.verifiedFeedbackBeacon).owner(), d.timelock, "VF beacon owner");
        assertEq(UpgradeableBeacon(d.cloneGateBeacon).owner(), d.timelock, "CloneGate beacon owner");

        assertEq(AgenticID(d.agenticId).owner(), owner, "AgenticID owner");
        assertEq(AgenticID(d.agenticId).pendingOwner(), address(0), "AgenticID pending");
        assertEq(TEEDataVerifier(d.verifier).owner(), owner, "verifier owner");
        assertEq(VerifiedFeedbackRegistry(d.verifiedFeedback).owner(), owner, "VF owner");
    }

    /// @dev The ONLY test here that touches process env (Deploy reads it), so
    ///      parallel tests can't race on it. Runs sequentially: default →
    ///      too-short override → valid override → testnet zero. The env it sets
    ///      (OWNER / PAUSER / TEE_ORACLE / CANONICAL_8004* / TIMELOCK_DELAY=0)
    ///      stays set for the rest of the forge process; no other test reads it.
    function test_run_enforcesMainnetGovernance() public {
        // Admin rule, library level: mainnet → none, elsewhere → OWNER (the
        // Deploy.run() legs below re-check it on the deployed Timelock).
        address someOwner = makeAddr("some-owner");
        assertEq(h.timelockAdmin(16661, someOwner), address(0), "mainnet: no admin");
        assertEq(h.timelockAdmin(16602, someOwner), someOwner, "Galileo: OWNER admin");
        assertEq(h.timelockAdmin(31337, someOwner), someOwner, "local: OWNER admin");

        address owner = makeAddr("owner");
        Canonical8004Stub identity = new Canonical8004Stub(address(0));
        Canonical8004Stub reputation = new Canonical8004Stub(address(identity));
        vm.setEnv("OWNER", vm.toString(owner));
        vm.setEnv("PAUSER", vm.toString(makeAddr("pauser")));
        vm.setEnv("TEE_ORACLE", vm.toString(makeAddr("oracle")));
        vm.setEnv("CANONICAL_8004", vm.toString(address(identity)));
        vm.setEnv("CANONICAL_8004_REPUTATION", vm.toString(address(reputation)));

        Deploy script = new Deploy();
        vm.chainId(16661);

        // TIMELOCK_DELAY unset → 1 day. Can't run if the calling shell exports
        // TIMELOCK_DELAY (forge has no unsetEnv) — say so instead of passing
        // silently; the library-level test_delay_mainnetDefaultsToOneDay still
        // covers the rule.
        if (!vm.envExists("TIMELOCK_DELAY")) {
            _assertGovernance(script.run(), owner, 86400, false);
        } else {
            console2.log("SKIPPED mainnet-default leg: TIMELOCK_DELAY is set in the calling environment");
        }

        vm.setEnv("TIMELOCK_DELAY", "3600");
        vm.expectRevert(DELAY_TOO_SHORT);
        script.run();

        vm.setEnv("TIMELOCK_DELAY", "172800");
        _assertGovernance(script.run(), owner, 172800, false);

        // Off mainnet a zero delay stays allowed and OWNER stays Timelock
        // admin (testnet / dev, matching §6.1 / §6.2).
        vm.chainId(16602);
        vm.setEnv("TIMELOCK_DELAY", "0");
        _assertGovernance(script.run(), owner, 0, true);
    }
}
