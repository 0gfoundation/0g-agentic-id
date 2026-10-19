// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {DeployVerifiedFeedback} from "../script/DeployVerifiedFeedback.s.sol";
import {DeployCloneGate} from "../script/DeployCloneGate.s.sol";
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

    function requireMainnetTimelockRoles(
        uint256 chainId,
        address owner,
        address[] memory proposers,
        address[] memory executors
    ) external pure {
        MainnetGovernance.requireMainnetTimelockRoles(chainId, owner, proposers, executors);
    }
}

/// @notice Deploy-script governance rules (script/MainnetGovernance.sol):
///         0G mainnet (16661) defaults TIMELOCK_DELAY to 1 day, refuses less,
///         gives a fresh Timelock no external admin and refuses role sets that
///         could never schedule / execute; every other chain stays lightweight
///         (delay defaults to 0, OWNER is the Timelock admin, role sets
///         unchecked); incremental deploys refuse a weak beacon owner on
///         mainnet. Library-level cases plus end-to-end runs of Deploy.s.sol,
///         DeployVerifiedFeedback.s.sol and DeployCloneGate.s.sol.
contract DeployScriptTest is Test {
    MainnetGovernanceHarness internal h;

    bytes internal constant DELAY_TOO_SHORT =
        bytes("TIMELOCK_DELAY below 86400 (1 day) is not allowed on 0G mainnet (chain 16661)");
    bytes internal constant PROPOSERS_EMPTY =
        bytes("PROPOSERS is empty on 0G mainnet (chain 16661): nobody could schedule");
    bytes internal constant PROPOSER_ZERO = bytes("PROPOSERS contains address(0) on 0G mainnet (chain 16661)");
    bytes internal constant PROPOSERS_NO_OWNER = bytes("PROPOSERS must include OWNER on 0G mainnet (chain 16661)");
    bytes internal constant EXECUTORS_EMPTY =
        bytes("EXECUTORS is empty on 0G mainnet (chain 16661): nobody could execute");
    bytes internal constant EXECUTORS_MIXED = bytes(
        "EXECUTORS mixes address(0) with named executors on 0G mainnet (chain 16661): use exactly 0x0 or only non-zero addresses"
    );
    bytes internal constant WEAK_TIMELOCK = bytes("TIMELOCK minDelay below 86400 (1 day) on 0G mainnet (chain 16661)");
    bytes internal constant CODELESS_TIMELOCK = bytes("TIMELOCK has no code (0G mainnet needs a TimelockController)");

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

        vm.expectRevert(WEAK_TIMELOCK);
        h.requireMainnetTimelock(16661, address(weak));
        vm.expectRevert(CODELESS_TIMELOCK);
        h.requireMainnetTimelock(16661, eoa);
        h.requireMainnetTimelock(16661, address(strong));

        // Off mainnet: no constraint.
        h.requireMainnetTimelock(16602, address(weak));
        h.requireMainnetTimelock(16602, eoa);
    }

    // ── Role sets for a fresh Timelock ────────────────────────────────────────

    function _list(address a) internal pure returns (address[] memory l) {
        l = new address[](1);
        l[0] = a;
    }

    function _list(address a, address b) internal pure returns (address[] memory l) {
        l = new address[](2);
        l[0] = a;
        l[1] = b;
    }

    function test_roles_mainnetRefusesUnusableSets() public {
        address owner = makeAddr("owner");
        address other = makeAddr("other");
        address[] memory none = new address[](0);
        address[] memory open = _list(address(0));

        vm.expectRevert(PROPOSERS_EMPTY);
        h.requireMainnetTimelockRoles(16661, owner, none, open);
        vm.expectRevert(PROPOSER_ZERO);
        h.requireMainnetTimelockRoles(16661, owner, _list(owner, address(0)), open);
        vm.expectRevert(PROPOSER_ZERO);
        h.requireMainnetTimelockRoles(16661, owner, _list(address(0)), open);
        vm.expectRevert(PROPOSERS_NO_OWNER);
        h.requireMainnetTimelockRoles(16661, owner, _list(other), open);
        vm.expectRevert(EXECUTORS_EMPTY);
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), none);
        vm.expectRevert(EXECUTORS_MIXED);
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), _list(address(0), other));
        vm.expectRevert(EXECUTORS_MIXED);
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), _list(other, address(0)));

        // Accepted: OWNER (plus extras) proposing; open or all-named execution.
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), open);
        h.requireMainnetTimelockRoles(16661, owner, _list(other, owner), open);
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), _list(other));
        h.requireMainnetTimelockRoles(16661, owner, _list(owner), _list(other, owner));
    }

    function test_roles_otherChainsUnchecked() public {
        address owner = makeAddr("owner");
        address[] memory none = new address[](0);
        h.requireMainnetTimelockRoles(16602, owner, none, none);
        h.requireMainnetTimelockRoles(31337, owner, _list(address(0)), _list(address(0), owner));
    }

    // ── End to end: the deploy scripts ────────────────────────────────────────

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

    /// @dev Pins the Timelock role sets for the next Deploy.run().
    function _pinRoles(string memory proposers, string memory executors) internal {
        vm.setEnv("PROPOSERS", proposers);
        vm.setEnv("EXECUTORS", executors);
    }

    function _expectRolesRevert(
        Deploy script,
        string memory proposers,
        string memory executors,
        bytes memory reason
    ) internal {
        _pinRoles(proposers, executors);
        vm.expectRevert(reason);
        script.run();
    }

    /// @dev The ONLY test here that touches process env (the scripts read it),
    ///      so parallel tests can't race on it. Runs sequentially: defaults →
    ///      delay floor → role sets → incremental scripts → testnet. Every leg
    ///      after the first pins TIMELOCK_DELAY / PROPOSERS / EXECUTORS itself,
    ///      so the calling shell's env can't change the outcome. The env it
    ///      sets (OWNER / PAUSER / TEE_ORACLE / CANONICAL_8004* / TIMELOCK_DELAY
    ///      / PROPOSERS / EXECUTORS / AGENTIC_ID / TIMELOCK) stays set for the
    ///      rest of the forge process; no other test reads it.
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

        string memory ownerStr = vm.toString(owner);
        string memory openStr = vm.toString(address(0));

        Deploy script = new Deploy();
        vm.chainId(16661);

        // 1. Defaults: TIMELOCK_DELAY → 1 day, PROPOSERS → [OWNER], EXECUTORS →
        //    [0x0]. forge has no unsetEnv, so a default is exercised only while
        //    the calling shell doesn't export that variable; otherwise pin it to
        //    the default's value and say so instead of passing silently (the
        //    library-level tests still cover the rules).
        if (vm.envExists("PROPOSERS") || vm.envExists("EXECUTORS")) {
            console2.log("SKIPPED default PROPOSERS/EXECUTORS: set in the calling environment, pinned");
            _pinRoles(ownerStr, openStr);
        }
        if (vm.envExists("TIMELOCK_DELAY")) {
            console2.log("SKIPPED default TIMELOCK_DELAY: set in the calling environment, pinned to 86400");
            vm.setEnv("TIMELOCK_DELAY", "86400");
        }
        _assertGovernance(script.run(), owner, 86400, false);

        // 2. Delay floor.
        _pinRoles(ownerStr, openStr);
        vm.setEnv("TIMELOCK_DELAY", "3600");
        vm.expectRevert(DELAY_TOO_SHORT);
        script.run();

        vm.setEnv("TIMELOCK_DELAY", "172800");
        Deploy.Deployed memory strong = script.run();
        _assertGovernance(strong, owner, 172800, false);

        // 3. Role sets. A set-but-empty variable parses to an empty list, not
        //    the default; each of these would deploy a Timelock that can never
        //    schedule or execute, with no admin to fix it.
        vm.setEnv("TIMELOCK_DELAY", "86400");
        address other = makeAddr("other");
        string memory otherStr = vm.toString(other);
        _expectRolesRevert(script, "", openStr, PROPOSERS_EMPTY);
        _expectRolesRevert(script, string.concat(ownerStr, ",", openStr), openStr, PROPOSER_ZERO);
        _expectRolesRevert(script, otherStr, openStr, PROPOSERS_NO_OWNER);
        _expectRolesRevert(script, ownerStr, "", EXECUTORS_EMPTY);
        _expectRolesRevert(script, ownerStr, string.concat(openStr, ",", otherStr), EXECUTORS_MIXED);

        // Accepted: an extra proposer and named executors only.
        address keeper = makeAddr("keeper");
        _pinRoles(string.concat(ownerStr, ",", otherStr), string.concat(otherStr, ",", vm.toString(keeper)));
        TimelockController t = TimelockController(payable(script.run().timelock));
        assertTrue(t.hasRole(t.PROPOSER_ROLE(), owner), "OWNER proposes");
        assertTrue(t.hasRole(t.PROPOSER_ROLE(), other), "extra proposer");
        assertTrue(t.hasRole(t.EXECUTOR_ROLE(), other), "named executor");
        assertTrue(t.hasRole(t.EXECUTOR_ROLE(), keeper), "named executor");
        assertFalse(t.hasRole(t.EXECUTOR_ROLE(), address(0)), "execution not open");

        // 4. Incremental deploys onto the stack from leg 2.
        _pinRoles(ownerStr, openStr);
        _runIncrementalScripts(strong);

        // 5. Off mainnet a zero delay stays allowed, OWNER stays Timelock admin
        //    (testnet / dev, matching §6.1 / §6.2) and the role sets are not
        //    checked — OWNER can grant a missing role directly.
        vm.chainId(16602);
        vm.setEnv("TIMELOCK_DELAY", "0");
        _assertGovernance(script.run(), owner, 0, true);

        _pinRoles("", "");
        t = TimelockController(payable(script.run().timelock));
        assertFalse(t.hasRole(t.PROPOSER_ROLE(), owner), "testnet: empty PROPOSERS deploys as-is");
        assertTrue(t.hasRole(t.DEFAULT_ADMIN_ROLE(), owner), "testnet: OWNER can grant roles");
    }

    /// @dev DeployVerifiedFeedback.s.sol / DeployCloneGate.s.sol on chain 16661
    ///      refuse a weak or code-less TIMELOCK and accept the >= 1-day one;
    ///      off mainnet they accept any. Leaves the chain id at 16661.
    function _runIncrementalScripts(Deploy.Deployed memory d) internal {
        TimelockController weak = new TimelockController(3600, _list(address(this)), _list(address(0)), address(0));
        DeployVerifiedFeedback vfScript = new DeployVerifiedFeedback();
        DeployCloneGate cgScript = new DeployCloneGate();
        vm.setEnv("AGENTIC_ID", vm.toString(d.agenticId));

        vm.setEnv("TIMELOCK", vm.toString(address(weak)));
        vm.expectRevert(WEAK_TIMELOCK);
        vfScript.run();
        vm.expectRevert(WEAK_TIMELOCK);
        cgScript.run();

        vm.setEnv("TIMELOCK", vm.toString(makeAddr("not-a-timelock")));
        vm.expectRevert(CODELESS_TIMELOCK);
        vfScript.run();
        vm.expectRevert(CODELESS_TIMELOCK);
        cgScript.run();

        vm.setEnv("TIMELOCK", vm.toString(d.timelock));
        (, address vfBeacon,,) = vfScript.run();
        (, address cgBeacon,) = cgScript.run();
        assertEq(UpgradeableBeacon(vfBeacon).owner(), d.timelock, "mainnet: VF beacon owned by the 1-day Timelock");
        assertEq(UpgradeableBeacon(cgBeacon).owner(), d.timelock, "mainnet: CloneGate beacon owned by the 1-day Timelock");

        vm.chainId(16602);
        vm.setEnv("TIMELOCK", vm.toString(address(weak)));
        (, vfBeacon,,) = vfScript.run();
        (, cgBeacon,) = cgScript.run();
        assertEq(UpgradeableBeacon(vfBeacon).owner(), address(weak), "testnet: weak Timelock accepted");
        assertEq(UpgradeableBeacon(cgBeacon).owner(), address(weak), "testnet: weak Timelock accepted");
        vm.chainId(16661);
    }
}
