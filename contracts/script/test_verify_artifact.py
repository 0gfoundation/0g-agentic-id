#!/usr/bin/env python3
"""Offline regression tests; no RPC, explorer or forge submission is made."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_artifact as verify


LIB = "src/Binding.sol:Binding"
LIB_ADDRESS = "0x" + "11" * 20
DEPLOYED = "0x" + "22" * 20
PLACEHOLDER = "__$" + "f" * 34 + "$__"


def artifact(source="src/Main.sol", name="Main"):
    return {
        "abi": [],
        "metadata": {
            "compiler": {"version": "0.8.38+commit.abcdef12"},
            "settings": {
                "compilationTarget": {source: name},
                "optimizer": {"enabled": True, "runs": 1},
                "viaIR": True, "evmVersion": "cancun", "libraries": {},
                "metadata": {"bytecodeHash": "ipfs"}, "remappings": [],
            },
        },
        "deployedBytecode": {"object": "0x60016002", "linkReferences": {}},
        "bytecode": {"object": "0x600360016002", "linkReferences": {}},
    }


def linked_artifact():
    result = artifact()
    result["deployedBytecode"] = {
        "object": "0xaaaa" + PLACEHOLDER + "bbbb" + PLACEHOLDER + "cccc",
        "linkReferences": {"src/Binding.sol": {"Binding": [{"start": 2, "length": 20}, {"start": 24, "length": 20}]}},
    }
    result["bytecode"] = {
        "object": "0x6000" + result["deployedBytecode"]["object"][2:],
        "linkReferences": {"src/Binding.sol": {"Binding": [{"start": 4, "length": 20}, {"start": 26, "length": 20}]}},
    }
    runtime = result["deployedBytecode"]["object"].replace(PLACEHOLDER, LIB_ADDRESS[2:])
    return result, runtime


def effective_config(plan):
    result = copy.deepcopy(plan["metadata_settings"])
    result.update(optimizer=plan["optimizer_enabled"], optimizer_runs=plan["optimizer_runs"],
                  via_ir=plan["via_ir"], evm_version=plan["evm_version"],
                  remappings=plan["remappings"], optimizer_details=None,
                  libraries=[f"{item['source']}:{item['address']}" for item in plan["libraries"]])
    return result


class ArtifactMatchingTests(unittest.TestCase):
    def run_verified_proxy_script(self, directory, consistent):
        path = Path(directory)
        artifacts = path / "out"
        artifacts.mkdir()
        proxy = "0x" + "ab" * 20
        beacon = LIB_ADDRESS
        implementation = "0x" + "33" * 20
        runtime_beacon = beacon if consistent else "0x" + "44" * 20
        proxy_artifact = artifact(*verify.BEACON_PROXY_TARGET.split(":"))
        proxy_artifact["deployedBytecode"] = {
            "object": "0x60" + "00" * 32 + "5b",
            "immutableReferences": {"42": [{"start": 1, "length": 32}]},
        }
        proxy_runtime = "0x60" + runtime_beacon[2:].zfill(64) + "5b"
        beacon_artifact = artifact(
            "lib/openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol", "UpgradeableBeacon")
        implementation_artifact = artifact("src/AgenticID.sol", "AgenticID")
        for name, data in [("Proxy", proxy_artifact), ("Beacon", beacon_artifact), ("Impl", implementation_artifact)]:
            (artifacts / (name + ".json")).write_text(json.dumps(data))
        fixture = path / "fixture.json"
        fixture.write_text(json.dumps({
            "beacon": beacon, "implementation": implementation,
            "runtime": {proxy: proxy_runtime, beacon: "0x60016002", implementation: "0x60016002"},
        }))
        binaries = path / "bin"
        binaries.mkdir()
        programs = {
            "cast": '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
fixture = json.loads(Path(os.environ["VERIFY_FIXTURE"]).read_text())
command = sys.argv[1]
if command == "storage": print("0x" + fixture["beacon"][2:].zfill(64))
elif command == "call": print(fixture["implementation"])
elif command == "code": print(fixture["runtime"][sys.argv[2].lower()])
else: raise SystemExit("unexpected cast call")
''',
            "curl": '''#!/usr/bin/env python3
import json, os
from pathlib import Path
with Path(os.environ["VERIFY_CALLS"]).open("a") as log: log.write("verified-check\\n")
print(json.dumps({"result": [{"SourceCode": "already verified"}]}))
''',
            "forge": '''#!/usr/bin/env python3
import os
from pathlib import Path
with Path(os.environ["VERIFY_CALLS"]).open("a") as log: log.write("unexpected forge submission\\n")
raise SystemExit(93)
''',
        }
        for name, program in programs.items():
            executable = binaries / name
            executable.write_text(program)
            executable.chmod(0o755)
        calls = path / "calls.log"
        env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""),
                   ARTIFACTS_DIR=str(artifacts), VERIFY_FIXTURE=str(fixture), VERIFY_CALLS=str(calls),
                   RPC_URL="https://rpc.invalid", VERIFIER_URL="https://explorer.invalid/api", CHAIN_ID="16602")
        result = subprocess.run(["bash", str(Path(__file__).with_name("verify.sh").resolve()),
                                 "0x" + "AB" * 20], cwd=path, env=env,
                                text=True, capture_output=True, timeout=10)
        return result, calls.read_text().splitlines() if calls.exists() else []

    @unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "verify.sh requires jq and bash")
    def test_matching_beacon_immutable_and_storage_verify_the_same_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            result, calls = self.run_verified_proxy_script(directory, True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["verified-check"] * 3)
        self.assertIn("done.", result.stdout)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "verify.sh requires jq and bash")
    def test_mismatched_beacon_is_rejected_before_already_verified_can_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            result, calls = self.run_verified_proxy_script(directory, False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime immutable does not match", result.stderr)
        self.assertEqual(calls, [], "chain mismatch must fail before even consulting the verified-source shortcut")

    def test_beacon_check_requires_one_canonical_immutable_on_the_exact_target(self):
        plan = {"source": verify.BEACON_PROXY_TARGET,
                "immutable_values": {"42": "0x" + LIB_ADDRESS[2:].zfill(64)}}
        verify.check_beacon(plan, LIB_ADDRESS)
        for change in [
            {"source": "src/Other.sol:BeaconProxy"},
            {"immutable_values": {}},
            {"immutable_values": {"42": "0x" + LIB_ADDRESS[2:]}},
            {"immutable_values": {"42": "0x" + "ff" * 32}},
            {"immutable_values": {"42": plan["immutable_values"]["42"], "43": plan["immutable_values"]["42"]}},
        ]:
            with self.assertRaises(verify.MatchError):
                verify.check_beacon(dict(plan, **change), LIB_ADDRESS)

    def test_link_addresses_and_compiler_flags_come_from_matched_artifact(self):
        data, runtime = linked_artifact()
        plan = verify.match_artifact(data, runtime, DEPLOYED)
        self.assertEqual(plan["libraries"], [{"source": LIB, "address": LIB_ADDRESS}])
        self.assertEqual(plan["compiler_version"], "0.8.38+commit.abcdef12")
        self.assertEqual(plan["optimizer_runs"], 1)
        self.assertIn(f"{LIB}:{LIB_ADDRESS}", plan["forge_args"])
        self.assertEqual(plan["creation_bytecode"], "6000" + runtime[2:])

    def test_every_occurrence_of_the_same_library_must_agree(self):
        data, runtime = linked_artifact()
        runtime = runtime[: 2 + 24 * 2] + "33" * 20 + runtime[2 + 44 * 2 :]
        with self.assertRaisesRegex(verify.MatchError, "conflicting addresses"):
            verify.match_artifact(data, runtime, DEPLOYED)

    def test_zero_library_address_is_not_a_match(self):
        data, runtime = linked_artifact()
        with self.assertRaisesRegex(verify.MatchError, "nonzero"):
            verify.match_artifact(data, runtime.replace("11" * 20, "00" * 20), DEPLOYED)

    def test_linking_does_not_mask_any_other_runtime_or_metadata_byte(self):
        data, runtime = linked_artifact()
        for changed in ["0xbb" + runtime[4:], runtime[:-2] + "dd"]:
            with self.assertRaisesRegex(verify.MatchError, "complete runtime mismatch"):
                verify.match_artifact(data, changed, DEPLOYED)

    def test_overlapping_link_references_are_rejected(self):
        data, runtime = linked_artifact()
        data["deployedBytecode"]["linkReferences"]["src/Binding.sol"]["Binding"][1]["start"] = 3
        with self.assertRaisesRegex(verify.MatchError, "overlapping"):
            verify.match_artifact(data, runtime, DEPLOYED)

    def test_proxy_immutables_match_but_creation_prefix_remains_unmodified(self):
        data = artifact("lib/BeaconProxy.sol", "BeaconProxy")
        data["abi"] = [{"type": "constructor", "inputs": [{"type": "address"}]}]
        data["deployedBytecode"] = {"object": "0x60" + "00" * 32 + "5b",
                                   "immutableReferences": {"42": [{"start": 1, "length": 32}]}}
        data["bytecode"]["object"] = "0x6000" + data["deployedBytecode"]["object"][2:]
        runtime = "0x60" + LIB_ADDRESS[2:].zfill(64) + "5b"
        plan = verify.match_artifact(data, runtime, DEPLOYED)
        encoded = LIB_ADDRESS[2:].zfill(64)
        self.assertEqual(verify.constructor_args(plan, data["bytecode"]["object"] + encoded), encoded)
        with self.assertRaisesRegex(verify.MatchError, "does not start"):
            verify.constructor_args(plan, "0x6000" + runtime[2:] + encoded)

    def test_library_self_address_must_equal_the_library_being_verified(self):
        data = artifact("src/Binding.sol", "Binding")
        data["deployedBytecode"] = {"object": "0x60" + "00" * 32 + "5b",
                                   "immutableReferences": {"library_deploy_address": [{"start": 1, "length": 32}]}}
        runtime = "0x60" + LIB_ADDRESS[2:].zfill(64) + "5b"
        self.assertEqual(verify.match_artifact(data, runtime, LIB_ADDRESS)["source"], LIB)
        with self.assertRaisesRegex(verify.MatchError, "another deployment address"):
            verify.match_artifact(data, runtime, DEPLOYED)

    def test_missing_creation_arguments_fail_closed(self):
        data = artifact()
        data["abi"] = [{"type": "constructor", "inputs": [{"type": "address"}]}]
        plan = verify.match_artifact(data, "0x60016002", DEPLOYED)
        for creation in ["", "0x", data["bytecode"]["object"]]:
            with self.assertRaises(verify.MatchError):
                verify.constructor_args(plan, creation)

    def test_custom_compiler_settings_are_explicitly_unsupported(self):
        for field, value in [("optimizer", {"enabled": True, "runs": 1, "details": {"yul": True}}), ("experimental", {})]:
            data = artifact()
            data["metadata"]["settings"][field] = value
            with self.assertRaisesRegex(verify.MatchError, "unsupported|not supported"):
                verify.match_artifact(data, "0x60016002", DEPLOYED)

    def test_explicit_source_hint_and_ambiguity_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "Main.json").write_text(json.dumps(artifact()))
            plan = verify.find_artifact(path, {"src/Main.sol:Main"}, "0x60016002", DEPLOYED)
            self.assertEqual(plan["source"], "src/Main.sol:Main")
            with self.assertRaisesRegex(verify.MatchError, "found 0"):
                verify.find_artifact(path, {"src/Other.sol:Other"}, "0x60016002", DEPLOYED)
            (path / "Duplicate.json").write_text(json.dumps(artifact()))
            with self.assertRaisesRegex(verify.MatchError, "found 2"):
                verify.find_artifact(path, {"src/Main.sol:Main"}, "0x60016002", DEPLOYED)

    def test_effective_config_must_match_before_any_submission(self):
        plan = verify.match_artifact(artifact(), "0x60016002", DEPLOYED)
        config = effective_config(plan)
        verify.validate_config(plan, config)
        for field, changed in [("optimizer_runs", 200), ("evm_version", "shanghai"),
                               ("optimizer_details", {"yul": True}), ("remappings", ["extra/=other/"])]:
            wrong = copy.deepcopy(config)
            wrong[field] = changed
            with self.assertRaises(verify.MatchError):
                verify.validate_config(plan, wrong)

    def test_false_metadata_options_override_global_defaults(self):
        data = artifact()
        data["metadata"]["settings"].update(viaIR=False, optimizer={"enabled": False, "runs": 0})
        plan = verify.match_artifact(data, "0x60016002", DEPLOYED)
        with patch.dict(os.environ, {"FOUNDRY_VIA_IR": "true", "FOUNDRY_OPTIMIZER": "true", "DAPP_LIBRARIES": "unrelated"}):
            env = verify.verification_environment(plan)
        self.assertEqual(env["FOUNDRY_VIA_IR"], "false")
        self.assertEqual(env["FOUNDRY_OPTIMIZER"], "false")
        self.assertEqual(env["FOUNDRY_OPTIMIZER_RUNS"], "0")
        self.assertNotIn("DAPP_LIBRARIES", env)
        self.assertNotIn("--via-ir", plan["forge_args"])

    def test_no_bytecode_hash_keeps_cbor_enabled(self):
        data = artifact()
        data["metadata"]["settings"]["metadata"] = {"bytecodeHash": "none", "appendCBOR": True}
        plan = verify.match_artifact(data, "0x60016002", DEPLOYED)
        env = verify.verification_environment(plan)
        self.assertEqual(env["FOUNDRY_BYTECODE_HASH"], "none")
        self.assertEqual(env["FOUNDRY_CBOR_METADATA"], "true")
        self.assertEqual(plan["compiler_version"], "0.8.38+commit.abcdef12")

    def test_verifier_receives_matched_version_and_linker_flags_without_watch(self):
        data, runtime = linked_artifact()
        plan = verify.match_artifact(data, runtime, DEPLOYED)
        with patch("verify_artifact.subprocess.check_output", return_value=json.dumps(effective_config(plan))) as config, patch("verify_artifact.subprocess.run") as run:
            verify.verify(plan, DEPLOYED, "16602", "https://explorer.invalid/api", "aa")
        command = run.call_args.args[0]
        self.assertIn("--libraries", command)
        self.assertIn(f"{LIB}:{LIB_ADDRESS}", command)
        self.assertIn("0.8.38+commit.abcdef12", command)
        self.assertIn("0xaa", command)
        self.assertNotIn("--watch", command)
        self.assertIn("--libraries", config.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
