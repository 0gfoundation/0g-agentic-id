#!/usr/bin/env python3
"""Match local Foundry artifacts before generating explorer verification inputs.

This helper is offline: its caller supplies runtime and creation bytecode read
from the intended chain/explorer. Only compiler-declared link/immutable slots may
vary; the resulting complete runtime, including its metadata, must match. Only
the OpenZeppelin proxy and beacon may instead stand on an explorer record.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


class MatchError(ValueError):
    pass


BEACON_PROXY_TARGET = "lib/openzeppelin-contracts/contracts/proxy/beacon/BeaconProxy.sol:BeaconProxy"
UPGRADEABLE_BEACON_TARGET = "lib/openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol:UpgradeableBeacon"


def hex_code(value):
    value = value.strip().removeprefix("0x")
    if not value or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise MatchError("expected nonempty hexadecimal bytecode")
    return value.lower()


def address(value):
    value = value.lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", value) or int(value, 16) == 0:
        raise MatchError("expected a nonzero 20-byte address")
    return value


def slots(refs):
    for source, names in refs.items():
        for name, positions in names.items():
            if not positions:
                raise MatchError(f"empty link references for {source}:{name}")
            yield source, name, positions


def replace_slot(code, position, replacement, occupied):
    start, length = position["start"], position["length"]
    if not isinstance(start, int) or not isinstance(length, int) or start < 0 or length <= 0:
        raise MatchError("invalid compiler bytecode reference")
    if 2 * (start + length) > len(code) or len(replacement) != length * 2:
        raise MatchError("bytecode reference is out of bounds")
    indexes = set(range(start, start + length))
    if occupied.intersection(indexes):
        raise MatchError("overlapping compiler bytecode references")
    occupied.update(indexes)
    return code[: start * 2] + replacement + code[(start + length) * 2 :]


def metadata(artifact):
    result = artifact.get("metadata")
    if result is None:
        result = artifact.get("rawMetadata")
    if isinstance(result, str):
        result = json.loads(result)
    if not isinstance(result, dict):
        raise MatchError("artifact has no Solidity metadata")
    return result


def match_artifact(artifact, runtime, deployed_address):
    runtime = hex_code(runtime)
    deployed_address = address(deployed_address)
    meta = metadata(artifact)
    settings = meta["settings"]
    supported = {"compilationTarget", "optimizer", "viaIR", "evmVersion", "libraries", "metadata", "remappings", "debug"}
    if set(settings) - supported:
        raise MatchError(f"unsupported Solidity settings: {sorted(set(settings) - supported)}")
    if set(settings["optimizer"]) - {"enabled", "runs"}:
        raise MatchError("custom optimizer details are not supported by this verification script")
    meta_settings = settings.get("metadata", {})
    if set(meta_settings) - {"bytecodeHash", "appendCBOR", "useLiteralContent"}:
        raise MatchError("unsupported Solidity metadata settings")
    if set(settings.get("debug", {})) - {"revertStrings"}:
        raise MatchError("unsupported Solidity debug settings")
    target = settings["compilationTarget"]
    if len(target) != 1:
        raise MatchError("metadata must identify exactly one compilation target")
    source, name = next(iter(target.items()))
    identifier = f"{source}:{name}"
    compiled = artifact["deployedBytecode"]["object"].removeprefix("0x").lower()
    if len(compiled) != len(runtime):
        raise MatchError("runtime length mismatch")
    libraries = {}
    occupied = set()
    for lib_source, lib_name, positions in slots(artifact["deployedBytecode"].get("linkReferences", {})):
        values = set()
        for position in positions:
            if position["length"] != 20:
                raise MatchError("library reference is not 20 bytes")
            start = position["start"] * 2
            value = runtime[start : start + 40]
            values.add(address("0x" + value))
            compiled = replace_slot(compiled, position, value, occupied)
        if len(values) != 1:
            raise MatchError(f"runtime uses conflicting addresses for {lib_source}:{lib_name}")
        libraries[f"{lib_source}:{lib_name}"] = values.pop()
    # BeaconProxy embeds its beacon, and Solidity libraries embed their own
    # deployment address. Preserve those declared relocations without masking
    # arbitrary runtime bytes; repeated instances must agree as well.
    immutable_values = {}
    for key, positions in artifact["deployedBytecode"].get("immutableReferences", {}).items():
        values = set()
        for position in positions:
            start, length = position["start"] * 2, position["length"] * 2
            value = runtime[start : start + length]
            values.add(value)
            if key == "library_deploy_address" and value != deployed_address[2:].zfill(length):
                raise MatchError("library runtime embeds another deployment address")
            compiled = replace_slot(compiled, position, value, occupied)
        if len(values) != 1:
            raise MatchError(f"runtime has conflicting immutable values for {key}")
        immutable_values[key] = "0x" + values.pop()
    if hex_code(compiled) != runtime:
        raise MatchError("complete runtime mismatch (including metadata)")

    # Pre-linked artifacts can have no relocation records. Their metadata still
    # names the exact library settings used in this fully matched runtime.
    for lib_source, names in settings.get("libraries", {}).items():
        for lib_name, value in names.items():
            qualified = f"{lib_source}:{lib_name}"
            value = address(value)
            if qualified in libraries and libraries[qualified] != value:
                raise MatchError(f"metadata and runtime disagree on {qualified}")
            libraries[qualified] = value

    creation = artifact["bytecode"]["object"].removeprefix("0x").lower()
    occupied = set()
    for lib_source, lib_name, positions in slots(artifact["bytecode"].get("linkReferences", {})):
        qualified = f"{lib_source}:{lib_name}"
        if qualified not in libraries:
            raise MatchError(f"constructor-only library cannot be resolved from runtime: {qualified}")
        for position in positions:
            if position["length"] != 20:
                raise MatchError("creation library reference is not 20 bytes")
            creation = replace_slot(creation, position, libraries[qualified][2:], occupied)
    creation = hex_code(creation)

    optimizer = settings["optimizer"]
    enabled, runs = optimizer["enabled"], optimizer["runs"]
    via_ir, evm = settings.get("viaIR", False), settings["evmVersion"]
    version = meta["compiler"]["version"]
    if not isinstance(enabled, bool) or not isinstance(via_ir, bool) or not isinstance(runs, int) or runs < 0:
        raise MatchError("invalid optimizer/viaIR metadata")
    if not isinstance(evm, str) or not evm or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\+commit\.[0-9a-f]+", version):
        raise MatchError("invalid compiler/EVM metadata")
    forge_args = ["--compiler-version", version, "--evm-version", evm]
    if enabled:
        forge_args += ["--num-of-optimizations", str(runs)]
    if via_ir:
        forge_args.append("--via-ir")
    for library, value in sorted(libraries.items()):
        forge_args += ["--libraries", f"{library}:{value}"]
    return {
        "source": identifier,
        "compiler_version": version,
        "optimizer_enabled": enabled,
        "optimizer_runs": runs,
        "via_ir": via_ir,
        "evm_version": evm,
        "metadata_settings": {
            "bytecode_hash": meta_settings.get("bytecodeHash", "ipfs"),
            "cbor_metadata": meta_settings.get("appendCBOR", True),
            "use_literal_content": meta_settings.get("useLiteralContent", False),
            "revert_strings": settings.get("debug", {}).get("revertStrings", "default"),
        },
        "remappings": settings.get("remappings", []),
        "libraries": [{"source": key, "address": value} for key, value in sorted(libraries.items())],
        "immutable_values": immutable_values,
        "forge_args": forge_args,
        "creation_bytecode": creation,
        "constructor_inputs": sum(len(entry.get("inputs", [])) for entry in artifact["abi"] if entry.get("type") == "constructor"),
    }


def find_artifact(directory, candidates, runtime, deployed_address):
    matches, failures = [], []
    for path in sorted(Path(directory).rglob("*.json")):
        if "build-info" in path.parts:
            continue
        try:
            artifact = json.loads(path.read_text())
            target = metadata(artifact).get("settings", {}).get("compilationTarget", {})
            if len(target) != 1 or f"{next(iter(target))}:{next(iter(target.values()))}" not in candidates:
                continue
            plan = match_artifact(artifact, runtime, deployed_address)
            plan["artifact"] = str(path.resolve())
            matches.append(plan)
        except (MatchError, KeyError, TypeError, json.JSONDecodeError) as error:
            failures.append(f"{path}: {error}")
    if len(matches) != 1:
        detail = "\n".join(failures[-8:])
        raise MatchError(f"expected one exact runtime-matching artifact, found {len(matches)}; build the deployment's actual compilation profile\n{detail}")
    return matches[0]


def constructor_args(plan, creation):
    if not creation.strip() or creation.strip() == "0x":
        if plan["constructor_inputs"]:
            raise MatchError("explorer did not supply creation bytecode for a constructor with arguments")
        return ""
    creation = hex_code(creation)
    prefix = plan["creation_bytecode"]
    if not creation.startswith(prefix):
        raise MatchError("explorer creation input does not start with the matched artifact's linked creation bytecode")
    args = creation[len(prefix) :]
    if plan["constructor_inputs"] and not args:
        raise MatchError("constructor arguments are missing from creation input")
    return args


def check_beacon(plan, beacon):
    if plan.get("source") != BEACON_PROXY_TARGET:
        raise MatchError("beacon check requires the matched OpenZeppelin BeaconProxy target")
    values = plan.get("immutable_values")
    if not isinstance(values, dict) or len(values) != 1:
        raise MatchError("BeaconProxy must declare exactly one immutable beacon")
    value = next(iter(values.values()))
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]{64}", value):
        raise MatchError("BeaconProxy beacon immutable must be one canonical 32-byte word")
    expected = "0x" + address(beacon)[2:].zfill(64)
    if value != expected:
        raise MatchError("BeaconProxy runtime immutable does not match its ERC1967 beacon storage slot")


def check_verified(response, target, beacon=None, creation=None):
    """Accept an explorer record in place of a local match of a proxy or beacon.

    The record must be verified source for exactly the OpenZeppelin contract. A
    BeaconProxy's constructor beacon is the immutable it delegates through, so it
    must be the slot's beacon, and the recorded arguments must end its creation input.
    """
    if target not in (BEACON_PROXY_TARGET, UPGRADEABLE_BEACON_TARGET):
        raise MatchError("only the OpenZeppelin proxy and beacon may stand on an explorer record")
    if (target == BEACON_PROXY_TARGET) != (beacon is not None):
        raise MatchError("a BeaconProxy record needs the beacon check, and only it")
    result = response.get("result") if isinstance(response, dict) else None
    record = result[0] if isinstance(result, list) and len(result) == 1 else None
    if not isinstance(record, dict) or not record.get("SourceCode"):
        raise MatchError("not reproduced by this build and not verified on the explorer")
    source, name = target.split(":")
    if record.get("ContractFileName") != source or record.get("ContractName") != name:
        raise MatchError(f"the explorer's verified source is not {target}")
    if beacon is None:
        return
    args = record.get("ConstructorArguments")
    if not isinstance(args, str) or not args.strip().removeprefix("0x"):
        raise MatchError("the explorer's BeaconProxy record has no constructor arguments")
    if not isinstance(creation, str) or not creation.strip().removeprefix("0x"):
        raise MatchError("the explorer supplied no creation input for the proxy")
    args = hex_code(args)
    if not hex_code(creation).endswith(args):
        raise MatchError("the explorer's constructor arguments do not end the proxy's creation input")
    if args[:64] != address(beacon)[2:].zfill(64):
        raise MatchError("BeaconProxy constructor beacon does not match its ERC1967 beacon storage slot")


def verification_environment(plan):
    env = dict(os.environ)
    # Environment defaults must not add another, unrecorded linker address.
    env.pop("DAPP_LIBRARIES", None)
    env.pop("FOUNDRY_LIBRARIES", None)
    values = dict(plan["metadata_settings"])
    values.update(optimizer=plan["optimizer_enabled"], optimizer_runs=plan["optimizer_runs"], via_ir=plan["via_ir"])
    for key, value in values.items():
        if not isinstance(value, (str, int, bool)):
            raise MatchError(f"unsupported config value: {key}")
        env["FOUNDRY_" + key.upper()] = str(value).lower() if isinstance(value, bool) else str(value)
    env["FOUNDRY_REMAPPINGS"] = "\n".join(plan["remappings"])
    return env


def validate_config(plan, config):
    expected = dict(plan["metadata_settings"])
    expected.update(optimizer=plan["optimizer_enabled"], optimizer_runs=plan["optimizer_runs"], via_ir=plan["via_ir"], evm_version=plan["evm_version"])
    for key, value in expected.items():
        if config.get(key) != value:
            raise MatchError(f"effective Foundry {key} differs from the matched artifact")
    if config.get("optimizer_details") not in (None, {}):
        raise MatchError("effective Foundry optimizer_details are unsupported")
    if sorted(config.get("remappings", [])) != sorted(plan["remappings"]):
        raise MatchError("effective Foundry remappings differ from the matched artifact")
    expected_libraries = sorted(f"{item['source']}:{item['address']}" for item in plan["libraries"])
    if sorted(config.get("libraries", [])) != expected_libraries:
        raise MatchError("effective Foundry libraries differ from the matched runtime")


def verify(plan, deployed_address, chain, verifier_url, encoded_args):
    env = verification_environment(plan)
    linker = [arg for item in plan["libraries"] for arg in ("--libraries", f"{item['source']}:{item['address']}")]
    config = json.loads(subprocess.check_output([
        "forge", "config", "--json", "--use", plan["compiler_version"].split("+")[0],
        "--evm-version", plan["evm_version"], *linker,
    ], env=env, text=True))
    validate_config(plan, config)
    command = ["forge", "verify-contract", address(deployed_address), plan["source"],
               "--chain", str(chain), "--verifier", "custom", "--verifier-url", verifier_url,
               "--verifier-api-key", "placeholder", *plan["forge_args"]]
    if encoded_args:
        command += ["--constructor-args", "0x" + hex_code(encoded_args)]
    subprocess.run(command, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    match = sub.add_parser("match")
    match.add_argument("--artifacts", required=True)
    match.add_argument("--runtime-file", required=True)
    match.add_argument("--address", required=True)
    match.add_argument("--candidate", action="append", required=True)
    ctor = sub.add_parser("constructor-args")
    ctor.add_argument("--plan-file", required=True)
    ctor.add_argument("--creation-file", required=True)
    beacon = sub.add_parser("check-beacon")
    beacon.add_argument("--plan-file", required=True)
    beacon.add_argument("--beacon", required=True)
    verified = sub.add_parser("check-verified")
    verified.add_argument("--record-file", required=True)
    verified.add_argument("--target", required=True)
    verified.add_argument("--beacon")
    verified.add_argument("--creation-file")
    submit = sub.add_parser("verify")
    submit.add_argument("--plan-file", required=True)
    submit.add_argument("--address", required=True)
    submit.add_argument("--chain", required=True)
    submit.add_argument("--verifier-url", required=True)
    submit.add_argument("--constructor-args", default="")
    args = parser.parse_args()
    try:
        if args.command == "match":
            result = find_artifact(args.artifacts, set(args.candidate), Path(args.runtime_file).read_text(), args.address)
            json.dump(result, sys.stdout)
            print()
        elif args.command == "constructor-args":
            print(constructor_args(json.loads(Path(args.plan_file).read_text()), Path(args.creation_file).read_text()))
        elif args.command == "check-beacon":
            check_beacon(json.loads(Path(args.plan_file).read_text()), args.beacon)
        elif args.command == "check-verified":
            creation = Path(args.creation_file).read_text() if args.creation_file else None
            check_verified(json.loads(Path(args.record_file).read_text()), args.target, args.beacon, creation)
        else:
            verify(json.loads(Path(args.plan_file).read_text()), args.address, args.chain, args.verifier_url, args.constructor_args)
    except (MatchError, KeyError, TypeError, json.JSONDecodeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
