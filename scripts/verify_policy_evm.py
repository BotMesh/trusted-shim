#!/usr/bin/env python3
"""Verify a remote-generated receipt with pinned upstream Solidity on local EVM.

Only copies small existing circuit artifacts; never initializes an SDK/prover.
All generated source, compiler outputs, broadcasts and reports stay outside git.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

REVISION = "c9988a098d92bc55a85ca9307c470d1f97be3337"
CHECKSUMS = {
    "Groth16Verifier.sol": "df6d436e9d9d97feef76dd80618f8e0b2ea8df2c1d9770df9dc73a38b7c0fb8b",
    "ZKMVerifierGroth16.sol": "92d0cc3e47724d1aecc18d9833d2441135e2803141b79fa0bb4e6669d68268cd",
    "groth16_vk.bin": "b3e14fe98042c3ff6f219172965bddd8dda586c556adac9b4acbd285e13d3cdb",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--circuits", required=True, type=Path, help="Ziren v2.0.0 Groth16 circuit directory")
    parser.add_argument("--ziren-source", required=True, type=Path, help="existing upstream git repository")
    parser.add_argument("--fixture", required=True, type=Path, help="export-policy-proof output")
    parser.add_argument("--work-dir", required=True, type=Path, help="new directory outside the repository")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    work, fixture = args.work_dir.resolve(), args.fixture.resolve()
    # Prevent diagnostic/proof files entering any tracked source checkout.
    for path in (work, fixture):
        parent = path.parent
        while not parent.exists():
            parent = parent.parent
        if subprocess.run(["git", "-C", str(parent), "rev-parse", "--show-toplevel"],
                          capture_output=True).returncode == 0 or path.is_relative_to(repo):
            parser.error("work directory and fixture must be outside a git checkout")
    data = json.loads(fixture.read_text())
    if data["verifierHash"] != "0x" + CHECKSUMS["groth16_vk.bin"]:
        parser.error("fixture does not use the pinned v2.0.0 circuit")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    vendor = work / "upstream"
    version = vendor / "v2.0.0"
    version.mkdir(parents=True)
    for name, digest in CHECKSUMS.items():
        content = (args.circuits / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError(f"pinned upstream artifact mismatch: {name}")
        if name.endswith(".sol"):
            (version / name).write_bytes(content)
    interface = subprocess.check_output(["git", "-C", str(args.ziren_source), "show",
        REVISION + ":crates/recursion/gnark-ffi/assets/IZKMVerifier.sol"])
    (vendor / "IZKMVerifier.sol").write_bytes(interface)
    config = (repo / "contracts/foundry.toml").read_text()
    for key in ("src", "test", "script"):
        config = config.replace(f'{key} = "{key}"', f'{key} = {json.dumps(str(repo / "contracts" / key))}')
    for key, value in {"out": str(work / "out"), "cache_path": str(work / "cache"),
                       "broadcast": str(work / "broadcast"),
                       "remappings": ["@ziren/=" + str(vendor) + "/"],
                       "allow_paths": [str(vendor)]}.items():
        config += f"{key} = {json.dumps(value)}\n"
    config += 'fs_permissions = [{access = "read", path = ' + json.dumps(str(fixture)) + '}]\n'
    config_path = work / "foundry.toml"
    config_path.write_text(config)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("FOUNDRY_", "DAPP_"))}
    env["TRUSTED_EVM_FIXTURE"] = str(fixture)

    def forge(*command):
        subprocess.run(["forge", *command, "--root", str(repo / "contracts"),
                        "--config-path", str(config_path)], cwd=repo / "contracts", env=env, check=True)

    forge("test", "-vv")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    rpc = f"http://127.0.0.1:{port}"

    def call(method):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
        request = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)["result"]

    # Anvil's ephemeral test keys are not printed or saved by the harness.
    with (work / "anvil.log").open("w") as log:
        node = subprocess.Popen(["anvil", "--silent", "--host", "127.0.0.1", "--port", str(port),
                                 "--chain-id", "31337"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    accounts = call("eth_accounts")
                    break
                except (OSError, urllib.error.URLError):
                    if node.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("isolated Anvil failed to start") from None
                    time.sleep(.1)
            forge("script", "script/VerifyPolicyProof.s.sol:VerifyPolicyProof", "--rpc-url", rpc,
                  "--unlocked", "--sender", accounts[0], "--broadcast")
            broadcast = json.loads((work / "broadcast/VerifyPolicyProof.s.sol/31337/run-latest.json").read_text())
            receipts = broadcast["receipts"]
            if len(receipts) != 3 or any(int(r["status"], 16) != 1 for r in receipts):
                raise RuntimeError("deployment/verification transaction did not succeed")
            from collections import Counter
            if Counter(t["transactionType"] for t in broadcast["transactions"]) != {"CREATE": 2, "CALL": 1}:
                raise RuntimeError("expected a mined record call, not only a simulated view call")
            if not any(r.get("logs") for r in receipts):
                raise RuntimeError("verification transaction did not emit its proof record")
            report = {"chain_id": 31337, "network": "isolated local Anvil", "ziren_revision": REVISION,
                "program_sha256": data["programSha256"], "verifier_hash": data["verifierHash"],
                "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                "transactions": [{"hash": r["transactionHash"], "gas_used": int(r["gasUsed"], 16)} for r in receipts]}
            (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            node.terminate()
            try:
                node.wait(timeout=5)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()


if __name__ == "__main__":
    main()
