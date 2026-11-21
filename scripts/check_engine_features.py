#!/usr/bin/env python3
"""Feature unification must not silently widen the proved evaluator profile."""
import json
import subprocess
import sys

manifest = sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml"
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--locked", "--all-features", "--format-version=1", "--manifest-path", manifest,
]))
ids = {p["id"] for p in metadata["packages"] if p["name"] == "regorus"}
assert len(ids) == 1, "exactly one Regorus version is required"
node = next(n for n in metadata["resolve"]["nodes"] if n["id"] in ids)
assert set(node["features"]) == {"no_std"}, f"unapproved Regorus features: {node['features']}"
print("Regorus deterministic feature profile verified")
