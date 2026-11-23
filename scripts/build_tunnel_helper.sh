#!/usr/bin/env bash
# Build the pinned Chisel tunnel helper from the exact trusted-router-transport
# revision locked in Cargo.lock, so the helper always matches the Router code
# the shim links against. Usage: scripts/build_tunnel_helper.sh /abs/output
set -euo pipefail

out=${1:?usage: $0 /absolute/output/path}
[[ $out == /* ]] || { echo "output path must be absolute" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
rev=$(awk '
  $0 == "name = \"trusted-router-transport\"" { found = 1; next }
  found && /^source = / { sub(/.*#/, ""); sub(/"$/, ""); print; exit }
' "$root/Cargo.lock")
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "no locked trusted-router-transport revision" >&2; exit 1; }

src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git -C "$src" init -q
git -C "$src" fetch -q --depth 1 https://github.com/attestx/trusted-data-router "$rev"
git -C "$src" checkout -q --detach FETCH_HEAD
[[ $(git -C "$src" rev-parse HEAD) == "$rev" ]]
# go.mod is authoritative for the toolchain; setup-go defaults to GOTOOLCHAIN=local.
(cd "$src/tunnel/chisel" && GOTOOLCHAIN=auto CGO_ENABLED=0 go build -trimpath -o "$out" .)
echo "built trusted-router-tunnel at router $rev -> $out"
