#!/usr/bin/env bash
# Extract the raw Rubeus.wasm from the wasmforge build pipeline for direct
# inspection with wasm-objdump / wasm2wat / wasmtime --gdb-stub.
#
# The default wasmforge-build.sh deletes /work/project at script exit, taking
# the intermediate .wasm with it. This script patches out the cleanup step
# so we can copy the .wasm out before the container exits.
#
# Usage:
#   ./extract-rubeus-wasm.sh [path-to-rubeus-source] [output-wasm-path]
#
# Defaults: /tmp/rubeus-fresh source → /tmp/rubeus-extracted.wasm
#
# Then inspect with:
#   wasm-objdump -h /tmp/rubeus-extracted.wasm
#   wasm-objdump -x -j Import /tmp/rubeus-extracted.wasm
#   wasm-objdump -x -j Export /tmp/rubeus-extracted.wasm
#   wasm-objdump -d /tmp/rubeus-extracted.wasm  # disassemble

set -euo pipefail

SRC="${1:-/tmp/rubeus-fresh}"
OUT="${2:-/tmp/rubeus-extracted.wasm}"

WASMFORGE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_PATCHED="$(mktemp -t wasmforge-build-keepwasm.XXXXXX.sh)"
trap "rm -f $SCRIPT_PATCHED" EXIT

# Strip the script's final cleanup line.
sed 's|rm -rf /work/wasmforge /work/project /tmp/dotnet-publish.log||' \
    "$WASMFORGE_ROOT/scripts/wasmforge-build.sh" > "$SCRIPT_PATCHED"

docker run --rm \
    -v "$WASMFORGE_ROOT:/wasmforge:ro" \
    -v "$SRC:/src:ro" \
    -v "/tmp:/host:rw" \
    -v "$SCRIPT_PATCHED:/usr/local/bin/wasmforge-build.sh:ro" \
    --entrypoint bash \
    wasmforge/build:latest \
    -c "bash /usr/local/bin/wasmforge-build.sh rubeus 2>&1 | tail -3; \
        find /work/project -name '*.wasm' -path '*native*' \
            -exec cp {} /host/$(basename "$OUT") \; ; \
        ls -la /host/$(basename "$OUT")"

echo "✓ Extracted: $OUT"
