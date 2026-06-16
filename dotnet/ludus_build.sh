#!/bin/bash
# ludus_build.sh — Build a .NET NativeAOT-WASI binary on Ludus.
#
# This script runs on the Ludus build host where .NET SDK, WASI SDK,
# and Go are pre-installed. It is pushed and executed by the E2E tests.
#
# Usage: ludus_build.sh <project-dir> <output-exe>
#
# Prerequisites (pre-installed on Ludus):
#   - .NET 10 SDK at $HOME/.dotnet
#   - WASI SDK at $HOME/.wasi-sdk/wasi-sdk-24.0
#   - Go at $HOME/go-install/go/bin
#   - wasmforge binary at /tmp/wasmforge-bin

set -euo pipefail

PROJECT_DIR="${1:?Usage: ludus_build.sh <project-dir> <output-exe>}"
OUTPUT_EXE="${2:?Usage: ludus_build.sh <project-dir> <output-exe>}"

export PATH="$HOME/.dotnet:$HOME/go-install/go/bin:$PATH"
export WASI_SDK_PATH="$HOME/.wasi-sdk/wasi-sdk-24.0"
WASMFORGE="${WASMFORGE:-/tmp/wasmforge-bin}"
BRIDGE_DIR="$PROJECT_DIR/bridge"

log() { echo "[ludus-build] $*"; }

# Step 1: Compile C bridge objects if bridge dir exists
if [ -d "$BRIDGE_DIR" ]; then
    log "Compiling C bridge objects..."
    WASI_CLANG="$WASI_SDK_PATH/bin/clang"
    $WASI_CLANG --target=wasm32-wasi -O2 -c "$BRIDGE_DIR/wf_bridge.c" -o /tmp/wf_bridge.o -I "$BRIDGE_DIR"
    $WASI_CLANG --target=wasm32-wasi -O2 -c "$BRIDGE_DIR/pinvoke_nativeaot.c" -o /tmp/pinvoke_nativeaot.o -I "$BRIDGE_DIR"
    log "  Bridge objects compiled"
fi

# Step 1.5: Apply C# source patches via the wasmforge dotnet-patch
# subcommand. Without this step, NativeAOT-WASI binaries get unpatched
# Environment.UserName / WindowsIdentity.GetCurrent().Name / etc. reads
# that all return "Browser" (the WASI default) instead of the real host
# user — causing Seatbelt OSInfo, LocalUsers, UserRightAssignments and
# Rubeus klist to show fake identity data in production output.
# Idempotent: re-running on already-patched source is a no-op.
log "Applying C# source patches (dotnet-patch)..."
"$WASMFORGE" dotnet-patch "$PROJECT_DIR" 2>&1 | tail -3

# Step 2: dotnet publish
log "Running dotnet publish (NativeAOT-WASI)..."
dotnet publish "$PROJECT_DIR" -c Release -r wasi-wasm 2>&1 | tail -5

# Find the .wasm output
WASM_FILE=$(find "$PROJECT_DIR/bin/Release" -name "*.wasm" -path "*/native/*" | head -1)
if [ -z "$WASM_FILE" ]; then
    log "ERROR: No .wasm file found in publish output"
    exit 1
fi
log "  WASM: $WASM_FILE ($(stat -c%s "$WASM_FILE" 2>/dev/null || stat -f%z "$WASM_FILE") bytes)"

# Step 3: wasmforge build
log "Running wasmforge build..."
GOWORK=off GOOS=windows GOARCH=amd64 \
    "$WASMFORGE" build \
    --wasm "$WASM_FILE" \
    --nativeaot --win32-apis --no-sign \
    -v -o "$OUTPUT_EXE" 2>&1 | tail -5

log "Done: $OUTPUT_EXE"
ls -lh "$OUTPUT_EXE"
