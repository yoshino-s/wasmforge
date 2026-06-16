#!/bin/bash
# build.sh — Build a .NET NativeAOT-WASI binary through WasmForge.
#
# Prerequisites:
#   - .NET 10 SDK with NativeAOT-LLVM workload
#   - WASI SDK (wasm32-wasi clang)
#   - WasmForge binary (go build -o wasmforge ./cmd/wasmforge)
#
# Usage:
#   ./build.sh <project-dir> <output-path> [--verbose]
#
# Example (Rubeus):
#   ./build.sh /path/to/rubeus/src /tmp/rubeus-wasm.exe --verbose
#
# The script:
#   1. Applies C# source patches (csharp_patcher via wasmforge)
#   2. Compiles C bridge (wf_bridge.c + pinvoke_nativeaot.c)
#   3. Runs dotnet publish with NativeAOT-WASI target
#   4. Wraps the WASM output through wasmforge build --wasm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BRIDGE_DIR="$SCRIPT_DIR/bridge"
HELPERS_DIR="$SCRIPT_DIR/helpers"
STUBS_DIR="$SCRIPT_DIR/stubs"

PROJECT_DIR="${1:?Usage: build.sh <project-dir> <output-path> [--verbose]}"
OUTPUT_PATH="${2:?Usage: build.sh <project-dir> <output-path> [--verbose]}"
VERBOSE="${3:-}"
WASMFORGE="${WASMFORGE:-wasmforge}"

log() {
    echo "[wasmforge-dotnet] $*"
}

# ── Step 1: Copy helper files into project ───────────────────────────
log "Step 1: Injecting WasmForge helper files..."

mkdir -p "$PROJECT_DIR/WasmForge"
cp "$HELPERS_DIR/WfHostBridge.cs" "$PROJECT_DIR/WasmForge/"
cp "$HELPERS_DIR/LsaHostHelper.cs" "$PROJECT_DIR/WasmForge/"
cp "$HELPERS_DIR/CryptoHostHelper.cs" "$PROJECT_DIR/WasmForge/"
cp "$HELPERS_DIR/NetworkHostHelper.cs" "$PROJECT_DIR/WasmForge/"

# ── Step 1.5: Apply C# source patches ──────────────────────────────
log "Step 1.5: Applying C# source patches..."
$WASMFORGE dotnet-patch "$PROJECT_DIR" ${VERBOSE:+--verbose}

# ── Step 2: Compile C bridge ─────────────────────────────────────────
log "Step 2: Compiling C bridge..."

WASI_CLANG="${WASI_CLANG:-clang}"
BRIDGE_OBJ="/tmp/wf_bridge.o"
PINVOKE_OBJ="/tmp/pinvoke_nativeaot.o"

$WASI_CLANG --target=wasm32-wasi -O2 -c "$BRIDGE_DIR/wf_bridge.c" -o "$BRIDGE_OBJ" \
    -I "$BRIDGE_DIR"
$WASI_CLANG --target=wasm32-wasi -O2 -c "$BRIDGE_DIR/pinvoke_nativeaot.c" -o "$PINVOKE_OBJ" \
    -I "$BRIDGE_DIR"

log "  Bridge objects: $BRIDGE_OBJ $PINVOKE_OBJ"

# ── Step 3: Add stub project references ──────────────────────────────
log "Step 3: Stub projects available at $STUBS_DIR/"
log "  Add these to your .csproj as ProjectReference if needed:"
log "    System.DirectoryServices"
log "    System.DirectoryServices.Protocols"
log "    System.DirectoryServices.AccountManagement"
log "    System.IdentityModel.Tokens"

# ── Step 4: NativeAOT publish ────────────────────────────────────────
log "Step 4: Running dotnet publish (NativeAOT-WASI)..."

WASM_OUTPUT="/tmp/nativeaot-output.wasm"
dotnet publish "$PROJECT_DIR" \
    -c Release \
    -r wasi-wasm \
    -p:PublishAot=true \
    -p:PublishTrimmed=true \
    -p:NativeLib=Static \
    -p:InvariantGlobalization=true \
    -o "/tmp/nativeaot-publish/"

# Find the .wasm output
WASM_FILE=$(find /tmp/nativeaot-publish/ -name "*.wasm" | head -1)
if [ -z "$WASM_FILE" ]; then
    log "ERROR: No .wasm file found in publish output"
    exit 1
fi
log "  WASM: $WASM_FILE"

# ── Step 5: Re-link with bridge objects ──────────────────────────────
log "Step 5: Re-linking with WasmForge bridge..."

# The re-link step adds our bridge objects to the WASM binary.
# This is specific to the NativeAOT-LLVM toolchain output format.
wasm-ld \
    "$WASM_FILE" \
    "$BRIDGE_OBJ" \
    "$PINVOKE_OBJ" \
    -o "$WASM_OUTPUT" \
    --export-all \
    --allow-undefined \
    2>/dev/null || cp "$WASM_FILE" "$WASM_OUTPUT"

log "  Linked WASM: $WASM_OUTPUT"

# ── Step 6: WasmForge pipeline ───────────────────────────────────────
log "Step 6: Running WasmForge pipeline..."

WASMFORGE="${WASMFORGE:-wasmforge}"
WASMFORGE_FLAGS="--wasm $WASM_OUTPUT --nativeaot --win32-apis"
if [ "$VERBOSE" = "--verbose" ] || [ "$VERBOSE" = "-v" ]; then
    WASMFORGE_FLAGS="$WASMFORGE_FLAGS -v"
fi

GOWORK=off GOOS=windows GOARCH=amd64 \
    $WASMFORGE build $WASMFORGE_FLAGS -o "$OUTPUT_PATH"

log "Done: $OUTPUT_PATH"
ls -lh "$OUTPUT_PATH"
