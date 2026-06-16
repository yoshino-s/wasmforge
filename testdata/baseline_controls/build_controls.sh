#!/bin/bash
# Build baseline control binaries for VT comparison testing.
#
# Produces two sets of binaries:
#   out/vanilla/   — standard `go build` (no wasmforge)
#   out/wasmforge/ — compiled through wasmforge pipeline
#
# Usage:
#   cd testdata/baseline_controls
#   ./build_controls.sh [wasmforge-binary-path]
#
# The vanilla set serves as a control group — any VT detections on these
# binaries are from the Go PE structure itself, not wasmforge.

set -euo pipefail

WASMFORGE="${1:-wasmforge}"
OUTDIR="${2:-out}"
GOOS_TARGET="${GOOS_TARGET:-windows}"
GOARCH_TARGET="${GOARCH_TARGET:-amd64}"

VANILLA_DIR="$OUTDIR/vanilla"
WF_DIR="$OUTDIR/wasmforge"

mkdir -p "$VANILLA_DIR" "$WF_DIR"

PROGRAMS=(
    hello_world
    http_server
    file_util
    json_processor
    tcp_client
    crypto_hash
    concurrent_workers
    kv_store
    dns_resolver
    sysinfo
)

echo "=== Building ${#PROGRAMS[@]} baseline controls ==="
echo "Target: ${GOOS_TARGET}/${GOARCH_TARGET}"
echo ""

# Vanilla builds (standard go build, cross-compiled)
echo "--- Vanilla (go build -trimpath) ---"
for prog in "${PROGRAMS[@]}"; do
    GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" go build -trimpath \
        -o "$VANILLA_DIR/${prog}.exe" "./${prog}" 2>&1
    size=$(ls -lh "$VANILLA_DIR/${prog}.exe" | awk '{print $5}')
    echo "  ${prog}.exe: $size"
done

# WasmForge builds (if wasmforge binary is available)
if command -v "$WASMFORGE" &>/dev/null || [ -f "$WASMFORGE" ]; then
    echo ""
    echo "--- WasmForge (wasmforge build --win32-apis) ---"
    for prog in "${PROGRAMS[@]}"; do
        GOWORK=off GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" \
            "$WASMFORGE" build --win32-apis \
            -o "$WF_DIR/${prog}.exe" "./${prog}" 2>/dev/null
        if [ -f "$WF_DIR/${prog}.exe" ]; then
            size=$(ls -lh "$WF_DIR/${prog}.exe" | awk '{print $5}')
            echo "  ${prog}.exe: $size"
        else
            echo "  ${prog}.exe: FAILED (retry with -v for details)"
        fi
    done
else
    echo ""
    echo "--- Skipping WasmForge builds ($WASMFORGE not found) ---"
    echo "  Run: ./build_controls.sh /path/to/wasmforge"
fi

echo ""
echo "=== Summary ==="
echo "Vanilla: $(ls "$VANILLA_DIR"/*.exe 2>/dev/null | wc -l | tr -d ' ') binaries in $VANILLA_DIR/"
echo "WasmForge: $(ls "$WF_DIR"/*.exe 2>/dev/null | wc -l | tr -d ' ') binaries in $WF_DIR/"
echo ""
echo "Upload to VT for comparison:"
echo "  Vanilla controls establish the Go PE baseline detection rate."
echo "  WasmForge builds show incremental detection from wasmforge code."
echo "  Any detection present in BOTH sets is from Go PE structure, not wasmforge."
