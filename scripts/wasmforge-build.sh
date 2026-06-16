#!/usr/bin/env bash
# wasmforge-build.sh — container entrypoint for building wasmforge .NET PEs.
#
# Executes the complete pipeline inside the image:
#   1. Build wasmforge from /wasmforge (the mounted source tree)
#   2. Stage the target project from /src to /work/project
#   3. Sync bridge/helpers/stubs from wasmforge over the project
#   4. Apply wasmforge dotnet-patch (regenerates WfDirectPInvoke.props,
#      adds <Import> to Seatbelt.csproj, applies 44+ C# source rewrites)
#   5. Build the WASM via `dotnet publish -c Release -r wasi-wasm`
#   6. Forge the Windows PE via `wasmforge build --nativeaot --win32-apis`
#
# Output lands in /out/<project>.exe. The host bind-mounts /out to
# capture it.

set -euo pipefail

#─── Argument parsing ──────────────────────────────────────────────────
PROJECT_NAME="${1:-}"
case "$PROJECT_NAME" in
    -h|--help|"")
        cat <<EOF
wasmforge-build — build a .NET project as a wasmforge-forged Windows PE.

Usage:
  docker run --rm \\
    -v "\$PWD/wasmforge:/wasmforge:ro" \\
    -v "\$PWD/seatbelt-fresh:/src:ro" \\
    -v "\$PWD/out:/out" \\
    wasmforge/build:latest <project-name>

  Where <project-name> becomes the output filename (e.g. seatbelt → seatbelt.exe).

Mounts:
  /wasmforge  required  wasmforge source tree (Go module root)
  /src        required  .NET project root (contains .csproj)
  /out        required  output directory (writable)
  /cache      optional  ~/.nuget cache (named volume recommended)

Environment:
  WASMFORGE_DEBUG=1    enable bash xtrace + keep intermediate artifacts
  WASMFORGE_GHOST=...  forward to wasmforge build --ghost
  WASMFORGE_TAGS=...   forward to wasmforge build --tags

Versions inside this image:
EOF
        echo "  go:       $(go version 2>/dev/null | awk '{print $3}' || echo unavailable)"
        echo "  dotnet:   $(dotnet --version 2>/dev/null || echo unavailable)"
        echo "  wasi-sdk: $("$WASI_SDK_PATH/bin/clang" --version 2>/dev/null | awk '/wasi-sdk/ {print $3}' | head -1)"
        exit 0
        ;;
esac

if [[ "${WASMFORGE_DEBUG:-}" == "1" ]]; then
    set -x
fi

#─── Mount sanity checks ────────────────────────────────────────────────
require_mount() {
    local path="$1" label="$2"
    if [[ ! -d "$path" ]]; then
        echo "ERROR: $label not mounted at $path" >&2
        echo "  hint: docker run -v \"\$PWD/...:/$(basename "$path"):ro\" ..." >&2
        exit 2
    fi
}
require_mount /wasmforge "wasmforge source"
require_mount /src       "target project"
require_mount /out       "output directory"

#─── Cache mount (optional) ─────────────────────────────────────────────
if [[ -d /cache ]]; then
    export NUGET_PACKAGES=/cache/nuget
    export GOPATH=/cache/go
    mkdir -p "$NUGET_PACKAGES" "$GOPATH"
    echo "→ Using cache mount: NUGET=$NUGET_PACKAGES GOPATH=$GOPATH"
fi

#─── [1/6] Build wasmforge from /wasmforge ─────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [1/6] Building wasmforge from /wasmforge"
echo "════════════════════════════════════════════════════════════════════"
# Copy the source tree to a writable location so `make` can regenerate
# internal/build/build_assets.tar.gz without modifying the host's tree.
rm -rf /work/wasmforge
cp -r /wasmforge /work/wasmforge
cd /work/wasmforge
GOWORK=off go run ./cmd/gen-build-assets >&2
GOWORK=off go build -trimpath -o /usr/local/bin/wasmforge ./cmd/wasmforge
echo "→ wasmforge: $(/usr/local/bin/wasmforge version 2>&1 | head -1)"

#─── [2/6] Stage target project ────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [2/6] Staging project from /src"
echo "════════════════════════════════════════════════════════════════════"
rm -rf /work/project
cp -r /src /work/project
echo "→ Project staged at /work/project ($(find /work/project -name '*.csproj' | wc -l) .csproj files)"

#─── [3/6] Sync wasmforge artifacts (bridge / helpers / stubs) ─────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [2.5/6] Migrate legacy .NET Framework csproj (if needed)"
echo "════════════════════════════════════════════════════════════════════"
STAGED_CSPROJ=$(find /work/project -maxdepth 1 -name '*.csproj' ! -name '*.framework-backup' | head -1)
if [[ -n "$STAGED_CSPROJ" ]] && grep -q 'TargetFrameworkVersion' "$STAGED_CSPROJ"; then
    echo "→ Old-style .csproj detected — running dotnet-migrate"
    /usr/local/bin/wasmforge dotnet-migrate /work/project
else
    echo "→ SDK-style .csproj detected — skipping migration"
fi

echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [3/6] Syncing wasmforge artifacts into project"
echo "════════════════════════════════════════════════════════════════════"
PROJECT_DIR=/work/project

# bridge/*.c and *.h — overlay canonical wasmforge bridge over project's.
if [[ -d /work/wasmforge/dotnet/bridge ]]; then
    mkdir -p "$PROJECT_DIR/bridge"
    cp /work/wasmforge/dotnet/bridge/*.c "$PROJECT_DIR/bridge/" 2>/dev/null || true
    cp /work/wasmforge/dotnet/bridge/*.h "$PROJECT_DIR/bridge/" 2>/dev/null || true
    echo "→ bridge files: $(ls "$PROJECT_DIR/bridge/" | wc -l)"
fi

# WasmForge/*.cs — managed helpers used by the C# patcher rules.
if [[ -d /work/wasmforge/dotnet/helpers ]]; then
    mkdir -p "$PROJECT_DIR/WasmForge"
    cp /work/wasmforge/dotnet/helpers/*.cs "$PROJECT_DIR/WasmForge/" 2>/dev/null || true
    echo "→ helpers: $(ls "$PROJECT_DIR/WasmForge/"*.cs 2>/dev/null | wc -l)"
fi

# stubs/* — Only copy stub directories that the target csproj actually
# references via <ProjectReference Include="stubs/<Name>/..."> (to avoid
# duplicate-type CS0101 errors when the project already supplies its own
# hand-written stub for the same namespace, e.g. Rubeus lib/).
#
# Special case: if the csproj has a <PackageReference ... Include="System.Management">
# (SharpUp/Seatbelt pattern) we still copy the System.Management stub so it can
# override the BCL via a same-named stub project.
if [[ -d /work/wasmforge/dotnet/stubs ]]; then
    # Find the single .csproj in the staged project directory.
    CSPROJ_FILE=""
    for f in "$PROJECT_DIR"/*.csproj; do
        [[ -f "$f" ]] && CSPROJ_FILE="$f" && break
    done

    STUBS_SYNCED=0
    if [[ -n "$CSPROJ_FILE" ]]; then
        # Read the csproj once to avoid repeated file I/O in the loop.
        CSPROJ_TEXT=$(<"$CSPROJ_FILE")

        mkdir -p "$PROJECT_DIR/stubs"
        for stub_dir in /work/wasmforge/dotnet/stubs/*/; do
            stub_name=$(basename "$stub_dir")

            # Check for a matching ProjectReference in the csproj.
            copy_stub=false
            if echo "$CSPROJ_TEXT" | grep -qE "<ProjectReference[[:space:]]+Include=\"stubs/${stub_name}/"; then
                copy_stub=true
            fi

            # Special case: System.Management PackageReference also needs our stub.
            if [[ "$stub_name" == "System.Management" ]]; then
                if echo "$CSPROJ_TEXT" | grep -qE "<PackageReference[^>]+Include=\"System\.Management\""; then
                    copy_stub=true
                fi
            fi

            if [[ "$copy_stub" == "true" ]]; then
                mkdir -p "$PROJECT_DIR/stubs/$stub_name"
                cp -r "$stub_dir"* "$PROJECT_DIR/stubs/$stub_name/" 2>/dev/null || true
                STUBS_SYNCED=$(( STUBS_SYNCED + 1 ))
            fi
        done
    fi
    echo "→ stubs synced (referenced by csproj): $STUBS_SYNCED"
fi

#─── [4/6] Apply wasmforge dotnet-patch ────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [4/6] Applying wasmforge dotnet-patch"
echo "════════════════════════════════════════════════════════════════════"
/usr/local/bin/wasmforge dotnet-patch "$PROJECT_DIR"

#─── [5/6] Build WASM via dotnet publish ───────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [5/6] Building WASM (dotnet publish -c Release -r wasi-wasm)"
echo "════════════════════════════════════════════════════════════════════"
cd "$PROJECT_DIR"
dotnet publish -c Release -r wasi-wasm --nologo \
    > /tmp/dotnet-publish.log 2>&1 \
    || { echo "ERROR: dotnet publish failed. Errors:" >&2
         grep -iE "error" /tmp/dotnet-publish.log | tail -40 >&2
         echo "--- Last 20 lines: ---" >&2
         tail -20 /tmp/dotnet-publish.log >&2
         exit 3
       }
WASM=$(find bin/Release -type f -name '*.wasm' -path '*/wasi-wasm/native/*' | head -1)
if [[ -z "$WASM" || ! -f "$WASM" ]]; then
    echo "ERROR: dotnet publish completed but no .wasm produced" >&2
    grep -iE "warning|error" /tmp/dotnet-publish.log | tail -20 >&2
    exit 3
fi
echo "→ WASM: $WASM ($(stat -c%s "$WASM" 2>/dev/null || stat -f%z "$WASM") bytes)"

#─── [6/6] Forge Windows PE ────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo "  [6/6] Forging Windows PE via wasmforge build"
echo "════════════════════════════════════════════════════════════════════"
OUT_PE="/out/${PROJECT_NAME}.exe"

FORGE_ARGS=(build
    --wasm "$WASM"
    --nativeaot
    --win32-apis
    --no-sign
    -o "$OUT_PE"
)
if [[ -n "${WASMFORGE_GHOST:-}" ]]; then
    FORGE_ARGS+=(--ghost "$WASMFORGE_GHOST")
fi
if [[ -n "${WASMFORGE_TAGS:-}" ]]; then
    FORGE_ARGS+=(--tags "$WASMFORGE_TAGS")
fi

GOOS=windows GOARCH=amd64 /usr/local/bin/wasmforge "${FORGE_ARGS[@]}"

echo
echo "════════════════════════════════════════════════════════════════════"
echo "✓ /out/${PROJECT_NAME}.exe ($(stat -c%s "$OUT_PE" 2>/dev/null || stat -f%z "$OUT_PE") bytes)"
echo "════════════════════════════════════════════════════════════════════"

if [[ "${WASMFORGE_DEBUG:-}" != "1" ]]; then
    rm -rf /work/wasmforge /work/project /tmp/dotnet-publish.log
fi
