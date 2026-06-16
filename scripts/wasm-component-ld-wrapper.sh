#!/usr/bin/env bash
# wasm-component-ld-wrapper.sh — bypass WASI P2 component encoding.
#
# NativeAOT-LLVM 10.0.0-rc1 invokes wasm-component-ld with --component-type
# pointing at WasiHttpWorld_component_type.wit. That tool tries to encode
# the WASM as a WASI Preview 2 component but rejects our raw `env` imports
# (mod_load, mod_invoke, fs_listdir, etc.) because they aren't declared in
# any .wit interface.
#
# This wrapper:
#   - strips --component-type / --adapt / --wasm-ld-path args
#   - links pre-built pthread stubs (libPortableRuntime references
#     pthread_mutex_lock etc. but NativeAOT-WASI is single-threaded)
#   - exports _start and __main_void so wasmtime/wazero can run it
#   - delegates to plain wasm-ld in the same WASI SDK directory
#
# Installed in the Docker image at $WASI_SDK_PATH/bin/wasm-component-ld
# in place of the original (which is preserved as wasm-component-ld.real).

set -euo pipefail

# Resolve wasm-ld from the same WASI SDK directory we're installed in.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
WASM_LD="${SCRIPT_DIR}/wasm-ld"

ARGS=()
SKIP_NEXT=0
for arg in "$@"; do
    if [[ "$SKIP_NEXT" == "1" ]]; then
        SKIP_NEXT=0
        continue
    fi
    case "$arg" in
        --component-type|--adapt|--wasm-ld-path)
            SKIP_NEXT=1
            continue
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

exec "$WASM_LD" "${ARGS[@]}" /tmp/pthread_stubs.o --export=_start --export=__main_void
