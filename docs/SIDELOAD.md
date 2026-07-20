# Sliver Sideload output (`--sideload`)

This fork adds `wasmforge build --sideload`: forge **Runtime (wazero + host shims) + one guest** into a shared library (`.dll` / `.so` / `.dylib`) with a C-exported `Run` entrypoint for Sliver Sideload.

| Role | Artifact |
|------|----------|
| Build machine | `wasmforge` CLI (`./cmd/wasmforge`) — never Sideload this |
| Implant | forged `.dll` / `.so` with exported `Run` |

Upstream: [praetorian-inc/wasmforge](https://github.com/praetorian-inc/wasmforge). This repo: [yoshino-s/wasmforge](https://github.com/yoshino-s/wasmforge).

## Operator flow

```bash
go build -o wasmforge ./cmd/wasmforge

# Linux .so — build on a Linux host (needs a Linux C compiler for c-shared)
WASMFORGE_RAW_BUILD=1 ./wasmforge build --sideload \
  -o dist/tool.so ./path/to/guest

# Windows .dll (from macOS/Linux with mingw-w64)
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  GOOS=windows GOARCH=amd64 \
  WASMFORGE_RAW_BUILD=1 \
  ./wasmforge build --sideload \
  -o dist/tool.dll ./path/to/guest
```

On the implant:

| OS | Mechanism | Notes |
|----|-----------|-------|
| Windows | `dlopen` + export `Run(char*)` | Set Sideload `EntryPoint=Run` |
| Linux / macOS | `LD_PRELOAD` + `LD_PARAMS` | EntryPoint is **ignored**; the `.so` auto-runs from `init` when preloaded |

Host process for Linux is typically `/bin/bash` (stdout/stderr captured as Result).

New tool or guest version → forge again and redeploy. There is no empty generic runtime that loads arbitrary wasm later.

## Export contract

```c
void Run(char *args);  /* nullable; Linux falls back to LD_PARAMS */
```

`main` is empty (`c-shared` requirement). Errors go to stderr; the library does not call `os.Exit`.

## Smoke sample

[`examples/sideload-hello`](../examples/sideload-hello) — prints a line and exits.

```bash
mkdir -p dist
WASMFORGE_RAW_BUILD=1 ./wasmforge build --sideload -o dist/hello.dylib ./examples/sideload-hello
cc -O2 -o dist/sideload-smoke scripts/sideload-smoke.c
./dist/sideload-smoke ./dist/hello.dylib   # expect: hello from wasmforge sideload
```

Guest `proc_exit(0)` may print a debug stack to stderr; that is normal. `Run` still returns to the loader.
