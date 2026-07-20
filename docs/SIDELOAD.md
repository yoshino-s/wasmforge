# Sliver Sideload output (`--sideload`)

This fork adds `wasmforge build --sideload`: forge **Runtime + one guest** into a shared library for Sliver Sideload.

Upstream: [praetorian-inc/wasmforge](https://github.com/praetorian-inc/wasmforge).  
Sliver contract: [Third Party Tools](https://sliver.sh/docs/?name=Third+Party+Tools).

## Platform behavior

| OS | Mechanism | Entry |
|----|-----------|-------|
| Windows | sRDI / inject into sacrificial process | Export `Run(char*)` via `-e Run` |
| Linux | `memfd` + `LD_PRELOAD` into sacrificial process (`/bin/ls` or `-p /bin/bash`) | `.init_array` constructor (EntryPoint ignored) |
| macOS | `DYLD_INSERT_LIBRARIES` | `constructor` attribute |

Linux/macOS libraries must:

1. Run work from constructor / `.init_array`
2. Read args from `LD_PARAMS`
3. `unsetenv("LD_PRELOAD")` / `DYLD_INSERT_LIBRARIES` before spawning children
4. `_exit(0)` when finished (implant waits for host process exit)

## Build

```bash
go build -o wasmforge ./cmd/wasmforge

WASMFORGE_RAW_BUILD=1 ./wasmforge build --sideload \
  -o dist/tool.so ./path/to/guest

# Windows
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 \
  WASMFORGE_RAW_BUILD=1 ./wasmforge build --sideload -o dist/tool.dll ./path/to/guest
```

## Operator

```text
# Linux
sideload -p /bin/bash -a "eva --full" ./tool.so

# Windows
sideload -e Run ./tool.dll "eva --full"
```

Do **not** Sideload the `wasmforge` CLI.

## Smoke

```bash
# Local LD_PRELOAD (Linux, Sliver-shaped)
LD_PRELOAD=./dist/hello.so LD_PARAMS='x' /bin/bash -c true
# expect guest stdout; host command should not run (_exit)

# Or: examples/sideload-hello + scripts/sideload-smoke.c (dlopen + Run, Windows-like)
```
