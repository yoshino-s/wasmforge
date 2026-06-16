# Contributing to WasmForge

Thanks for your interest in WasmForge. This guide covers everything a new
contributor needs to start hacking: repository layout, prerequisites, build
and test workflows, and the conventions we follow for code, commits, and
PRs.

For the deeper "how this works" reference, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
For the catalogue of every build-time environment variable, see
[docs/ENVIRONMENT.md](docs/ENVIRONMENT.md).

## Repository layout

| Path | What lives here |
|---|---|
| `cmd/wasmforge/` | The user-facing CLI (`wasmforge build`, `run`, `clean`, etc.) |
| `cmd/gen-ghost-profile/` | Tool that turns any Go binary into a `gopclntab` ghost profile |
| `cmd/gen-build-assets/` | Generates the embedded `internal/build/build_assets.tar.gz` |
| `cmd/gen-ptrmasks/` | Regenerates Win32 pointer-mask tables from win32json metadata |
| `internal/build/` | The three-stage Go pipeline (GOROOT prep, WASM compile, host embed) and the R80 stealth recipe |
| `internal/hostmod/` | 90+ host functions wazero exposes to guest code (networking, OS proxies, Win32, darwin, NativeAOT) |
| `internal/runtime/` | wazero runtime configuration and execution |
| `internal/patch/` | Stdlib + C# source patchers (AST transforms applied before compile) |
| `internal/sysshim/windows/` | `golang.org/x/sys/windows` shim for `wasip1` targets |
| `internal/names/` | Per-build identifier randomization tables |
| `internal/platform/` | Platform-specific socket handling on host |
| `internal/devtools/` | Maintainer-only diagnostic binaries (pointer-mask audit, host-export lister, live-import probe, mono runner) |
| `dotnet/` | C bridge, P/Invoke implementations, C# helpers, and assembly stubs for NativeAOT-WASI |
| `guest/` | Guest-side libraries that ship inside the guest WASM (`win32`, `darwin`, `rawnet`) |
| `examples/` | Runnable example programs — start here if you're new |
| `testdata/` | Self-verifying test programs for each host-function group |
| `test/` | Integration tests and the parity harness (`//go:build integration` gated) |
| `docs/` | User docs and the architecture reference |
| `docs/internals/` | Contributor-targeted reference docs (AST patcher, host API contract, parity harness) |
| `wazero/` | Pinned + lightly forked wazero runtime (per-build identifier randomization) |

## Prerequisites

* **Go 1.25** or later. The host binary, all `cmd/*` targets, and the
  patched GOROOT all use the same Go toolchain.
* **Make** (any reasonably modern GNU/BSD make).
* If you're going to touch the C# / .NET path:
  * **.NET 10 SDK** (preview / RC channel as of writing — see
    `Dockerfile.build` for the exact `--quality` setting),
  * **NativeAOT-LLVM** workload (`dotnet workload install wasi-experimental`),
  * **WASI SDK 24** (`WASI_SDK_PATH` env var),
  * the `wasm-component-ld` wrapper at `scripts/wasm-component-ld-wrapper.sh`.

  For a hands-off setup, use the Docker container described in
  `docs/CSHARP.md` — it bundles every C# prerequisite and pins versions.

WasmForge has been developed and tested on macOS (Intel + Apple Silicon)
and Linux x64. Cross-compiled output runs on Windows x64 and macOS, and the
toolchain itself runs on Linux/macOS hosts.

## Building wasmforge itself

Two paths, with different trade-offs:

```bash
# Quick: compile the CLI directly. Fine for development against the local
# tree. Uses live source under internal/hostmod/, internal/runtime/, etc.
go build -o wasmforge ./cmd/wasmforge

# Canonical: regenerate the embedded build_assets.tar.gz first, then build.
# This is what `make build` does. The archive snapshots internal/hostmod,
# internal/runtime, internal/names, and the wazero fork — wasmforge embeds
# it via //go:embed so distribution-mode builds (binary shipped without
# source tree) can still compile their host stage.
make build
```

If you modify anything under `internal/hostmod/`, `internal/runtime/`,
`internal/names/`, or `wazero/`, you **must** regenerate the archive
(`make generate` or `make build`) before distribution-mode builds will
reflect your changes. Development-mode builds (with the local source tree
present) are unaffected.

## Running tests

The repository ships several test surfaces; they have different prerequisites.

### Unit tests (no external deps)

```bash
go vet ./...
go test ./...
```

Unit tests for the host module, build pipeline, patchers, and devtools all
run from a fresh clone with no environment setup.

### `testdata/` end-to-end programs

Each program under `testdata/` is a self-verifying executable that prints
`PASS:` / `FAIL:` lines. Run the ones touching the area you changed:

```bash
./wasmforge build -o /tmp/test ./testdata/echo_tcp && /tmp/test
GOOS=windows GOARCH=amd64 ./wasmforge build -o /tmp/test.exe ./testdata/win32_registry
# (then run /tmp/test.exe on a Windows host)
```

### Integration + parity tests

The `test/` tree is its own Go module and is gated by
`//go:build integration` tags. Running it requires a target Windows host
that your test runner can reach. See `docs/internals/PARITY-HARNESS.md`.

Target configuration uses `WASMFORGE_PARITY_*` env vars (`_DOMAIN`, `_DC`,
`_DC_IP`, `_CA`, `_USER`). Defaults match the [GOAD (Game of Active
Directory)](https://github.com/Orange-Cyberdefense/GOAD) topology stood
up under [Ludus](https://gitlab.com/badsectorlabs/ludus) — see
`test/parity/internal/lab/lab.go` for the full list (`sevenkingdoms.local`,
`dc01.sevenkingdoms.local`, `10.3.10.10`, etc.). Tests SKIP cleanly when
the target is unreachable, so vetting on a machine with no lab works.

```bash
cd test
go vet ./...
WASMFORGE_PARITY_DOMAIN=corp.example.com \
WASMFORGE_PARITY_DC=dc01.corp.example.com \
go test -tags integration ./parity/...
```

## Adding a new host function

Host functions are how guest WebAssembly code reaches host OS APIs. The
pattern is the same for networking, OS proxies, Win32, darwin, and
NativeAOT functions.

1. Add the implementation in `internal/hostmod/`. Use platform-specific
   files (`_windows.go`, `_darwin.go`, `_stub.go`) when the function maps
   to a syscall not portable across hosts.
2. Register the function in the relevant `register*Functions()` body in
   `module.go` (or `win32.go` / `darwin.go` for platform-scoped registries).
3. Add no-op or `ENOSYS` stubs for platforms that don't implement it. The
   build tags must keep the package compilable on every supported host.
4. Add the anonymized export name in `internal/names/names.go`. Host
   exports are renamed per build to defeat static signature matching.
5. Add the `//go:wasmimport env <anonymized_name>` declaration in the
   matching `guest/*/imports.go`. The guest sees only the anonymized name.
6. Wrap the raw import in a high-level Go API in the guest package so
   guest code never deals with raw `uintptr` or untyped errnos.
7. Add a `testdata/` program exercising the new function end-to-end.

For the contract-test side (every registered export must appear in the
`host-api-contract`), see `docs/internals/HOST-API-CONTRACT.md` —
`internal/hostmod/contract_test.go` enforces it in CI.

## Adding a new guest library

1. Create the package under `guest/`.
2. Add `imports.go` containing `//go:wasmimport env <anonymized_name>`
   declarations. Build-tag every file `//go:build wasip1`.
3. Add a high-level Go API that wraps the raw imports with sensible
   types, errors, and lifecycle (Open/Close, etc.).
4. Document the new library in `docs/ARCHITECTURE.md` under "Guest
   Libraries" and link a `testdata/` program demonstrating it.

## Compiling complex Go projects: the wasip1 stub pattern

When you compile a third-party Go project for `wasip1`, the compiler's
`relaxWindowsBuildConstraints` pass rewrites every `!windows` constraint to
`!windows && !wasip1`. Files with platform-specific implementations under
`_generic.go` / `_other.go` get excluded — and if anything references
their exported symbols, the build fails with "undefined" errors.

The fix is to provide `_wasip1.go` stub files:

1. Read the build error and identify the undefined function or type.
2. Locate the `_generic.go` / `_other.go` file that normally defines it.
3. Create a `foo_wasip1.go` sibling with stub implementations. Returning
   empty values or `ErrNotSupported` is usually fine — the goal is to
   satisfy the linker, not to functionally implement the platform API.
4. The compiler's collision handler will reconcile the new `_wasip1.go`
   file with any existing `_windows.go` / `_generic.go` siblings
   automatically.

## Code style

* `go fmt` and `go vet` must pass cleanly. CI rejects PRs that don't.
* Comments should explain **why** — the non-obvious constraint, the
  surprising design choice, the workaround for a specific upstream bug.
  Don't narrate **what** the code does when the code is self-explanatory.
* Avoid backwards-compatibility shims for unreleased code. We're pre-1.0;
  breaking changes are fine as long as they're called out in the PR.
* Don't add `-s -w` or `-trimpath` to the embedder. WasmForge intentionally
  preserves Go debug info — stripping has historically increased
  detection rates from ML-based classifiers that flag stripped Go binaries
  as suspicious by default. See `docs/ARCHITECTURE.md` "WASM Embedding and
  AV Evasion" for the longer reasoning.

## Commits and pull requests

* **Conventional Commits**: prefix the subject line with `feat:`, `fix:`,
  `chore:`, `docs:`, `refactor:`, `test:`. The body should focus on the
  **why** — what motivated the change, what alternative was rejected,
  what the reviewer should pay attention to.
* **One concern per PR.** Mechanical renames and behavior changes go in
  separate PRs.
* **Test plan in the PR description.** Use the template at
  `.github/PULL_REQUEST_TEMPLATE.md`. Check the boxes that apply; explain
  what you did for the rest.
* **Don't commit submodule pointer updates** for `wazero/` unless you
  explicitly intend to bump the fork. Accidental pointer bumps are the
  most common source of PR conflicts.
* **CI must pass before merge.** `go vet`, `go test`, build matrix.

## Security

If you find a security issue (memory safety, sandbox escape, supply-chain
risk in the build pipeline), please don't open a public issue. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
Treat one another with respect. Disagreement is fine; harassment isn't.

## Questions

Open a [GitHub Discussion](https://github.com/praetorian-inc/wasmforge/discussions)
for design questions, integration help, or anything that isn't a bug or a
concrete feature request. Bug reports and feature requests go through the
Issue templates.
