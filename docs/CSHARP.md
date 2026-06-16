# Compiling C# / .NET Projects

WasmForge compiles .NET C# projects through the NativeAOT-WASI toolchain, producing standalone Windows PE binaries that run .NET code inside WASM — no .NET runtime required on the target.

WasmForge auto-detects C# projects (`.csproj` files) and handles migration, patching, and building automatically.

## Quick Start

```bash
# Migrate and build a .NET Framework project (e.g., GhostPack tools)
git clone https://github.com/GhostPack/Seatbelt.git
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis -o seatbelt.exe Seatbelt/Seatbelt/
```

That single command runs the full pipeline (migrate → patch → WASM compile → PE forge → sign).

## Step-by-Step (Advanced)

If you want to inspect or customize intermediate steps:

```bash
# Step 1: Convert .NET Framework → .NET 10 NativeAOT-WASI project structure
./wasmforge dotnet-migrate Seatbelt/Seatbelt/

# Step 2: Apply NativeAOT-WASI compatibility patches (bridge files, helpers, stubs, source patches)
./wasmforge dotnet-patch Seatbelt/Seatbelt/

# Step 3: Build the WASM yourself (or skip and let `wasmforge build` do it)
cd Seatbelt/Seatbelt && dotnet publish -c Release -r wasi-wasm

# Step 4: Forge the PE from a pre-built WASM
GOOS=windows GOARCH=amd64 ./wasmforge build \
  --wasm /path/to/App.wasm \
  --nativeaot \
  --win32-apis \
  -o app.exe
```

## Build Prerequisites

If you build directly on the host (not recommended — see Docker workflow below), you need:

- .NET 10 SDK with NativeAOT-LLVM workload
- WASI SDK 24.0 (`WASI_SDK_PATH` environment variable set)
- `wasm-ld` linker (included in WASI SDK)

## Docker Build Environment (Recommended)

The Docker image bundles every C# build prerequisite — no host setup required. This is the preferred workflow for `.NET` projects and is the only path that's been validated across multiple machines.

```bash
# One-time: build the image
make docker-build

# Build a project (output lands in ./out/<project>.exe)
make docker-run DOCKER_SRC=/path/to/seatbelt-fresh DOCKER_PROJECT=seatbelt

# Or use docker run directly
docker run --rm \
  -v "$PWD:/wasmforge:ro" \
  -v "/path/to/seatbelt-fresh:/src:ro" \
  -v "$PWD/out:/out" \
  wasmforge/build:latest seatbelt
```

### What the Docker Image Does

- Mounts the wasmforge source tree at `/wasmforge` (read-only) and rebuilds wasmforge from it on every run, so your local edits are always used
- Mounts the target .NET project at `/src` and stages it to `/work/project` inside the container before patching
- Automatically syncs canonical `dotnet/bridge/*.c`, `dotnet/helpers/*.cs`, and `dotnet/stubs/System.Management/Stubs.cs` over the project's copies before patching — eliminating bridge/helper drift between machines
- Runs `wasmforge dotnet-patch` (auto-generates `Properties/WfDirectPInvoke.props`)
- Runs `dotnet publish -c Release -r wasi-wasm` to produce the WASM module
- Runs `wasmforge build --nativeaot --win32-apis` to forge the Windows PE

The image includes a `wasm-component-ld` wrapper that bypasses WASI Preview 2 component encoding (which would otherwise reject our raw `env.*` imports) and links pre-built pthread stubs for `libPortableRuntime.a`'s thread primitives.

Builds are reproducible from any host with Docker — no sync between machines needed.

## How the Pipeline Works

The `dotnet-migrate` and `dotnet-patch` commands together:

- Convert old-style `.csproj` to SDK-style `.NET 10` with `NativeAOT-LLVM`
- Inject WasmForge bridge files (C bridge for P/Invoke, C# helpers for LSA, crypto, networking)
- Add stub assemblies for unavailable namespaces (`DirectoryServices`, `IdentityModel.Tokens`, `CERTENROLLLib`, etc.)
- Apply 20+ C# source patches for NativeAOT-WASI compatibility
- Generate `nuget.config` pointing at the `NativeAOT-LLVM` experimental feed
- Emit `Properties/WfDirectPInvoke.props` for link-time DirectPInvoke wiring

The final binary is a single Windows PE that bundles the WASM module and runs the .NET program inside the WasmForge sandbox.

## Validated .NET Tools

WasmForge has been used to port substantial real-world C# tools to NativeAOT-WASI:

| Tool          | Commands Working | Notes                                             |
| ------------- | ---------------- | ------------------------------------------------- |
| **Seatbelt**  | 34/37            | Security enumeration — full pipeline PE           |
| **Rubeus**    | 9/10             | Kerberos: hash, asktgt, klist, triage, dump, purge|
| **SharpUp**   | Runs             | Privilege escalation checks                       |
| **SharpDPAPI**| Partial          | DPAPI triage (path normalization pending)         |
| **Certify**   | Starts           | AD CS tool (CommandLineParser reflection trimmed) |

## Writing New C# Capabilities

If you're authoring new C# code targeting the NativeAOT-WASI bridge (rather than porting an existing project), there are several patterns you must follow to avoid runtime crashes — see the in-tree skill at `.claude/skill-library/redteam/building-wasmforge-csharp-capabilities/SKILL.md` for the full rule set, including:

- Never use raw `[DllImport]` — go through the `WfHostBridge.Invoke` bridge
- Use `WfHost.HostAlloc` for OUT buffers that receive host pointers
- BCL replacements for trim-incompatible classes (e.g., `WindowsIdentity`, `ManagementObjectSearcher`)
- Two-call size-probe pattern for variable-length structs
- BOOL vs NTSTATUS vs LSTATUS return-code discipline
- NativeAOT trim preservation via `WfPreserve.rd.xml`

## Related Documentation

- [Main README](../README.md) — quick start and feature overview
- [GHOST-PROFILES.md](./GHOST-PROFILES.md) — anti-detection profiling for .NET PE outputs
- [MACOS.md](./MACOS.md) — Apple targets and macOS framework bridge
- [PARITY-HARNESS.md](./PARITY-HARNESS.md) — how we validate C# output parity against native binaries
