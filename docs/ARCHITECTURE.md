# WasmForge Architecture

This document describes the internals of the WasmForge toolchain: how guest
code reaches the host operating system, how the build pipeline produces a
single native binary from Go or C# source, and the design decisions behind
the runtime. Read this if you are extending WasmForge, debugging a guest
program that does not behave like the native equivalent, or porting a new
class of target program to the sandbox.

For a higher-level pitch and quickstart, see [`README.md`](../README.md).
For contributor workflow (how to build, test, and send a PR), see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Table of Contents

- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Three-Stage Go Build Pipeline](#three-stage-go-build-pipeline)
- [NativeAOT-WASI .NET Build Pipeline](#nativeaot-wasi-net-build-pipeline)
- [Host Module Layout](#host-module-layout)
- [Key Design Decisions](#key-design-decisions)
- [Guest Libraries](#guest-libraries)
- [Host Functions Reference](#host-functions-reference)
- [WASM Embedding and AV Evasion](#wasm-embedding-and-av-evasion)
- [Extension API Callbacks](#extension-api-callbacks)

## Overview

WasmForge compiles Go and C# programs to WebAssembly and packages them as
single native binaries. The resulting executables sandbox guest code inside
a WASM runtime (a per-build fork of [wazero](https://github.com/tetratelabs/wazero))
while exposing transparent access to networking, raw sockets, the Win32 API,
and macOS frameworks.

The runtime presents the guest with a normal-looking environment: standard
`net/http`, `os/exec`, `syscall.SyscallN`, COM mirroring, macOS framework
`dlopen`/`dlsym`, and `execute-assembly` for hosted CLR all work without
guest code modifications. The bridge between sandbox and host is the host
module — a wazero module published under the `env` namespace that exposes
roughly ninety functions.

WasmForge supports three guest sources:

| Source | Path | Output |
|--------|------|--------|
| Standard Go | `./examples/tcpscanner` | Native PE / Mach-O |
| .NET Framework C# | Auto-migrated to .NET 10 + NativeAOT-WASI | Native PE |
| Pre-compiled `.wasm` | Any WASI P1 module + optional NativeAOT-WASI | Native PE |

The output is always one statically-linked binary with no external runtime
dependency. Windows targets are Authenticode-signed by default. Every build
is structurally unique: WASM opcodes are permuted, custom magic bytes
randomize the WASM header, identifiers are renamed, PE imports are
shuffled, and gopclntab symbols can be camouflaged to match real Go
binaries (Traefik, Caddy, Terraform, etc.).

## High-Level Architecture

```
+---------------- WASM Guest (wasip1 / NativeAOT-WASI) ---------------+
|                                                                     |
|  Standard Go    Standard .NET    guest/rawnet   guest/win32         |
|  (net, exec,    (Win32 P/Invoke  guest/darwin                       |
|   syscall, ...)  via bridge)                                        |
|                                                                     |
+----------- go:wasmimport ABI / NativeAOT mod_invoke ----------------+
                              |
+--------------- Host Module (env namespace) -------------------------+
|                                                                     |
|  90+ host functions:                                                |
|   * Networking (TCP/UDP/raw, DNS)                                   |
|   * OS proxies (hostname, exec, pipe, net interfaces)               |
|   * Win32 (LoadLibrary, SyscallN, registry, file, process, COM)     |
|   * macOS frameworks (dlopen/dlsym + assembly trampolines)          |
|   * NativeAOT helpers (SDDL, WMI, LSA Kerberos, dir/file)           |
|                                                                     |
+----------- wazero (custom VM: permuted opcodes/magic) --------------+
                              |
              OS Kernel / Windows APIs / macOS Frameworks
```

The host module is the bridge. All guest networking, file I/O, process
control, registry access, COM dispatch, and framework calls flow through
its functions. On platforms where a host function does not apply (for
example, `win32_*` on Linux), the function is replaced with an ENOSYS
stub at compile time via build tags.

## Three-Stage Go Build Pipeline

Go projects are compiled in three stages. The pipeline is orchestrated by
`internal/build/pipeline.go`.

### Stage 1: Prepare Patched GOROOT

Implemented in `internal/build/goroot.go`.

WasmForge cannot use the system Go's stdlib as-is for `GOOS=wasip1`. The
stdlib disables most of `net/`, `syscall/`, and `os/exec`, returning
`ENOSYS` for syscalls that the WASI runtime cannot satisfy. The patched
GOROOT replaces those stubs with implementations that route through the
host module's syscall surface.

The patched GOROOT is built by symlinking immutable directories from the
real GOROOT (compiler binaries, headers, `cmd/`) and overlaying patched
copies of `src/syscall/` and `src/net/`. Patches live under
`internal/patch/files/` and are embedded into the wasmforge binary.

The result is cached per `(Go version, wasmforge version, flag set)` at
`~/.wasmforge/cache/<hash>/`. Subsequent builds with the same parameters
reuse the cache.

**Gotcha:** the patched GOROOT's `go` binary must be invoked directly with
`GOTOOLCHAIN=local`. The system `go` ignores `GOROOT` and delegates to the
module cache, which would build with the unpatched stdlib.

### Stage 2: Compile Go to WASM

Implemented in `internal/build/compiler.go`.

The guest is compiled with `GOOS=wasip1 GOARCH=wasm` using the patched
GOROOT. The compiler also performs two key transformations:

1. **Build-constraint relaxation.** Files with `_windows.go` suffixes have
   an implicit `GOOS=windows` constraint that excludes them from wasip1
   builds. WasmForge needs many of these files. The compiler rewrites
   `//go:build` headers (adding `|| wasip1` where appropriate) and renames
   `foo_windows.go` to `foo.go` where doing so resolves cleanly. Collisions
   are handled by a small set of rules — see
   [`_windows.go` build constraint relaxation](#_windowsgo-build-constraint-relaxation).
2. **Sysshim injection.** Guest `go.mod` files that depend on
   `golang.org/x/sys` are automatically given a `replace` directive
   pointing at WasmForge's vendored sysshim. The sysshim provides the
   `golang.org/x/sys/windows` type and constant surface on wasip1 so that
   guest code calling `windows.RegOpenKeyEx` (and similar) compiles cleanly.

The compiler also performs per-build identifier randomization on the
patched stdlib (`randomizeGOROOTNetFunctions`) to prevent YARA matching on
gopclntab entries.

### Stage 3: Generate Host Binary

Implemented in `internal/build/embedder.go`.

The generated `.wasm` file is XOR-encoded (key derived from
`SHA256(plaintext)`) and embedded into a generated `main.go` template. The
template instantiates wazero, registers host functions, and runs the WASM
module. The final binary is compiled with the native Go toolchain for the
target `GOOS`/`GOARCH`.

Windows targets receive additional post-processing:

- PE VERSIONINFO and an application manifest are embedded (`winres.go`).
- The import directory is enriched with non-functional decoy imports.
- An optional manifest of payload chunks distributes the encoded WASM
  across PE debug sections (default in the R80 stealth recipe).
- Authenticode signing applies a self-signed cert or, with `--sign <domain>`,
  a spoofed TLS certificate fetched from the domain and re-signed by
  `osslsigncode`.

All optional behaviors are governed by environment variables, documented
in [`docs/ENVIRONMENT.md`](ENVIRONMENT.md).

## NativeAOT-WASI .NET Build Pipeline

For .NET programs, the Go compilation stage is skipped and `.NET → WASM`
compilation is done by NativeAOT-LLVM + WASI SDK. The result is fed to
Stage 3 of the Go pipeline.

```
C# Source
  │
  ├─ dotnet/bridge/wf_bridge.{c,h}        Universal WASM↔host C bridge
  ├─ dotnet/bridge/pinvoke_nativeaot.c    73 P/Invoke implementations
  ├─ dotnet/helpers/WfHostBridge.cs       C# P/Invoke declarations
  ├─ dotnet/helpers/LsaHostHelper.cs      High-level LSA Kerberos API
  └─ dotnet/stubs/                        Assembly stubs (DirectoryServices, etc.)
  │
  ▼ dotnet publish -r wasi-wasm (NativeAOT-LLVM + WASI SDK + pthread stubs)
  │
NativeAOT-WASI module
  │
  ├─ env imports (4 functions):           Anonymized WasmForge host functions
  │   mod_invoke   →  win32_syscalln
  │   mod_load     →  win32_load_library
  │   mod_resolve  →  win32_get_proc_address
  │   lsa_kerbop   →  win32_lsa_kerberos_op
  │
  ├─ WASI P1 imports                      Standard WASI (fd_read, fd_write, ...)
  └─ WASI P2 stub modules                 No-op stubs (wasip2_stubs.go)
  │
  ▼ wasmforge build --wasm App.wasm
  │
Host Binary (polymorphic PE)
```

**End-to-end flow:** `dotnet publish -r wasi-wasm` produces a wasm32
NativeAOT module. WasmForge's `--wasm` flag feeds that module directly to
Stage 3, skipping Go compilation. NativeAOT-specific host functions (SDDL,
WMI, LSA, atomic directory listing) are registered when the `nativeaot`
build tag is set, which the CLI does automatically whenever `--wasm` is
passed.

### Build Prerequisites

- .NET 10 SDK with the NativeAOT-LLVM workload
  (`dotnet workload install wasi-experimental`)
- WASI SDK 24.0 (`WASI_SDK_PATH=$HOME/.wasi-sdk/wasi-sdk-24.0`)
- `wasm-component-ld` wrapper that strips the WASI P2 component encoding
  and links pthread stubs (provided in `scripts/`)
- Go 1.25.3 for the host binary

The recommended way to get all four in a consistent environment is the
bundled Docker image — see [`docs/CSHARP.md`](CSHARP.md) for the
container-based workflow.

### NativeAOT-specific host functions

| Function | Purpose |
|----------|---------|
| `win32_get_sddl` | `GetNamedSecurityInfoW + ConvertToSddl` as a single atomic call |
| `win32_lsa_kerberos_op` | Atomic LSA Kerberos operations (SYSTEM impersonation + LSA on a COM STA thread) |
| `os_list_dir` | Host directory listing (bypasses WASI path mapping) |
| `os_file_exists` | Host file existence check (bypasses WASI) |

The `win32_lsa_kerberos_op` function supports four operations:

| Operation | Mechanism | Purpose |
|-----------|-----------|---------|
| `enumerate_tickets` | `KERB_QUERY_TKT_CACHE_EX2_MESSAGE` | List cached tickets (klist, triage) |
| `retrieve_ticket` | `KERB_RETRIEVE_TKT_REQUEST` with `KERB_RETRIEVE_TICKET_AS_KERB_CRED` | Dump a single ticket as base64 `.kirbi` |
| `purge_tickets` | `KERB_PURGE_TKT_CACHE_REQUEST` | Remove cached tickets |
| `submit_ticket` | `KERB_SUBMIT_TKT_REQUEST` with base64 `.kirbi` input | Inject a ticket (`ptt`) |

### C# Source Patcher

Before NativeAOT compilation, `internal/patch/csharp_patcher.go` applies
~16 string-replacement transforms to the C# source. These fix patterns
that compile under .NET Framework but crash on NativeAOT-WASI:

- `Marshal.PtrToStringUni(x).Trim()` → null-guarded equivalent
- `WindowsIdentity.GetCurrent().Name` → try/catch → `Environment.UserName`
- `new SecurityIdentifier(ptr)` → `ConvertSidToStringSid` bridge call
- `AllocCoTaskMem` → `AllocHGlobal` (CoTaskMem is unsupported on NativeAOT-WASI)

The transform list is data-driven; new patterns can be added without
changing the runner.

### wasm32 vs x64 Bridge

NativeAOT-WASI compiles to wasm32 (4-byte pointers) but calls x64 Windows
APIs (8-byte pointers). The C bridge in `dotnet/bridge/wf_bridge.c`
(`wf_call()`) saves and restores 4 bytes after every WASM pointer
argument to prevent x64 APIs from overwriting adjacent stack data. The
same bridge applies pointer translation, so guest code can pass WASM
linear-memory addresses unchanged.

### WASI P2 Networking Limitation

NativeAOT-WASI uses WASI Preview 2 sockets for all networking instead of
Winsock. Because P2 stubs in WasmForge are currently no-ops, any guest
operation that needs an outbound TCP or LDAP connection from the .NET
side will hang silently. Two paths forward:

1. Route P2 socket imports through the existing `sock_*` host functions.
2. Provide dedicated bridge functions for the small set of network ops
   that real-world guests need (Kerberos AS/TGS, LDAP bind).

The bridge-function path is the one currently used for LSA Kerberos
operations, which is why offline Kerberos commands work while
network-issued ones do not.

## Host Module Layout

The host module is implemented in `internal/hostmod/`. Files are grouped
by purpose; the prefix indicates the platform constraint.

### Always available (`internal/hostmod/`)

| File | Purpose |
|------|---------|
| `module.go` | Module registration, errno constants, common helpers |
| `memory.go` | WASM linear-memory read/write helpers |
| `fdtable.go` | Guest FD ↔ host FD mapping (base = 10000) |
| `fd_unix.go` / `fd_windows.go` | `osFDType` alias (`int` on Unix, `syscall.Handle` on Windows) |
| `tcp.go`, `udp.go`, `io.go` | Socket lifecycle and I/O |
| `raw.go` | Raw sockets (`SOCK_RAW`) |
| `dns.go` | DNS resolution (`getaddrinfo`) |
| `addr.go`, `sockopt.go` | Address conversion and socket options |
| `os_host.go` | OS proxies: hostname, getwd, chdir, current user |
| `os_exec.go` | Exec proxy: `CreateProcess` + output capture |
| `net_iface.go` | Network interface enumeration |
| `pipe.go`, `pipe_table.go` | Host pipe creation for `os.Pipe()` |

### Pointer-translation infrastructure

| File | Purpose |
|------|---------|
| `mirror.go` | Mirror table (host → WASM pointer mirroring) |
| `mirror_windows.go` | `VirtualQuery`-based mirror validation, MEM_IMAGE filter |
| `mirror_stub.go` | Mirror stubs for non-Windows |
| `shadow_map.go` | Shadow-memory tracking for VirtualAlloc-style host regions |

### Windows (`win32_*`, built with `//go:build windows`)

| File | Purpose |
|------|---------|
| `win32.go` | Win32 function registration |
| `win32_handle.go` | Win32 handle table (base = 20000) |
| `win32_windows_dll.go` | `LoadLibrary`, `Call`, `SyscallN` + pointer translation |
| `win32_windows_file.go` | `CreateFile`, `ReadFile`, `WriteFile` |
| `win32_windows_process.go` | `CreateProcess`, `OpenProcess` |
| `win32_windows_registry.go` | `RegOpenKey`, `RegQueryValue`, etc. |
| `win32_windows_security.go` | `OpenProcessToken`, SCManager |
| `win32_windows_memory.go` | `VirtualAlloc`, host memory read/write |
| `win32_windows_shadow.go` | Shadow-memory interception (VirtualAlloc routing) |
| `win32_windows_ext.go` | Extension API callbacks (native function pointers) |
| `win32_stub*.go` | ENOSYS stubs for non-Windows builds |

### macOS (`darwin_*`, built with `//go:build darwin`)

| File | Purpose |
|------|---------|
| `darwin.go` | Darwin function registration (7 functions) |
| `darwin_host_darwin.go` | Real `dlopen`/`dlsym` + `ccall9` assembly trampoline |
| `darwin_host_stub.go` | ENOSYS stubs for non-darwin |
| `darwin_trampoline_amd64.s` / `_arm64.s` | Assembly trampolines (SysV ABI / AArch64) |
| `sock_io_darwin.go` | macOS-specific `select()`-based connect completion |

### NativeAOT helpers (`nativeaot_*`, built with `//go:build nativeaot`)

| File | Purpose |
|------|---------|
| `nativeaot.go` | Registration of SDDL, LSA, dir, file_exists |
| `nativeaot_os.go` | `list_dir`, `file_exists` host implementations |
| `nativeaot_security_windows.go` | `win32LsaKerberosOp` (atomic SYSTEM + LSA on COM STA) |
| `nativeaot_security_stub.go` | ENOSYS stubs for non-Windows |
| `nativeaot_wmi_windows.go` | WMI query functions |
| `nativeaot_wmi_stub.go` | ENOSYS stubs for non-Windows |
| `nativeaot_stub.go` | No-op registration when the `nativeaot` tag is absent |

## Key Design Decisions

### Error Code Domains

Two separate error domains travel from host to guest:

1. **WASI errnos** for networking and transport. Returned by
   `errnoFromError()` in `module.go`. Maps Linux syscall errnos to WASI
   errnos: `EAGAIN→6`, `EBADF→8`, `ENOSYS→52`, etc.
2. **Raw Windows error codes** for Win32 API results. Returned by
   `win32Errno()` in `win32_windows_dll.go`. Passes through raw
   `uint32(errno)` values so guest code can handle Win32 semantics like
   `ERROR_NO_MORE_ITEMS = 259` or `ERROR_MORE_DATA = 234`.

Transport-level errors (`ENOSYS`, `EFAULT`, `EBADF`) are returned directly
by host functions before `win32Errno()` is ever called, so the two domains
do not interleave.

### Handle Tables

Two handle tables map guest tokens to host resources:

| Table | Base | Used for |
|-------|------|----------|
| `fdTable` (`fdtable.go`) | 10000 | Networking sockets |
| `win32HandleTable` (`win32_handle.go`) | 20000 | DLLs, procs, registry keys, files, tokens, host memory, dylibs, symbols |

The 10000 / 20000 floors give plenty of room above WASI's normal FD
range (0–9) and below the natural address-range of host pointers.

### Platform-Specific FD Types

Unix file descriptors are `int`; Windows handles are `syscall.Handle`
(a `uintptr`). The type alias `osFDType` resolves to whichever applies:

- `fd_unix.go`: `type osFDType = int`
- `fd_windows.go`: `type osFDType = syscall.Handle`

This keeps the rest of the host module platform-agnostic.

### Scheduler Starvation Fix

wazero's compiled WASM execution monopolizes the OS thread on which it
runs. Non-blocking host reads return `EAGAIN` forever because the kernel
never gets a chance to deliver packets to the goroutine waiting on the
socket. The fix is a `time.Sleep(100µs)` in all host-function `EAGAIN`
return paths (`io.go`, `raw.go`). The sleep is short enough that
latency-sensitive code is not noticeably affected but long enough to let
the Go scheduler drain other goroutines.

### Cooperative Yield Protocol (Blocking Win32 APIs)

WASM is single-threaded under wasip1. All Go goroutines run cooperatively
on one OS thread. When a `//go:wasmimport` host function blocks (for
example, `WaitForSingleObject` during a hosted CLR `execute-assembly`),
it freezes every guest goroutine — the WASM guest hangs.

**Solution.** Async dispatch with a yield-retry protocol. No guest code
changes required.

**Protocol flow:**

1. The host identifies blocking APIs by name via the `blockingAPIs` map
   (14 entries: `WaitForSingleObject`, `Sleep`, `ReadFile`, etc.).
2. First call: the host dispatches the work to a background goroutine and
   returns `errnoYIELD` (255).
3. The guest's `SyscallN` retry loop yields (`runtime.Gosched()` in
   `guest/win32`, channel-based `goYield()` in the patched `syscall`
   package) and re-issues the call.
4. Retry calls check `pendingAsync.done`. If still pending, the host
   returns `errnoYIELD` again.
5. When the background work finishes, the host writes the results into
   the guest's output buffers and jumps to the `postCall:` label for
   the normal mirror-undo and Step 6/7 post-processing.

**Key design points:**

- **`ret1Ptr` as owner token.** Each goroutine's `SyscallN` frame has a
  unique stack-allocated `ret1Buf`. The WASM address of `&ret1Buf[0]`
  disambiguates concurrent callers without guest-side changes.
- **Single async slot.** Only one blocking call runs async at a time. A
  second concurrent blocker falls back to synchronous
  `comSyscallNWithMsgPump`. This is enough because WASM is
  single-threaded — true concurrency does not exist.
- **No COM affinity needed.** Blocking APIs (`WaitForSingleObject`,
  `Sleep`) are kernel waits that work on any OS thread. They bypass the
  COM worker's STA-thread affinity.
- **Channel-based yield in the patched `syscall` package.** Go 1.25's
  linker blocks `//go:linkname runtime.Gosched` from the `syscall`
  package. The workaround is `go func(){ c <- struct{}{} }(); <-c`,
  which creates a proper scheduling point via channel blocking.
- **`postCall:` label.** The async-done path sets the local
  `r1`/`r2`/`err` and jumps to `postCall:`, which handles deep mirror
  patch undo, writable mirror refresh, Step 6 output mirroring, Step 7
  r1 mirroring, and the single `writeReturnValues` call.

**Implementation files:**

- `win32_windows_dll.go`: `blockingAPIs`, `pendingAsyncState`, async
  dispatch in `win32SyscallN`, `postCall:` label
- `module.go`: `errnoYIELD` constant (255)
- `internal/patch/files/syscall_win32_wasip1.go`: `goYield()`, retry loop
  in `SyscallN`
- `guest/win32/win32.go`: retry loops in `SyscallN` and `SyscallN64`

**Note:** Only the `win32SyscallN` path (used by `golang.org/x/sys/windows`
via `syscall.SyscallN`) has the yield protocol. The `win32Call` path
(used by `guest/win32.Proc.Call()`) calls `syscall.SyscallN` directly
without async dispatch.

### x/sys/windows API Gaps

`RegSetValueExW` and `RegDeleteValueW` are not exported from
`golang.org/x/sys/windows` — they live unexported in the
`windows/registry` sub-package. The host uses `syscall.SyscallN` with
lazy procs loaded directly from `advapi32.dll`
(`win32_windows_registry.go`).

### Host Memory Proxy (for goffloader-style tools)

WASM linear memory is an isolated contiguous byte array. `unsafe.Pointer`
operations only reach that linear memory, not host process memory. Host
addresses returned by `VirtualAlloc` (for example, `0x7FFE12340000`) are
outside WASM's 32-bit address space and would cause out-of-bounds traps.
Tools like goffloader that manipulate host memory via `unsafe.Pointer`
cannot work transparently inside WASM.

**Solution.** The host memory proxy pattern. `VirtualAlloc` returns an
opaque **handle**, not a pointer. Every subsequent memory operation goes
through a host function call: `HMemWrite`, `HMemRead`, `HMemWrite32`,
`HMemRead64`, etc. Pointer arithmetic happens on the host side.
`HMemAddr` retrieves the real host address when it needs to be passed to
`SyscallN`.

**Implementation:** `win32_windows_memory.go` (Windows),
`win32_stub_memory.go` (ENOSYS stubs), `guest/win32/hostmem.go` (the
guest-side API).

### Selective Host Pointer Mirroring (COM Support)

Some Win32 APIs write host pointers into output parameters that the guest
needs to dereference. The clearest example is COM: `CLRCreateInstance`
writes an `ICLRMetaHost*` to a caller-supplied output location. WASM
guest code can only read from WASM linear memory, so these host pointers
must be **mirrored** — copied into WASM memory with a reverse-lookup
table maintained by the host.

**The problem.** Indiscriminately mirroring every host pointer (including
r1 return values) corrupts opaque handles. `LoadLibraryExW` returns an
HMODULE in r1 — a DLL base address. Mirroring it would copy the entire
PE image into WASM and replace the handle with a WASM address; then
`GetProcAddress(corruptedHandle)` crashes with `0xc0000005`.

**The solution — two tiers of automatic classification:**

1. **Never mirror r1.** Handle-returning functions (`LoadLibrary`,
   `CreateFile`, `OpenProcess`) return opaque tokens in r1. COM functions
   return HRESULT in r1, a small status code. No legitimate Win32 API
   returns a dereferenceable pointer in r1 that WASM code needs to read.
2. **Selectively mirror output parameters.** After the native call, for
   each arg that was a WASM pointer (translated in Step 3), the host
   reads the 8-byte value at that WASM location and mirrors it only if:
   - Value > `wasmMemSize` (outside WASM linear memory)
   - Value > `0x10000` (not a small scalar or flag)
   - Value < `0x7FFFFFFFFFFF` (within the user-mode address range)
   - `VirtualQuery` reports `MEM_COMMIT` (real accessible memory)
   - `VirtualQuery` reports type **NOT** `MEM_IMAGE` (not a loaded DLL or EXE)

The **MEM_IMAGE filter** is the key discriminator:

| Memory Type | `VirtualQuery` Type | Mirror? | Examples |
|-------------|---------------------|---------|----------|
| Heap object | `MEM_PRIVATE` | YES | COM interface, `SECURITY_DESCRIPTOR` |
| DLL module | `MEM_IMAGE` | NO | `kernel32.dll`, `ntdll.dll` (HMODULE) |
| Kernel handle | (fails `VirtualQuery`) | NO | `HANDLE`, token values |

**Recursive scanning.** After mirroring a host object,
`ScanAndMirrorPointers` follows embedded host pointers (COM vtable
chains). The MEM_IMAGE filter is **intentionally NOT applied** during
recursive scanning, because COM vtables live inside DLL memory
(MEM_IMAGE) and must be mirrored for method dispatch. The filter applies
only at Step 6's top level to prevent HMODULE corruption.

**Implementation.** `mirror.go` (mirrorTable with `byWasm`/`byHost` maps
and a bump allocator), `mirror_windows.go` (`VirtualQuery` + MEM_IMAGE
filter via `mirrorShouldMirror()`), `mirror_stub.go` (non-Windows stubs).
Step 0 in `win32_windows_dll.go` handles reverse translation
(WASM mirror → host address) before `SyscallN` calls. Step 6 handles
forward mirroring after calls.

### Pipe Infrastructure

`os.Pipe()` returns `ENOSYS` on wasip1, which breaks `exec.Cmd` output
capture. The host provides a pipe infrastructure that mirrors WASI's FD
model:

- `pipe.go` — `os_pipe` host function creates a native pipe pair.
- `pipe_table.go` — `PipeTable` tracks host pipe FDs.
- `internal/patch/files/syscall_pipe_wasip1.go` — guest-side
  `syscall.Pipe` wrapper.

FDs ≥ 10000 are routed to host pipe I/O via the fd table in
`syscall_os_wasip1.go`. Patches in `patcher_os.go` wire `syscall.Pipe`,
`syscall.Read`, `syscall.Write`, and `syscall.Close` to the host pipe
functions.

### OS Host Function Proxies

Standard library functions like `os.Hostname()`, `os.Getwd()`,
`os.UserHomeDir()`, `net.Interfaces()`, and `os/exec.Command().Run()`
do not work in wasip1 because they rely on syscalls unavailable to WASM.
WasmForge provides host proxies and patches the guest's stdlib to use
them:

| File | Functions |
|------|-----------|
| `os_host.go` | `os_hostname`, `os_getwd`, `os_chdir`, `os_user_current` |
| `os_exec.go` | `os_exec`, `os_start_process`, `os_wait4` (with output capture, stdin pipe support, and WASI path denormalization `/c/Users/foo` → `C:\Users\foo`) |
| `net_iface.go` | `os_net_interfaces` |

The patches in `patcher_os.go` and `patcher.go` wire these into the
guest's stdlib at compile time, so guest code can call `os.Hostname()`,
`exec.Command().Run()`, etc. transparently.

### macOS Framework Bridge (`darwin_call`)

The `darwin_call` gateway is structurally identical to Win32's
`win32SyscallN` but dramatically simpler — it only needs Step 3 (WASM
pointer translation) and Step 4 (the syscall). No shadow memory, no
mirror table, no COM interfaces.

**Design points:**

- **No CGO.** Go's runtime on darwin already links `libSystem.B.dylib`.
  WasmForge accesses `dlopen`/`dlsym` via `//go:cgo_import_dynamic` plus
  assembly trampolines.
- **Assembly trampolines (`ccall9`).** `syscall.Syscall` on macOS issues
  a raw kernel SYSCALL instruction (trap number `+ 0x2000000`). It cannot
  call C function pointers returned by `dlsym`. The trampoline uses the
  SysV AMD64 ABI (args in RDI, RSI, RDX, RCX, R8, R9, stack for 7–9) and
  the equivalent AArch64 layout for arm64 (x0–x7).
- **`darwin_call_raw`.** A variant that skips pointer translation for
  APIs operating on remote process memory (for example, `mach_vm_write`,
  `mach_vm_allocate`). Mirrors the `ntAPINoMirrorArgs` pattern from
  Windows.
- **Handle table reuse.** Uses the existing `win32HandleTable` with
  `handleDylib = 4` and `handleSymbol = 5`.
- **Auto-detection.** `DarwinAPIs` is auto-set when `GOOS=darwin` — no
  opt-in flag like `--win32-apis`. Every macOS binary needs framework
  access, so making the user opt in would be pure friction.
- **Framework path expansion.** Friendly names like `"Security"` resolve
  to `"/System/Library/Frameworks/Security.framework/Security"`.

**Implementation files.** `darwin.go` (registration),
`darwin_host_darwin.go` (real impl), `darwin_host_stub.go` (ENOSYS stubs
for non-darwin), `darwin_trampoline_{amd64,arm64}.s` (assembly).

### macOS Runtime Fixes

Four runtime issues require macOS-specific handling:

- **Non-blocking connect.** macOS `getsockopt(SO_ERROR)` returns 0
  immediately after `EINPROGRESS`. That means "no error yet" — not
  "connected". `sock_io_darwin.go` uses `select()` for write-readiness.
- **Wall clock.** `WithSysWalltime()` and `WithSysNanotime()` must be set
  on the wazero runtime config explicitly; the default is a fake
  2022-01-01 clock.
- **TMPDIR.** macOS sets `TMPDIR=/var/folders/...`, which is not mounted
  in WASI. The runtime overrides it to `/tmp`.
- **SSL CA certs.** Go's wasip1 `crypto/x509` does not find the system
  trust store automatically. WasmForge auto-detects and sets
  `SSL_CERT_FILE` for the guest.

### Windows Environment Variable Filtering

Windows has drive-specific current-directory entries in the environment
(for example, `=C:=C:\Windows`). These start with `=`, which produces an
empty key after `SplitN`. wazero's `WithEnv` rejects empty keys. The
runtime filters these entries in `runtime.go`.

### WASM Linear Memory Pointer Translation

**The most critical runtime mechanism for complex Win32 programs.** When
WASM guest code calls Win32 APIs via `SyscallN`, pointer arguments hold
WASM linear-memory addresses (for example, `0x2a39b3a`). These are
offsets into wazero's `MemoryInstance.Buffer` byte slice, not valid host
addresses. Passing them directly to Windows APIs causes access violations
(`0xc0000005`).

**Solution (`win32_windows_dll.go`):** before every `syscall.SyscallN`
call, translate WASM pointer arguments to host addresses:

1. Get the host base address: `mem.Read(0, 1)` returns `Buffer[0:1]`;
   take `&buf[0]` → `wasmMemBase`.
2. For each arg: if `arg >= 0x10000 && arg < wasmMemSize`, replace it
   with `wasmMemBase + arg`.
3. The `0x10000` (64 KB) threshold distinguishes pointers from scalar
   values (flags, sizes, handles).

This works because wazero's `Memory.Read(offset, size)` returns
`m.Buffer[offset : offset+size]` — a subslice of the backing array, not a
copy. `wasmMemBase + wasmOffset` therefore yields a valid host pointer
for the duration of the call.

**Execution order in `win32SyscallN`:**

0. Mirror reverse translation. If an arg is a WASM mirror address,
   replace it with the original host address so the native API sees the
   real pointer.
1. Shadow memory interception (VirtualAlloc / VirtualProtect /
   VirtualFree).
2. Shadow memory translation (pre-existing VirtualAlloc'd regions).
3. WASM linear-memory pointer translation (everything else).
4. `syscall.SyscallN` call.
5. Post-sync shadow memory back to WASM.
6. Selective output-parameter mirroring (see
   [Selective Host Pointer Mirroring](#selective-host-pointer-mirroring-com-support)).

The same linear-memory translation is applied in `win32Call` (the
32-bit-arg variant).

### `_windows.go` Build Constraint Relaxation

`internal/build/compiler.go:relaxWindowsBuildConstraints` handles the
fundamental challenge: Go files with `_windows.go` suffixes carry an
implicit `GOOS=windows` constraint that excludes them from `GOOS=wasip1`
builds. WasmForge needs them.

**Two-pass approach:**

1. **First pass — header tags.** Files with `windows` in a positive
   constraint get `|| wasip1` added. Files with `!windows` that have a
   `_windows.go` counterpart get disabled.
2. **Second pass — filename suffixes.** `foo_windows.go` → `foo.go`
   removes the GOOS constraint from the filename.

**Collision handling.** When `foo_windows.go` → `foo.go` collides with an
existing `foo.go`:

- If the existing file excludes wasip1 (negative build tag like
  `!windows`): replace it. The `_windows.go` version is the correct
  implementation.
- If the existing file has shared types or interfaces: rename to
  `foo_wfwin.go`. The `_wfwin` suffix matches no real GOOS, so the file
  is included unconditionally.
- If a `foo_wasip1.go` stub exists: check whether the renamed
  `_windows.go` will compile for wasip1. If yes, drop the stub; if no,
  keep the stub and constrain `_wfwin.go` to windows-only.

**Old-style build tags.** `convertPlusBuildToGoBuild()` handles the
`// +build` syntax used before Go 1.17.

**Skip list.** A few vendor packages with deep Windows kernel APIs are
skipped entirely (for example, `go-winio`). The sysshim vendor directory
is also skipped to prevent redeclaration errors.

### Sysshim Sub-Packages

The sysshim at `internal/sysshim/windows/` provides `golang.org/x/sys/windows`
for wasip1 builds. Complex projects may also import:

- `registry/` — `golang.org/x/sys/windows/registry`
- `svc/` — `golang.org/x/sys/windows/svc`
- `svc/mgr/` — `golang.org/x/sys/windows/svc/mgr`

These were copied from the real `golang.org/x/sys` vendor directory with
build constraints relaxed. The compiler's `injectSysshimVendored()`
auto-discovers sub-directories, so new sub-packages are picked up
without changes to the compiler.

### Automatic Sysshim Injection

If a guest program's `go.mod` depends on `golang.org/x/sys`, the
compiler automatically injects a `replace` directive pointing at
WasmForge's vendored sysshim. This makes the full
`golang.org/x/sys/windows` type surface available on `wasip1` without
manual configuration.

### Verbose Debug Mode

Setting `Config.Verbose = true` in `runtime.go` (or passing `-v` to the
CLI) enables syscall tracing. Each `win32SyscallN` call prints:

```
[wasmforge] SyscallN: GetUserDefaultLocaleName (proc=0x7ffd8ee8d6b0, nargs=2, args=[0x2a39b3a, 0x55])
```

The `debugName` field on `win32HandleEntry` records the proc name from
`GetProcAddress`. The verbose log is what `internal/devtools/audit-ptrmasks`
consumes to identify Win32 APIs without explicit pointer-mask coverage.

## Guest Libraries

### `guest/rawnet` — Raw Sockets

```go
import "github.com/praetorian-inc/wasmforge/guest/rawnet"

conn, err := rawnet.Open(rawnet.AF_INET, rawnet.IPPROTO_ICMP)
defer conn.Close()
n, err := conn.SendTo(packet, &rawnet.Addr4{IP: [4]byte{8, 8, 8, 8}})
```

Requires `--raw-sockets` and either `CAP_NET_RAW` or root.

### `guest/win32` — Win32 APIs

```go
import "github.com/praetorian-inc/wasmforge/guest/win32"

if !win32.Available() {
    log.Fatal("Win32 APIs not available")
}

// Registry
key, _ := win32.RegOpenKey(
    win32.HKEY_LOCAL_MACHINE,
    `SOFTWARE\Microsoft\Windows\CurrentVersion`,
    win32.KEY_READ,
)
defer win32.RegCloseKey(key)
val, _ := win32.RegQueryString(key, "ProgramFilesDir")

// DLL loading
lib, _ := win32.LoadLibrary("kernel32.dll")
proc, _ := lib.GetProcAddress("GetCurrentProcessId")
pid, _ := proc.Call()
lib.Free()
```

The Win32 API bridge is auto-enabled when the target is `GOOS=windows`.
`--win32-apis` is kept as an explicit override. On non-Windows hosts,
`win32.Available()` returns `false` and every call returns
`ErrNotAvailable`.

#### Host Memory (for COFF/BOF loaders)

```go
// Allocate RW memory on the host
mem, _ := win32.VirtualAlloc(4096, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
defer mem.Free()

// Copy data from WASM → host memory
mem.Write(0, shellcodeBytes)

// Scalar read/write
mem.WriteUint32(offset, 0xDEADBEEF)
val, _ := mem.ReadUint32(offset)

// Change to executable
mem.VirtualProtect(win32.PAGE_EXECUTE_READ)

// Get real host address for SyscallN
addr, _ := mem.Addr()
```

### `guest/darwin` — macOS Framework APIs

```go
import "github.com/praetorian-inc/wasmforge/guest/darwin"

if !darwin.Available() {
    log.Fatal("macOS framework APIs not available")
}

fw, _ := darwin.LoadFramework("Security")
// or load any dylib by path:
fw, _ = darwin.LoadFramework("/usr/lib/libSystem.B.dylib")

sym, _ := fw.GetSymbol("SecItemCopyMatching")

// Args are uintptr, WASM→host pointer translation is automatic
result, _ := sym.Call(arg1, arg2, arg3)

// CallRaw skips pointer translation (for remote process memory)
result, _ = sym.CallRaw(arg1, arg2, arg3)

// Host memory access
buf := make([]byte, 1024)
darwin.ReadHostMemory(hostAddr, buf)
darwin.WriteHostMemory(hostAddr, data)
```

Auto-detected when `GOOS=darwin`. Framework paths expand from friendly
names: `"Security"` → `"/System/Library/Frameworks/Security.framework/Security"`.

## Host Functions Reference

### Networking (always available)

| Function | Purpose |
|----------|---------|
| `sock_open` | Create socket (TCP / UDP) |
| `sock_bind` | Bind to address |
| `sock_listen` | Mark as listening |
| `sock_connect` | Connect to remote |
| `sock_accept` | Accept connection |
| `sock_read` / `sock_write` | Non-blocking I/O |
| `sock_sendto` / `sock_recvfrom` | UDP datagrams |
| `sock_shutdown` | Graceful shutdown |
| `sock_setsockopt` / `sock_getsockopt` | Socket options |
| `sock_getpeername` / `sock_getsockname` | Address queries |
| `sock_getaddrinfo` | DNS resolution |

### Raw Sockets (requires `--raw-sockets`)

| Function | Purpose |
|----------|---------|
| `raw_sock_open` | Create `SOCK_RAW` socket |
| `raw_sock_send` | Send raw packet |
| `raw_sock_recv` | Receive raw packet |

### OS Proxies (always available)

| Function | Purpose |
|----------|---------|
| `os_hostname` | Get system hostname |
| `os_getwd` | Get current working directory |
| `os_chdir` | Change working directory |
| `os_user_current` | Get current user (name, uid, home) |
| `os_exec` | Execute command with output capture |
| `os_start_process` | Start process (non-blocking) |
| `os_wait4` | Wait for process completion |
| `os_pipe` | Create host pipe pair (for exec stdin/stdout) |
| `os_net_interfaces` | Enumerate network interfaces |

### Win32 APIs (auto-enabled on Windows targets)

| Function | Purpose |
|----------|---------|
| `win32_available` | Check if Win32 APIs are enabled |
| `win32_load_library` | `LoadLibraryA` |
| `win32_get_proc_address` | `GetProcAddress` |
| `win32_call` | Call proc (up to 6 uint32 args) |
| `win32_syscalln` | `SyscallN` (up to 15 int64 args) |
| `win32_free_library` | `FreeLibrary` |
| `win32_close_handle` | `CloseHandle` (generic) |
| `win32_reg_open_key` | `RegOpenKeyExW` |
| `win32_reg_close_key` | `RegCloseKey` |
| `win32_reg_query_value` | `RegQueryValueExW` |
| `win32_reg_set_value` | `RegSetValueExW` |
| `win32_reg_delete_value` | `RegDeleteValueW` |
| `win32_reg_enum_key` | `RegEnumKeyExW` |
| `win32_create_file` | `CreateFileW` |
| `win32_read_file` | `ReadFile` |
| `win32_write_file` | `WriteFile` |
| `win32_get_file_attrs` | `GetFileAttributesW` |
| `win32_set_file_attrs` | `SetFileAttributesW` |
| `win32_get_computer_name` | `GetComputerNameW` |
| `win32_create_process` | `CreateProcessW` |
| `win32_open_process` | `OpenProcess` |
| `win32_terminate_process` | `TerminateProcess` |
| `win32_open_process_token` | `OpenProcessToken` |
| `win32_get_token_info` | `GetTokenInformation` |
| `win32_open_sc_manager` | `OpenSCManagerW` |
| `win32_query_service_status` | `QueryServiceStatus` |
| `win32_virtual_alloc` | `VirtualAlloc` (host memory, returns handle) |
| `win32_virtual_protect` | `VirtualProtect` |
| `win32_virtual_free` | `VirtualFree` |
| `win32_hmem_write` | Copy bytes WASM → host memory |
| `win32_hmem_read` | Copy bytes host → WASM memory |
| `win32_hmem_write32` / `win32_hmem_write64` | Scalar write at offset |
| `win32_hmem_read32` / `win32_hmem_read64` | Scalar read at offset |
| `win32_hmem_addr` | Get real host address (for `SyscallN`) |
| `win32_ext_get_func` | Get native address of extension API callback |
| `win32_ext_read_output` | Read accumulated extension output |
| `win32_ext_reset_output` | Clear extension output buffer |

### macOS Framework APIs (auto-enabled on darwin targets)

| Function | Purpose |
|----------|---------|
| `fw_available` | Check if darwin framework APIs are enabled |
| `fw_load` | Load framework / dylib via `dlopen` (returns handle) |
| `fw_sym` | Resolve symbol via `dlsym` (returns handle) |
| `fw_call` | Call function pointer with WASM → host pointer translation |
| `fw_call_raw` | Call function pointer without pointer translation |
| `fw_mem_r` | Read host memory into WASM linear memory |
| `fw_mem_w` | Write WASM data to host memory |

## WASM Embedding and AV Evasion

The WASM module is XOR-encoded before embedding to eliminate magic bytes,
string patterns, and tool signatures from static analysis. The full
default recipe ("R80") combines chunked payload distribution, IAT
patching, Go runtime marker scrambling, zlib compression, debug-symbol
stripping, PE header normalization, and Traefik-style ghost profiling.
Every transform has an environment-variable kill switch — see
[`docs/ENVIRONMENT.md`](ENVIRONMENT.md) for the full matrix.

The core mechanisms:

1. **XOR encoding** (`embedder.go`). `SHA256(wasm_plaintext)` produces a
   32-byte key. The WASM data is XOR'd with this key. The key is appended
   as a trailer. The runtime reads the trailer, XOR-decodes the payload,
   and passes the result to wazero.
2. **PE hardening** (`winres.go`). Windows targets automatically get
   VERSIONINFO resources and an application manifest. Defaults are
   neutral (no "WasmForge" strings); custom values can be set via
   `--pe-company`, `--pe-product`, `--pe-description`, etc.
3. **Identifier hygiene.** All host-side function names use neutral
   terminology (`extCallbackState`, `nativeSprintf`, `readNativeString`)
   to avoid signature matches in gopclntab. Guest-side identifiers are
   inside the XOR-encoded WASM blob and are not visible in static
   strings.
4. **Debug info preserved.** WasmForge intentionally does NOT strip with
   `-s -w`. Stripped Go binaries lack metadata that ML classifiers
   associate with legitimate software, which raises false-positive rates.
   Keep this in mind if you are tempted to add stripping to the embedder.
5. **Per-build randomization.** Custom WASM opcodes, magic bytes, section
   IDs, and the bundled wazero fork's identifiers are randomized per
   build. Two consecutive builds of the same source produce structurally
   distinct binaries.

## Extension API Callbacks

For COFF/BOF loading, object files need to call host functions at native
speed. The extension API (`win32_windows_ext.go`) creates native function
pointers via `windows.NewCallback`:

| ID | Function | Signature |
|----|----------|-----------|
| 0 | Output | `(type, data*, len) → ok` |
| 1 | Printf | `(type, fmt*, args...) → 0` |
| 2 | DataParse | `(parser*, buf*, size) → ok` |
| 3 | DataInt | `(parser*) → uint32` |
| 4 | DataShort | `(parser*) → uint16` |
| 5 | DataLength | `(parser*) → remaining` |
| 6 | DataExtract | `(parser*, outSize*) → ptr` |
| 7 | AddValue | `(key*, ptr) → ok` |
| 8 | GetValue | `(key*) → ptr` |
| 9 | RemoveValue | `(key*) → existed` |

Guest code calls `win32.ExtGetFunc(id)` to get the native address, then
writes it into the loaded object file's GOT. The `nativeSprintf`
implementation handles `%s` (ANSI), `%S` and `%ls` (wide), `%p`, and
integer specifiers (`%d`, `%u`, `%x`, `%X`, `%o`, `%c`, with `l` and `ll`
modifiers).

## Further Reading

- [`README.md`](../README.md) — pitch and quickstart
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — contributor workflow
- [`docs/ENVIRONMENT.md`](ENVIRONMENT.md) — every `WASMFORGE_*` env var
- [`docs/GHOST-PROFILES.md`](GHOST-PROFILES.md) — gopclntab camouflage
- [`docs/CSHARP.md`](CSHARP.md) — Docker-based C# build pipeline
- [`docs/MACOS.md`](MACOS.md) — macOS-specific notes
- [`docs/BUILDING-SLIVER.md`](BUILDING-SLIVER.md) — end-to-end Sliver build walkthrough
- [`docs/internals/AST-PATCHER.md`](internals/AST-PATCHER.md) — C# AST patcher internals
- [`docs/internals/PARITY-HARNESS.md`](internals/PARITY-HARNESS.md) — native-vs-WasmForge parity harness
- [`docs/internals/HOST-API-CONTRACT.md`](internals/HOST-API-CONTRACT.md) — the host module's public ABI contract
