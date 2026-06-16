# NativeAOT-WASI argv silent-exit bug

## Symptom

When a wasmforge-compiled .NET binary is invoked with argv containing a specific
verb-name token followed immediately by a `/`-prefix token, the WASM module
exits cleanly (exit code 0, no stdout/stderr, no `proc_exit` log) **before
`Program.Main` is called**.

Triggering pattern: `argv[N] ∈ {asktgt, asktgs, kerberoast, asreproast}` AND
`argv[N+1]` starts with `/`.

```
rubeus-test.exe asktgt /foo            → silent-exit (0 bytes)
rubeus-test.exe asktgt -foo            → works
rubeus-test.exe asktgt foo             → works
rubeus-test.exe asktgt bar /foo        → works (non-slash arg breaks adjacency)
rubeus-test.exe /foo asktgt            → works (order matters)
rubeus-test.exe triage /foo            → works (different verb)
```

Critical: **The string "asktgt" does not need to appear anywhere in the
compiled WASM**. We renamed the class, all string literals, all usage text;
clean obj/ + bin/; verified with `strings rubeus.exe | grep asktgt` → 0
matches. `asktgt /foo` still silent-exits.

## Confirmed scope

- Real native .NET Framework `Rubeus.exe` (462KB PE) works **perfectly** with
  `asktgt /foo`. Bug is in the wasmforge / NativeAOT-LLVM-WASI pipeline.
- `test/argv-harness` (minimal C# WASI program that just dumps argv) works
  fine with the same args.
- `test/mini-rubeus` (Rubeus-like dispatch with same verb class names) works
  fine — does NOT reproduce.
- Adding `<PackageReference Include="System.Security.Cryptography.Pkcs" />` +
  full Rubeus `<DirectPInvoke>` + all 10 `<NativeLibrary>` C bridges to
  mini-rubeus did NOT reproduce.

The trigger requires enough of Rubeus's source graph (lib/, krb_structures/,
Asn1/) to compile in. Multiple incremental additions hit namespace-conflict
compile errors that need deeper integration to bypass.

## Workaround (shipped)

`commit 507cdb1` — WF_RUN sentinel pattern. Test framework invokes:
```
rubeus.exe asktgt WF_RUN /user:foo /password:bar
```
A C# patcher rule in `csharp_patcher.go` strips the WF_RUN sentinel at the
top of `Program.Main` before `ArgumentParser.Parse` sees it. The non-slash
arg between the verb and the first `/`-arg breaks the trigger pattern.

**This works** — `asktgt WF_RUN /user:domainuser /password:password
/domain:sevenkingdoms.local /nowrap` produces a real TGT (3201 bytes
including base64 kirbi). Verified against the live GOAD DC.

The workaround is acceptable for parity testing but inappropriate as a
permanent solution because forward-slash args are a Windows convention
that many C# tools use. **Other tools beyond Rubeus may hit this** —
the failing verb names happen to be Kerberos-related but there's no
reason to believe other verb names couldn't trigger if the class graph
is shaped similarly.

## Ruled out (12+ build cycles, task #47)

- WfTcp injection not the cause (works without it too)
- Failing verb class graph reachability (removed verb files entirely)
- Literal "asktgt"/"Asktgt" strings in compiled C# (clean build, no occurrence
  in WASM, still crashes)
- WASI/NativeAOT runtime itself (argv-harness works with same args)
- Bridge file additions, DirectPInvoke specificity, TrimmerRootAssembly
- Stale obj/bin caching

## Suspected root cause area

The crash is in NativeAOT-WASI's pre-Main runtime initialization. Specifically
the path that converts WASI argv (via `wasi:cli/environment.get-arguments`)
into a managed `string[]`. The `string[]` construction or some metadata
loading triggered by string-array layout is somehow content-sensitive in a
way that interacts with Rubeus's specific compiled WASM structure.

Hypotheses to test:
1. The wasmforge `get-arguments` host implementation has a path-dependent bug
   when `cabi_realloc` returns specific addresses (the fallback strCursor
   path packs strings without alignment).
2. NativeAOT-LLVM emits a content-dependent hash/dispatch table that
   coincidentally collides for these verb names + Rubeus's type metadata
   layout.
3. wasi-libc's `__wasi_args_get` does some path-canonicalization or
   environment-variable detection on `/`-prefix tokens.

## Confirmed via raw WASM inspection (wasm-objdump)

Used `extract-rubeus-wasm.sh` to extract `Rubeus.wasm` (21MB) before the
docker container's auto-cleanup. Findings:

- **Rubeus uses WASI Preview 1 (`wasi_snapshot_preview1.args_get`) for argv,
  NOT P2 `wasi:cli/environment.get-arguments`**. The previous suspicion that
  our P2 stub's get-arguments implementation was at fault is incorrect.
- The P1 `args_get` path through `writeOffsetsAndNullTerminatedValues` in
  wazero is straightforward and content-independent (just writes NUL-
  terminated bytes).
- Exports: `_start` (func[152]) and `__main_void` (func[21475]). No custom
  Start section.
- Total imports: 141 (env.*, wasi_snapshot_preview1.*, wasi:* P2 stubs).

Implication: the bug is NOT in our `get-arguments` stub. It's either:
- In wasi-libc's crt1 (the `_start` function executing on the WASM side
  before reaching managed code)
- In NativeAOT's runtime initialization (loading types, running module
  cctors, building managed `string[]` from argv)
- In a content-dependent codepath emitted by NativeAOT-LLVM for Rubeus's
  specific class graph

## Diff between Rubeus.wasm (fails) and mini-rubeus.wasm (works)

Sizes — Rubeus 20.2MB / 21576 funcs / 141 imports vs mini-rubeus 2.6MB /
2783 funcs / 39 imports. Mini-rubeus has zero imports that Rubeus lacks.
Rubeus has **102 extra imports** that mini-rubeus doesn't pull in:

- **WASI P2 BCL surface** (the big one): full `wasi:http/types`,
  `wasi:http/outgoing-handler`, `wasi:io/streams`, `wasi:io/poll`,
  `wasi:sockets/tcp`, `wasi:sockets/udp`, `wasi:sockets/ip-name-lookup`,
  `wasi:sockets/instance-network` — System.Net.Http + System.Net.Sockets
  + DNS code reachable through Rubeus's class graph.
- **WASI P1 filesystem**: `fd_read`, `fd_filestat_get`, `fd_filestat_set_size`,
  `fd_pread`, `fd_pwrite`, `fd_readdir`, `fd_sync`, `path_open`,
  `path_readlink`, `adapter_open_badfd`.
- **WasmForge env**: `env.crypto_kerb{hash,enc,dec,cksum}`, `env.fs_findfiles`,
  `env.lsa_kerbop`, `env.mem_alloc/free/read/write/etc`, `env.mod_hread`,
  `env.mod_regptr`, `env.wmi_query_r`, `env.net_tcpsendrecv`.

The trigger is almost certainly in one of these expansive reachability graphs.
The leading suspect is the BCL `System.Net.*` chain because the failing verb
names (asktgt, kerberoast, asreproast) are exactly the ones that go through
TCP/LDAP networking, while triage/klist/currentluid (which don't pull
System.Net.Sockets) work fine.

Hypothesis: a static initializer in the System.Net.* chain (or in NativeAOT's
eager init for any of these P2 socket imports) runs at module load and
allocates buffers / sets up state in a way that interacts with the argv
layout in WASI memory. When argv contains specific byte sequences (verb
name + slash), the layout overlaps with allocator metadata and a silent
trap occurs.

To validate this hypothesis, the next investigator should:
1. Remove `Networking.SendBytes` calls from Asktgt.Execute, see if that
   eliminates `wasi:sockets/tcp` from Rubeus's import graph and stops the
   crash. If yes, the BCL socket types are the trigger.
2. Or strip `System.Security.Cryptography.Pkcs` package ref (which pulls
   in System.Net through the X509 chain via OCSP).

## System.Net.Sockets hypothesis FALSIFIED

Directly stripped `System.Net.Sockets` + `System.Net.Dns` references from
`Networking.cs` (full body replacement of SendBytes to call WfTcp.SendRecv,
neutered GetDCIP's DNS fallback path) and from `Roast.cs` (kerberoast DC
resolution stubbed). Confirmed via WASM diff: **`wasi:sockets/tcp` imports
and `wasi:sockets/ip-name-lookup` are GONE** from the rebuilt binary (45
imports dropped, binary 177KB smaller).

Result: `asktgt /foo` STILL silent-exits.

So the System.Net.Sockets reachability shown in the import diff was a
correlation, not causation. The trigger is in one of the remaining 57
"extra" imports vs mini-rubeus:

- **WASI P2 HTTP** (24 imports): `wasi:http/types.*`, `wasi:http/outgoing-handler.handle`
  — comes from System.Security.Cryptography.Pkcs (OCSP/CRL fetching).
- **WASI P1 filesystem** (9): `fd_read`, `fd_pread`, `fd_pwrite`, `fd_readdir`,
  `fd_sync`, `path_open`, `path_readlink`, `fd_filestat_*`, `fd_advise`.
- **WasmForge env helpers** (16): `crypto_kerb*` (4), `lsa_kerbop`,
  `fs_findfiles`, `wmi_query_r`, `mem_alloc/free/read/write/etc` (8),
  `mod_hread`, `mod_regptr`, `net_tcpsendrecv`.

The next bisection should attempt to:
1. Strip `<PackageReference Include="System.Security.Cryptography.Pkcs"/>`
   from Rubeus.csproj (if Rubeus still builds — X509 usage might block).
2. Or strip File I/O usage to drop the WASI P1 filesystem cluster.
3. Or strip the WfHelper static graph (rename `Wf*` classes to break trim
   reachability from Rubeus's call sites).

## Concrete next steps for root cause

The fastest path needs WASM-level debugging tooling that wasn't available in
this session:

1. **Step-debug Rubeus.wasm in wasmtime**: `wasmtime run --debug-info
   --gdb-stub=:9999 Rubeus.wasm asktgt /foo`. Attach gdb, break on `_start`,
   step through wasi-libc's argv processing.

2. **Diff get-arguments output**: instrument `internal/runtime/wasip2_stubs.go`
   to log every `mem.Write` call in the `get-arguments` handler. Compare
   what's written for `asktgt /foo` (crashes) vs `asktgt foo` (works).

3. **Build NativeAOT-LLVM from source with debug**: `git clone
   dotnet/runtime` + build with `-c Debug` to get readable IL → WASM
   mappings.

4. **Continue mini-rubeus bisect**: clone /tmp/rubeus-fresh to a bisect dir,
   binary-search by deleting half of lib/ at a time. Build cycle ~25 min,
   so 5-6 cycles → minimal repro.

## Files in this directory

- `Program.cs` — minimal CommandCollection-style dispatcher with 6 verb
  classes including the 4 failing names. Does NOT reproduce.
- `MiniRubeus.csproj` — minimal csproj. Mirroring Rubeus's full csproj
  structure also does not reproduce.

This directory is preserved for future bisection work, not as a working
reproducer.
