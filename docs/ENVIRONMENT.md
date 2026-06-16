# Environment Variables

`wasmforge build` reads a number of `WASMFORGE_*` environment variables to
override defaults and toggle individual stealth transforms. The default
**R80 recipe** sets several of these automatically — most users never need
to touch any of them.

This page documents every variable, grouped by purpose. Each entry lists
the **read site** (file:line) so behaviour can be cross-checked against the
source.

## Quick reference

| Use case | Set |
|---|---|
| Disable every stealth transform (pure debug build) | `WASMFORGE_RAW_BUILD=1` |
| Keep build temp directories for inspection | `WASMFORGE_KEEP_DIR=1` |
| Force a specific signer subject across a batch | `WASMFORGE_FIXED_SIGNER="GitLab Inc."` |
| Force a specific per-build package name | `WASMFORGE_FIXED_RUNTIME_PKG=engine` |
| Run with verbose host-side WASM tracing | `WASMFORGE_VERBOSE=1` |

## Master toggle

### `WASMFORGE_RAW_BUILD`

- **Default**: unset → R80 stealth defaults apply.
- **Effect**: when set to `1`, `applyR80Defaults` returns early and no
  `WASMFORGE_*` defaults are written. Use for debug / dev builds where
  reproducibility and inspectability matter more than evasion.
- **Read by**: `internal/build/pipeline.go:375`.

## The R80 recipe

When `WASMFORGE_RAW_BUILD` is **unset**, `wasmforge build` enables the
proven-clean R80 stealth recipe by setting the following variables, but
only when the user has not already exported a value:

| Variable | R80 value | Effect |
|---|---|---|
| `WASMFORGE_CHUNK_PAYLOAD` | `1` | Split PE payload across multiple debug sections to keep per-section entropy below 7.0. |
| `WASMFORGE_EMBED_COMPRESS` | `1` | zlib-compress the WASM payload before XOR encoding to shrink `.rdata` footprint. |
| `WASMFORGE_PATCH_IAT_RE27` | `1` | Strip `GetThreadContext`/`SetThreadContext` from the static IAT and resolve them at runtime instead (defeats CrowdStrike on-sensor ML rule Re27). |
| `WASMFORGE_SCRAMBLE_GO_MARKERS` | `1` | Randomise the `\xff Go build ID:` / `\xff Go buildinf:` byte markers that YARA rules anchor on. |
| `WASMFORGE_STRIP` | `1` | Pass `-ldflags "-s -w"` to `go build` to strip the symbol table + DWARF info. |
| `WASMFORGE_PE_NORMALIZE` | `1` | Run `normalizeGoPEHeaders` against the produced PE. |
| `WASMFORGE_NO_ENRICH` | `1` | Skip PE import enrichment (R80 builds use minimal imports). |
| `WASMFORGE_NO_NATIVEAOT_HOST` | `1` (or `0` for `--nativeaot`) | Exclude NativeAOT-only host functions from Go builds; force-included for NativeAOT-WASI builds. |

The R80 recipe also sets `--ghost traefik` when no ghost profile was
chosen on the CLI.

All defaults are applied in `internal/build/pipeline.go:374` (`applyR80Defaults`).
Override any single transform by exporting it explicitly, e.g.
`WASMFORGE_STRIP=0`.

## Payload distribution and encoding

### `WASMFORGE_CHUNK_PAYLOAD`

- **Default**: `1` under R80.
- **Effect**: when `1` and targeting Windows, distribute the encoded WASM
  payload across multiple debug sections (`.zdebug_*`) so each section
  stays under entropy 7.0. Falls back to a single section on failure.
- **Read by**: `internal/build/embedder.go:378`, `internal/build/pipeline.go:283`.

### `WASMFORGE_EMBED_COMPRESS`

- **Default**: `1` under R80.
- **Effect**: zlib-compress the WASM payload before XOR encoding. Reduces
  `.rdata` size by ~79 % and removes the WASM magic byte sequence from
  any byte scanner. Runtime reverses the order (XOR decode → zlib
  decompress).
- **Read by**: `internal/build/embedder.go:394`.

### `WASMFORGE_PAYLOAD_XORSHIFT`

- **Default**: unset.
- **Effect**: replace the 32-byte rotating XOR with an `xorshift64`
  keystream seeded from `PayloadKey`. Defeats cyclic-XOR pattern matching.
- **Read by**: `internal/build/embedder.go:409`, `internal/build/embedder.go:541`,
  `internal/build/polymorph.go:1262`.

### `WASMFORGE_EMBED_PAYLOAD`

- **Default**: unset.
- **Effect**: when set to `1`, force the WASM payload to be embedded via
  `//go:embed` even when targeting Windows. Default Windows behaviour is
  to defer-inject into a PE section.
- **Read by**: `internal/build/embedder.go:376`.

### `WASMFORGE_SKIP_DISTRIBUTE`

- **Default**: unset.
- **Effect**: force single-section payload mode even when chunked
  distribution succeeds. Useful for debugging the post-injection path.
- **Read by**: `internal/build/pipeline.go:295`.

## PE / Go binary scrubbing

### `WASMFORGE_PATCH_IAT_RE27`

- **Default**: `1` under R80.
- **Effect**: when set, the host build patches `runtime/os_windows.go` so
  `GetThreadContext` / `SetThreadContext` are resolved dynamically via
  `LoadLibrary` + `GetProcAddress` instead of being baked into the
  static import address table. Targets CrowdStrike on-sensor ML rule
  importance #25 ("Re27").
- **Read by**: `internal/build/embedder.go:1082`.

### `WASMFORGE_SCRAMBLE_GO_MARKERS`

- **Default**: `1` under R80.
- **Effect**: rewrite the `\xff Go build ID:` and `\xff Go buildinf:`
  byte sequences in the final binary so YARA-style anchors stop matching.
- **Read by**: `internal/build/pipeline.go:246`.

### `WASMFORGE_STRIP`

- **Default**: `1` under R80.
- **Effect**: pass `-ldflags "-s -w"` to `go build` for the host binary,
  removing the symbol table and DWARF debug info. Reduces gopclntab
  leakage of suspicious API names.
- **Read by**: `internal/build/embedder.go:476`.

### `WASMFORGE_PE_NORMALIZE`

- **Default**: `1` under R80.
- **Effect**: run `normalizeGoPEHeaders` against the produced PE during
  post-processing.
- **Read by**: `internal/build/pe_postprocess.go:83`.

### `WASMFORGE_NO_ENRICH`

- **Default**: `1` under R80.
- **Effect**: when `1`, skip PE import enrichment entirely. The host
  binary keeps only the imports the Go compiler emitted. Lowers
  Symantec ML.Attribute.HighConfidence detection in VT testing.
- **Read by**: `internal/build/pe_postprocess.go:39`.

### `WASMFORGE_RSRC`

- **Default**: unset.
- **Effect**: when set to `1`, generate Windows VERSIONINFO + manifest
  resources for the host binary. Default behaviour (no resources) lowered
  Avira/AVG/Bkav detection from 60 %+ to under 3 % in VT testing.
- **Read by**: `internal/build/embedder.go:461`.

### `WASMFORGE_GCFLAGS`

- **Default**: unset → standard Go optimisations.
- **Effect**: forwarded to `go build` as `-gcflags=all=<value>`. Use to
  experiment with `-N` (disable optimisation) or other gcflag knobs.
- **Read by**: `internal/build/embedder.go:483`.

## Host source transforms

The host transformer (`internal/build/host_transform.go`) runs a series
of polymorphism phases against the host module sources. Each phase has
its own `WASMFORGE_NO_*` opt-out. All phases are **on by default**; set
the variable to any non-empty string to disable.

### `WASMFORGE_NO_HOST_TRANSFORM`

- **Default**: unset → host transforms run.
- **Effect**: skip wazero/host source rewriting entirely (Phase 0 — import
  path neutralisation and downstream rewrites).
- **Read by**: `internal/build/embedder.go:152` (+ 247, 273, 296).

### `WASMFORGE_NO_CHAIN_SPLIT`

- **Default**: unset.
- **Effect**: skip the registration-chain splitter. Set automatically when
  using NativeAOT to avoid a known boundary-counting regression on chains
  longer than ~45 entries.
- **Read by**: `internal/build/host_transform.go:126`,
  `internal/build/embedder.go:87`.

### `WASMFORGE_NO_STRUCT_REORDER`

- **Default**: unset.
- **Effect**: skip Phase 9 struct field reordering against host source
  packages.
- **Read by**: `internal/build/host_transform.go:136` (+ 2949).

### `WASMFORGE_NO_OPAQUE`

- **Default**: unset.
- **Effect**: skip Phase 10 opaque-predicate insertion (always-true
  branches that vary control-flow graph).
- **Read by**: `internal/build/host_transform.go:162` (+ 2957).

### `WASMFORGE_NO_CODEXFORM`

- **Default**: unset.
- **Effect**: skip Phase 11 source-level AST transforms (branch flipping,
  loop inversion, temp extraction).
- **Read by**: `internal/build/host_transform.go:172` (+ 2970).

### `WASMFORGE_NO_REORDER`

- **Default**: unset.
- **Effect**: skip Phase 5 function reordering.
- **Read by**: `internal/build/host_transform.go:195`.

### `WASMFORGE_NO_DEADCODE`

- **Default**: unset → dead-code injection runs.
- **Effect**: when set to **any** non-empty value, skip Phase 6
  dead-code injection. (Note: the polarity here is inverted from the
  other `NO_*` variables — empty string means "inject", any value means
  "skip".)
- **Read by**: `internal/build/host_transform.go:204`.

### `WASMFORGE_NO_NATIVEAOT_HOST`

- **Default**: `1` under R80 for Go builds; `0` under R80 for NativeAOT
  builds.
- **Effect**: when `1`, exclude files behind `//go:build nativeaot` build
  tags during host generation (WMI / SDDL / LSA / RPC bridges). Forced
  off when `--wasm` is passed or a C# project is detected.
- **Read by**: `internal/build/embedder.go:652`.

### `WASMFORGE_WAZERO_STRUCT_REORDER`

- **Default**: unset → off.
- **Effect**: opt-in. Apply Phase 9 struct field reordering to the
  bundled wazero source tree. Off by default because wazero uses
  reflection (`wazero/internal/wasm/gofunc.go`) that depends on field
  declaration order.
- **Read by**: `internal/build/host_transform.go:2948`.

### `WASMFORGE_WAZERO_CODEXFORM`

- **Default**: unset → off.
- **Effect**: opt-in. Apply Phase 11 source-level AST transforms to the
  bundled wazero source tree. Off by default because branch flips and
  loop inversion can alter decoder semantics that wazero relies on.
- **Read by**: `internal/build/host_transform.go:2969`.

## Polymorphism / per-build overrides

These variables pin a per-build random choice to a fixed value. Useful
when running batch experiments where you want every output to share one
attribute while everything else varies.

### `WASMFORGE_FIXED_SIGNER`

- **Default**: unset → random pick from the company pool.
- **Effect**: override the Authenticode self-signed certificate subject.
  Pass any string (e.g. `"GitLab Inc."`).
- **Read by**: `internal/build/codesign.go:183`.

### `WASMFORGE_FIXED_HOSTMOD_PKG`

- **Default**: unset → derived from the active ghost profile.
- **Effect**: pin the per-build package name used for the hostmod
  internal package.
- **Read by**: `internal/build/polymorph.go:397`.

### `WASMFORGE_FIXED_RUNTIME_PKG`

- **Default**: unset.
- **Effect**: pin the per-build package name used for the runtime
  internal package.
- **Read by**: `internal/build/polymorph.go:393`.

### `WASMFORGE_FIXED_NAMES_PKG`

- **Default**: unset.
- **Effect**: pin the per-build package name used for the host-export
  names package.
- **Read by**: `internal/build/polymorph.go:401`.

### `WASMFORGE_VARIANT`

- **Default**: unset → random value in `[0, 5)`.
- **Effect**: force the WASM decode-loop variant to a specific value
  (`0`–`4`). Useful when reproducing a runtime crash tied to one variant.
- **Read by**: `internal/build/polymorph.go:511`.

### `WASMFORGE_WORDLIST`

- **Default**: unset → built-in word list.
- **Effect**: path to a custom word list used by the package-name
  generator. File format: prefixes (one per line), blank line, suffixes
  (one per line).
- **Read by**: `internal/build/wordlist.go:250`.

## Diagnostics and debug

### `WASMFORGE_KEEP_DIR`

- **Default**: unset → temp build directories are removed on exit.
- **Effect**: when set to any non-empty value, the top-level build temp
  directory is retained and its path is printed to stderr.
- **Read by**: `internal/build/pipeline.go:153`.

### `WASMFORGE_KEEP_HOST`

- **Default**: unset → host build directory is removed.
- **Effect**: retain the generated host source / build tree for
  inspection (`host-build-*`).
- **Read by**: `internal/build/embedder.go:105`.

### `WASMFORGE_KEEP_GOROOT`

- **Default**: unset → host GOROOT overlay is cleaned up after build.
- **Effect**: when set, the per-build host GOROOT overlay is retained.
- **Read by**: `internal/build/embedder.go:512`.

### `WASMFORGE_VERBOSE`

- **Default**: unset → runtime tracing is off.
- **Effect**: when set to `1`, the embedded wasmforge runtime emits
  per-syscall trace lines to stderr (`[wasmforge] SyscallN: ...`). Used
  with `internal/devtools/audit-ptrmasks` to diagnose missing pointer
  masks.
- **Read by**: `internal/runtime/runtime.go:43`.

### `WASMFORGE_DEBUG`

- **Default**: unset.
- **Effect**: enables verbose network I/O logging from
  `internal/hostmod/io.go`. Set to any non-empty value.
- **Read by**: `internal/hostmod/io.go:12`.

### `WASMFORGE_DEBUG_PKGS`

- **Default**: unset.
- **Effect**: when set, dump the chosen per-build package name set to
  stderr at the start of the polymorph stage. Useful for diagnosing name
  collisions across packages.
- **Read by**: `internal/build/polymorph.go:730`.

## See also

- `cmd/wasmforge/main.go` — the CLI flags (`--ghost`, `--target`,
  `--win32-apis`, `--sign`, etc.) that drive the higher-level recipes.
- `internal/build/pipeline.go:374` — `applyR80Defaults` — the source of
  truth for which variables R80 enables.
