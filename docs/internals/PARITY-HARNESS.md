# Parity Harness

The parity harness is a Go test suite that runs each wasmforge-built tool
on a Windows test target, normalizes the output, and diffs against
committed "golden" baselines. It exists to lock in known-good behavior
so future work (AST patcher migration, new bridge functions, etc.)
cannot silently regress tool output.

## Lab requirements

The harness assumes you have stood up an Active Directory test range using:

- **[Ludus](https://gitlab.com/badsectorlabs/ludus)** — Proxmox-based range
  orchestration. Provides the Win11 attacker box, the DC, and the
  `labctl` workflow used by `internal/labctl` / `scripts/lab-setup/`.
- **[GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD)** —
  the AD topology. The defaults baked into the suite
  (`sevenkingdoms.local`, `dc01.sevenkingdoms.local`,
  `kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA`,
  `sevenkingdoms\domainuser`, `10.3.10.10`, the GOAD domain SID, etc.)
  are GOAD's documented defaults. The five most-used values live in
  `test/parity/internal/lab/lab.go` and can be overridden per-range
  with `WASMFORGE_PARITY_DOMAIN`, `WASMFORGE_PARITY_DC`,
  `WASMFORGE_PARITY_DC_IP`, `WASMFORGE_PARITY_CA`, and
  `WASMFORGE_PARITY_USER` environment variables. Tool-specific
  constants (domain SID, kerberoast SPNs, etc.) still live as
  literals in `test/parity/<tool>/cases.go` — edit those directly if
  your range uses different values.

The PowerShell scripts under `scripts/lab-setup/` are idempotent lab
plants run against a freshly-deployed GOADf97252-style range to seed
the misconfigurations the parity tests probe (GPP cpassword, modifiable
services, SharpDPAPI blobs, kerberoastable SPNs, etc.).

## What it does

For every supported tool (`seatbelt`, `rubeus`):

1. **Push** the locally-built `.exe` to `C:\Users\<test-user>\<tool>-parity.exe` on the Windows target.
2. **Run** each tool verb/command on the target via your preferred remote-exec channel (WinRM, SSH, etc.).
3. **Normalize** the captured stdout: strip timestamps, GUIDs, durations, PIDs (opt-in), the Seatbelt ASCII banner, and any remote-exec wrapper prefix. Also convert CRLF → LF.
4. **Diff** the cleaned output against the committed `.golden` file under `testdata/parity-baselines/<tool>/<command>.golden`.
5. **Report** byte-exact mismatches with both versions in the failure message.

Tests are tagged `//go:build parity` so they do not run in normal
`go test ./...` — they are slow (several minutes per tool sweep) and
require remote access to a Windows test target.

## Target configuration

The parity tests resolve the Windows target's domain identity from
environment variables. Defaults match the GOAD topology described above,
so on a stock Ludus + GOAD range no env vars need to be set; override
only when running against a range with different names.

| Env var | Default | Used as |
|---|---|---|
| `WASMFORGE_PARITY_DOMAIN` | `sevenkingdoms.local` | NT-style domain |
| `WASMFORGE_PARITY_DC` | `dc01.sevenkingdoms.local` | DC FQDN |
| `WASMFORGE_PARITY_DC_IP` | `10.3.10.10` | DC IP (Ludus range default) |
| `WASMFORGE_PARITY_CA` | `kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA` | CA in CONFIG format |
| `WASMFORGE_PARITY_USER` | `domainuser` | non-priv test user |

See the helper at `test/parity/internal/lab/lab.go` for the canonical
resolution logic. New parity cases should use `lab.Domain()`, `lab.DC()`,
etc. rather than hardcoding any target-specific values.

## What it doesn't do

- **No host-side mocking.** The harness depends on a live Windows test target. If the target is unreachable, tests SKIP (not FAIL).
- **No semantic comparison.** Output diffs are byte-exact after normalization. If a Win32 API legitimately changes its output format upstream, the baseline must be re-captured.
- **No coverage of dynamic data.** The Processes/Services baselines only assert the header lines because the non-Microsoft process list on a stock Windows box is sparse and depends on the box's runtime state.

## How to add a new tool

Five steps to onboard a new tool (e.g., `sharpdpapi`, `certify`):

1. **Build the .exe** via the existing Docker pipeline:
   ```bash
   make docker-run DOCKER_SRC=/tmp/<tool>-fresh DOCKER_PROJECT=<tool>
   ```
   Produces `out/<tool>.exe`.

2. **Pick the verbs/commands** the parity sweep should exercise. Reference each tool's known-working verb list as you go.

3. **Capture baselines** via the CLI:
   ```bash
   cd test
   GOWORK=off go run ./parity/cmd/capture-baseline \
       -binary ../out/<tool>.exe \
       -tool <tool> \
       -commands <verb1>,<verb2>,... \
       -output ../testdata/parity-baselines/<tool>/ \
       -allow-errors
   ```
   `-allow-errors` tolerates non-zero exits for verbs that are intentionally stubbed.

4. **Create the test file** at `test/parity/<tool>/<tool>_parity_test.go` using the seatbelt template. Replace the `commands` slice with your verb list. The rest is unchanged.

5. **Add a Makefile target** mirroring `test-parity-seatbelt`. Extend the `test-parity-all` dependency list to include it.

Commit the `.golden` files alongside the test file. Re-running `capture-baseline` against the same binary must produce byte-identical files (idempotency); verify with `git diff testdata/parity-baselines/<tool>/`.

## How to add a new command to an existing tool

1. Capture the new baseline:
   ```bash
   cd test
   GOWORK=off go run ./parity/cmd/capture-baseline \
       -binary /tmp/wf-out/seatbelt.exe \
       -tool seatbelt \
       -commands NewCommand \
       -output ../testdata/parity-baselines/seatbelt/ \
       -allow-errors
   ```
2. Append `"NewCommand"` to the `commands` slice in `seatbelt_parity_test.go`.
3. Run `make test-parity-seatbelt` to confirm the sub-test passes.
4. Commit both the test change and the new `.golden` file together.

## How to update a baseline after an intentional behavior change

When a wasmforge code change is expected to alter a command's output:

1. Re-build the binary via `make docker-run`.
2. Run the parity test → confirm only the expected sub-tests fail.
3. Re-capture only the affected baselines:
   ```bash
   cd test
   GOWORK=off go run ./parity/cmd/capture-baseline \
       -binary /tmp/wf-out/seatbelt.exe \
       -tool seatbelt \
       -commands AffectedCommand1,AffectedCommand2 \
       -output ../testdata/parity-baselines/seatbelt/ \
       -allow-errors
   ```
4. Diff the new baselines against the old: `git diff testdata/parity-baselines/seatbelt/` — review carefully, the change must match the expected behavior.
5. Re-run `make test-parity-seatbelt` → should be green again.
6. Commit the code change and the baseline update in the same commit so future bisects find them together.

## Limitations

- **Target dependency.** Tests SKIP when the Windows target is unreachable. CI cannot rely on parity tests as a gating signal until you have durable target uptime — historically this is the single biggest operational drag on the harness.
- **Stub baselines.** Some commands (e.g., `AntiVirus`, `WMIEventConsumer`) reflect the stubbed C# implementation, not real native output. If a future change adds WASM↔host callback support for WMI providers, those baselines must be regenerated and the stubs removed.
- **Environment-specific data.** Baselines capture SIDs, group memberships, and computer names from the environment they were recorded in. Re-running against a different domain requires regenerating the baselines.
- **No CI integration in this phase.** The harness is a manual local gate. Wiring it into a CI job requires durable target access, which is a separate workstream.

## Environment variables

- `WASMFORGE_TEST_BINARY` — override the path to the `.exe` under test. Defaults to `/tmp/wf-out/seatbelt.exe` for the Seatbelt sweep; the Makefile target defaults to `$(DOCKER_OUT_DIR)/seatbelt.exe` = `out/seatbelt.exe`.
- `WASMFORGE_PARITY_*` — Windows target identity (see [Target configuration](#target-configuration) above).

## Quick commands

```bash
# Run the full Seatbelt sweep
make test-parity-seatbelt

# Run the full Rubeus sweep
make test-parity-rubeus

# Or with an explicit binary
WASMFORGE_TEST_BINARY=/tmp/wf-out/seatbelt.exe make test-parity-seatbelt
WASMFORGE_TEST_BINARY=/tmp/wf-out/rubeus.exe   make test-parity-rubeus

# Run all tool parity sweeps
make test-parity-all

# Run just one command (debugging)
cd test
GOWORK=off go test -tags parity ./parity/seatbelt/ -v -run TestSeatbeltParity/LocalGroups

# Re-capture all 16 Seatbelt baselines (intentional regen)
cd test
GOWORK=off go run ./parity/cmd/capture-baseline \
    -binary /tmp/wf-out/seatbelt.exe -tool seatbelt \
    -commands LocalGroups,LocalUsers,WindowsVault,RDPSessions,Processes,Services,NetworkShares,OSInfo,McAfeeSiteList,AMSIProviders,WindowsFirewall,WindowsAutoLogon,TokenGroups,TokenPrivileges,AntiVirus,WMIEventConsumer \
    -output ../testdata/parity-baselines/seatbelt/ -allow-errors
```

## Honest-Stub Convention

When a command's underlying Win32 / WMI / LSA primitive can't yet be
bridged on NativeAOT-WASI, do **not** silently return empty output —
that pattern hides the gap behind a "passing" parity test (empty wf
output happens to match empty native output on test VMs with no AV / no
saved credentials / no WiFi adapter).

Instead, the Execute body MUST print an explicit banner identifying:
1. The specific command that's not implemented.
2. The Win32 API or bridge primitive that's missing.
3. A note that the empty output below is a stub, not a real query.

Example (Seatbelt AntiVirusCommand):
```
[!] WasmForge: AntiVirus enumeration is NOT IMPLEMENTED — root\SecurityCenter2 WMI provider requires bidirectional callback dispatch. Output below is a stub, not a real query.
```

The baseline locks the banner text; parity passes only when wf still
emits the banner. When someone implements the bridge, the parity test
FAILS until they refresh the baseline with the real output — which is
the desired behavior because it forces a deliberate check that the new
implementation is correct.

**Anti-pattern** (do not do this):
```csharp
public override IEnumerable<CommandDTOBase?> Execute(string[] args)
{
    yield break;  // wf has no AV detection, but baselines pass on test VMs anyway
}
```

**Correct pattern**:
```csharp
public override IEnumerable<CommandDTOBase?> Execute(string[] args)
{
    WriteHost("[!] WasmForge: AntiVirus enumeration is NOT IMPLEMENTED — root\\SecurityCenter2 WMI provider requires bidirectional callback dispatch. Output below is a stub, not a real query.");
    yield break;
}
```
