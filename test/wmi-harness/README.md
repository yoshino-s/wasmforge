# WMI Bridge Test Harness

Mirrors `crypto-harness/` and `lsa-harness/` — minimal NativeAOT-WASI C#
program that triages Seatbelt's `AntiVirus` and `WMIEventConsumer` parity
failures with a three-layer probe.

## What it tests

Five test calls across three diagnostic layers:

| Layer | What it exercises | What a failure here means |
|-------|--------------------|---------------------------|
| **L1** — raw env import `wmi_query_r` (DllImport) | The host-side WMI bridge in `internal/hostmod/nativeaot_wmi_windows.go`. Runs `root\SecurityCenter2 / AntiVirusProduct` and `ROOT\Subscription / __EventConsumer`. | Host bridge broken or never registered. |
| **L2** — `WfWmi.QueryRestricted` (the path Seatbelt's patched commands use) | The C# JSON walk in `dotnet/helpers/WfWmi.cs`. Same two queries. | `JsonDocument.Parse` chokes, or `EnsureInitialized`/`WfCom.Initialize` throws. |
| **L3** — local `AntiVirusDTO` (mirror of Seatbelt's `internal class`, getter-only `object` props) + `type.GetProperties()` reflection | NativeAOT trim preservation of getter-only auto-properties — the path Seatbelt's `DefaultTextFormatter` uses. | Trim stripped DTO properties; `GetProperties()` returns 0; Seatbelt formatter prints empty rows. |

Each layer prints exit-aware progress: bytes written, JSON head, row dump,
or reflection property counts. The process exit code = number of failed
layers.

## Build & run (Docker)

```bash
make docker-run DOCKER_SRC=$(pwd)/test/wmi-harness DOCKER_PROJECT=wmitest
labctl push --force out/wmitest.exe win11-ssh:'C:\WfBin\wmitest.exe'
labctl exec win11-ssh 'C:\WfBin\wmitest.exe'
```

## What it found (2026-06-03)

Under the rd.xml shipped in this harness — `<Type Name="WmiTest.AntiVirusDTO"
Dynamic="Required All" />` — all three layers PASS. With that single line
removed (or downgraded to assembly-level `<Assembly … Dynamic="Required
All" />`), L1 and L2 still pass but L3 returns `GetProperties() returned 0
props` and prints nothing.

This is the same symptom Seatbelt's AntiVirus / WMIEventConsumer commands
exhibit on Win11: the WMI bridge returns rows, the C# wrapper parses them,
but `DefaultTextFormatter`'s reflection walk finds zero properties on the
DTO so nothing prints. The current production `internal/patch/rdxml.go`
emits Assembly-level `Required All`, which evidently does not preserve
getter-only auto-properties on `object`-typed members under NativeAOT-LLVM.

Seven Seatbelt DTOs share the failing shape (`public object X { get; }`):
- AntiVirusCommand.cs
- WMIEventConsumerCommand.cs
- WMIEventFilterCommand.cs
- WMIFilterToConsumerBindingCommand.cs
- RegistryValueCommand.cs
- NetworkSharesCommand.cs
- LocalGPOCommand.cs

## Files in this directory

| File | Purpose |
|------|---------|
| `Program.cs` | 3-layer probe |
| `WmiTest.csproj` | SDK-style project; references ILCompiler.LLVM + bridge `.c` files |
| `Properties/WfPreserve.rd.xml` | Type-level trim preservation for `AntiVirusDTO` — without this, L3 fails |
| `nuget.config` | `dotnet-experimental` feed (required to resolve `Microsoft.DotNet.ILCompiler.LLVM`) |
| `README.md` | this file |
