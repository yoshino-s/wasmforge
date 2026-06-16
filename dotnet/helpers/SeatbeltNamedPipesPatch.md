# NamedPipes Re-enablement — COMPLETED (2026-05-25)

Status: **WORKING** as of commit dcb5522. NamedPipes enumerates real
Windows named pipes on Win11 lab (PSHost.*, LOCAL\mojo.*, system pipes).

## Architecture (proven template for the other 4 disabled commands)

```
┌──────────────────────────────────────────────────────────┐
│ C# guest (NamedPipesCommand.cs)                          │
│                                                          │
│   [DllImport("env", EntryPoint = "fs_pipes")]            │
│   private static extern uint FsListPipes(...);           │
└──────────────┬───────────────────────────────────────────┘
               │ WASM env import
               ▼
┌──────────────────────────────────────────────────────────┐
│ C bridge (pinvoke_env_ext.c)                             │
│                                                          │
│   uint32_t fs_pipes(...) {                               │
│       return wf_list_named_pipes(...);                   │
│   }                                                      │
│                                                          │
│   // wf_bridge.h — actual WASM env import attribute      │
│   __attribute__((import_module("env"),                   │
│                  import_name("fs_pipes")))               │
│   extern uint32_t wf_list_named_pipes(...);              │
└──────────────┬───────────────────────────────────────────┘
               │ wasm-ld resolves at link time
               ▼
┌──────────────────────────────────────────────────────────┐
│ Go host (nativeaot_pipes_windows.go)                     │
│                                                          │
│   func osListNamedPipes(... stack []uint64) {            │
│       // syscall.FindFirstFile on \\.\pipe\*             │
│       // proper x64 pointer sizes here                   │
│   }                                                      │
│                                                          │
│   Export(export("os_list_named_pipes"))  // → fs_pipes   │
└──────────────────────────────────────────────────────────┘
```

## Per-API per-command work needed

To restore the other 4 commands using this template:

| Command | Native API | Host fn name | Anonymized export |
|---------|-----------|--------------|-------------------|
| UserRightAssignments | LsaEnumerateAccountRights | osEnumUserRights | priv_rights |
| WifiProfile | WlanEnumInterfaces + WlanQueryInterface | osEnumWifiProfiles | net_wifi |
| SecPackageCreds | EnumerateSecurityPackages | osEnumSecPkgCreds | sec_pkg |
| Printers | EnumPrinters | osEnumPrinters | sys_printers |

Each requires:
1. Go file `nativeaot_<api>_windows.go` + matching `_stub.go` (~50 lines each)
2. Registration in nativeaot.go (~10 lines)
3. names.go mapping (~1 line)
4. C bridge wrapper in pinvoke_env_ext.c (~6 lines)
5. wf_bridge.h declaration (~3 lines)
6. C# `<Command>Command.cs` rewrite (~50 lines, mirroring NamedPipesCommand.cs)
7. Push bridge files + rebuild + test on Win11 lab

Total ~120 lines per command × 4 commands = ~500 lines.

## Critical bridge file deployment gotcha

The Seatbelt project has its OWN copy of bridge files at
`/tmp/seatbelt-src/Seatbelt/bridge/` — independent from the wasmforge
source tree's `dotnet/bridge/`. After editing the wasmforge bridge
files, push them to the seatbelt bridge dir before rebuilding:

```bash
labctl push wf_bridge.h kali:/tmp/seatbelt-src/Seatbelt/bridge/wf_bridge.h
labctl push pinvoke_env_ext.c kali:/tmp/seatbelt-src/Seatbelt/bridge/pinvoke_env_ext.c
```

This is also why earlier attempts (v3, v4, v5, v6) silently produced
undefined_stub even though the wasmforge build assets contained the
new C bridge — Seatbelt's local copy lagged behind.
