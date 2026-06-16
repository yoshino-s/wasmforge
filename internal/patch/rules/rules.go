// Package rules contains AST-based C# patch rules for NativeAOT-WASI migration.
// AllNativeAOTASTRules wraps the legacy CSharpPatch slice via LegacyTextRule
// adapters so the entire patcher runs through one code path. Future work can
// replace individual LegacyTextRule entries with true-AST rules without
// changing this function's signature or its callers.
package rules

import "github.com/praetorian-inc/wasmforge/internal/patch"

// AllNativeAOTASTRules returns every AST rule registered for the
// NativeAOT-WASI patcher. Mixes:
//   - Native AST rules (MemberChainRewrite, InvocationRewrite) for
//     anything that benefits from structural matching — these survive
//     upstream whitespace and naming churn.
//   - LegacyTextRule adapters around the CSharpPatch slice for the
//     remaining substring rules. Each migrated rule should be removed
//     from CSharpPatch when its AST equivalent lands here.
func AllNativeAOTASTRules() []patch.ASTRule {
	out := nativeASTRules()
	legacy := patch.NativeAOTCSharpPatches()
	for _, p := range legacy {
		out = append(out, &LegacyTextRule{
			Glob:     p.FileGlob,
			Excludes: p.ExcludeGlobs,
			Old:      p.Old,
			New:      p.New,
			Desc:     p.Description,
		})
	}
	return out
}

// nativeASTRules returns the list of true-AST rules. Keep this function
// small and organised by gap area; each block is a short paragraph that
// closes one engine gap end-to-end.
func nativeASTRules() []patch.ASTRule {
	var out []patch.ASTRule

	// ── OSInfo / general host-info gap ────────────────────────────────
	// Seatbelt's OSInfoCommand.cs (and any other command that touches
	// these BCL APIs) gets WASI defaults: hostname="localhost",
	// ProcessorCount=1, TimeZone=UTC, DomainName="". Route all reads
	// through the WfOsInfo helper, which calls kernel32 via wf_call.

	// Environment.ProcessorCount → WfOsInfo.ProcessorCount() everywhere.
	out = append(out, &patch.MemberChainRewrite{
		Chain: []string{"Environment", "ProcessorCount"},
		Repl:  "WasmForge.Helpers.WfOsInfo.ProcessorCount()",
		Desc:  "Environment.ProcessorCount → WfOsInfo.ProcessorCount (WASI returns 1)",
	})

	// Dns.GetHostName() → WfOsInfo.MachineName() — covers OSInfo,
	// remote enumerators, anything else that pulls the local hostname.
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Dns"},
		Method:   "GetHostName",
		Repl:     "WasmForge.Helpers.WfOsInfo.MachineName()",
		KeepArgs: false,
		ArgCount: 0,
		Desc:     "Dns.GetHostName() → WfOsInfo.MachineName (WASI returns 'localhost')",
	})

	// System.Net.Dns.GetHostName() — same target, fully-qualified form.
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "Net", "Dns"},
		Method:   "GetHostName",
		Repl:     "WasmForge.Helpers.WfOsInfo.MachineName()",
		KeepArgs: false,
		ArgCount: 0,
		Desc:     "System.Net.Dns.GetHostName() → WfOsInfo.MachineName (FQ form)",
	})

	// IPGlobalProperties.GetIPGlobalProperties() — throws PNS under
	// NativeAOT-WASI. Most callers only want .DomainName from it, so
	// rewrite the constructor call to a stub that returns an object
	// whose DomainName property reads WfOsInfo.DnsDomain(). The stub
	// type WasmForge.Helpers.WfOsInfo.GlobalProperties (added on the C#
	// side) supplies DomainName + HostName backed by wf_call.
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"IPGlobalProperties"},
		Method:   "GetIPGlobalProperties",
		Repl:     "WasmForge.Helpers.WfOsInfo.GlobalProperties.Get()",
		KeepArgs: false,
		ArgCount: 0,
		Desc:     "IPGlobalProperties.GetIPGlobalProperties() → WfOsInfo.GlobalProperties.Get (PNS under WASI)",
	})

	// TimeZone.CurrentTimeZone.{StandardName,GetUtcOffset(...)}.
	// TimeZone is null under NativeAOT-WASI; rewrite the prefix
	// "TimeZone.CurrentTimeZone" to WfOsInfo.TimeZone — a static
	// helper class on the C# side that exposes the same properties
	// backed by kernel32!GetTimeZoneInformation.
	out = append(out, &patch.MemberChainRewrite{
		Chain: []string{"TimeZone", "CurrentTimeZone"},
		Repl:  "WasmForge.Helpers.WfOsInfo.TimeZone",
		Desc:  "TimeZone.CurrentTimeZone.* → WfOsInfo.TimeZone (WASI returns UTC)",
	})

	// Environment.TickCount → (int)WfOsInfo.TickCount64() — used for
	// boot-time math. WASI's TickCount is 0 immediately after start.
	out = append(out, &patch.MemberChainRewrite{
		Chain: []string{"Environment", "TickCount"},
		Repl:  "(int)WasmForge.Helpers.WfOsInfo.TickCount64()",
		Desc:  "Environment.TickCount → (int)WfOsInfo.TickCount64 (WASI returns 0)",
	})

	// ── Filesystem ────────────────────────────────────────────────────
	// SharpUp's recursive FileUtils.FindFiles calls Directory.GetFiles +
	// Directory.GetDirectories. Under NativeAOT-WASI both return empty
	// without throwing — silent zero. Route through WfFs which uses the
	// os_list_dir host bridge.

	// Directory.GetFiles(path) / (path, pattern) / (path, pattern, scope)
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Directory"},
		Method:   "GetFiles",
		Repl:     "WasmForge.Helpers.WfFs.GlobFiles",
		KeepArgs: true,
		ArgCount: -1,
		Desc:     "Directory.GetFiles(...) → WfFs.GlobFiles (WASI returns empty silently)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "Directory"},
		Method:   "GetFiles",
		Repl:     "WasmForge.Helpers.WfFs.GlobFiles",
		KeepArgs: true,
		ArgCount: -1,
		Desc:     "System.IO.Directory.GetFiles(...) → WfFs.GlobFiles (FQ form)",
	})

	// Directory.GetDirectories(path)
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Directory"},
		Method:   "GetDirectories",
		Repl:     "WasmForge.Helpers.WfFs.ListDirectoriesOnly",
		KeepArgs: true,
		ArgCount: -1,
		Desc:     "Directory.GetDirectories(...) → WfFs.ListDirectoriesOnly (WASI returns empty silently)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "Directory"},
		Method:   "GetDirectories",
		Repl:     "WasmForge.Helpers.WfFs.ListDirectoriesOnly",
		KeepArgs: true,
		ArgCount: -1,
		Desc:     "System.IO.Directory.GetDirectories(...) → WfFs.ListDirectoriesOnly (FQ form)",
	})

	// File.Exists(path) / File.ReadAllBytes(path) / File.ReadAllText(path):
	// the BCL paths fail under WASI because absolute Windows paths get
	// rewritten to "/C:/…" which then errors with DirectoryNotFound. WfFs
	// routes through the fs_exists / fs_read_all host bridges that take
	// raw native Windows path strings — same root cause class as the
	// Directory.GetFiles/GetDirectories problem above. Single AST rule
	// per BCL method covers every site, replacing dozens of legacy
	// per-file text rules.

	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"File"},
		Method:   "Exists",
		Repl:     "WasmForge.Helpers.WfFs.Exists",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "File.Exists(path) → WfFs.Exists (WASI absolute path bypass)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "File"},
		Method:   "Exists",
		Repl:     "WasmForge.Helpers.WfFs.Exists",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.File.Exists(path) → WfFs.Exists (FQ form)",
	})

	// Directory.Exists(path) — same WASI failure mode as File.Exists.
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Directory"},
		Method:   "Exists",
		Repl:     "WasmForge.Helpers.WfFs.Exists",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "Directory.Exists(path) → WfFs.Exists (WASI absolute path bypass)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "Directory"},
		Method:   "Exists",
		Repl:     "WasmForge.Helpers.WfFs.Exists",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.Directory.Exists(path) → WfFs.Exists (FQ form)",
	})

	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"File"},
		Method:   "ReadAllBytes",
		Repl:     "WasmForge.Helpers.WfFs.ReadAllBytes",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "File.ReadAllBytes(path) → WfFs.ReadAllBytes (WASI absolute path bypass)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "File"},
		Method:   "ReadAllBytes",
		Repl:     "WasmForge.Helpers.WfFs.ReadAllBytes",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.File.ReadAllBytes(path) → WfFs.ReadAllBytes (FQ form)",
	})

	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"File"},
		Method:   "ReadAllText",
		Repl:     "WasmForge.Helpers.WfFs.ReadAllText",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "File.ReadAllText(path) → WfFs.ReadAllText (WASI absolute path bypass)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "File"},
		Method:   "ReadAllText",
		Repl:     "WasmForge.Helpers.WfFs.ReadAllText",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.File.ReadAllText(path) → WfFs.ReadAllText (FQ form)",
	})

	// Path.GetFileName / GetDirectoryName / GetExtension / GetFileNameWithoutExtension
	// → WfPath.* — the NativeAOT-WASI runtime sets DirectorySeparatorChar='/'
	// and AltDirectorySeparatorChar='/', so the BCL helpers don't split on
	// backslash. A path like `C:\Users\foo\bar.txt` comes back from
	// Path.GetFileName unchanged. The WfPath equivalents split on EITHER
	// '\' or '/'. Verified with a minimal harness:
	//   PATH=[C:\Users\foo\bar.txt] -> [C:\Users\foo\bar.txt]   (broken)
	//   DirSep=[/] AltDirSep=[/]
	// Affects SharpDPAPI credential / vault / certificate triage (filename
	// columns) and any future tool that processes Win32 paths.
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Path"},
		Method:   "GetFileName",
		Repl:     "WasmForge.Helpers.WfPath.GetFileName",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "Path.GetFileName(path) → WfPath.GetFileName (Windows-aware basename)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "Path"},
		Method:   "GetFileName",
		Repl:     "WasmForge.Helpers.WfPath.GetFileName",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.Path.GetFileName(path) → WfPath.GetFileName (FQ form)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Path"},
		Method:   "GetDirectoryName",
		Repl:     "WasmForge.Helpers.WfPath.GetDirectoryName",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "Path.GetDirectoryName(path) → WfPath.GetDirectoryName",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"System", "IO", "Path"},
		Method:   "GetDirectoryName",
		Repl:     "WasmForge.Helpers.WfPath.GetDirectoryName",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "System.IO.Path.GetDirectoryName(path) → WfPath.GetDirectoryName (FQ form)",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Path"},
		Method:   "GetExtension",
		Repl:     "WasmForge.Helpers.WfPath.GetExtension",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "Path.GetExtension(path) → WfPath.GetExtension",
	})
	out = append(out, &patch.InvocationRewrite{
		Receiver: []string{"Path"},
		Method:   "GetFileNameWithoutExtension",
		Repl:     "WasmForge.Helpers.WfPath.GetFileNameWithoutExtension",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "Path.GetFileNameWithoutExtension(path) → WfPath",
	})

	// WindowsIdentity.GetCurrent().Name → WfOsInfo.WindowsIdentityName().
	// WindowsIdentity throws PNS under WASI; the previous text rules
	// rewrote this to Environment.UserName which then returns "Browser"
	// (the WASI default user). WindowsIdentityName goes through
	// secur32!GetUserNameExW(NameSamCompatible) for the real
	// "DOMAIN\username" form.
	out = append(out, &patch.MethodResultMemberRewrite{
		Receiver: []string{"WindowsIdentity"},
		Method:   "GetCurrent",
		Member:   "Name",
		Repl:     "WasmForge.Helpers.WfOsInfo.WindowsIdentityName()",
		Desc:     "WindowsIdentity.GetCurrent().Name → WfOsInfo.WindowsIdentityName (secur32!GetUserNameExW)",
	})
	out = append(out, &patch.MethodResultMemberRewrite{
		Receiver: []string{"System", "Security", "Principal", "WindowsIdentity"},
		Method:   "GetCurrent",
		Member:   "Name",
		Repl:     "WasmForge.Helpers.WfOsInfo.WindowsIdentityName()",
		Desc:     "System.Security.Principal.WindowsIdentity.GetCurrent().Name → WfOsInfo.WindowsIdentityName (FQ form)",
	})

	// Environment.UserName → WfOsInfo.UserName(). On NativeAOT-WASI the
	// CoreLib default-returns "Browser" (the WASI environ default user).
	// Rubeus' EnumerateTickets builds its synthetic LogonSessionData
	// straight from Environment.UserName → "Browser" leaked into klist
	// output as the displayed UserName. Same crash mode as
	// WindowsIdentity.GetCurrent().Name but a different sink.
	// OSInfoCommand.cs needs DOMAIN\user (WindowsIdentityName), not bare
	// username (UserName) — handled by a dedicated targeted text rule
	// further down. Exclude here to avoid overlapping-edit conflicts.
	out = append(out, &patch.MemberChainRewrite{
		Chain:    []string{"Environment", "UserName"},
		Repl:     "WasmForge.Helpers.WfOsInfo.UserName()",
		Excludes: []string{"**/Windows/OSInfoCommand.cs"},
	})
	out = append(out, &patch.MemberChainRewrite{
		Chain:    []string{"System", "Environment", "UserName"},
		Repl:     "WasmForge.Helpers.WfOsInfo.UserName()",
		Excludes: []string{"**/Windows/OSInfoCommand.cs"},
	})

	// Environment.MachineName → WfOsInfo.NetBiosName(). On real .NET this
	// returns the NetBIOS computer name (uppercase, max 15 chars) which
	// is what Seatbelt's LocalGroups / LocalUsers / UserRightAssignments
	// baselines use as the local-account prefix. WfOsInfo.MachineName()
	// returns the DNS hostname and is reserved for the
	// IPGlobalProperties.HostName redirect (different field).
	out = append(out, &patch.MemberChainRewrite{
		Chain: []string{"Environment", "MachineName"},
		Repl:  "WasmForge.Helpers.WfOsInfo.NetBiosName()",
	})
	out = append(out, &patch.MemberChainRewrite{
		Chain: []string{"System", "Environment", "MachineName"},
		Repl:  "WasmForge.Helpers.WfOsInfo.NetBiosName()",
	})

	return out
}
