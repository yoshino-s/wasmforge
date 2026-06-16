// pinvoke_kernel32_ext.c — Additional unprefixed P/Invoke stubs for NativeAOT-LLVM.
//
// These functions were discovered as undefined symbols when building Seatbelt
// against the WasmForge NativeAOT-WASI pipeline.  Each stub forwards to
// wf_call() which dispatches to the real Win32 API on the host at runtime.
//
// Naming convention: function names are UNPREFIXED (e.g. "CloseHandle", not
// "kernel32_CloseHandle").  NativeAOT-LLVM resolves DllImport symbols by the
// bare function name when the csproj contains:
//   <DirectPInvoke Include="kernel32" />
//   <DirectPInvoke Include="ntdll" />
//   <DirectPInvoke Include="user32" />
//   <DirectPInvoke Include="advapi32" />
// The prefixed variants in pinvoke_nativeaot.c serve a different code path
// (WfHostBridge.cs explicit EntryPoint= declarations) and must not be removed.
//
// All pointer arguments are uint64_t (WASM linear-memory offsets; the host
// bridge translates them to host pointers before the Win32 call).
// Small scalar arguments (DWORD, BOOL) use uint32_t in the parameter list but
// are widened to uint64_t at the wf_call() call site.
// HANDLE return values use uint64_t; DWORD/BOOL return values use uint32_t.

#include "wf_bridge.h"

// ---------------------------------------------------------------------------
// kernel32.dll
// ---------------------------------------------------------------------------

// CloseHandle(HANDLE hObject) -> BOOL
uint32_t CloseHandle(uint32_t hObject) {
    return (uint32_t)wf_call("kernel32.dll", "CloseHandle", 1,
        (uint64_t)hObject);
}

// CopyMemory is a macro for RtlCopyMemory which lives in ntdll.dll.
// Void return — caller ignores the value; we return 0 as a harmless sentinel.
uint32_t CopyMemory(uint32_t Destination, uint32_t Source, uint32_t Length) {
    return (uint32_t)wf_call("ntdll.dll", "RtlCopyMemory", 3,
        (uint64_t)Destination, (uint64_t)Source, (uint64_t)Length);
}

// CreateFile(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
// -> HANDLE
// Seatbelt uses Unicode strings throughout; the W variant is correct.
uint32_t CreateFile(uint32_t lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, uint32_t lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, uint32_t hTemplateFile) {
    return (uint32_t)wf_call("kernel32.dll", "CreateFileW", 7,
        (uint64_t)lpFileName,
        (uint64_t)dwDesiredAccess,
        (uint64_t)dwShareMode,
        (uint64_t)lpSecurityAttributes,
        (uint64_t)dwCreationDisposition,
        (uint64_t)dwFlagsAndAttributes,
        (uint64_t)hTemplateFile);
}

// FindClose(HANDLE hFindFile) -> BOOL
uint32_t FindClose(uint32_t hFindFile) {
    return (uint32_t)wf_call("kernel32.dll", "FindClose", 1,
        (uint64_t)hFindFile);
}

// FindFirstFile(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) -> HANDLE
uint32_t FindFirstFile(uint32_t lpFileName, uint32_t lpFindFileData) {
    return (uint32_t)wf_call("kernel32.dll", "FindFirstFileW", 2,
        (uint64_t)lpFileName, (uint64_t)lpFindFileData);
}

// FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) -> BOOL
uint32_t FindNextFile(uint32_t hFindFile, uint32_t lpFindFileData) {
    return (uint32_t)wf_call("kernel32.dll", "FindNextFileW", 2,
        (uint64_t)hFindFile, (uint64_t)lpFindFileData);
}

// GetConsoleWindow(void) -> HWND
// Seatbelt's DllImport declaration requires a resolvable symbol even though
// the C# source patches this call out at a higher level.
uint32_t GetConsoleWindow(void) {
    return (uint32_t)wf_call("kernel32.dll", "GetConsoleWindow", 0);
}

// GetLastError(void) -> DWORD
// Use the wf_get_last_error() helper directly — it reads the per-call cached
// error code maintained by the bridge, which is more efficient than a full
// wf_call() round-trip through the host.
uint32_t GetLastError(void) {
    return wf_get_last_error();
}

// GetNamedPipeServerProcessId(HANDLE Pipe, PULONG ServerProcessId) -> BOOL
uint32_t GetNamedPipeServerProcessId(uint32_t Pipe, uint32_t ServerProcessId) {
    return (uint32_t)wf_call("kernel32.dll", "GetNamedPipeServerProcessId", 2,
        (uint64_t)Pipe, (uint64_t)ServerProcessId);
}

// GetNamedPipeServerSessionId(HANDLE Pipe, PULONG ServerSessionId) -> BOOL
uint32_t GetNamedPipeServerSessionId(uint32_t Pipe, uint32_t ServerSessionId) {
    return (uint32_t)wf_call("kernel32.dll", "GetNamedPipeServerSessionId", 2,
        (uint64_t)Pipe, (uint64_t)ServerSessionId);
}

// GetPrivateProfileSection(LPCWSTR lpAppName, LPWSTR lpReturnedString,
//                          DWORD nSize, LPCWSTR lpFileName) -> DWORD
uint32_t GetPrivateProfileSection(uint32_t lpAppName, uint32_t lpReturnedString, uint32_t nSize, uint32_t lpFileName) {
    return (uint32_t)wf_call("kernel32.dll", "GetPrivateProfileSectionW", 4,
        (uint64_t)lpAppName,
        (uint64_t)lpReturnedString,
        (uint64_t)nSize,
        (uint64_t)lpFileName);
}

// GetPrivateProfileString(LPCWSTR lpAppName, LPCWSTR lpKeyName,
//                         LPCWSTR lpDefault, LPWSTR lpReturnedString,
//                         DWORD nSize, LPCWSTR lpFileName) -> DWORD
uint32_t GetPrivateProfileString(uint32_t lpAppName, uint32_t lpKeyName, uint32_t lpDefault, uint32_t lpReturnedString, uint32_t nSize, uint32_t lpFileName) {
    return (uint32_t)wf_call("kernel32.dll", "GetPrivateProfileStringW", 6,
        (uint64_t)lpAppName,
        (uint64_t)lpKeyName,
        (uint64_t)lpDefault,
        (uint64_t)lpReturnedString,
        (uint64_t)nSize,
        (uint64_t)lpFileName);
}

// IsWow64Process(HANDLE hProcess, PBOOL Wow64Process) -> BOOL
uint32_t IsWow64Process(uint32_t hProcess, uint32_t Wow64Process) {
    return (uint32_t)wf_call("kernel32.dll", "IsWow64Process", 2,
        (uint64_t)hProcess, (uint64_t)Wow64Process);
}

// OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
// -> HANDLE
uint32_t OpenProcess(uint32_t dwDesiredAccess, uint32_t bInheritHandle, uint32_t dwProcessId) {
    return (uint32_t)wf_call("kernel32.dll", "OpenProcess", 3,
        (uint64_t)dwDesiredAccess,
        (uint64_t)bInheritHandle,
        (uint64_t)dwProcessId);
}

// ---------------------------------------------------------------------------
// ntdll.dll
// ---------------------------------------------------------------------------

// NtQueryInformationProcess(HANDLE ProcessHandle,
//                           PROCESSINFOCLASS ProcessInformationClass,
//                           PVOID ProcessInformation,
//                           ULONG ProcessInformationLength,
//                           PULONG ReturnLength) -> NTSTATUS (uint32_t)
uint32_t NtQueryInformationProcess(uint32_t ProcessHandle, uint32_t ProcessInformationClass, uint32_t ProcessInformation, uint32_t ProcessInformationLength, uint32_t ReturnLength) {
    return (uint32_t)wf_call("ntdll.dll", "NtQueryInformationProcess", 5,
        (uint64_t)ProcessHandle,
        (uint64_t)ProcessInformationClass,
        (uint64_t)ProcessInformation,
        (uint64_t)ProcessInformationLength,
        (uint64_t)ReturnLength);
}

// ---------------------------------------------------------------------------
// advapi32.dll
// ---------------------------------------------------------------------------

// OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess,
//                  PHANDLE TokenHandle) -> BOOL
// Note: technically advapi32.dll, included here for linker convenience.
// Deduplication against any existing csproj DirectPInvoke entries is handled
// at the project level.
uint32_t OpenProcessToken(uint32_t ProcessHandle, uint32_t DesiredAccess, uint32_t TokenHandle) {
    return (uint32_t)wf_call("advapi32.dll", "OpenProcessToken", 3,
        (uint64_t)ProcessHandle,
        (uint64_t)DesiredAccess,
        (uint64_t)TokenHandle);
}

// ResumeThread(HANDLE hThread) -> DWORD (previous suspend count, or -1 on err).
// Required by Rubeus createnetonly which calls CreateProcessWithLogonW with
// CREATE_SUSPENDED then resumes the created process's primary thread.
uint32_t ResumeThread(uint32_t hThread) {
    return (uint32_t)wf_call("kernel32.dll", "ResumeThread", 1,
        (uint64_t)hThread);
}

// CreateProcessWithLogonW: 11-arg advapi32 call used by Rubeus createnetonly
// to spawn cmd.exe in a netonly logon (LOGON_NETCREDENTIALS_ONLY=0x2) so
// network requests go out with the supplied credentials. Most args are WCHAR*
// pointers in wasm32 memory; ptr_mask 0x7b7 covers them, and out8_mask 0x400
// marks lpProcessInformation as a host-pointer slot the API writes back into.
uint32_t CreateProcessWithLogonW(
    uint32_t lpUsername,
    uint32_t lpDomain,
    uint32_t lpPassword,
    uint32_t dwLogonFlags,
    uint32_t lpApplicationName,
    uint32_t lpCommandLine,
    uint32_t dwCreationFlags,
    uint32_t lpEnvironment,
    uint32_t lpCurrentDirectory,
    uint32_t lpStartupInfo,
    uint32_t lpProcessInformation
) {
    return (uint32_t)wf_call_v2("advapi32.dll", "CreateProcessWithLogonW", 11,
        /*out8_mask=*/0,
        (uint64_t)lpUsername,
        (uint64_t)lpDomain,
        (uint64_t)lpPassword,
        (uint64_t)dwLogonFlags,
        (uint64_t)lpApplicationName,
        (uint64_t)lpCommandLine,
        (uint64_t)dwCreationFlags,
        (uint64_t)lpEnvironment,
        (uint64_t)lpCurrentDirectory,
        (uint64_t)lpStartupInfo,
        (uint64_t)lpProcessInformation);
}

// ---------------------------------------------------------------------------
// user32.dll
// ---------------------------------------------------------------------------

// SetProcessDPIAware(void) -> BOOL
uint32_t SetProcessDPIAware(void) {
    return (uint32_t)wf_call("user32.dll", "SetProcessDPIAware", 0);
}
