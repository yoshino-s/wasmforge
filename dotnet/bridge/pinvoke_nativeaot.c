// pinvoke_nativeaot.c — NativeAOT P/Invoke implementations for WasmForge.
//
// Maps C# [DllImport("kernel32")] etc. to wf_call() bridge calls.
// NativeAOT-WASI links these statically — DllImport("kernel32") resolves
// to kernel32_FunctionName() at link time.
//
// Each function: resolves DLL+proc → calls wf_call() with overflow protection.
//
// COMPILATION:
//   clang --target=wasm32-wasi -O2 -c pinvoke_nativeaot.c -o pinvoke_nativeaot.o
//
// NAMING CONVENTION:
//   C# [DllImport("kernel32", EntryPoint="CreateFileW")]
//   Maps to C function: kernel32_CreateFileW(...)
//
// This file covers the Win32 APIs used by Rubeus and Seatbelt.
// The full production version has 73+ functions; this is the essential subset.

#include "wf_bridge.h"
#include <string.h>

// WF_KEEP — mark a bridge stub as link-time required, so wasm-ld does
// NOT dead-strip it. NativeAOT-LLVM DirectPInvoke resolution creates
// the C# wrapper → C symbol reference lazily during code emit; if the
// linker sweep runs before that reference is materialised in any
// translation unit, the bridge function is dropped as "unused", and
// the resulting runtime call hits "Lazy PInvoke resolution is not
// supported when targeting WebAssembly" (the WASM fallback path
// because the static binding was lost).
//
// `used` + `externally_visible` together cover both clang's local
// optimization passes and LTO sweep. `noinline` keeps the trampoline
// shape so the symbol stays addressable as a function table entry.
#define WF_KEEP __attribute__((used, visibility("default"), noinline))

// ── kernel32.dll ────────────────────────────────────────────────────

uint64_t kernel32_GetCurrentProcess(void) {
    return wf_call("kernel32.dll", "GetCurrentProcess", 0);
}

uint64_t kernel32_GetCurrentThread(void) {
    // GetCurrentThread returns -2 (pseudo-handle). On wasm32 this
    // sign-extends incorrectly if treated as uint32. The bridge
    // handles this by returning the proper pseudo-handle value.
    return wf_call("kernel32.dll", "GetCurrentThread", 0);
}

uint32_t kernel32_GetCurrentProcessId(void) {
    return (uint32_t)wf_call("kernel32.dll", "GetCurrentProcessId", 0);
}

uint32_t kernel32_GetCurrentThreadId(void) {
    return (uint32_t)wf_call("kernel32.dll", "GetCurrentThreadId", 0);
}

uint32_t kernel32_CloseHandle(uint64_t hObject) {
    return (uint32_t)wf_call("kernel32.dll", "CloseHandle", 1,
        hObject);
}

uint32_t kernel32_GetLastError(void) {
    return wf_get_last_error();
}

uint64_t kernel32_CreateToolhelp32Snapshot(uint32_t dwFlags, uint32_t th32ProcessID) {
    return wf_call("kernel32.dll", "CreateToolhelp32Snapshot", 2,
        (uint64_t)dwFlags, (uint64_t)th32ProcessID);
}

uint32_t kernel32_Process32FirstW(uint64_t hSnapshot, uint64_t lppe) {
    return (uint32_t)wf_call("kernel32.dll", "Process32FirstW", 2,
        hSnapshot, lppe);
}

uint32_t kernel32_Process32NextW(uint64_t hSnapshot, uint64_t lppe) {
    return (uint32_t)wf_call("kernel32.dll", "Process32NextW", 2,
        hSnapshot, lppe);
}

uint64_t kernel32_OpenProcess(uint32_t dwDesiredAccess, uint32_t bInheritHandle, uint32_t dwProcessId) {
    return wf_call("kernel32.dll", "OpenProcess", 3,
        (uint64_t)dwDesiredAccess, (uint64_t)bInheritHandle, (uint64_t)dwProcessId);
}

uint32_t kernel32_GetComputerNameW(uint64_t lpBuffer, uint64_t nSize) {
    return (uint32_t)wf_call("kernel32.dll", "GetComputerNameW", 2,
        lpBuffer, nSize);
}

// ── advapi32.dll ────────────────────────────────────────────────────

uint32_t advapi32_OpenProcessToken(uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t TokenHandle) {
    return (uint32_t)wf_call("advapi32.dll", "OpenProcessToken", 3,
        ProcessHandle, (uint64_t)DesiredAccess, TokenHandle);
}

uint32_t advapi32_OpenThreadToken(uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t OpenAsSelf, uint64_t TokenHandle) {
    return (uint32_t)wf_call("advapi32.dll", "OpenThreadToken", 4,
        ThreadHandle, (uint64_t)DesiredAccess, (uint64_t)OpenAsSelf, TokenHandle);
}

uint32_t advapi32_GetTokenInformation(uint64_t TokenHandle, uint32_t TokenInformationClass,
    uint64_t TokenInformation, uint32_t TokenInformationLength, uint64_t ReturnLength) {
    return (uint32_t)wf_call("advapi32.dll", "GetTokenInformation", 5,
        TokenHandle, (uint64_t)TokenInformationClass,
        TokenInformation, (uint64_t)TokenInformationLength, ReturnLength);
}

uint32_t advapi32_DuplicateToken(uint64_t ExistingTokenHandle, uint32_t ImpersonationLevel, uint64_t DuplicateTokenHandle) {
    return (uint32_t)wf_call("advapi32.dll", "DuplicateToken", 3,
        ExistingTokenHandle, (uint64_t)ImpersonationLevel, DuplicateTokenHandle);
}

uint32_t advapi32_DuplicateTokenEx(uint64_t hExistingToken, uint32_t dwDesiredAccess,
    uint64_t lpTokenAttributes, uint32_t ImpersonationLevel, uint32_t TokenType, uint64_t phNewToken) {
    return (uint32_t)wf_call("advapi32.dll", "DuplicateTokenEx", 6,
        hExistingToken, (uint64_t)dwDesiredAccess, lpTokenAttributes,
        (uint64_t)ImpersonationLevel, (uint64_t)TokenType, phNewToken);
}

uint32_t advapi32_ImpersonateLoggedOnUser(uint64_t hToken) {
    return (uint32_t)wf_call("advapi32.dll", "ImpersonateLoggedOnUser", 1, hToken);
}

uint32_t advapi32_RevertToSelf(void) {
    return (uint32_t)wf_call("advapi32.dll", "RevertToSelf", 0);
}

uint32_t advapi32_SetThreadToken(uint64_t Thread, uint64_t Token) {
    return (uint32_t)wf_call("advapi32.dll", "SetThreadToken", 2, Thread, Token);
}

uint32_t advapi32_LookupAccountSidW(uint64_t lpSystemName, uint64_t Sid,
    uint64_t Name, uint64_t cchName, uint64_t ReferencedDomainName,
    uint64_t cchReferencedDomainName, uint64_t peUse) {
    return (uint32_t)wf_call("advapi32.dll", "LookupAccountSidW", 7,
        lpSystemName, Sid, Name, cchName,
        ReferencedDomainName, cchReferencedDomainName, peUse);
}

uint32_t advapi32_LookupPrivilegeValueW(uint64_t lpSystemName, uint64_t lpName, uint64_t lpLuid) {
    return (uint32_t)wf_call("advapi32.dll", "LookupPrivilegeValueW", 3,
        lpSystemName, lpName, lpLuid);
}

uint32_t advapi32_LookupPrivilegeNameW(uint64_t lpSystemName, uint64_t lpLuid,
    uint64_t lpName, uint64_t cchName) {
    return (uint32_t)wf_call("advapi32.dll", "LookupPrivilegeNameW", 4,
        lpSystemName, lpLuid, lpName, cchName);
}

uint32_t advapi32_ConvertSidToStringSidW(uint64_t Sid, uint64_t StringSid) {
    return (uint32_t)wf_call("advapi32.dll", "ConvertSidToStringSidW", 2,
        Sid, StringSid);
}

uint32_t advapi32_ConvertStringSidToSidW(uint64_t StringSid, uint64_t Sid) {
    return (uint32_t)wf_call("advapi32.dll", "ConvertStringSidToSidW", 2,
        StringSid, Sid);
}

uint32_t advapi32_RegOpenKeyExW(uint64_t hKey, uint64_t lpSubKey,
    uint32_t ulOptions, uint32_t samDesired, uint64_t phkResult) {
    return (uint32_t)wf_call("advapi32.dll", "RegOpenKeyExW", 5,
        hKey, lpSubKey, (uint64_t)ulOptions, (uint64_t)samDesired, phkResult);
}

uint32_t advapi32_RegQueryValueExW(uint64_t hKey, uint64_t lpValueName,
    uint64_t lpReserved, uint64_t lpType, uint64_t lpData, uint64_t lpcbData) {
    return (uint32_t)wf_call("advapi32.dll", "RegQueryValueExW", 6,
        hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

uint32_t advapi32_RegCloseKey(uint64_t hKey) {
    return (uint32_t)wf_call("advapi32.dll", "RegCloseKey", 1, hKey);
}

// ── secur32.dll ─────────────────────────────────────────────────────
// NOTE: LSA operations for Rubeus go through the dedicated lsa_kerbop
// host function (LsaHostHelper.cs → WfHostBridge.LsaKerberosOp) which
// runs atomically on the host COM STA thread with SYSTEM impersonation.
// These direct P/Invoke stubs are for lower-level scenarios.

uint32_t secur32_LsaConnectUntrusted(uint64_t LsaHandle) {
    return (uint32_t)wf_call("secur32.dll", "LsaConnectUntrusted", 1, LsaHandle);
}

uint32_t secur32_LsaLookupAuthenticationPackage(uint64_t LsaHandle,
    uint64_t PackageName, uint64_t AuthenticationPackage) {
    return (uint32_t)wf_call("secur32.dll", "LsaLookupAuthenticationPackage", 3,
        LsaHandle, PackageName, AuthenticationPackage);
}

uint32_t secur32_LsaCallAuthenticationPackage(uint64_t LsaHandle,
    uint32_t AuthenticationPackage, uint64_t ProtocolSubmitBuffer,
    uint32_t SubmitBufferLength, uint64_t ProtocolReturnBuffer,
    uint64_t ReturnBufferLength, uint64_t ProtocolStatus) {
    return (uint32_t)wf_call("secur32.dll", "LsaCallAuthenticationPackage", 7,
        LsaHandle, (uint64_t)AuthenticationPackage, ProtocolSubmitBuffer,
        (uint64_t)SubmitBufferLength, ProtocolReturnBuffer,
        ReturnBufferLength, ProtocolStatus);
}

uint32_t secur32_LsaFreeReturnBuffer(uint64_t Buffer) {
    return (uint32_t)wf_call("secur32.dll", "LsaFreeReturnBuffer", 1, Buffer);
}

uint32_t secur32_LsaDeregisterLogonProcess(uint64_t LsaHandle) {
    return (uint32_t)wf_call("secur32.dll", "LsaDeregisterLogonProcess", 1, LsaHandle);
}

uint32_t secur32_LsaEnumerateLogonSessions(uint64_t LogonSessionCount, uint64_t LogonSessionList) {
    return (uint32_t)wf_call("secur32.dll", "LsaEnumerateLogonSessions", 2,
        LogonSessionCount, LogonSessionList);
}

uint32_t secur32_LsaGetLogonSessionData(uint64_t LogonId, uint64_t ppLogonSessionData) {
    return (uint32_t)wf_call("secur32.dll", "LsaGetLogonSessionData", 2,
        LogonId, ppLogonSessionData);
}

// ── cryptdll.dll ────────────────────────────────────────────────────
// Used by Rubeus for encryption type lookups.

uint32_t cryptdll_CDLocateCSystem(uint32_t dwEtype, uint64_t ppCSystem) {
    return (uint32_t)wf_call("cryptdll.dll", "CDLocateCSystem", 2,
        (uint64_t)dwEtype, ppCSystem);
}

// ── netapi32.dll ────────────────────────────────────────────────────

uint32_t netapi32_DsGetDcNameW(uint64_t ComputerName, uint64_t DomainName,
    uint64_t DomainGuid, uint64_t SiteName, uint32_t Flags, uint64_t DomainControllerInfo) {
    return (uint32_t)wf_call("netapi32.dll", "DsGetDcNameW", 6,
        ComputerName, DomainName, DomainGuid, SiteName,
        (uint64_t)Flags, DomainControllerInfo);
}

uint32_t netapi32_NetApiBufferFree(uint64_t Buffer) {
    return (uint32_t)wf_call("netapi32.dll", "NetApiBufferFree", 1, Buffer);
}

// ── iphlpapi.dll ────────────────────────────────────────────────────

uint32_t iphlpapi_GetTcpTable(uint64_t TcpTable, uint64_t SizePointer, uint32_t Order) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetTcpTable", 3,
        TcpTable, SizePointer, (uint64_t)Order);
}

uint32_t iphlpapi_GetUdpTable(uint64_t UdpTable, uint64_t SizePointer, uint32_t Order) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetUdpTable", 3,
        UdpTable, SizePointer, (uint64_t)Order);
}

uint32_t iphlpapi_GetIpNetTable(uint64_t ArpTable, uint64_t SizePointer, uint32_t Order) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetIpNetTable", 3,
        ArpTable, SizePointer, (uint64_t)Order);
}

uint32_t iphlpapi_GetAdaptersInfo(uint64_t AdapterInfo, uint64_t SizePointer) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetAdaptersInfo", 2,
        AdapterInfo, SizePointer);
}

// ── mpr.dll ─────────────────────────────────────────────────────────
// Used by Rubeus for network resource enumeration.

uint32_t mpr_WNetAddConnection2W(uint64_t lpNetResource, uint64_t lpPassword,
    uint64_t lpUserName, uint32_t dwFlags) {
    return (uint32_t)wf_call("mpr.dll", "WNetAddConnection2W", 4,
        lpNetResource, lpPassword, lpUserName, (uint64_t)dwFlags);
}

uint32_t mpr_WNetCancelConnection2W(uint64_t lpName, uint32_t dwFlags, uint32_t fForce) {
    return (uint32_t)wf_call("mpr.dll", "WNetCancelConnection2W", 3,
        lpName, (uint64_t)dwFlags, (uint64_t)fForce);
}

// ── ole32.dll (Certify COM) ──────────────────────────────────────────

uintptr_t ole32_CoInitializeEx(uintptr_t reserved, uintptr_t dwCoInit) {
    return wf_call("ole32.dll", "CoInitializeEx", 2, (uint64_t)reserved, (uint64_t)dwCoInit);
}

uintptr_t ole32_CoInitializeSecurity(uintptr_t pSecDesc, uintptr_t cAuthSvc, uintptr_t asAuthSvc, uintptr_t pReserved1, uintptr_t dwAuthnLevel, uintptr_t dwImpLevel, uintptr_t pAuthList, uintptr_t dwCapabilities, uintptr_t pReserved3) {
    return wf_call("ole32.dll", "CoInitializeSecurity", 9, (uint64_t)pSecDesc, (uint64_t)cAuthSvc, (uint64_t)asAuthSvc, (uint64_t)pReserved1, (uint64_t)dwAuthnLevel, (uint64_t)dwImpLevel, (uint64_t)pAuthList, (uint64_t)dwCapabilities, (uint64_t)pReserved3);
}

uintptr_t ole32_CoCreateInstanceEx(uintptr_t rclsid, uintptr_t punkOuter, uintptr_t dwClsCtx, uintptr_t pServerInfo, uintptr_t dwCount, uintptr_t pResults) {
    return wf_call("ole32.dll", "CoCreateInstanceEx", 6, (uint64_t)rclsid, (uint64_t)punkOuter, (uint64_t)dwClsCtx, (uint64_t)pServerInfo, (uint64_t)dwCount, (uint64_t)pResults);
}

// ── crypt32.dll (Certify certificate ops) ───────────────────────────

uintptr_t crypt32_CertOpenStore(uintptr_t lpszStoreProvider, uintptr_t dwEncodingType, uintptr_t hCryptProv, uintptr_t dwFlags, uintptr_t pvPara) {
    return wf_call("crypt32.dll", "CertOpenStore", 5, (uint64_t)lpszStoreProvider, (uint64_t)dwEncodingType, (uint64_t)hCryptProv, (uint64_t)dwFlags, (uint64_t)pvPara);
}

// ── WfCertStore wrappers (manageself verb) ──────────────────────────
// These declare 8-byte return types and are paired with semanticOverrides
// pointer masks so the host knows which args are real WASM pointers vs
// HOST-pointer handles (HCERTSTORE, PCCERT_CONTEXT) that must pass through.
// The existing crypt32_* wrappers above truncate handles to 4 bytes
// (uintptr_t on wasm32), which is fine when those handles' low halves
// fall under 4GB — but the cert-store enumeration path returns the same
// handle through multiple calls, so a clean 8-byte return surface is
// safer and matches what the C# code expects (ulong).

// CertOpenSystemStoreW returns an 8-byte HCERTSTORE. To avoid the
// uint64-return marshaling path (which appears to mis-handle in C# under
// NativeAOT-WASI and produces wasmMemBase-like garbage), we write the
// raw r0 to an out parameter and return a status code (0=success).
// ── WfCom: fixed-arity wrapper around variadic wf_call_ptr ─────────
//
// NativeAOT-WASI's DllImport requires a fixed signature. The variadic
// wf_call_ptr produces "indirect call type mismatch" traps at runtime
// because the wasm function table entry's signature doesn't match the
// C# call site. This wrapper exposes a fixed 8-arg uint64_t API.
uint64_t wf_call_ptr_fixed8(uint64_t funcptr, int nargs,
    uint32_t ptr_mask, uint32_t out8_mask,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
    return wf_call_ptr(funcptr, nargs, ptr_mask, out8_mask,
        a0, a1, a2, a3, a4, a5, a6, a7);
}

// Fixed-12 variant for COM methods with >8 args (e.g. IWbemLocator::
// ConnectServer takes this+8=9 args). WF_MAX_ARGS in the C variadic
// dispatch is 15, so 12 is well within bounds.
uint64_t wf_call_ptr_fixed12(uint64_t funcptr, int nargs,
    uint32_t ptr_mask, uint32_t out8_mask,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11) {
    return wf_call_ptr(funcptr, nargs, ptr_mask, out8_mask,
        a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

// ── env.mod_hread bare-name wrapper for WfWmiCom ──────────────────
// WfWmiCom.cs declares [DllImport("env", EntryPoint="mod_hread")]
// which requires a C symbol literally named "mod_hread". The bridge
// only exposes the import as wf_host_read_bytes, so we provide a
// bare-name forwarder.
uint32_t mod_hread(uint64_t host_addr, uint32_t len, void* out_buf) {
    return wf_host_read_bytes(host_addr, len, out_buf);
}

// ── env.mod_load / mod_resolve / mod_invoke bare-name forwarders ────
// Same rationale as mod_hread above: lets WfNetapi.cs (and any future
// helper) do [DllImport("env", EntryPoint="mod_load|mod_resolve|
// mod_invoke")] directly from C#. wf_bridge.h declares these env
// imports under wf_load_library / wf_get_proc_address / wf_mod_invoke;
// this file exposes the bare-name aliases NativeAOT-LLVM's
// DirectPInvoke resolver expects. (An earlier session reported these
// breaking Hotfixes — re-verified empirically: Hotfixes was already
// broken in the baseline build for unrelated reasons. These
// forwarders only add new symbols and do not affect existing
// code paths.)
uint32_t mod_load(uint32_t name_ptr) {
    return wf_load_library(name_ptr);
}

uint32_t mod_resolve(uint32_t lib_handle, uint32_t name_ptr) {
    return wf_get_proc_address(lib_handle, name_ptr);
}

uint64_t mod_invoke(
    uint64_t proc_handle, uint32_t nargs,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11,
    uint64_t a12, uint64_t a13, uint64_t a14,
    uint64_t ret1_ptr, uint64_t err_ptr) {
    return wf_mod_invoke(proc_handle, nargs,
        a0, a1, a2, a3, a4, a5, a6, a7,
        a8, a9, a10, a11, a12, a13, a14,
        ret1_ptr, err_ptr);
}

// ── env.mem_* bare-name forwarders ────────────────────────────────────
// Required by DllImport("env", EntryPoint="mem_alloc"/"mem_free"/etc.)
// declarations in WfHost.cs. Without these C-side bare-name symbols,
// NativeAOT-LLVM's DirectPInvoke resolver emits undefined_stub at link
// time and the host-memory allocator path traps at runtime. The actual
// env imports live in wf_bridge.h under the wf_mem_* aliases.
uint32_t mem_alloc(uint32_t size, uint32_t alloc_type, uint32_t protect, uint32_t handle_ptr) {
    return wf_mem_alloc(size, alloc_type, protect, handle_ptr);
}

uint32_t mem_free(int32_t handle) {
    return wf_mem_free(handle);
}

uint32_t mem_write(int32_t handle, uint32_t offset, const void* data_ptr, uint32_t data_len) {
    return wf_mem_write(handle, offset, data_ptr, data_len);
}

uint32_t mem_read(int32_t handle, uint32_t offset, void* buf_ptr, uint32_t buf_len) {
    return wf_mem_read(handle, offset, buf_ptr, buf_len);
}

uint32_t mem_write32(int32_t handle, uint32_t offset, uint32_t value) {
    return wf_mem_write32(handle, offset, value);
}

uint32_t mem_write64(int32_t handle, uint32_t offset, uint32_t value_ptr) {
    return wf_mem_write64(handle, offset, value_ptr);
}

uint32_t mem_read32(int32_t handle, uint32_t offset, uint32_t out_ptr) {
    return wf_mem_read32(handle, offset, out_ptr);
}

uint32_t mem_read64(int32_t handle, uint32_t offset, uint32_t out_ptr) {
    return wf_mem_read64(handle, offset, out_ptr);
}

uint32_t mem_addr(int32_t handle, uint32_t addr_ptr) {
    return wf_mem_addr(handle, addr_ptr);
}

// ── env.fd_* / addr_resolve bare-name forwarders (WfTcp WASI sockets) ───
// Required by DllImport("env", EntryPoint="fd_open"/etc.) declarations in
// dotnet/helpers/WfTcp.cs. Without these C-side bare-name symbols,
// NativeAOT-LLVM's DirectPInvoke="*" resolver emits undefined_stub at
// link time and the TCP path traps at runtime. The actual env imports
// live in wf_bridge.h under wf_sock_* aliases.
uint32_t fd_open(int32_t domain, int32_t socktype, int32_t protocol, int32_t* fd_ptr) {
    return wf_sock_open(domain, socktype, protocol, fd_ptr);
}

uint32_t fd_connect(int32_t fd, const void* addr_ptr, uint32_t addr_len) {
    return wf_sock_connect(fd, addr_ptr, addr_len);
}

uint32_t fd_read2(int32_t fd, void* buf_ptr, uint32_t buf_len, uint32_t* nread_ptr) {
    return wf_sock_read(fd, buf_ptr, buf_len, nread_ptr);
}

uint32_t fd_write2(int32_t fd, const void* buf_ptr, uint32_t buf_len, uint32_t* nwritten_ptr) {
    return wf_sock_write(fd, buf_ptr, buf_len, nwritten_ptr);
}

uint32_t fd_close2(int32_t fd) {
    return wf_sock_close(fd);
}

uint32_t addr_resolve(
    const void* name_ptr, uint32_t name_len,
    const void* svc_ptr, uint32_t svc_len,
    uint32_t hints,
    void* result_ptr, uint32_t max_results,
    uint32_t* n_ptr) {
    return wf_sock_getaddrinfo(name_ptr, name_len, svc_ptr, svc_len, hints,
                               result_ptr, max_results, n_ptr);
}

// ── oleaut32.dll wrappers — VARIANT/BSTR primitives for WfWmiCom ────
uint64_t SysAllocString(uint32_t sz_ptr) {
    return wf_call("oleaut32.dll", "SysAllocString", 1, (uint64_t)sz_ptr);
}

void SysFreeString(uint64_t bstr) {
    wf_call("oleaut32.dll", "SysFreeString", 1, bstr);
}

uint32_t VariantClear(uint32_t pVar) {
    return (uint32_t)wf_call("oleaut32.dll", "VariantClear", 1, (uint64_t)pVar);
}

// ── ole32.dll (CoCreateInstance for WfCom helpers) ─────────────────
// (CoInitializeEx, CoUninitialize already exist as aliases below.)
//
// CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
//   rclsid, riid: pointers to 16-byte GUIDs (in WASM)
//   ppv: pointer to 8-byte output slot (in WASM)
// out8_mask = 0x10 (bit 4 = ppv) so the 4-byte overflow protection
// doesn't zero the high 4 bytes of the returned interface pointer.
uint32_t CoCreateInstance(uint32_t rclsid, uint32_t pUnkOuter,
    uint32_t dwClsContext, uint32_t riid, uint32_t ppv) {
    return (uint32_t)wf_call_v2("ole32.dll", "CoCreateInstance", 5,
        /*out8_mask=*/ 0x10,
        (uint64_t)rclsid, (uint64_t)pUnkOuter,
        (uint64_t)dwClsContext, (uint64_t)riid, (uint64_t)ppv);
}

// CoSetProxyBlanket: set authn/imp posture on a COM proxy. Called after
// IWbemLocator.ConnectServer against restricted WMI namespaces
// (root\SecurityCenter2, ROOT\Subscription) to prevent IUnknown auth
// callbacks during ExecQuery from re-entering WASM and corrupting the
// Go runtime syscall frame. pProxy is the host VA of the IWbemServices
// interface (we receive the WASM mirror address; wf_call's standard
// mirror reverse-translation step kicks in for it).
uint32_t CoSetProxyBlanket(uint32_t pProxy, uint32_t dwAuthnSvc, uint32_t dwAuthzSvc,
    uint32_t pServerPrincName, uint32_t dwAuthnLevel, uint32_t dwImpLevel,
    uint32_t pAuthInfo, uint32_t dwCapabilities) {
    return (uint32_t)wf_call("ole32.dll", "CoSetProxyBlanket", 8,
        (uint64_t)pProxy, (uint64_t)dwAuthnSvc, (uint64_t)dwAuthzSvc,
        (uint64_t)pServerPrincName, (uint64_t)dwAuthnLevel, (uint64_t)dwImpLevel,
        (uint64_t)pAuthInfo, (uint64_t)dwCapabilities);
}

uint32_t WfCertStore_OpenSystemStoreW(uint32_t hCryptProv, uint32_t lpszStoreName, uint64_t* phStoreOut) {
    uint64_t r0 = wf_call("crypt32.dll", "CertOpenSystemStoreW", 2,
        (uint64_t)hCryptProv, (uint64_t)lpszStoreName);
    if (phStoreOut != 0) {
        *phStoreOut = r0;
    }
    if (r0 == 0) return wf_get_last_error() != 0 ? wf_get_last_error() : 1;
    return 0;
}

// CertEnumCertificatesInStore also returns 8-byte PCCERT_CONTEXT — same
// pattern: out param avoids the C# 8-byte-return marshaling issue.
// Returns 0 on success (handle written), 1 when no more entries.
uint32_t WfCertStore_EnumCertificatesInStore(uint64_t hCertStore, uint64_t pPrevCertContext, uint64_t* pCertOut) {
    uint64_t r0 = wf_call("crypt32.dll", "CertEnumCertificatesInStore", 2,
        hCertStore, pPrevCertContext);
    if (pCertOut != 0) {
        *pCertOut = r0;
    }
    return r0 == 0 ? 1 : 0;
}

uint32_t WfCertStore_GetNameStringW(uint64_t pCertContext, uint32_t dwType, uint32_t dwFlags,
    uint32_t pvTypePara, uint32_t pszNameString, uint32_t cchNameString) {
    // arg 0 pCertContext = HOST ptr (no translate)
    // arg 4 pszNameString = WASM out buffer (translate, skip overflow protection)
    // out8_mask = 0x10 (bit 4) so the C bridge's 4-byte overflow protection
    // doesn't zero out buf[4..7] of the output wide-char buffer.
    return (uint32_t)wf_call_v2("crypt32.dll", "CertGetNameStringW", 6,
        /*out8_mask=*/ 0x10,
        pCertContext, (uint64_t)dwType, (uint64_t)dwFlags,
        (uint64_t)pvTypePara, (uint64_t)pszNameString, (uint64_t)cchNameString);
}

uint32_t WfCertStore_CloseStore(uint64_t hCertStore, uint32_t dwFlags) {
    return (uint32_t)wf_call("crypt32.dll", "CertCloseStore", 2,
        hCertStore, (uint64_t)dwFlags);
}

uintptr_t crypt32_CertCloseStore(uintptr_t hCertStore, uintptr_t dwFlags) {
    return wf_call("crypt32.dll", "CertCloseStore", 2, (uint64_t)hCertStore, (uint64_t)dwFlags);
}

uintptr_t crypt32_CertEnumCertificatesInStore(uintptr_t hCertStore, uintptr_t pPrevCertContext) {
    return wf_call("crypt32.dll", "CertEnumCertificatesInStore", 2, (uint64_t)hCertStore, (uint64_t)pPrevCertContext);
}

uintptr_t crypt32_CertFreeCertificateContext(uintptr_t pCertContext) {
    return wf_call("crypt32.dll", "CertFreeCertificateContext", 1, (uint64_t)pCertContext);
}

uintptr_t crypt32_CertGetCertificateChain(uintptr_t hChainEngine, uintptr_t pCertContext, uintptr_t pTime, uintptr_t hAdditionalStore, uintptr_t pChainPara, uintptr_t dwFlags, uintptr_t pvReserved, uintptr_t ppChainContext) {
    return wf_call("crypt32.dll", "CertGetCertificateChain", 8, (uint64_t)hChainEngine, (uint64_t)pCertContext, (uint64_t)pTime, (uint64_t)hAdditionalStore, (uint64_t)pChainPara, (uint64_t)dwFlags, (uint64_t)pvReserved, (uint64_t)ppChainContext);
}

uintptr_t crypt32_CertFreeCertificateChain(uintptr_t pChainContext) {
    return wf_call("crypt32.dll", "CertFreeCertificateChain", 1, (uint64_t)pChainContext);
}

uintptr_t crypt32_CertAddCertificateContextToStore(uintptr_t hCertStore, uintptr_t pCertContext, uintptr_t dwAddDisposition, uintptr_t ppStoreContext) {
    return wf_call("crypt32.dll", "CertAddCertificateContextToStore", 4, (uint64_t)hCertStore, (uint64_t)pCertContext, (uint64_t)dwAddDisposition, (uint64_t)ppStoreContext);
}

uintptr_t crypt32_CertAddEncodedCertificateToStore(uintptr_t hCertStore, uintptr_t dwCertEncodingType, uintptr_t pbCertEncoded, uintptr_t cbCertEncoded, uintptr_t dwAddDisposition, uintptr_t ppCertContext) {
    return wf_call("crypt32.dll", "CertAddEncodedCertificateToStore", 6, (uint64_t)hCertStore, (uint64_t)dwCertEncodingType, (uint64_t)pbCertEncoded, (uint64_t)cbCertEncoded, (uint64_t)dwAddDisposition, (uint64_t)ppCertContext);
}

// CryptEncodeObjectEx: pvEncoded (arg 5) is the output byte buffer (>=8 bytes
// when caller asks for >4-byte structures), pcbEncoded (arg 6) is a ULONG
// in/out (4-byte). out8_mask=0x20 protects arg 5. Explicit uint64_t casts
// avoid the wasm32 va_arg(uint64_t)-reads-4-byte-slot bug fixed for LSA in
// commit facc51d.
uintptr_t crypt32_CryptEncodeObjectEx(uintptr_t dwCertEncodingType, uintptr_t lpszStructType, uintptr_t pvStructInfo, uintptr_t dwFlags, uintptr_t pEncodePara, uintptr_t pvEncoded, uintptr_t pcbEncoded) {
    return wf_call_v2("crypt32.dll", "CryptEncodeObjectEx", 7, /*out8_mask=*/ 0x20,
        (uint64_t)dwCertEncodingType, (uint64_t)lpszStructType,
        (uint64_t)pvStructInfo, (uint64_t)dwFlags, (uint64_t)pEncodePara,
        (uint64_t)pvEncoded, (uint64_t)pcbEncoded);
}

uintptr_t crypt32_PFXExportCertStoreEx(uintptr_t hStore, uintptr_t pPFX, uintptr_t szPassword, uintptr_t pvPara, uintptr_t dwFlags) {
    return wf_call("crypt32.dll", "PFXExportCertStoreEx", 5, (uint64_t)hStore, (uint64_t)pPFX, (uint64_t)szPassword, (uint64_t)pvPara, (uint64_t)dwFlags);
}

// CertGetCertificateContextProperty: pvData and pcbData are both WASM output
// pointers. out8_mask = 0xC (bits 2+3 = args 2+3) prevents the 4-byte
// overflow protection from zeroing the high half of either out parameter.
uint32_t crypt32_CertGetCertificateContextProperty(uint64_t pCertContext, uint32_t dwPropId,
    uint32_t pvData, uint32_t pcbData) {
    return (uint32_t)wf_call_v2("crypt32.dll", "CertGetCertificateContextProperty", 4,
        /*out8_mask=*/0xC, pCertContext, (uint64_t)dwPropId,
        (uint64_t)pvData, (uint64_t)pcbData);
}

// WfCertStore_OpenStore — open a system certificate store with explicit
// location. isLocalMachine=0 → CurrentUser (0x00010000),
// isLocalMachine=1 → LocalMachine (0x00020000).
// The flags are computed in C (not passed from C#) to avoid the wf_call
// is_wasm_ptr heuristic misidentifying 0x00010000/0x00020000 as WASM ptrs.
uint32_t WfCertStore_OpenStore(uint32_t lpszStoreName, uint32_t isLocalMachine, uint64_t* phStoreOut) {
    // CERT_STORE_PROV_SYSTEM_W  = 10
    // CERT_SYSTEM_STORE_CURRENT_USER  = 0x00010000
    // CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
    // encoding mask (ignored for PROV_SYSTEM_W, pass 0)
    uint32_t flags = isLocalMachine ? 0x00020000u : 0x00010000u;
    uint64_t r0 = wf_call("crypt32.dll", "CertOpenStore", 5,
        (uint64_t)10u, (uint64_t)0u, (uint64_t)0u,
        (uint64_t)flags, (uint64_t)lpszStoreName);
    if (phStoreOut != 0) *phStoreOut = r0;
    if (r0 == 0) return wf_get_last_error() != 0 ? wf_get_last_error() : 1;
    return 0;
}

// ── version.dll (FileVersionInfo for ChromiumPresence et al) ────────
uint32_t version_GetFileVersionInfoSizeW(uint32_t lptstrFilename, uint32_t lpdwHandle) {
    return (uint32_t)wf_call_v2("version.dll", "GetFileVersionInfoSizeW", 2,
        /*out8_mask=*/0x2, (uint64_t)lptstrFilename, (uint64_t)lpdwHandle);
}
uint32_t version_GetFileVersionInfoW(uint32_t lptstrFilename, uint32_t dwHandle,
    uint32_t dwLen, uint32_t lpData) {
    return (uint32_t)wf_call_v2("version.dll", "GetFileVersionInfoW", 4,
        /*out8_mask=*/0x8, (uint64_t)lptstrFilename, (uint64_t)dwHandle,
        (uint64_t)dwLen, (uint64_t)lpData);
}
uint32_t version_VerQueryValueW(uint32_t pBlock, uint32_t lpSubBlock,
    uint32_t lplpBuffer, uint32_t puLen) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        /*out8_mask=*/0xC, (uint64_t)pBlock, (uint64_t)lpSubBlock,
        (uint64_t)lplpBuffer, (uint64_t)puLen);
}

// ── uint64_t-safe v2 wrappers (version.dll + crypt32.dll) ─────────────────
//
// NativeAOT-WASI compiles to wasm32: all pointers are 4 bytes in the WASM
// linear memory.  However WfFileVersionInfo.cs and WfX509Store.cs declare
// these P/Invokes with `ulong` (8-byte) parameters so the ABI on the
// WASM→C boundary passes each arg as a 64-bit value.  The _v2 variants
// accept uint64_t directly and forward without truncating through uint32_t.

// version_GetFileVersionInfoSizeW_v2 — uint64_t-safe.
// lptstrFilename: host address of the path string (8 bytes).
// lpdwHandle: host address of the dwHandle output dword (8 bytes, out8_mask
// bit 1 = 0x2 prevents 4-byte overflow protection from zeroing the high half).
uint32_t version_GetFileVersionInfoSizeW_v2(uint64_t lptstrFilename, uint64_t lpdwHandle) {
    return (uint32_t)wf_call_v2("version.dll", "GetFileVersionInfoSizeW", 2,
        /*out8_mask=*/0x2, lptstrFilename, lpdwHandle);
}

// version_GetFileVersionInfoW_v2 — uint64_t-safe.
// lptstrFilename: host address of path string (8 bytes).
// lpData: host address of the version-info blob output buffer (8 bytes,
// out8_mask bit 3 = 0x8).  dwHandle and dwLen are plain scalars (uint32).
uint32_t version_GetFileVersionInfoW_v2(uint64_t lptstrFilename, uint32_t dwHandle,
    uint32_t dwLen, uint64_t lpData) {
    return (uint32_t)wf_call_v2("version.dll", "GetFileVersionInfoW", 4,
        /*out8_mask=*/0x8, lptstrFilename, (uint64_t)dwHandle,
        (uint64_t)dwLen, lpData);
}

// version_VerQueryValueW_v2 — uint64_t-safe.
// pBlock: host address of the version-info blob (8 bytes).
// lpSubBlock: host address of the sub-block path string (8 bytes).
// lplpBuffer: host address where the value pointer is written back (8 bytes,
// out8_mask bit 2 = 0x4).
// puLen: host address where the value length is written back (8 bytes,
// out8_mask bit 3 = 0x8).  Combined out8_mask = 0xC (bits 2+3).
uint32_t version_VerQueryValueW_v2(uint64_t pBlock, uint64_t lpSubBlock,
    uint64_t lplpBuffer, uint64_t puLen) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        /*out8_mask=*/0xC, pBlock, lpSubBlock, lplpBuffer, puLen);
}

// WfCertStore_OpenStore_v2 — uint64_t-safe variant.
// lpszStoreName: host address of the store-name wide string (8 bytes).
// isLocalMachine: scalar 0/1 (uint32), computed flag stays in C (same quirk
// as v1 to prevent is_wasm_ptr misidentifying 0x10000/0x20000 as WASM ptrs).
// phStoreOut: host address of the HCERTSTORE output slot (8 bytes).
// WfCertStore_OpenStore_v2: same signature shape as v1 (writes to WASM-side
// pointer), but accepts uint64_t for lpszStoreName so 8-byte host addresses
// don't get truncated by uint32_t. phStoreOut is a WASM-side pointer to a
// uint64_t slot (C# `out ulong`), which is safe to deref in C code because
// wasm32 already addresses WASM memory natively.
uint32_t WfCertStore_OpenStore_v2(uint64_t lpszStoreName, uint32_t isLocalMachine, uint64_t* phStoreOut) {
    uint32_t flags = isLocalMachine ? 0x00020000u : 0x00010000u;
    uint64_t r0 = wf_call("crypt32.dll", "CertOpenStore", 5,
        (uint64_t)10u, (uint64_t)0u, (uint64_t)0u,
        (uint64_t)flags, lpszStoreName);
    if (phStoreOut != 0) *phStoreOut = r0;
    if (r0 == 0) return wf_get_last_error() != 0 ? wf_get_last_error() : 1;
    return 0;
}

// WfCertStore_GetNameStringW_v2 — uint64_t-safe variant.
// pCertContext: 8-byte host PCCERT_CONTEXT handle.
// pvTypePara: host pointer for type-specific parameter (8 bytes).
// pszNameString: host address of the wide-char output buffer (8 bytes,
// out8_mask bit 4 = 0x10 prevents overflow-protection from zeroing buf[4..7]).
// dwType, dwFlags, cchNameString are scalars (uint32).
uint32_t WfCertStore_GetNameStringW_v2(uint64_t pCertContext, uint32_t dwType, uint32_t dwFlags,
    uint64_t pvTypePara, uint64_t pszNameString, uint32_t cchNameString) {
    return (uint32_t)wf_call_v2("crypt32.dll", "CertGetNameStringW", 6,
        /*out8_mask=*/0x10,
        pCertContext, (uint64_t)dwType, (uint64_t)dwFlags,
        pvTypePara, pszNameString, (uint64_t)cchNameString);
}

// crypt32_CertGetCertificateContextProperty_v2 — uint64_t-safe variant.
// pCertContext: 8-byte host PCCERT_CONTEXT handle.
// pvData: host address of the data buffer (8 bytes, out8_mask bit 2 = 0x4).
// pcbData: host address of the size DWORD (8 bytes, out8_mask bit 3 = 0x8).
// Combined out8_mask = 0xC (bits 2+3).  dwPropId is a scalar (uint32).
uint32_t crypt32_CertGetCertificateContextProperty_v2(uint64_t pCertContext, uint32_t dwPropId,
    uint64_t pvData, uint64_t pcbData) {
    return (uint32_t)wf_call_v2("crypt32.dll", "CertGetCertificateContextProperty", 4,
        /*out8_mask=*/0xC, pCertContext, (uint64_t)dwPropId, pvData, pcbData);
}

// ── secur32.dll (Certify SSPI) ───────────────────────────────────────

uintptr_t secur32_AcquireCredentialsHandleW(uintptr_t pszPrincipal, uintptr_t pszPackage, uintptr_t fCredentialUse, uintptr_t pvLogonId, uintptr_t pAuthData, uintptr_t pGetKeyFn, uintptr_t pvGetKeyArgument, uintptr_t phCredential, uintptr_t ptsExpiry) {
    return wf_call("secur32.dll", "AcquireCredentialsHandleW", 9, (uint64_t)pszPrincipal, (uint64_t)pszPackage, (uint64_t)fCredentialUse, (uint64_t)pvLogonId, (uint64_t)pAuthData, (uint64_t)pGetKeyFn, (uint64_t)pvGetKeyArgument, (uint64_t)phCredential, (uint64_t)ptsExpiry);
}

uintptr_t secur32_InitializeSecurityContextW(uintptr_t phCredential, uintptr_t phContext, uintptr_t pszTargetName, uintptr_t fContextReq, uintptr_t Reserved1, uintptr_t TargetDataRep, uintptr_t pInput, uintptr_t Reserved2, uintptr_t phNewContext, uintptr_t pOutput, uintptr_t pfContextAttr, uintptr_t ptsExpiry) {
    return wf_call("secur32.dll", "InitializeSecurityContextW", 12, (uint64_t)phCredential, (uint64_t)phContext, (uint64_t)pszTargetName, (uint64_t)fContextReq, (uint64_t)Reserved1, (uint64_t)TargetDataRep, (uint64_t)pInput, (uint64_t)Reserved2, (uint64_t)phNewContext, (uint64_t)pOutput, (uint64_t)pfContextAttr, (uint64_t)ptsExpiry);
}

uintptr_t secur32_DeleteSecurityContext(uintptr_t phContext) {
    return wf_call("secur32.dll", "DeleteSecurityContext", 1, (uint64_t)phContext);
}

uintptr_t secur32_FreeCredentialsHandle(uintptr_t phCredential) {
    return wf_call("secur32.dll", "FreeCredentialsHandle", 1, (uint64_t)phCredential);
}

uintptr_t secur32_QueryContextAttributesW(uintptr_t phContext, uintptr_t ulAttribute, uintptr_t pBuffer) {
    return wf_call("secur32.dll", "QueryContextAttributesW", 3, (uint64_t)phContext, (uint64_t)ulAttribute, (uint64_t)pBuffer);
}

// ── kernel32.dll (Certify + SharpDPAPI) ─────────────────────────────

uintptr_t kernel32_LocalAlloc(uintptr_t uFlags, uintptr_t uBytes) {
    return wf_call("kernel32.dll", "LocalAlloc", 2, (uint64_t)uFlags, (uint64_t)uBytes);
}

uintptr_t kernel32_LocalFree(uintptr_t hMem) {
    return wf_call("kernel32.dll", "LocalFree", 1, (uint64_t)hMem);
}

// ── ntdll.dll (Certify) ──────────────────────────────────────────────

uintptr_t ntdll_NtQuerySystemTime(uintptr_t SystemTime) {
    return wf_call("ntdll.dll", "NtQuerySystemTime", 1, (uint64_t)SystemTime);
}

// ── advapi32.dll (SharpDPAPI registry + LSA) ────────────────────────

uintptr_t advapi32_RegQueryInfoKeyW(uintptr_t hKey, uintptr_t lpClass, uintptr_t lpcchClass, uintptr_t lpReserved, uintptr_t lpcSubKeys, uintptr_t lpcbMaxSubKeyLen, uintptr_t lpcbMaxClassLen, uintptr_t lpcValues, uintptr_t lpcbMaxValueNameLen, uintptr_t lpcbMaxValueLen, uintptr_t lpcbSecurityDescriptor, uintptr_t lpftLastWriteTime) {
    return wf_call("advapi32.dll", "RegQueryInfoKeyW", 12, (uint64_t)hKey, (uint64_t)lpClass, (uint64_t)lpcchClass, (uint64_t)lpReserved, (uint64_t)lpcSubKeys, (uint64_t)lpcbMaxSubKeyLen, (uint64_t)lpcbMaxClassLen, (uint64_t)lpcValues, (uint64_t)lpcbMaxValueNameLen, (uint64_t)lpcbMaxValueLen, (uint64_t)lpcbSecurityDescriptor, (uint64_t)lpftLastWriteTime);
}

// LsaOpenPolicy: PolicyHandle (arg 3) is an `out LSA_HANDLE` — 8-byte slot.
// out8_mask=0x8 prevents the default 4-byte protection from zeroing bytes
// 4-7 of the handle. Same fix applied to LsaEnumerateAccountsWithUserRight
// and the bcrypt wrappers (commit 0e4bde1) — minimum LSA harness caught the
// crash with all three previous variants of this bug.
uintptr_t advapi32_LsaOpenPolicy(uintptr_t SystemName, uintptr_t ObjectAttributes, uintptr_t DesiredAccess, uintptr_t PolicyHandle) {
    // Explicit uint64_t casts: wf_call_v2 reads varargs with va_arg(ap, uint64_t).
    // uintptr_t is 4 bytes on wasm32, so without the cast va_arg reads 8 bytes
    // from a 4-byte stack slot, pulling adjacent garbage into the high half of
    // each arg. The host then sees a 64-bit value whose high 32 bits are
    // random — passing it to LsaOpenPolicy as RCX/RDX/R8/R9 corrupts the
    // ObjectAttributes / PolicyHandle pointer addresses and triggers a
    // 0xC0000005 access violation deep in advapi32.
    return wf_call_v2("advapi32.dll", "LsaOpenPolicy", 4, /*out8_mask=*/ 0x8,
        (uint64_t)SystemName, (uint64_t)ObjectAttributes,
        (uint64_t)DesiredAccess, (uint64_t)PolicyHandle);
}

uintptr_t advapi32_LsaRetrievePrivateData(uintptr_t PolicyHandle, uintptr_t KeyName, uintptr_t PrivateData) {
    return wf_call("advapi32.dll", "LsaRetrievePrivateData", 3, (uint64_t)PolicyHandle, (uint64_t)KeyName, (uint64_t)PrivateData);
}

uintptr_t advapi32_LsaClose(uintptr_t ObjectHandle) {
    return wf_call("advapi32.dll", "LsaClose", 1, (uint64_t)ObjectHandle);
}

uintptr_t advapi32_LsaFreeMemory(uintptr_t Buffer) {
    return wf_call("advapi32.dll", "LsaFreeMemory", 1, (uint64_t)Buffer);
}

uintptr_t advapi32_LsaNtStatusToWinError(uintptr_t Status) {
    return wf_call("advapi32.dll", "LsaNtStatusToWinError", 1, (uint64_t)Status);
}

uintptr_t advapi32_GetSidSubAuthority(uintptr_t pSid, uintptr_t nSubAuthority) {
    return wf_call("advapi32.dll", "GetSidSubAuthority", 2, (uint64_t)pSid, (uint64_t)nSubAuthority);
}

uintptr_t advapi32_GetSidSubAuthorityCount(uintptr_t pSid) {
    return wf_call("advapi32.dll", "GetSidSubAuthorityCount", 1, (uint64_t)pSid);
}

uintptr_t advapi32_SystemFunction032(uintptr_t memoryRegion, uintptr_t keyPointer) {
    return wf_call("advapi32.dll", "SystemFunction032", 2, (uint64_t)memoryRegion, (uint64_t)keyPointer);
}

// ── ncrypt.dll (SharpDPAPI CNG) ──────────────────────────────────────

// NCryptOpenStorageProvider: phProvider (arg 0) is `out NCRYPT_PROV_HANDLE` —
// 8-byte slot. out8_mask=0x1.
uintptr_t ncrypt_NCryptOpenStorageProvider(uintptr_t phProvider, uintptr_t pszProviderName, uintptr_t dwFlags) {
    return wf_call_v2("ncrypt.dll", "NCryptOpenStorageProvider", 3, /*out8_mask=*/ 0x1,
        (uint64_t)phProvider, (uint64_t)pszProviderName, (uint64_t)dwFlags);
}

// NCryptImportKey: phKey (arg 4) is `out NCRYPT_KEY_HANDLE` — 8-byte slot.
// out8_mask=0x10.
uintptr_t ncrypt_NCryptImportKey(uintptr_t hProvider, uintptr_t hImportKey, uintptr_t pszBlobType, uintptr_t pParameterList, uintptr_t phKey, uintptr_t pbData, uintptr_t cbData, uintptr_t dwFlags) {
    return wf_call_v2("ncrypt.dll", "NCryptImportKey", 8, /*out8_mask=*/ 0x10,
        (uint64_t)hProvider, (uint64_t)hImportKey,
        (uint64_t)pszBlobType, (uint64_t)pParameterList,
        (uint64_t)phKey, (uint64_t)pbData, (uint64_t)cbData,
        (uint64_t)dwFlags);
}

// NCryptExportKey: pbOutput (arg 4) is output buffer (>=8 bytes typical).
// out8_mask=0x10.
uintptr_t ncrypt_NCryptExportKey(uintptr_t hKey, uintptr_t hExportKey, uintptr_t pszBlobType, uintptr_t pParameterList, uintptr_t pbOutput, uintptr_t cbOutput, uintptr_t pcbResult, uintptr_t dwFlags) {
    return wf_call_v2("ncrypt.dll", "NCryptExportKey", 8, /*out8_mask=*/ 0x10,
        (uint64_t)hKey, (uint64_t)hExportKey,
        (uint64_t)pszBlobType, (uint64_t)pParameterList,
        (uint64_t)pbOutput, (uint64_t)cbOutput,
        (uint64_t)pcbResult, (uint64_t)dwFlags);
}

uintptr_t ncrypt_NCryptSetProperty(uintptr_t hObject, uintptr_t pszProperty, uintptr_t pbInput, uintptr_t cbInput, uintptr_t dwFlags) {
    return wf_call("ncrypt.dll", "NCryptSetProperty", 5, (uint64_t)hObject, (uint64_t)pszProperty, (uint64_t)pbInput, (uint64_t)cbInput, (uint64_t)dwFlags);
}

uintptr_t ncrypt_NCryptFinalizeKey(uintptr_t hKey, uintptr_t dwFlags) {
    return wf_call("ncrypt.dll", "NCryptFinalizeKey", 2, (uint64_t)hKey, (uint64_t)dwFlags);
}

uintptr_t ncrypt_NCryptFreeObject(uintptr_t hObject) {
    return wf_call("ncrypt.dll", "NCryptFreeObject", 1, (uint64_t)hObject);
}

// ── shlwapi.dll (SharpDPAPI) ─────────────────────────────────────────

uintptr_t shlwapi_PathIsUNCW(uintptr_t pszPath) {
    return wf_call("shlwapi.dll", "PathIsUNCW", 1, (uint64_t)pszPath);
}

// ── advapi32.dll (SharpDPAPI DES decrypt) ───────────────────────────
// RtlDecryptDES2blocks1DWORD is exported as SystemFunction025 in advapi32.dll.

uintptr_t advapi32_RtlDecryptDES2blocks1DWORD(uintptr_t data, uintptr_t key, uintptr_t output) {
    return wf_call("advapi32.dll", "SystemFunction025", 3, (uint64_t)data, (uint64_t)key, (uint64_t)output);
}

// ── advapi32.dll (IsTextUnicode) ─────────────────────────────────────

uintptr_t advapi32_IsTextUnicode(uintptr_t lpv, uintptr_t iSize, uintptr_t lpiResult) {
    return wf_call("advapi32.dll", "IsTextUnicode", 3, (uint64_t)lpv, (uint64_t)iSize, (uint64_t)lpiResult);
}

// ── rpcrt4.dll (SharpDPAPI MS-BKRP) ─────────────────────────────────

uintptr_t rpcrt4_RpcStringBindingComposeW(uintptr_t ObjUuid, uintptr_t ProtSeq, uintptr_t NetworkAddr, uintptr_t Endpoint, uintptr_t Options, uintptr_t StringBinding) {
    return wf_call("rpcrt4.dll", "RpcStringBindingComposeW", 6, (uint64_t)ObjUuid, (uint64_t)ProtSeq, (uint64_t)NetworkAddr, (uint64_t)Endpoint, (uint64_t)Options, (uint64_t)StringBinding);
}

uintptr_t rpcrt4_RpcBindingFromStringBindingW(uintptr_t StringBinding, uintptr_t Binding) {
    return wf_call("rpcrt4.dll", "RpcBindingFromStringBindingW", 2, (uint64_t)StringBinding, (uint64_t)Binding);
}

uintptr_t rpcrt4_RpcBindingSetAuthInfoExW(uintptr_t Binding, uintptr_t ServerPrincName, uintptr_t AuthnLevel, uintptr_t AuthnSvc, uintptr_t AuthIdentity, uintptr_t AuthzSvc, uintptr_t SecurityQOS) {
    return wf_call("rpcrt4.dll", "RpcBindingSetAuthInfoExW", 7, (uint64_t)Binding, (uint64_t)ServerPrincName, (uint64_t)AuthnLevel, (uint64_t)AuthnSvc, (uint64_t)AuthIdentity, (uint64_t)AuthzSvc, (uint64_t)SecurityQOS);
}

uintptr_t rpcrt4_RpcBindingSetOption(uintptr_t hBinding, uintptr_t option, uintptr_t optionValue) {
    return wf_call("rpcrt4.dll", "RpcBindingSetOption", 3, (uint64_t)hBinding, (uint64_t)option, (uint64_t)optionValue);
}

uintptr_t rpcrt4_RpcBindingFree(uintptr_t Binding) {
    return wf_call("rpcrt4.dll", "RpcBindingFree", 1, (uint64_t)Binding);
}

uintptr_t rpcrt4_I_RpcBindingInqSecurityContext(uintptr_t Binding, uintptr_t SecurityContextHandle) {
    return wf_call("rpcrt4.dll", "I_RpcBindingInqSecurityContext", 2, (uint64_t)Binding, (uint64_t)SecurityContextHandle);
}

// NdrClientCall2 is a variadic NDR marshalling function. We bridge it with
// up to 12 args total (pStubDescriptor + pFormatString + 10 variable args)
// to cover typical MS-BKRP usage.
uintptr_t rpcrt4_NdrClientCall2(uintptr_t pStubDescriptor, uintptr_t pFormatString,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5,
    uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9, uintptr_t a10) {
    return wf_call("rpcrt4.dll", "NdrClientCall2", 12, (uint64_t)pStubDescriptor, (uint64_t)pFormatString, (uint64_t)a1, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (uint64_t)a5, (uint64_t)a6, (uint64_t)a7, (uint64_t)a8, (uint64_t)a9, (uint64_t)a10);
}

// ── Bare-name aliases ─────────────────────────────────────────────────
//
// NativeAOT DirectPInvoke looks for the bare function name when DllImport
// uses a name with the .dll extension (e.g. [DllImport("ole32.dll")]).
// Without the .dll suffix (e.g. [DllImport("kernel32")]) it uses the
// dll_FunctionName convention already implemented above.  These aliases
// make both conventions work by delegating to the prefixed versions.

// ole32.dll
uintptr_t CoInitializeEx(uintptr_t reserved, uintptr_t dwCoInit) {
    return ole32_CoInitializeEx(reserved, dwCoInit);
}

uintptr_t CoInitializeSecurity(uintptr_t pSecDesc, uintptr_t cAuthSvc, uintptr_t asAuthSvc, uintptr_t pReserved1, uintptr_t dwAuthnLevel, uintptr_t dwImpLevel, uintptr_t pAuthList, uintptr_t dwCapabilities, uintptr_t pReserved3) {
    return ole32_CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
}

uintptr_t CoCreateInstanceEx(uintptr_t rclsid, uintptr_t punkOuter, uintptr_t dwClsCtx, uintptr_t pServerInfo, uintptr_t dwCount, uintptr_t pResults) {
    return ole32_CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);
}

// crypt32.dll
uintptr_t CertOpenStore(uintptr_t lpszStoreProvider, uintptr_t dwEncodingType, uintptr_t hCryptProv, uintptr_t dwFlags, uintptr_t pvPara) {
    return crypt32_CertOpenStore(lpszStoreProvider, dwEncodingType, hCryptProv, dwFlags, pvPara);
}

uintptr_t CertCloseStore(uintptr_t hCertStore, uintptr_t dwFlags) {
    return crypt32_CertCloseStore(hCertStore, dwFlags);
}

uintptr_t CertEnumCertificatesInStore(uintptr_t hCertStore, uintptr_t pPrevCertContext) {
    return crypt32_CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
}

uintptr_t CertFreeCertificateContext(uintptr_t pCertContext) {
    return crypt32_CertFreeCertificateContext(pCertContext);
}

uintptr_t CertGetCertificateChain(uintptr_t hChainEngine, uintptr_t pCertContext, uintptr_t pTime, uintptr_t hAdditionalStore, uintptr_t pChainPara, uintptr_t dwFlags, uintptr_t pvReserved, uintptr_t ppChainContext) {
    return crypt32_CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext);
}

uintptr_t CertFreeCertificateChain(uintptr_t pChainContext) {
    return crypt32_CertFreeCertificateChain(pChainContext);
}

uintptr_t CertAddCertificateContextToStore(uintptr_t hCertStore, uintptr_t pCertContext, uintptr_t dwAddDisposition, uintptr_t ppStoreContext) {
    return crypt32_CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext);
}

uintptr_t CertAddEncodedCertificateToStore(uintptr_t hCertStore, uintptr_t dwCertEncodingType, uintptr_t pbCertEncoded, uintptr_t cbCertEncoded, uintptr_t dwAddDisposition, uintptr_t ppCertContext) {
    return crypt32_CertAddEncodedCertificateToStore(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}

uintptr_t CryptEncodeObjectEx(uintptr_t dwCertEncodingType, uintptr_t lpszStructType, uintptr_t pvStructInfo, uintptr_t dwFlags, uintptr_t pEncodePara, uintptr_t pvEncoded, uintptr_t pcbEncoded) {
    return crypt32_CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded);
}

uintptr_t PFXExportCertStoreEx(uintptr_t hStore, uintptr_t pPFX, uintptr_t szPassword, uintptr_t pvPara, uintptr_t dwFlags) {
    return crypt32_PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags);
}

// secur32.dll
uintptr_t AcquireCredentialsHandleW(uintptr_t pszPrincipal, uintptr_t pszPackage, uintptr_t fCredentialUse, uintptr_t pvLogonId, uintptr_t pAuthData, uintptr_t pGetKeyFn, uintptr_t pvGetKeyArgument, uintptr_t phCredential, uintptr_t ptsExpiry) {
    return secur32_AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}

uintptr_t InitializeSecurityContextW(uintptr_t phCredential, uintptr_t phContext, uintptr_t pszTargetName, uintptr_t fContextReq, uintptr_t Reserved1, uintptr_t TargetDataRep, uintptr_t pInput, uintptr_t Reserved2, uintptr_t phNewContext, uintptr_t pOutput, uintptr_t pfContextAttr, uintptr_t ptsExpiry) {
    return secur32_InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}

uintptr_t DeleteSecurityContext(uintptr_t phContext) {
    return secur32_DeleteSecurityContext(phContext);
}

uintptr_t FreeCredentialsHandle(uintptr_t phCredential) {
    return secur32_FreeCredentialsHandle(phCredential);
}

uintptr_t QueryContextAttributesW(uintptr_t phContext, uintptr_t ulAttribute, uintptr_t pBuffer) {
    return secur32_QueryContextAttributesW(phContext, ulAttribute, pBuffer);
}

// kernel32.dll (new functions — LocalAlloc/LocalFree use bare names with .dll suffix)
uintptr_t LocalAlloc(uintptr_t uFlags, uintptr_t uBytes) {
    return kernel32_LocalAlloc(uFlags, uBytes);
}

uintptr_t LocalFree(uintptr_t hMem) {
    return kernel32_LocalFree(hMem);
}

// ntdll.dll
uintptr_t NtQuerySystemTime(uintptr_t SystemTime) {
    return ntdll_NtQuerySystemTime(SystemTime);
}

// advapi32.dll (new functions)
uintptr_t RegQueryInfoKeyW(uintptr_t hKey, uintptr_t lpClass, uintptr_t lpcchClass, uintptr_t lpReserved, uintptr_t lpcSubKeys, uintptr_t lpcbMaxSubKeyLen, uintptr_t lpcbMaxClassLen, uintptr_t lpcValues, uintptr_t lpcbMaxValueNameLen, uintptr_t lpcbMaxValueLen, uintptr_t lpcbSecurityDescriptor, uintptr_t lpftLastWriteTime) {
    return advapi32_RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
}

uintptr_t LsaOpenPolicy(uintptr_t SystemName, uintptr_t ObjectAttributes, uintptr_t DesiredAccess, uintptr_t PolicyHandle) {
    return advapi32_LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
}

uintptr_t LsaRetrievePrivateData(uintptr_t PolicyHandle, uintptr_t KeyName, uintptr_t PrivateData) {
    return advapi32_LsaRetrievePrivateData(PolicyHandle, KeyName, PrivateData);
}

uintptr_t LsaClose(uintptr_t ObjectHandle) {
    return advapi32_LsaClose(ObjectHandle);
}

uintptr_t LsaFreeMemory(uintptr_t Buffer) {
    return advapi32_LsaFreeMemory(Buffer);
}

uintptr_t LsaNtStatusToWinError(uintptr_t Status) {
    return advapi32_LsaNtStatusToWinError(Status);
}

uintptr_t GetSidSubAuthority(uintptr_t pSid, uintptr_t nSubAuthority) {
    return advapi32_GetSidSubAuthority(pSid, nSubAuthority);
}

uintptr_t GetSidSubAuthorityCount(uintptr_t pSid) {
    return advapi32_GetSidSubAuthorityCount(pSid);
}

uintptr_t IsTextUnicode(uintptr_t lpv, uintptr_t iSize, uintptr_t lpiResult) {
    return advapi32_IsTextUnicode(lpv, iSize, lpiResult);
}

uintptr_t SystemFunction032(uintptr_t memoryRegion, uintptr_t keyPointer) {
    return advapi32_SystemFunction032(memoryRegion, keyPointer);
}

uintptr_t RtlDecryptDES2blocks1DWORD(uintptr_t data, uintptr_t key, uintptr_t output) {
    return advapi32_RtlDecryptDES2blocks1DWORD(data, key, output);
}

// ncrypt.dll
uintptr_t NCryptOpenStorageProvider(uintptr_t phProvider, uintptr_t pszProviderName, uintptr_t dwFlags) {
    return ncrypt_NCryptOpenStorageProvider(phProvider, pszProviderName, dwFlags);
}

uintptr_t NCryptImportKey(uintptr_t hProvider, uintptr_t hImportKey, uintptr_t pszBlobType, uintptr_t pParameterList, uintptr_t phKey, uintptr_t pbData, uintptr_t cbData, uintptr_t dwFlags) {
    return ncrypt_NCryptImportKey(hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags);
}

uintptr_t NCryptExportKey(uintptr_t hKey, uintptr_t hExportKey, uintptr_t pszBlobType, uintptr_t pParameterList, uintptr_t pbOutput, uintptr_t cbOutput, uintptr_t pcbResult, uintptr_t dwFlags) {
    return ncrypt_NCryptExportKey(hKey, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);
}

uintptr_t NCryptSetProperty(uintptr_t hObject, uintptr_t pszProperty, uintptr_t pbInput, uintptr_t cbInput, uintptr_t dwFlags) {
    return ncrypt_NCryptSetProperty(hObject, pszProperty, pbInput, cbInput, dwFlags);
}

uintptr_t NCryptFinalizeKey(uintptr_t hKey, uintptr_t dwFlags) {
    return ncrypt_NCryptFinalizeKey(hKey, dwFlags);
}

uintptr_t NCryptFreeObject(uintptr_t hObject) {
    return ncrypt_NCryptFreeObject(hObject);
}

// shlwapi.dll
uintptr_t PathIsUNCW(uintptr_t pszPath) {
    return shlwapi_PathIsUNCW(pszPath);
}

// PathIsUNC (without W suffix) — some DllImport declarations omit the W
uintptr_t PathIsUNC(uintptr_t pszPath) {
    return shlwapi_PathIsUNCW(pszPath);
}

// rpcrt4.dll
uintptr_t RpcStringBindingComposeW(uintptr_t ObjUuid, uintptr_t ProtSeq, uintptr_t NetworkAddr, uintptr_t Endpoint, uintptr_t Options, uintptr_t StringBinding) {
    return rpcrt4_RpcStringBindingComposeW(ObjUuid, ProtSeq, NetworkAddr, Endpoint, Options, StringBinding);
}

uintptr_t RpcBindingFromStringBindingW(uintptr_t StringBinding, uintptr_t Binding) {
    return rpcrt4_RpcBindingFromStringBindingW(StringBinding, Binding);
}

uintptr_t RpcBindingSetAuthInfoExW(uintptr_t Binding, uintptr_t ServerPrincName, uintptr_t AuthnLevel, uintptr_t AuthnSvc, uintptr_t AuthIdentity, uintptr_t AuthzSvc, uintptr_t SecurityQOS) {
    return rpcrt4_RpcBindingSetAuthInfoExW(Binding, ServerPrincName, AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvc, SecurityQOS);
}

uintptr_t RpcBindingSetOption(uintptr_t hBinding, uintptr_t option, uintptr_t optionValue) {
    return rpcrt4_RpcBindingSetOption(hBinding, option, optionValue);
}

uintptr_t RpcBindingFree(uintptr_t Binding) {
    return rpcrt4_RpcBindingFree(Binding);
}

uintptr_t I_RpcBindingInqSecurityContext(uintptr_t Binding, uintptr_t SecurityContextHandle) {
    return rpcrt4_I_RpcBindingInqSecurityContext(Binding, SecurityContextHandle);
}

uintptr_t NdrClientCall2(uintptr_t pStubDescriptor, uintptr_t pFormatString,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5,
    uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9, uintptr_t a10) {
    return rpcrt4_NdrClientCall2(pStubDescriptor, pFormatString,
        a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
}

// Bare-name aliases for existing bridge functions (needed by SharpDPAPI/Certify
// when DllImport uses "advapi32.dll" with .dll suffix instead of bare "advapi32")
uintptr_t RegOpenKeyEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e) { return advapi32_RegOpenKeyExW(a,b,c,d,e); }
uintptr_t RegCloseKey(uintptr_t a) { return advapi32_RegCloseKey(a); }
uintptr_t RegQueryValueEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) { return advapi32_RegQueryValueExW(a,b,c,d,e,f); }
uintptr_t RevertToSelf(void) { return advapi32_RevertToSelf(); }
uintptr_t CDLocateCSystem(uintptr_t a, uintptr_t b) { return cryptdll_CDLocateCSystem(a,b); }
uintptr_t DsGetDcName(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) { return netapi32_DsGetDcNameW(a,b,c,d,e,f); }
uintptr_t NetApiBufferFree(uintptr_t a) { return netapi32_NetApiBufferFree(a); }

// New functions for SharpDPAPI
uintptr_t CryptProtectData(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    return wf_call("crypt32.dll", "CryptProtectData", 7, (uint64_t)a, (uint64_t)b, (uint64_t)c, (uint64_t)d, (uint64_t)e, (uint64_t)f, (uint64_t)g);
}
uintptr_t CryptUnprotectData(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    return wf_call("crypt32.dll", "CryptUnprotectData", 7, (uint64_t)a, (uint64_t)b, (uint64_t)c, (uint64_t)d, (uint64_t)e, (uint64_t)f, (uint64_t)g);
}
uintptr_t FormatMessageW(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    return wf_call("kernel32.dll", "FormatMessageW", 7, (uint64_t)a, (uint64_t)b, (uint64_t)c, (uint64_t)d, (uint64_t)e, (uint64_t)f, (uint64_t)g);
}
uintptr_t RegQueryInfoKey(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h, uintptr_t i, uintptr_t j, uintptr_t k, uintptr_t l) {
    return advapi32_RegQueryInfoKeyW(a,b,c,d,e,f,g,h,i,j,k,l);
}

// Forward declaration for wf_pbkdf2 (static, defined later in this file).
// Required because WfKerberosHash is textually before wf_pbkdf2.
static uint32_t wf_pbkdf2(const uint16_t* alg_name, int name_len,
    uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uintptr_t out, uint32_t olen);

// ── WASM-side Kerberos crypto (replaces crypto_kerb* env imports) ──────────
//
// WfKerberosHash/Encrypt/Decrypt/Checksum were previously thin shims that
// called the crypto_kerb* env imports (Go side). This section implements
// them entirely in C using wf_call chains and wf_call_ptr_fixed8, removing
// the last four env imports from the kerberos/crypto path.
//
// KERB_ECRYPT struct layout (x64, from Windows internal headers and
// confirmed by nativeaot_crypto_windows.go's kerberosTransform):
//   off  0: Type0      (u32)
//   off  4: BlockSize  (u32)
//   off  8: Type1      (u32)
//   off 12: KeySize    (u32)
//   off 16: Size       (u32) — extra bytes added by encryption
//   off 20: unk2       (u32)
//   off 24: unk3       (u32)
//   off 28: pad        (u32) — 8-byte align
//   off 32: AlgName    (u64) — pointer
//   off 40: Initialize (u64) — fn(key,klen,usage,&ctx) → NTSTATUS
//   off 48: Encrypt    (u64) — fn(ctx,data,dlen,out,&outLen) → NTSTATUS
//   off 56: Decrypt    (u64) — fn(ctx,data,dlen,out,&outLen) → NTSTATUS
//   off 64: Finish     (u64) — fn(&ctx) → void
//
// KERB_CHECKSUM struct layout (x64):
//   off  0: Type       (u32)
//   off  4: Size       (u32) — output size
//   off  8: Flag       (u32)
//   off 12: pad        (u32)
//   off 16: Initialize     (u64) — fn(key,klen,usage,&ctx) → NTSTATUS (simple)
//   off 24: Sum            (u64) — fn(ctx,len,data) → NTSTATUS
//   off 32: Finalize       (u64) — fn(ctx,out) → NTSTATUS
//   off 40: Finish         (u64) — fn(&ctx) → void
//   off 48: InitializeEx   (u64) — fn(key,klen,usage,&ctx) → NTSTATUS (with usage)
//
// Helper: read N bytes from host address (64-bit) into a WASM local buffer.
// Uses wf_host_read_bytes which is already declared in wf_bridge.h.
// Pass localBuf as void* (WASM ptr); the type is compatible since wasm32
// pointers and void* are the same width.
#define WF_HREAD(hostAddr, len, localBuf) \
    wf_host_read_bytes((uint64_t)(hostAddr), (uint32_t)(len), (void*)(localBuf))

// Read a 64-bit value (pointer/function ptr) from host memory.
static uint64_t wf_hread64(uint64_t host_addr) {
    uint64_t v = 0;
    WF_HREAD(host_addr, 8, &v);
    return v;
}
// Read a 32-bit value from host memory.
static uint32_t wf_hread32(uint64_t host_addr) {
    uint32_t v = 0;
    WF_HREAD(host_addr, 4, &v);
    return v;
}

// ── WfKerberosHash ──────────────────────────────────────────────────────────
// Kerberos password → session key derivation.
//
// etype 23 (RC4_HMAC): MD4(UTF-16LE(password))
// etype 17 (AES128):   PBKDF2-HMAC-SHA1(pwd, salt, iter, 16) → DK
// etype 18 (AES256):   PBKDF2-HMAC-SHA1(pwd, salt, iter, 32) → DK
// etype 3  (DES):      not used on modern KDCs; return 0.
//
// DK(tkey, "kerberos"):
//   folded = nfold("kerberos", 128) = pre-computed constant below.
//   out[0:16] = AES-ECB-enc(tkey, folded)
//   out[16:32] = AES-ECB-enc(tkey, out[0:16])   [AES256 only]
//
// The MD4 and AES algorithms are accessed via bcrypt.dll wf_call chains.
// The AES-ECB DK step uses BCryptEncrypt (no IV, ECB mode).

// nfold("kerberos", 128 bits) — precomputed. Verified by go nfold() impl.
static const uint8_t wf_kerb_dk_const[16] = {
    0x6b,0x65,0x72,0x62,0x65,0x72,0x6f,0x73,
    0x7b,0x9b,0x5b,0x2b,0x93,0x13,0x2b,0x93
};

// AES-ECB single-block encrypt: 16-byte key_buf → encrypt plain[16] into
// cipher_out[16]. Uses BCrypt with ChainingMode=ECB.
// All buffers are local WASM memory.
static int wf_aes_ecb_block(const uint8_t* key_buf, uint32_t klen,
                              const uint8_t* plain, uint8_t* cipher_out) {
    // Stack UTF-16 names — must be in WASM linear memory for wf_call ptr-translate.
    uint16_t aes_name[4]   = {'A','E','S', 0};
    uint16_t ecb_name[16]  = {'C','h','a','i','n','i','n','g','M','o','d','e','E','C','B',0};
    uint16_t prop_name[13] = {'C','h','a','i','n','i','n','g','M','o','d','e', 0};

    uint64_t hAlg = 0;
    uint64_t st = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)aes_name,
        (uint64_t)0, (uint64_t)0);
    if (st != 0 || hAlg == 0) return 0;

    // Set ECB chaining mode.
    wf_call_v2("bcrypt.dll", "BCryptSetProperty", 5, 0,
        hAlg,
        (uint64_t)(uintptr_t)prop_name,
        (uint64_t)(uintptr_t)ecb_name,
        (uint64_t)(15 * 2), // byte length of "ChainingModeECB" (no NUL)
        (uint64_t)0);

    // Import key.
    uint64_t hKey = 0;
    // BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, keyBuf, klen, 0)
    st = wf_call_v2("bcrypt.dll", "BCryptGenerateSymmetricKey", 7,
        /*out8_mask=*/0x2,
        hAlg,
        (uint64_t)(uintptr_t)&hKey,
        (uint64_t)0, (uint64_t)0,
        (uint64_t)(uintptr_t)key_buf, (uint64_t)klen,
        (uint64_t)0);
    if (st != 0 || hKey == 0) {
        wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
        return 0;
    }

    // BCryptEncrypt(hKey, plain, 16, NULL, NULL, 0, cipher_out, 16, &cbResult, 0)
    // &cbResult is a 4-byte output → use wf_call (standard overflow protection).
    uint32_t cbResult = 0;
    st = wf_call("bcrypt.dll", "BCryptEncrypt", 10,
        hKey,
        (uint64_t)(uintptr_t)plain, (uint64_t)16,
        (uint64_t)0, (uint64_t)0, (uint64_t)0,
        (uint64_t)(uintptr_t)cipher_out, (uint64_t)16,
        (uint64_t)(uintptr_t)&cbResult, (uint64_t)0);

    wf_call("bcrypt.dll", "BCryptDestroyKey", 1, hKey);
    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return (st == 0) ? 1 : 0;
}

// MD4(UTF-16LE(pwd)): used for RC4_HMAC (etype 23).
static uint32_t wf_kerb_md4_hash(uintptr_t pwd, uint32_t plen, uintptr_t out, uint32_t olen) {
    if (olen < 16) return 0;
    // BCryptHash(MD4, no-hmac) on UTF-16LE(pwd).
    // Build UTF-16LE in a stack buffer (pwd is UTF-8 ASCII for passwords).
    if (plen > 256) return 0;
    uint16_t utf16[256];
    const uint8_t* p = (const uint8_t*)(uintptr_t)pwd;
    for (uint32_t i = 0; i < plen; i++) utf16[i] = (uint16_t)p[i];

    static const uint16_t md4_name[4] = {'M','D','4', 0};
    uint64_t hAlg = 0;
    uint64_t st = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)md4_name,
        (uint64_t)0, (uint64_t)0);
    if (st != 0 || hAlg == 0) return 0;

    uint64_t hHash = 0;
    st = wf_call_v2("bcrypt.dll", "BCryptCreateHash", 7,
        /*out8_mask=*/0x2,
        hAlg,
        (uint64_t)(uintptr_t)&hHash,
        (uint64_t)0, (uint64_t)0,
        (uint64_t)0, (uint64_t)0,
        (uint64_t)0);
    if (st != 0 || hHash == 0) {
        wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
        return 0;
    }

    // Hash UTF-16LE bytes.
    st = wf_call("bcrypt.dll", "BCryptHashData", 4,
        hHash, (uint64_t)(uintptr_t)utf16, (uint64_t)(plen * 2), (uint64_t)0);
    uint32_t bytes_written = 0;
    if (st == 0) {
        st = wf_call_v2("bcrypt.dll", "BCryptFinishHash", 4,
            /*out8_mask=*/0x2,
            hHash, (uint64_t)out, (uint64_t)16, (uint64_t)0);
        if (st == 0) bytes_written = 16;
    }
    wf_call("bcrypt.dll", "BCryptDestroyHash", 1, hHash);
    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return bytes_written;
}

uint32_t WfKerberosHash(uint32_t etype, uintptr_t pwd, uint32_t plen, uintptr_t salt, uint32_t slen,
    uint32_t iter, uintptr_t out, uint32_t olen) {
    if (etype == 23) {
        // RC4_HMAC: MD4(UTF-16LE(password))
        return wf_kerb_md4_hash(pwd, plen, out, olen);
    }
    if (etype == 17 || etype == 18) {
        uint32_t keylen = (etype == 17) ? 16 : 32;
        if (olen < keylen) return 0;

        // Step 1: PBKDF2-HMAC-SHA1(pwd, salt, iter, keylen) → tkey
        uint8_t tkey[32];
        // Local SHA1 name constant (WF_BCRYPT_SHA1_NAME defined later in file).
        const uint16_t sha1_name_local[5] = {'S','H','A','1', 0};
        uint32_t got = wf_pbkdf2(sha1_name_local, 4,
            pwd, plen, salt, slen, iter,
            (uintptr_t)tkey, keylen);
        if (got == 0) return 0;

        // Step 2: DK(tkey, "kerberos") = AES-ECB loop with nfold constant.
        // out[0:16] = AES-ECB(tkey, nfold("kerberos",128))
        uint8_t* outptr = (uint8_t*)(uintptr_t)out;
        if (!wf_aes_ecb_block(tkey, keylen, wf_kerb_dk_const, outptr)) return 0;
        if (etype == 18) {
            // out[16:32] = AES-ECB(tkey, out[0:16])
            if (!wf_aes_ecb_block(tkey, keylen, outptr, outptr + 16)) return 0;
        }
        return keylen;
    }
    // etype 3 (DES) and others: not implemented — CDLocateCSystem's
    // hashpassword vtable slot is unreliable on Win11 22H2+.
    return 0;
}

// ── WfKerberosEncrypt / WfKerberosDecrypt ───────────────────────────────────
// Uses CDLocateCSystem → KERB_ECRYPT vtable → Initialize/Encrypt|Decrypt/Finish.
//
// CDLocateCSystem writes the host pointer to pCSystem into a WASM uint64_t.
// We then use wf_host_read_bytes to read vtable function pointers at the
// known offsets, and wf_call_ptr_fixed8 to invoke them.

// Helper: call CDLocateCSystem and return the host pointer to KERB_ECRYPT.
// Returns 0 on failure.
static uint64_t wf_get_kerb_ecrypt(uint32_t etype) {
    uint64_t pCSystem = 0;
    uint32_t st = cryptdll_CDLocateCSystem(etype, (uint64_t)(uintptr_t)&pCSystem);
    if (st != 0) return 0;
    return pCSystem;
}

// Helper: call CDLocateCheckSum and return the host pointer to KERB_CHECKSUM.
static uint64_t wf_get_kerb_checksum(uint32_t cksumType) {
    uint64_t pCheckSum = 0;
    uint64_t r = wf_call("cryptdll.dll", "CDLocateCheckSum", 2,
        (uint64_t)cksumType, (uint64_t)(uintptr_t)&pCheckSum);
    if (r != 0) return 0;
    return pCheckSum;
}

// Perform Kerberos encrypt or decrypt via KERB_ECRYPT function pointer chain.
// is_encrypt: 1 for encrypt, 0 for decrypt.
static uint32_t wf_kerb_transform(uint32_t etype, uint32_t key_usage,
    uintptr_t key, uint32_t klen,
    uintptr_t data, uint32_t dlen,
    uintptr_t out, uint32_t olen,
    int is_encrypt) {

    uint64_t pCSystem = wf_get_kerb_ecrypt(etype);
    if (pCSystem == 0) return 0;

    // Read scalar fields for output size calculation.
    uint32_t blockSize = wf_hread32(pCSystem + 4);
    uint32_t extraSize = wf_hread32(pCSystem + 16);

    // Read function pointers from the KERB_ECRYPT vtable.
    uint64_t fnInit    = wf_hread64(pCSystem + 40);
    uint64_t fnEncrypt = wf_hread64(pCSystem + 48);
    uint64_t fnDecrypt = wf_hread64(pCSystem + 56);
    uint64_t fnFinish  = wf_hread64(pCSystem + 64);

    if (fnInit == 0 || fnEncrypt == 0 || fnDecrypt == 0 || fnFinish == 0) return 0;
    if (blockSize == 0) blockSize = 16; // safety

    // Calculate output buffer size.
    uint32_t outSize = dlen;
    if (is_encrypt) {
        if ((dlen % blockSize) != 0)
            outSize += blockSize - (dlen % blockSize);
        outSize += extraSize;
    }
    if (outSize > olen) return 0;

    // Initialize: fn(key, klen, key_usage, &pContext).
    uint64_t pContext = 0;
    // ptr_mask=0x1 (arg0 key is WASM ptr), out8_mask=0x8 (arg3 &pContext is 8-byte out)
    uint64_t st = wf_call_ptr_fixed8(fnInit, 4,
        /*ptr_mask=*/0x1, /*out8_mask=*/0x8,
        (uint64_t)key, (uint64_t)klen, (uint64_t)key_usage,
        (uint64_t)(uintptr_t)&pContext, 0,0,0,0);
    if (st != 0) return 0;
    if (pContext == 0) return 0;

    // Encrypt or Decrypt: fn(pContext, data, dlen, out, &outLen).
    uint64_t fn = is_encrypt ? fnEncrypt : fnDecrypt;
    int32_t outLen = (int32_t)outSize;
    // ptr_mask=0x2|0x8 (arg1=data WASM ptr, arg3=out WASM ptr), out8_mask=0x10 (arg4 &outLen 4-byte)
    st = wf_call_ptr_fixed8(fn, 5,
        /*ptr_mask=*/0x2|0x8, /*out8_mask=*/0x0,
        pContext, (uint64_t)data, (uint64_t)dlen,
        (uint64_t)out, (uint64_t)(uintptr_t)&outLen,
        0,0,0);

    // Finish: fn(&pContext).
    wf_call_ptr_fixed8(fnFinish, 1, /*ptr_mask=*/0x1, 0,
        (uint64_t)(uintptr_t)&pContext, 0,0,0, 0,0,0,0);

    if (st != 0) return 0;
    return (outLen > 0 && (uint32_t)outLen <= olen) ? (uint32_t)outLen : outSize;
}

uint32_t WfKerberosEncrypt(uint32_t etype, uint32_t ku, uintptr_t key, uint32_t klen,
    uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen) {
    return wf_kerb_transform(etype, ku, key, klen, data, dlen, out, olen, 1);
}

uint32_t WfKerberosDecrypt(uint32_t etype, uint32_t ku, uintptr_t key, uint32_t klen,
    uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen) {
    return wf_kerb_transform(etype, ku, key, klen, data, dlen, out, olen, 0);
}

// ── WfKerberosChecksum ──────────────────────────────────────────────────────
// Uses CDLocateCheckSum → KERB_CHECKSUM vtable → InitializeEx/Sum/Finalize/Finish.

uint32_t WfKerberosChecksum(uint32_t ct, uint32_t ku, uintptr_t key, uint32_t klen,
    uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen) {

    uint64_t pCheckSum = wf_get_kerb_checksum(ct);
    if (pCheckSum == 0) return 0;

    // Read output size and function pointers.
    uint32_t cksumSize    = wf_hread32(pCheckSum + 4);
    uint64_t fnInitEx     = wf_hread64(pCheckSum + 48);
    uint64_t fnSum        = wf_hread64(pCheckSum + 24);
    uint64_t fnFinalize   = wf_hread64(pCheckSum + 32);
    uint64_t fnFinish     = wf_hread64(pCheckSum + 40);

    if (fnInitEx == 0 || fnSum == 0 || fnFinalize == 0) return 0;
    if (cksumSize == 0 || cksumSize > olen) return 0;

    // InitializeEx: fn(key, klen, key_usage, &pContext).
    uint64_t pContext = 0;
    uint64_t st = wf_call_ptr_fixed8(fnInitEx, 4,
        /*ptr_mask=*/0x1, /*out8_mask=*/0x8,
        (uint64_t)key, (uint64_t)klen, (uint64_t)ku,
        (uint64_t)(uintptr_t)&pContext, 0,0,0,0);
    if (st != 0 || pContext == 0) return 0;

    // Sum: fn(pContext, len, data).
    st = wf_call_ptr_fixed8(fnSum, 3,
        /*ptr_mask=*/0x4, 0,
        pContext, (uint64_t)dlen, (uint64_t)data,
        0, 0,0,0,0);

    // Finalize: fn(pContext, out).
    if (st == 0) {
        st = wf_call_ptr_fixed8(fnFinalize, 2,
            /*ptr_mask=*/0x2, 0,
            pContext, (uint64_t)out,
            0,0, 0,0,0,0);
    }

    // Finish: fn(&pContext).
    if (fnFinish != 0) {
        wf_call_ptr_fixed8(fnFinish, 1, /*ptr_mask=*/0x1, 0,
            (uint64_t)(uintptr_t)&pContext, 0,0,0, 0,0,0,0);
    }

    if (st != 0) return 0;
    return cksumSize;
}
// BCrypt algorithm names as UTF-16LE C strings — stored in WASM data segment
// so wf_call's pointer translation hands them to BCryptOpenAlgorithmProvider
// as proper UTF-16 PCWSTR arguments.
static const uint16_t WF_BCRYPT_SHA1_NAME[]   = { 'S','H','A','1', 0 };
static const uint16_t WF_BCRYPT_SHA256_NAME[] = { 'S','H','A','2','5','6', 0 };
static const uint16_t WF_BCRYPT_SHA512_NAME[] = { 'S','H','A','5','1','2', 0 };
#define WF_BCRYPT_HMAC_FLAG 0x00000008u

// PBKDF2 chain: open HMAC-<hash> alg → BCryptDeriveKeyPBKDF2 → close.
//
// Three subtleties (caught by /tmp/wf-crypto-test/Program.cs against RFC
// vectors on Win11):
//
//   1. Algorithm name (UTF-16 PCWSTR) is copied onto the C stack so the
//      passed pointer is guaranteed to land above wf_call's 0x10000
//      pointer-translation threshold. `static const` rodata can land below
//      that boundary depending on link layout; when it does, BCrypt sees an
//      unrelated host address and returns STATUS_BUFFER_TOO_SMALL (0xC0000023).
//
//   2. BCryptOpenAlgorithmProvider uses wf_call_v2 with out8_mask=0x1 so the
//      8-byte BCRYPT_ALG_HANDLE output slot at &hAlg is NOT subject to the
//      default 4-byte overflow-protect (which would zero bytes 4-7 of the
//      host pointer, corrupting the handle).
//
//   3. cIterations is a single ULONGLONG (8 bytes) — passed as ONE uint64_t
//      arg, NOT split. Splitting it leaves dwFlags out and shifts
//      pbDerivedKey/cbDerivedKey into the wrong positions.
//
// Also out8_mask bit 6 covers pbDerivedKey (output buffer >= 8 bytes) for
// BCryptDeriveKeyPBKDF2.
static WF_KEEP uint32_t wf_pbkdf2(const uint16_t* alg_name, int name_len,
    uintptr_t pw, uint32_t pwl,
    uintptr_t salt, uint32_t sl,
    uint32_t iters, uintptr_t out, uint32_t olen)
{
    uint16_t id[16];
    int n = name_len < 15 ? name_len : 15;
    for (int i = 0; i < n; i++) id[i] = alg_name[i];
    id[n] = 0;

    uint64_t hAlg = 0;
    uint64_t status = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/ 0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)id,
        (uint64_t)0,
        (uint64_t)WF_BCRYPT_HMAC_FLAG);
    if (status != 0 || hAlg == 0) return 0;

    status = wf_call_v2("bcrypt.dll", "BCryptDeriveKeyPBKDF2", 9,
        /*out8_mask=*/ 0x40,
        hAlg,
        (uint64_t)pw, (uint64_t)pwl,
        (uint64_t)salt, (uint64_t)sl,
        (uint64_t)iters,
        (uint64_t)out, (uint64_t)olen,
        (uint64_t)0);

    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return status == 0 ? olen : 0;
}

uint32_t WfPbkdf2Sha1(uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uint32_t klen, uintptr_t out, uint32_t olen) {
    (void)klen; // klen == olen for PBKDF2 callers
    return wf_pbkdf2(WF_BCRYPT_SHA1_NAME, 4, pw, pwl, salt, sl, iters, out, olen);
}
uint32_t WfPbkdf2Sha256(uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uint32_t klen, uintptr_t out, uint32_t olen) {
    (void)klen;
    return wf_pbkdf2(WF_BCRYPT_SHA256_NAME, 6, pw, pwl, salt, sl, iters, out, olen);
}
uint32_t WfPbkdf2Sha512(uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uint32_t klen, uintptr_t out, uint32_t olen) {
    (void)klen;
    return wf_pbkdf2(WF_BCRYPT_SHA512_NAME, 6, pw, pwl, salt, sl, iters, out, olen);
}

// wf_ms_pbkdf2: implements the Microsoft CryptoAPI PBKDF2 variant used by
// Windows DPAPI for master key derivation. Differs from RFC2898 §5.2 by
// feeding the accumulated XOR result back into HMAC each iteration instead
// of the previous U_i. Mimikatz / SharpDPAPI / impacket all replicate this
// "MS PBKDF2 bug" to match what Windows actually produces.
//
// Implemented host-side (in this C bridge, via wf_call) so the iteration
// loop doesn't pay the WASM↔host boundary cost per HMAC. Critical perf
// note: each iteration uses bcrypt.dll's ONE-SHOT BCryptHash API which
// computes HMAC(key, data) in a single call (vs the 4-call sequence
// CreateHash/HashData/FinishHash/DestroyHash). This brings the per-
// iteration cost from ~4 wf_call round-trips down to 1, making 8000-iter
// DPAPI master-key derivation tractable across many keys.
//
// salt/pw/out are WASM pointers (already translated by the bridge). hash_len
// is the HMAC output size (20 for SHA1, 64 for SHA512). key_len is the
// total bytes the caller wants — multiple blocks if key_len > hash_len.
static WF_KEEP uint32_t wf_ms_pbkdf2(
    const uint16_t* alg_name, int name_len,
    uintptr_t pw, uint32_t pwl,
    uintptr_t salt, uint32_t sl,
    uint32_t iters, uint32_t hash_len,
    uintptr_t out, uint32_t key_len)
{
    if (key_len == 0 || hash_len == 0) return 0;
    if (sl > 252) return 0;  // sanity: legitimate DPAPI salts are 16 bytes

    uint16_t id[16];
    int n = name_len < 15 ? name_len : 15;
    for (int i = 0; i < n; i++) id[i] = alg_name[i];
    id[n] = 0;

    // Open HMAC algorithm provider once for the whole derivation.
    uint64_t hAlg = 0;
    uint64_t status = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/ 0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)id,
        (uint64_t)0,
        (uint64_t)WF_BCRYPT_HMAC_FLAG);
    if (status != 0 || hAlg == 0) return 0;

    // Working buffers. hash_len ≤ 64 (SHA512).
    uint8_t hash1[64];
    uint8_t finalHash[64];
    uint8_t hash1_input[256];  // salt + 4-byte block index

    uint32_t result_offset = 0;
    uint32_t block_index = 1;
    uint32_t produced = 0;

    // hmac_once: invokes the 4-call BCrypt HMAC chain.
    //
    // We tried BCryptHash (one-shot) here, but it has an [in, out] on
    // hAlgorithm — reusing the same hAlg across thousands of calls
    // produced garbage output (only 4 bytes of digest were populated,
    // suggesting an internal state mismatch). The explicit chain works
    // correctly per the CryptoTest harness vectors.
    //
    // Returns 1 on success, 0 on failure.
    #define HMAC_ONCE(key_ptr, key_len, data_ptr, data_len, out_ptr) ({ \
        uint64_t _hH = 0; \
        uint64_t _s = wf_call_v2("bcrypt.dll", "BCryptCreateHash", 7, \
            /*out8_mask=*/ 0x2, hAlg, (uint64_t)(uintptr_t)&_hH, \
            (uint64_t)0, (uint64_t)0, \
            (uint64_t)(key_ptr), (uint64_t)(key_len), (uint64_t)0); \
        if (_s == 0 && _hH != 0) { \
            _s = wf_call("bcrypt.dll", "BCryptHashData", 4, _hH, \
                (uint64_t)(data_ptr), (uint64_t)(data_len), (uint64_t)0); \
            if (_s == 0) { \
                _s = wf_call_v2("bcrypt.dll", "BCryptFinishHash", 4, \
                    /*out8_mask=*/ 0x2, _hH, \
                    (uint64_t)(out_ptr), (uint64_t)hash_len, (uint64_t)0); \
            } \
            wf_call("bcrypt.dll", "BCryptDestroyHash", 1, _hH); \
        } \
        (_s == 0); \
    })

    while (result_offset < key_len) {
        for (uint32_t i = 0; i < sl; i++)
            hash1_input[i] = *(uint8_t*)(uintptr_t)(salt + i);
        hash1_input[sl + 0] = (uint8_t)((block_index >> 24) & 0xff);
        hash1_input[sl + 1] = (uint8_t)((block_index >> 16) & 0xff);
        hash1_input[sl + 2] = (uint8_t)((block_index >>  8) & 0xff);
        hash1_input[sl + 3] = (uint8_t)( block_index        & 0xff);

        if (!HMAC_ONCE(pw, pwl, (uintptr_t)hash1_input, sl + 4, (uintptr_t)hash1)) break;

        for (uint32_t j = 0; j < hash_len; j++) finalHash[j] = hash1[j];

        for (uint32_t i = 2; i <= iters; i++) {
            if (!HMAC_ONCE(pw, pwl, (uintptr_t)hash1, hash_len, (uintptr_t)hash1)) { status = 1; break; }
            for (uint32_t j = 0; j < hash_len; j++) finalHash[j] ^= hash1[j];
            // MS-PBKDF2 BUG: feed accumulated XOR result back as next HMAC input.
            for (uint32_t j = 0; j < hash_len; j++) hash1[j] = finalHash[j];
        }
        if (status != 0) break;

        uint32_t take = (hash_len < key_len - result_offset) ? hash_len : (key_len - result_offset);
        for (uint32_t j = 0; j < take; j++)
            *(uint8_t*)(uintptr_t)(out + result_offset + j) = finalHash[j];
        result_offset += take;
        produced += take;
        block_index++;
    }

    #undef HMAC_ONCE
    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return produced;
}

uint32_t WfMsPbkdf2Sha512(uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uintptr_t out, uint32_t out_len) {
    return wf_ms_pbkdf2(WF_BCRYPT_SHA512_NAME, 6, pw, pwl, salt, sl, iters, 64, out, out_len);
}
uint32_t WfMsPbkdf2Sha1(uintptr_t pw, uint32_t pwl, uintptr_t salt, uint32_t sl,
    uint32_t iters, uintptr_t out, uint32_t out_len) {
    return wf_ms_pbkdf2(WF_BCRYPT_SHA1_NAME, 4, pw, pwl, salt, sl, iters, 20, out, out_len);
}
// HMAC wrappers now share the BCrypt chain helper below — see WfSha1 area.
// (Implementations moved after WfAesCbcDecrypt to reuse the helper definition.)
uint32_t WfProcModulesAll(uintptr_t out, uint32_t olen) {
    return proc_modules_all((uint32_t)out, olen);
}
// AES algorithm name + chaining-mode property constants for BCrypt.
static const uint16_t WF_BCRYPT_AES_NAME[]        = { 'A','E','S', 0 };
static const uint16_t WF_BCRYPT_CHAINING_MODE_PR[] = { 'C','h','a','i','n','i','n','g','M','o','d','e', 0 };
static const uint16_t WF_BCRYPT_CHAIN_MODE_CBC[]   = { 'C','h','a','i','n','i','n','g','M','o','d','e','C','B','C', 0 };

// AES-CBC decrypt via wf_call chain. Replaces the dedicated crypto_aes_cbc_dec
// host bridge. Outputs raw decryption (no padding strip) — caller (WfDpapi) is
// responsible for trimming PKCS7 if needed.
uint32_t WfAesCbcDecrypt(uintptr_t key, uint32_t klen, uintptr_t iv, uint32_t ivl,
    uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen)
{
    if (ivl != 16) return 0;

    // Stack-local UTF-16 names — see wf_pbkdf2 comment block for why.
    uint16_t aesName[4]  = {'A','E','S', 0};
    uint16_t propName[14]= {'C','h','a','i','n','i','n','g','M','o','d','e', 0, 0};
    uint16_t cbcVal[17]  = {'C','h','a','i','n','i','n','g','M','o','d','e','C','B','C', 0, 0};

    uint64_t hAlg = 0;
    uint64_t status = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/ 0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)aesName,
        (uint64_t)0,
        (uint64_t)0);
    if (status != 0 || hAlg == 0) return 0;

    // BCryptSetProperty: ChainingMode = "ChainingModeCBC". 16 wide chars
    // including the trailing NUL = 32 bytes.
    status = wf_call("bcrypt.dll", "BCryptSetProperty", 5,
        hAlg,
        (uint64_t)(uintptr_t)propName,
        (uint64_t)(uintptr_t)cbcVal,
        (uint64_t)(16 * sizeof(uint16_t)),
        (uint64_t)0);
    if (status != 0) {
        wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
        return 0;
    }

    // BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj=NULL, cbKeyObj=0,
    //   pbSecret, cbSecret, dwFlags=0). out8_mask covers arg 1 (phKey, 8-byte).
    uint64_t hKey = 0;
    status = wf_call_v2("bcrypt.dll", "BCryptGenerateSymmetricKey", 7,
        /*out8_mask=*/ 0x2,
        hAlg,
        (uint64_t)(uintptr_t)&hKey,
        (uint64_t)0, (uint64_t)0,
        (uint64_t)key, (uint64_t)klen,
        (uint64_t)0);
    if (status != 0 || hKey == 0) {
        wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
        return 0;
    }

    // BCryptDecrypt: out8_mask covers arg 6 (pbOutput, plaintext buf >= 8 bytes).
    uint32_t cbResult = 0;
    status = wf_call_v2("bcrypt.dll", "BCryptDecrypt", 10,
        /*out8_mask=*/ 0x40,
        hKey,
        (uint64_t)data, (uint64_t)dlen,
        (uint64_t)0,
        (uint64_t)iv, (uint64_t)ivl,
        (uint64_t)out, (uint64_t)olen,
        (uint64_t)(uintptr_t)&cbResult,
        (uint64_t)0);

    wf_call("bcrypt.dll", "BCryptDestroyKey", 1, hKey);
    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return status == 0 ? cbResult : 0;
}
// Shared BCrypt hash routine. Used by WfSha1/WfSha256 (plain hash, hmacFlag=0,
// key=NULL/klen=0) AND by WfHmacSha1/256/512 (hmacFlag=8, real key/klen). One
// place to maintain instead of five copies. All calls route through wf_call →
// mod_invoke so the host never sees a dedicated hashing import.
//
// Subtleties (same triage notes as wf_pbkdf2 — see those for derivation):
//   - algId copied to C stack to dodge rodata-below-0x10000 collision
//   - BCryptOpenAlgorithmProvider uses wf_call_v2 + out8_mask=0x1 for the
//     8-byte BCRYPT_ALG_HANDLE output
//   - BCryptCreateHash uses wf_call_v2 + out8_mask=0x2 for the 8-byte
//     BCRYPT_HASH_HANDLE output (it is also at arg index 1)
//   - BCryptFinishHash uses wf_call_v2 + out8_mask=0x2 for the >=8-byte
//     output digest buffer (arg index 1 = pbOutput)
static WF_KEEP uint32_t wf_bcrypt_hash(
    const uint16_t* alg_name, int name_len,
    uint32_t hmac_flag,
    uintptr_t key, uint32_t klen,
    uintptr_t data, uint32_t dlen,
    uintptr_t out, uint32_t out_cap,
    uint32_t hash_len)
{
    if (out_cap < hash_len) return 0;
    uint16_t id[16];
    int n = name_len < 15 ? name_len : 15;
    for (int i = 0; i < n; i++) id[i] = alg_name[i];
    id[n] = 0;

    uint64_t hAlg = 0;
    uint64_t status = wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/ 0x1,
        (uint64_t)(uintptr_t)&hAlg,
        (uint64_t)(uintptr_t)id,
        (uint64_t)0,
        (uint64_t)hmac_flag);
    if (status != 0 || hAlg == 0) return 0;

    uint64_t hHash = 0;
    status = wf_call_v2("bcrypt.dll", "BCryptCreateHash", 7,
        /*out8_mask=*/ 0x2,
        hAlg,
        (uint64_t)(uintptr_t)&hHash,
        (uint64_t)0, (uint64_t)0,
        (uint64_t)key, (uint64_t)klen,
        (uint64_t)0);
    if (status != 0 || hHash == 0) {
        wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
        return 0;
    }

    status = wf_call("bcrypt.dll", "BCryptHashData", 4,
        hHash, (uint64_t)data, (uint64_t)dlen, (uint64_t)0);
    uint32_t bytes_written = 0;
    if (status == 0) {
        status = wf_call_v2("bcrypt.dll", "BCryptFinishHash", 4,
            /*out8_mask=*/ 0x2,
            hHash, (uint64_t)out, (uint64_t)hash_len, (uint64_t)0);
        if (status == 0) bytes_written = hash_len;
    }

    wf_call("bcrypt.dll", "BCryptDestroyHash", 1, hHash);
    wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2, hAlg, (uint64_t)0);
    return bytes_written;
}

uint32_t WfSha1(uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen) {
    return wf_bcrypt_hash(WF_BCRYPT_SHA1_NAME, 4, 0, 0, 0, data, dlen, out, olen, 20);
}
uint32_t WfSha256(uintptr_t data, uint32_t dlen, uintptr_t out, uint32_t olen) {
    return wf_bcrypt_hash(WF_BCRYPT_SHA256_NAME, 6, 0, 0, 0, data, dlen, out, olen, 32);
}
uint32_t WfHmacSha1(uintptr_t key, uint32_t klen, uintptr_t data, uint32_t dlen,
    uintptr_t out, uint32_t olen) {
    return wf_bcrypt_hash(WF_BCRYPT_SHA1_NAME, 4, WF_BCRYPT_HMAC_FLAG, key, klen, data, dlen, out, olen, 20);
}
uint32_t WfHmacSha256(uintptr_t key, uint32_t klen, uintptr_t data, uint32_t dlen,
    uintptr_t out, uint32_t olen) {
    return wf_bcrypt_hash(WF_BCRYPT_SHA256_NAME, 6, WF_BCRYPT_HMAC_FLAG, key, klen, data, dlen, out, olen, 32);
}
uint32_t WfHmacSha512(uintptr_t key, uint32_t klen, uintptr_t data, uint32_t dlen,
    uintptr_t out, uint32_t olen) {
    return wf_bcrypt_hash(WF_BCRYPT_SHA512_NAME, 6, WF_BCRYPT_HMAC_FLAG, key, klen, data, dlen, out, olen, 64);
}
// WfTcpSendRecv: Kerberos TCP send-recv via WASM-side sock_* primitives.
//
// Replaces the former net_tcpsendrecv env import with a fully WASM-side
// implementation using the sock_* host functions already exported for
// WfTcp.cs.  Avoids the env→Go round-trip that was required by the
// previous delegation and removes the last caller of net_tcpsendrecv.
//
// Wire protocol: 4-byte big-endian length prefix on send and on receive
// (standard Kerberos TCP framing, RFC 4120 §7.2.2).
//
// DNS resolution: wf_sock_getaddrinfo result format (per internal/hostmod/dns.go):
//   per-entry header: [family:u16 LE][socktype:u16 LE][protocol:u16 LE][addrlen:u16 LE]
//   IPv4 body (addrlen=8): [family:u16 LE][port:u16 BE][addr:4 bytes]
//   total per IPv4 entry = 16 bytes; actual addr at header_offset + 8 + 4 = +12.
//
// sockaddr_in layout expected by wf_sock_connect (internal/hostmod/addr.go):
//   [family:u16 LE][port:u16 BE][addr:4 bytes] = 8 bytes total.
//
// Parameters:
//   h/hl  — hostname UTF-8 (WASM ptr + byte length, not NUL-terminated)
//   p     — TCP port
//   d/dl  — raw Kerberos request payload (no length prefix; this fn adds it)
//   o/ol  — output buffer (WASM ptr + capacity)
// Returns: bytes of payload written to o (0 on error; length prefix not included).
uint32_t WfTcpSendRecv(uintptr_t h, uint32_t hl, uint32_t p,
                        uintptr_t d, uint32_t dl,
                        uintptr_t o, uint32_t ol) {
    const uint32_t AF_INET     = 2;
    const uint32_t SOCK_STREAM = 1;
    const uint32_t IPPROTO_TCP = 6;
    const uint32_t EAGAIN      = 6;

    // ── 1. DNS resolution ───────────────────────────────────────────────
    // Result buffer: up to 4 entries × 16 bytes each.
    uint8_t result_buf[64];
    uint32_t n_results = 0;
    uint32_t err = wf_sock_getaddrinfo(
        (const void*)h, hl,
        NULL, 0,
        0u,
        result_buf, 4u,
        &n_results);
    if (err != 0 || n_results == 0) return 0;

    // Walk entries to find first IPv4.
    uint8_t ip4[4];
    int found_ip = 0;
    uint32_t off = 0;
    for (uint32_t i = 0; i < n_results && off + 8 <= sizeof(result_buf); i++) {
        uint16_t family  = (uint16_t)(result_buf[off+0] | (result_buf[off+1] << 8));
        uint16_t addrlen = (uint16_t)(result_buf[off+6] | (result_buf[off+7] << 8));
        uint32_t entry_end = off + 8 + (addrlen == 0 ? 8 : addrlen);
        if (family == AF_INET && addrlen >= 8 && entry_end <= sizeof(result_buf)) {
            // addr bytes at off+8+4 (skip inner sockaddr_in family+port)
            ip4[0] = result_buf[off+12];
            ip4[1] = result_buf[off+13];
            ip4[2] = result_buf[off+14];
            ip4[3] = result_buf[off+15];
            found_ip = 1;
            break;
        }
        off = entry_end;
    }
    if (!found_ip) return 0;

    // ── 2. Open TCP socket ──────────────────────────────────────────────
    int32_t fd = -1;
    err = wf_sock_open((int32_t)AF_INET, (int32_t)SOCK_STREAM, (int32_t)IPPROTO_TCP, &fd);
    if (err != 0 || fd < 0) return 0;

    // ── 3. Connect ──────────────────────────────────────────────────────
    // sockaddr_in: [family:u16 LE][port:u16 BE][addr:4]
    uint8_t addr[8];
    addr[0] = (uint8_t)(AF_INET & 0xff);
    addr[1] = (uint8_t)((AF_INET >> 8) & 0xff);
    addr[2] = (uint8_t)((p >> 8) & 0xff);   // port big-endian
    addr[3] = (uint8_t)(p & 0xff);
    addr[4] = ip4[0]; addr[5] = ip4[1];
    addr[6] = ip4[2]; addr[7] = ip4[3];
    err = wf_sock_connect(fd, addr, 8);
    // EINPROGRESS(26) / EAGAIN on non-blocking connect are acceptable.
    if (err != 0 && err != 26 && err != EAGAIN) {
        wf_sock_close(fd);
        return 0;
    }

    // ── 4. Build framed send buffer: [4-byte BE length][payload] ───────
    // Stack-allocate a small header + pointer-to-payload write.
    uint8_t lenbuf[4];
    lenbuf[0] = (uint8_t)((dl >> 24) & 0xff);
    lenbuf[1] = (uint8_t)((dl >> 16) & 0xff);
    lenbuf[2] = (uint8_t)((dl >>  8) & 0xff);
    lenbuf[3] = (uint8_t)(dl & 0xff);

    // Write length prefix.
    uint32_t total_w = 0;
    int tries = 0;
    while (total_w < 4 && tries < 200) {
        uint32_t nw = 0;
        err = wf_sock_write(fd, lenbuf + total_w, 4 - total_w, &nw);
        if (err == 0) {
            total_w += nw;
            if (nw == 0) tries++;
        } else if (err == EAGAIN) {
            tries++;
        } else {
            wf_sock_close(fd);
            return 0;
        }
    }
    if (total_w < 4) { wf_sock_close(fd); return 0; }

    // Write payload.
    total_w = 0; tries = 0;
    while (total_w < dl && tries < 200) {
        uint32_t nw = 0;
        err = wf_sock_write(fd, (const void*)(d + total_w), dl - total_w, &nw);
        if (err == 0) {
            total_w += nw;
            if (nw == 0) tries++;
        } else if (err == EAGAIN) {
            tries++;
        } else {
            wf_sock_close(fd);
            return 0;
        }
    }
    if (total_w < dl) { wf_sock_close(fd); return 0; }

    // ── 5. Read 4-byte response length prefix ───────────────────────────
    uint8_t rlen_buf[4];
    uint32_t got = 0;
    int idle = 0;
    while (got < 4) {
        uint32_t nr = 0;
        err = wf_sock_read(fd, rlen_buf + got, 4 - got, &nr);
        if (err == 0) {
            if (nr == 0) { idle++; if (idle > 200) { wf_sock_close(fd); return 0; } continue; }
            got += nr; idle = 0;
        } else if (err == EAGAIN) {
            idle++; if (idle > 200) { wf_sock_close(fd); return 0; }
        } else {
            wf_sock_close(fd); return 0;
        }
    }
    uint32_t resp_len = ((uint32_t)rlen_buf[0] << 24) | ((uint32_t)rlen_buf[1] << 16)
                      | ((uint32_t)rlen_buf[2] <<  8) |  (uint32_t)rlen_buf[3];
    if (resp_len == 0 || resp_len > ol) { wf_sock_close(fd); return 0; }

    // ── 6. Read response payload ────────────────────────────────────────
    got = 0; idle = 0;
    while (got < resp_len) {
        uint32_t nr = 0;
        err = wf_sock_read(fd, (void*)(o + got), resp_len - got, &nr);
        if (err == 0) {
            if (nr == 0) { idle++; if (idle > 200) { wf_sock_close(fd); return 0; } continue; }
            got += nr; idle = 0;
        } else if (err == EAGAIN) {
            idle++; if (idle > 200) { wf_sock_close(fd); return 0; }
        } else {
            wf_sock_close(fd); return 0;
        }
    }

    wf_sock_close(fd);
    return resp_len;
}
// LDAP infrastructure — wldap32 wf_call chain.
//
// Shared helper between LdapSearch / LdapSearchExt. Wire-out format the C#
// consumer (System.DirectoryServices stub) parses:
//   entry := (attr ":" value "\n")+
//   output := entry "\0" entry "\0" ...
//
// Attribute list is tab-separated in `attrs`. Empty attrs means "all".

#define WF_LDAP_OPT_VERSION     0x11
#define WF_LDAP_OPT_REFERRALS   0x08
#define WF_LDAP_OPT_SIGN        0x95
#define WF_LDAP_OPT_ENCRYPT     0x96
#define WF_LDAP_SCOPE_BASE      0
#define WF_LDAP_SCOPE_SUBTREE   2
#define WF_LDAP_AUTH_NEGOTIATE  0x0486

// SEC_WINNT_AUTH_IDENTITY_W layout (x64):
//   0:  USHORT* User              (8) — pointer (after padding)
//   8:  ULONG   UserLength         (4)
//   12: pad                        (4)
//   16: USHORT* Domain             (8)
//   24: ULONG   DomainLength       (4)
//   28: pad                        (4)
//   32: USHORT* Password           (8)
//   40: ULONG   PasswordLength     (4)
//   44: ULONG   Flags              (4) — 2 = SEC_WINNT_AUTH_IDENTITY_UNICODE
//   Total 48 bytes
typedef struct {
    uint64_t userPtr;
    uint32_t userLen;
    uint32_t _pad1;
    uint64_t domainPtr;
    uint32_t domainLen;
    uint32_t _pad2;
    uint64_t passwordPtr;
    uint32_t passwordLen;
    uint32_t flags;
} wf_sec_winnt_auth_identity_w;

// Convert UTF-8 (ASCII subset) into a UTF-16LE buffer. Returns chars written
// (excluding NUL). Caller provides target.
static uint32_t wf_utf8_to_wide_buf(const uint8_t* src, uint32_t srclen, uint16_t* dst, uint32_t dstcap) {
    if (srclen + 1 > dstcap) return 0;
    for (uint32_t i = 0; i < srclen; i++) {
        if (src[i] & 0x80) return 0;
        dst[i] = src[i];
    }
    dst[srclen] = 0;
    return srclen;
}

// Reads UTF-16LE wide string at host_ptr into UTF-8 ASCII at dst (up to dst_cap-1
// chars). Returns chars written.
//
// host_ptr is a host-side virtual address (returned from ldap_*W calls) that
// cannot be dereferenced directly from WASM linear memory. We pull the wide
// chars across the WASM/host boundary in chunks using wf_host_read_bytes,
// scanning for a NUL terminator while we go. Stops at dst_cap-1 to leave
// space for the trailing NUL, and bounds the read length defensively so a
// missing NUL never walks past either buffer end.
static uint32_t wf_wide_to_ascii(uintptr_t host_ptr, uint8_t* dst, uint32_t dst_cap) {
    if (host_ptr == 0 || dst_cap == 0) return 0;
    // Pull up to (dst_cap-1) wide chars in chunks; stop on first NUL.
    uint16_t scratch[128];
    uint32_t k = 0;
    while (k + 1 < dst_cap) {
        uint32_t want = dst_cap - 1 - k;
        if (want > 128) want = 128;
        uint32_t got = wf_host_read_bytes(
            (uint64_t)host_ptr + (uint64_t)k * 2,
            want * 2,
            (void*)scratch);
        if (got == 0) break;
        uint32_t got_chars = got / 2;
        for (uint32_t i = 0; i < got_chars; i++) {
            if (scratch[i] == 0) {
                dst[k] = 0;
                return k;
            }
            dst[k++] = (uint8_t)(scratch[i] & 0xff);
            if (k + 1 >= dst_cap) break;
        }
    }
    dst[k] = 0;
    return k;
}

// Iterate LDAP attribute values and emit "attr:value\n" lines. Returns chars
// written. Stops when buf would overflow.
static uint32_t wf_ldap_emit_entry(uint64_t ld, uint64_t entry, uint8_t* out, uint32_t out_pos, uint32_t out_cap) {
    uint64_t berElem = 0;
    uint64_t attr = wf_call_v2("wldap32.dll", "ldap_first_attributeW", 3, /*out8_mask=*/0x4,
        ld, entry, (uint64_t)(uintptr_t)&berElem);
    while (attr != 0 && out_pos < out_cap) {
        // Attribute name (wide string at attr).
        uint8_t name_buf[256];
        uint32_t name_len = wf_wide_to_ascii((uintptr_t)attr, name_buf, sizeof(name_buf));

        uint64_t vals = wf_call("wldap32.dll", "ldap_get_valuesW", 3, ld, entry, attr);
        if (vals != 0) {
            // vals is a null-terminated array of host pointers — cannot
            // dereference directly from WASM. Pull each WCHAR* slot across
            // the boundary one at a time.
            for (uint32_t vi = 0; vi < 256; vi++) {
                uint64_t valptr = 0;
                if (wf_host_read_bytes(vals + (uint64_t)vi * 8, 8, &valptr) != 8) break;
                if (valptr == 0) break;
                uint8_t val_buf[1024];
                uint32_t val_len = wf_wide_to_ascii((uintptr_t)valptr, val_buf, sizeof(val_buf));
                if (out_pos + name_len + val_len + 2 > out_cap) goto done;
                for (uint32_t i = 0; i < name_len; i++) out[out_pos++] = name_buf[i];
                out[out_pos++] = ':';
                for (uint32_t i = 0; i < val_len; i++) out[out_pos++] = val_buf[i];
                out[out_pos++] = '\n';
            }
            wf_call("wldap32.dll", "ldap_value_freeW", 1, vals);
        }

        wf_call("wldap32.dll", "ldap_memfreeW", 1, attr);
        attr = wf_call_v2("wldap32.dll", "ldap_next_attributeW", 3, /*out8_mask=*/0x4,
            ld, entry, (uint64_t)(uintptr_t)&berElem);
    }
done:
    return out_pos;
}

// Shared LDAP search routine. If creds are provided (userlen > 0 or pwlen > 0)
// uses NEGOTIATE bind with SEC_WINNT_AUTH_IDENTITY_W; else uses NULL bind.
static uint32_t wf_ldap_search_inner(
    const uint16_t* server_w, uint32_t port,
    const uint16_t* basedn_w, const uint16_t* filter_w, uint16_t** attr_array,
    const uint16_t* user_w, uint32_t userlen,
    const uint16_t* domain_w, uint32_t domainlen,
    const uint16_t* password_w, uint32_t passwordlen,
    uint8_t* out, uint32_t out_cap)
{
    // ldap_initW(server, port) → LDAP*
    uint64_t ld = wf_call("wldap32.dll", "ldap_initW", 2,
        (uint64_t)(uintptr_t)server_w, (uint64_t)port);
    if (ld == 0) return 0;

    // Protocol version 3.
    static uint32_t version = 3;
    wf_call("wldap32.dll", "ldap_set_optionW", 3,
        ld, (uint64_t)WF_LDAP_OPT_VERSION, (uint64_t)(uintptr_t)&version);

    // No referrals.
    static uint32_t no_referrals = 0;
    wf_call("wldap32.dll", "ldap_set_optionW", 3,
        ld, (uint64_t)WF_LDAP_OPT_REFERRALS, (uint64_t)(uintptr_t)&no_referrals);

    // Force SASL sign + seal — required for modern AD policies.
    static uint32_t enabled = 1;
    wf_call("wldap32.dll", "ldap_set_optionW", 3,
        ld, (uint64_t)WF_LDAP_OPT_SIGN, (uint64_t)(uintptr_t)&enabled);
    wf_call("wldap32.dll", "ldap_set_optionW", 3,
        ld, (uint64_t)WF_LDAP_OPT_ENCRYPT, (uint64_t)(uintptr_t)&enabled);

    // Bind.
    uint64_t bind_status;
    if (userlen > 0 || passwordlen > 0) {
        static wf_sec_winnt_auth_identity_w ident;
        ident.userPtr = (uint64_t)(uintptr_t)user_w;
        ident.userLen = userlen;
        ident._pad1 = 0;
        ident.domainPtr = (uint64_t)(uintptr_t)domain_w;
        ident.domainLen = domainlen;
        ident._pad2 = 0;
        ident.passwordPtr = (uint64_t)(uintptr_t)password_w;
        ident.passwordLen = passwordlen;
        ident.flags = 2; // SEC_WINNT_AUTH_IDENTITY_UNICODE
        bind_status = wf_call("wldap32.dll", "ldap_bind_sW", 4,
            ld, (uint64_t)0,
            (uint64_t)(uintptr_t)&ident,
            (uint64_t)WF_LDAP_AUTH_NEGOTIATE);
    } else {
        bind_status = wf_call("wldap32.dll", "ldap_bind_sW", 4,
            ld, (uint64_t)0, (uint64_t)0, (uint64_t)WF_LDAP_AUTH_NEGOTIATE);
    }
    if (bind_status != 0) {
        wf_call("wldap32.dll", "ldap_unbind", 1, ld);
        return 0;
    }

    // Scope: BASE if basedn is empty (RootDSE), else SUBTREE.
    uint32_t scope = (basedn_w[0] == 0) ? WF_LDAP_SCOPE_BASE : WF_LDAP_SCOPE_SUBTREE;

    // ldap_search_sW(ld, base, scope, filter, attrs, attrsonly=0, &results)
    uint64_t results = 0;
    uint64_t srch = wf_call_v2("wldap32.dll", "ldap_search_sW", 7, /*out8_mask=*/0x40,
        ld,
        (uint64_t)(uintptr_t)basedn_w,
        (uint64_t)scope,
        (uint64_t)(uintptr_t)filter_w,
        (uint64_t)(uintptr_t)attr_array,
        (uint64_t)0,
        (uint64_t)(uintptr_t)&results);
    if (srch != 0 || results == 0) {
        wf_call("wldap32.dll", "ldap_unbind", 1, ld);
        return 0;
    }

    // Iterate entries.
    uint32_t out_pos = 0;
    uint64_t entry = wf_call("wldap32.dll", "ldap_first_entry", 2, ld, results);
    int first = 1;
    while (entry != 0 && out_pos < out_cap) {
        if (!first && out_pos + 1 < out_cap) out[out_pos++] = 0; // entry separator
        first = 0;
        out_pos = wf_ldap_emit_entry(ld, entry, out, out_pos, out_cap);
        entry = wf_call("wldap32.dll", "ldap_next_entry", 2, ld, entry);
    }
    if (out_pos < out_cap) out[out_pos] = 0;

    wf_call("wldap32.dll", "ldap_msgfree", 1, results);
    wf_call("wldap32.dll", "ldap_unbind", 1, ld);
    return out_pos;
}

// Build a NULL-terminated array of UTF-16 attribute name pointers from a
// tab-separated UTF-8 attribute list. Returns NULL if no attrs (search all).
static uint16_t** wf_build_attr_array(const uint8_t* attrs, uint32_t attrs_len) {
    static uint16_t attr_storage[32][128];   // up to 32 attrs, 128 chars each
    static uint16_t* attr_ptrs[33];          // +1 for NULL terminator
    if (attrs_len == 0) return NULL;
    uint32_t count = 0;
    uint32_t i = 0;
    while (i < attrs_len && count < 32) {
        uint32_t start = i;
        while (i < attrs_len && attrs[i] != '\t') i++;
        uint32_t len = i - start;
        if (len > 0 && len < 127) {
            for (uint32_t k = 0; k < len; k++) attr_storage[count][k] = attrs[start + k];
            attr_storage[count][len] = 0;
            attr_ptrs[count] = attr_storage[count];
            count++;
        }
        if (i < attrs_len) i++; // skip tab
    }
    attr_ptrs[count] = NULL;
    return count > 0 ? attr_ptrs : NULL;
}

uint32_t WfLdapSearch(uintptr_t s, uint32_t sl, uint32_t p, uintptr_t b, uint32_t bl,
    uintptr_t f, uint32_t fl, uintptr_t a, uint32_t al, uintptr_t o, uint32_t ol)
{
    static uint16_t srv_w[512], base_w[1024], filt_w[1024];
    if (!wf_utf8_to_wide_buf((const uint8_t*)s, sl, srv_w, sizeof(srv_w)/2)) return 0;
    if (bl > 0 && !wf_utf8_to_wide_buf((const uint8_t*)b, bl, base_w, sizeof(base_w)/2)) return 0;
    if (bl == 0) base_w[0] = 0;
    if (!wf_utf8_to_wide_buf((const uint8_t*)f, fl, filt_w, sizeof(filt_w)/2)) return 0;
    uint16_t** attrs = wf_build_attr_array((const uint8_t*)a, al);
    return wf_ldap_search_inner(srv_w, p, base_w, filt_w, attrs,
        NULL, 0, NULL, 0, NULL, 0,
        (uint8_t*)o, ol);
}

uint32_t WfLdapSearchExt(uintptr_t s, uint32_t sl, uint32_t p, uintptr_t b, uint32_t bl,
    uintptr_t f, uint32_t fl, uintptr_t a, uint32_t al,
    uintptr_t u, uint32_t ul, uintptr_t d, uint32_t dl,
    uintptr_t pw, uint32_t pwl, uintptr_t o, uint32_t ol)
{
    static uint16_t srv_w[512], base_w[1024], filt_w[1024];
    static uint16_t user_w[256], dom_w[256], pw_w[256];
    if (!wf_utf8_to_wide_buf((const uint8_t*)s, sl, srv_w, sizeof(srv_w)/2)) return 0;
    if (bl > 0 && !wf_utf8_to_wide_buf((const uint8_t*)b, bl, base_w, sizeof(base_w)/2)) return 0;
    if (bl == 0) base_w[0] = 0;
    if (!wf_utf8_to_wide_buf((const uint8_t*)f, fl, filt_w, sizeof(filt_w)/2)) return 0;
    if (ul > 0 && !wf_utf8_to_wide_buf((const uint8_t*)u, ul, user_w, sizeof(user_w)/2)) return 0;
    if (dl > 0 && !wf_utf8_to_wide_buf((const uint8_t*)d, dl, dom_w, sizeof(dom_w)/2)) return 0;
    if (pwl > 0 && !wf_utf8_to_wide_buf((const uint8_t*)pw, pwl, pw_w, sizeof(pw_w)/2)) return 0;
    uint16_t** attrs = wf_build_attr_array((const uint8_t*)a, al);
    return wf_ldap_search_inner(srv_w, p, base_w, filt_w, attrs,
        ul > 0 ? user_w : NULL, ul,
        dl > 0 ? dom_w : NULL, dl,
        pwl > 0 ? pw_w : NULL, pwl,
        (uint8_t*)o, ol);
}
// WfGetDCName: WASM-side netapi32!DsGetDcNameW chain. Returns DC DNS name
// (UTF-8 ASCII subset) in `out`, length as return value.
//
// DOMAIN_CONTROLLER_INFOW layout on x64:
//   0:  LPWSTR DomainControllerName       (8) — "\\foo.example.com"
//   8:  LPWSTR DomainControllerAddress    (8) — "\\\\1.2.3.4"
//   16: ULONG  DomainControllerAddressType (4)
//   20: GUID   DomainGuid                  (16)
//   36: pad to 8                           (4)
//   40: LPWSTR DomainName                  (8)
//   ...
//
// DsGetDcNameW(NULL ComputerName, domain_w, NULL DomainGuid, NULL SiteName,
//   flags, &DomainControllerInfo) — last arg out-pointer to PDOMAIN_CONTROLLER_INFOW
// ── Seatbelt-named wrapper aliases ──────────────────────────────────
// Seatbelt's Interop layer DllImports these under slightly different names
// than SharpDPAPI/Rubeus. Provide thin aliases mapping to the canonical Wf*.

// Forward decls (defined elsewhere in this file or pinvoke_env_ext.c).
extern uint32_t fs_listdir(uint32_t path_ptr, uint32_t path_len,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr);
extern uint32_t sec_sddl(uint32_t path_ptr,
    uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t sec_parsesddl(uint32_t sddl_ptr, uint32_t sddl_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t net_adapters(uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t ver_info(uint32_t path_ptr, uint32_t path_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t sec_enumrights(uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t rpc_enumeps(uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t wmi_query(uint32_t q, uint32_t ql, uint32_t n, uint32_t nl, uint32_t o, uint32_t ol);
extern uint32_t proc_modules_all(uint32_t out_buf_ptr, uint32_t out_buf_len);
extern uint32_t WfEnumLogonSessions(uint32_t o, uint32_t ol);

uint32_t WfListDir(uint32_t path_ptr, uint32_t path_len,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    return fs_listdir(path_ptr, path_len, buf_ptr, buf_cap, count_ptr);
}
uint32_t WfGetPathSddl(uint32_t path_ptr, uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return sec_sddl(path_ptr, out_buf_ptr, out_buf_len);
}
uint32_t WfParseSddlAcl(uint32_t sddl_ptr, uint32_t sddl_len, uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return sec_parsesddl(sddl_ptr, sddl_len, out_buf_ptr, out_buf_len);
}
uint32_t WfEnumNetworkAdapters(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return net_adapters(out_buf_ptr, out_buf_len);
}
uint32_t WfGetFileVersionInfo(uint32_t path_ptr, uint32_t path_len, uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return ver_info(path_ptr, path_len, out_buf_ptr, out_buf_len);
}
uint32_t WfEnumUserRights(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return sec_enumrights(out_buf_ptr, out_buf_len);
}
uint32_t WfEnumRpcEndpoints(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return rpc_enumeps(out_buf_ptr, out_buf_len);
}
uint32_t WfWmiQuery(uint32_t q, uint32_t ql, uint32_t n, uint32_t nl, uint32_t o, uint32_t ol) {
    return wmi_query(q, ql, n, nl, o, ol);
}
// wmi_query_r: bare-name forwarder for WfWmi.QueryRestricted DllImport.
// The DllImport entrypoint "wmi_query_r" resolves to this C symbol at
// wasm-ld link time; this forwards to the host import wf_wmi_query_restricted.
uint32_t wmi_query_r(uint32_t query_ptr, uint32_t query_len,
    uint32_t ns_ptr, uint32_t ns_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return wf_wmi_query_restricted(query_ptr, query_len, ns_ptr, ns_len, out_buf_ptr, out_buf_len);
}

// reg_search: bare-name forwarder for WfRegistrySearch.NativeRegSearch DllImport.
// The DllImport entrypoint "reg_search" resolves to this C symbol at wasm-ld
// link time; this forwards to the host import wf_reg_search. Same forwarder
// pattern as wmi_query_r above — without it the linker stubs the unresolved
// import with undefined_stub and the WASM traps at first call.
uint32_t reg_search(uint32_t hive, uint32_t out_buf_ptr, uint32_t out_buf_cap) {
    return wf_reg_search(hive, out_buf_ptr, out_buf_cap);
}

// dpapi_bkey: bare-name forwarder for WfDpapiBackupkey.NativeDpapiBackupkey
// DllImport. Same wmi_query_r / reg_search pattern.
uint32_t dpapi_bkey(uint32_t server_ptr, uint32_t server_len,
    uint32_t out_buf_ptr, uint32_t out_buf_cap) {
    return wf_dpapi_backupkey(server_ptr, server_len, out_buf_ptr, out_buf_cap);
}

// x509_match: bare-name forwarder for WfCertModulusMatch.NativeX509Match.
uint32_t x509_match(uint32_t modulus_ptr, uint32_t modulus_len,
    uint32_t out_buf_ptr, uint32_t out_buf_cap) {
    return wf_x509_match(modulus_ptr, modulus_len, out_buf_ptr, out_buf_cap);
}
uint32_t WfEnumProcesses(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return proc_modules_all(out_buf_ptr, out_buf_len);
}
uint32_t WfEnumDnsCache(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    (void)out_buf_ptr; (void)out_buf_len; return 0;
}

// ── Direct P/Invoke shims for Seatbelt-imported Win32 APIs ────────────
// Seatbelt's Interop.* classes DllImport these directly under their canonical
// names. We provide C entrypoints that forward to wf_call so wasm-ld resolves
// them at link time.

// GetCurrentProcess returns HANDLE which is sizeof(void*). NativeAOT-WASI
// uses 32-bit pointers (wasm32), so the P/Invoke signature is i32.
uintptr_t GetCurrentProcess(void) {
    return (uintptr_t)wf_call("kernel32.dll", "GetCurrentProcess", 0);
}

// OpenProcessToken / GetTokenInformation / IsWow64Process already defined
// in pinvoke_advapi32_ext.c / pinvoke_kernel32_ext.c.

// CloseHandle already defined in pinvoke_kernel32_ext.c.

// GetTickCount / GetTickCount64 for IdleTime
uint32_t GetTickCount(void) {
    return (uint32_t)wf_call("kernel32.dll", "GetTickCount", 0);
}
uint64_t GetTickCount64(void) {
    return wf_call("kernel32.dll", "GetTickCount64", 0);
}

// GetLastInputInfo already defined in pinvoke_extras.c.

// QueryDosDeviceW for device-path mapping (used by some Seatbelt commands)
uint32_t QueryDosDeviceW(uintptr_t lpDeviceName, uintptr_t lpTargetPath, uint32_t ucchMax) {
    return (uint32_t)wf_call_v2("kernel32.dll", "QueryDosDeviceW", 3, /*out8_mask=*/0x2,
        (uint64_t)lpDeviceName, (uint64_t)lpTargetPath, (uint64_t)ucchMax);
}

// GetSystemInfo / GetVersionExW
void GetSystemInfo(uintptr_t lpSystemInfo) {
    wf_call_v2("kernel32.dll", "GetSystemInfo", 1, /*out8_mask=*/0x1, (uint64_t)lpSystemInfo);
}

// LookupAccountSidW for SID resolution
uint32_t LookupAccountSidW(uintptr_t lpSystemName, uintptr_t lpSid,
    uintptr_t lpName, uintptr_t cchName,
    uintptr_t lpReferencedDomainName, uintptr_t cchReferencedDomainName,
    uintptr_t peUse) {
    return (uint32_t)wf_call_v2("advapi32.dll", "LookupAccountSidW", 7, /*out8_mask=*/0x54,
        (uint64_t)lpSystemName, (uint64_t)lpSid,
        (uint64_t)lpName, (uint64_t)cchName,
        (uint64_t)lpReferencedDomainName, (uint64_t)cchReferencedDomainName,
        (uint64_t)peUse);
}

// ConvertSidToStringSidW
uint32_t ConvertSidToStringSidW(uintptr_t Sid, uintptr_t StringSid) {
    return (uint32_t)wf_call_v2("advapi32.dll", "ConvertSidToStringSidW", 2, /*out8_mask=*/0x2,
        (uint64_t)Sid, (uint64_t)StringSid);
}

// ConvertStringSidToSidW(LPCWSTR, PSID*) — PSID* is an 8-byte OUT slot on x64;
// out8_mask bit 1. Unprefixed for direct C# DllImport binding from WfSec.cs.
// Lives in pinvoke_nativeaot.c (always-included NativeLibrary) so the symbol
// is reliably linked.
uint32_t ConvertStringSidToSidW(uintptr_t StringSid, uintptr_t Sid) {
    return (uint32_t)wf_call_v2("advapi32.dll", "ConvertStringSidToSidW", 2, /*out8_mask=*/0x2,
        (uint64_t)StringSid, (uint64_t)Sid);
}

// LookupAccountSidW_8 — variant accepting an 8-byte SID pointer (uint64_t)
// instead of the canonical uintptr_t. The canonical wrapper truncates the
// PSID host-pointer to 4 bytes on wasm32; this variant preserves the full
// 64-bit pointer the host wrote into the caller's `out long pSid` slot
// after ConvertStringSidToSidW. lpSystemName is hardcoded to NULL (local
// computer). out8_mask 0x54 = bits 2 (Name), 4 (Domain), 6 (peUse) —
// >4-byte writes that should skip overflow protection.
uint32_t LookupAccountSidW_8(uint64_t lpSid,
    uintptr_t lpName, uintptr_t cchName,
    uintptr_t lpReferencedDomainName, uintptr_t cchReferencedDomainName,
    uintptr_t peUse) {
    return (uint32_t)wf_call_v2("advapi32.dll", "LookupAccountSidW", 7, /*out8_mask=*/0x54,
        (uint64_t)0,                // lpSystemName = NULL
        lpSid,
        (uint64_t)lpName, (uint64_t)cchName,
        (uint64_t)lpReferencedDomainName, (uint64_t)cchReferencedDomainName,
        (uint64_t)peUse);
}

// LocalFree already defined above as kernel32_LocalFree alias.

__attribute__((weak)) uint32_t GetExtendedTcpTable(uintptr_t pTcpTable, uintptr_t pdwSize,
    uint32_t bOrder, uint32_t ulAf, uint32_t TableClass, uint32_t Reserved) {
    return (uint32_t)wf_call_v2("iphlpapi.dll", "GetExtendedTcpTable", 6, /*out8_mask=*/0x1,
        (uint64_t)pTcpTable, (uint64_t)pdwSize, (uint64_t)bOrder,
        (uint64_t)ulAf, (uint64_t)TableClass, (uint64_t)Reserved);
}

__attribute__((weak)) uint32_t GetExtendedUdpTable(uintptr_t pUdpTable, uintptr_t pdwSize,
    uint32_t bOrder, uint32_t ulAf, uint32_t TableClass, uint32_t Reserved) {
    return (uint32_t)wf_call_v2("iphlpapi.dll", "GetExtendedUdpTable", 6, /*out8_mask=*/0x1,
        (uint64_t)pUdpTable, (uint64_t)pdwSize, (uint64_t)bOrder,
        (uint64_t)ulAf, (uint64_t)TableClass, (uint64_t)Reserved);
}

uint32_t RegOpenKeyExW(uintptr_t hKey, uintptr_t lpSubKey, uint32_t ulOptions,
    uint32_t samDesired, uintptr_t phkResult) {
    return (uint32_t)wf_call_v2("advapi32.dll", "RegOpenKeyExW", 5, /*out8_mask=*/0x10,
        (uint64_t)hKey, (uint64_t)lpSubKey, (uint64_t)ulOptions,
        (uint64_t)samDesired, (uint64_t)phkResult);
}

uint32_t RegEnumKeyExW(uintptr_t hKey, uint32_t dwIndex, uintptr_t lpName,
    uintptr_t lpcName, uintptr_t lpReserved, uintptr_t lpClass,
    uintptr_t lpcClass, uintptr_t lpftLastWriteTime) {
    // lpName (arg 2) and lpClass (arg 5) are WCHAR output buffers
    // longer than 4 bytes. Without out8_mask, wf_call's 4-byte overflow
    // guard saves+restores bytes 4-7, corrupting chars 2-3 of every
    // returned name/class string. Set out8_mask to skip the guard for
    // both buffers.
    //
    // Also include lpcName (arg 3) and lpcClass (arg 6) in the mask:
    // these point to `ref uint` DWORDs the API writes back. When two
    // such locals are declared adjacent in the same C# method (e.g.,
    // `uint nameLen = 260; uint classLen = 260;`) NativeAOT places
    // them at consecutive WASM stack slots. The guard's save+restore
    // of bytes at addr+4 for arg 6 (lpcClass) overwrites the OTHER
    // DWORD's freshly-updated value (or vice-versa). Observed
    // symptom: lpcClass stays at in-value 260 while lpcName updates
    // correctly (or some permutation depending on stack layout).
    // Skip the guard for these slots; the DWORDs are exactly 4 bytes
    // wide so the x64 overflow concern that motivated the guard
    // doesn't apply.
    return (uint32_t)wf_call_v2("advapi32.dll", "RegEnumKeyExW", 8,
        /*out8_mask*/ (1u<<2) | (1u<<3) | (1u<<5) | (1u<<6),
        (uint64_t)hKey, (uint64_t)dwIndex, (uint64_t)lpName, (uint64_t)lpcName,
        (uint64_t)lpReserved, (uint64_t)lpClass, (uint64_t)lpcClass,
        (uint64_t)lpftLastWriteTime);
}

uint32_t RegEnumValueW(uintptr_t hKey, uint32_t dwIndex, uintptr_t lpValueName,
    uintptr_t lpcchValueName, uintptr_t lpReserved, uintptr_t lpType,
    uintptr_t lpData, uintptr_t lpcbData) {
    return (uint32_t)wf_call("advapi32.dll", "RegEnumValueW", 8,
        (uint64_t)hKey, (uint64_t)dwIndex, (uint64_t)lpValueName,
        (uint64_t)lpcchValueName, (uint64_t)lpReserved, (uint64_t)lpType,
        (uint64_t)lpData, (uint64_t)lpcbData);
}

uint32_t RegQueryValueExW(uintptr_t hKey, uintptr_t lpValueName,
    uintptr_t lpReserved, uintptr_t lpType, uintptr_t lpData, uintptr_t lpcbData) {
    return (uint32_t)wf_call("advapi32.dll", "RegQueryValueExW", 6,
        (uint64_t)hKey, (uint64_t)lpValueName, (uint64_t)lpReserved,
        (uint64_t)lpType, (uint64_t)lpData, (uint64_t)lpcbData);
}

// RPC stubs — return ERROR_NOT_SUPPORTED for now. Seatbelt's
// RPCMappedEndpoints command will print "no endpoints".
__attribute__((weak)) uint32_t RpcBindingFromStringBinding(uintptr_t s, uintptr_t b) { (void)s;(void)b; return 50; }
__attribute__((weak)) uint32_t RpcBindingToStringBinding(uintptr_t b, uintptr_t s) { (void)b;(void)s; return 50; }
// These RPC stubs are weak so they yield to strong definitions in
// pinvoke_net_ext.c when that file is also linked (Rubeus's case).
// Seatbelt doesn't include pinvoke_net_ext.c, so it uses these stubs.
__attribute__((weak)) uint32_t RpcMgmtEpEltInqBegin(uintptr_t b, uint32_t f, uintptr_t i, uint32_t v, uintptr_t o, uintptr_t c) {
    (void)b;(void)f;(void)i;(void)v;(void)o;(void)c; return 50;
}
__attribute__((weak)) uint32_t RpcMgmtEpEltInqNext(uintptr_t c, uintptr_t i, uintptr_t b, uintptr_t u, uintptr_t a) {
    (void)c;(void)i;(void)b;(void)u;(void)a; return 1772; // EPT_S_NOT_REGISTERED
}
__attribute__((weak)) uint32_t RpcMgmtEpEltInqDone(uintptr_t c) { (void)c; return 0; }
__attribute__((weak)) uint32_t RpcStringBindingCompose(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 50;
}
__attribute__((weak)) uint32_t RpcStringFree(uintptr_t s) { (void)s; return 0; }

uint32_t WfGetDCName(uintptr_t d, uint32_t dl, uint32_t fl, uintptr_t o, uint32_t ol) {
    if (dl > 254) return 0;
    // Convert UTF-8 ASCII domain to UTF-16LE.
    static uint16_t dom_wide[256];
    const uint8_t* dsrc = (const uint8_t*)d;
    for (uint32_t i = 0; i < dl; i++) {
        if (dsrc[i] & 0x80) return 0;
        dom_wide[i] = dsrc[i];
    }
    dom_wide[dl] = 0;

    uint64_t pDcInfo = 0;
    uint64_t status = wf_call_v2("netapi32.dll", "DsGetDcNameW", 6, /*out8_mask=*/0x20,
        (uint64_t)0,                              // ComputerName=NULL
        (uint64_t)(uintptr_t)dom_wide,            // DomainName
        (uint64_t)0,                              // DomainGuid=NULL
        (uint64_t)0,                              // SiteName=NULL
        (uint64_t)fl,                             // Flags
        (uint64_t)(uintptr_t)&pDcInfo);           // DomainControllerInfo out

    if (status != 0 || pDcInfo == 0) return 0;

    // Read DomainControllerName at offset 0.
    uint64_t pName = *(uint64_t*)(uintptr_t)pDcInfo;
    uint32_t written = 0;
    if (pName != 0) {
        const uint16_t* name = (const uint16_t*)(uintptr_t)pName;
        uint8_t* dst = (uint8_t*)(uintptr_t)o;
        // Skip leading "\\" if present (DC name is reported as "\\dc.foo.com").
        uint32_t i = 0;
        if (name[0] == '\\' && name[1] == '\\') i = 2;
        for (; name[i] != 0 && written + 1 < ol; i++) {
            dst[written++] = (uint8_t)(name[i] & 0xff);
        }
        dst[written] = 0;
    }

    // Free the buffer returned by DsGetDcName.
    wf_call("netapi32.dll", "NetApiBufferFree", 1, pDcInfo);
    return written;
}

// ── WfForge.cs P/Invoke wrappers ──────────────────────────────────
// Only adding the symbols not already defined elsewhere in this file.

uint32_t CertStrToNameW(uint32_t dwCertEncodingType, uint32_t pszX500,
    uint32_t dwStrType, uint32_t pvReserved, uint32_t pbEncoded,
    uint32_t pcbEncoded, uint32_t ppszError) {
    return (uint32_t)wf_call("crypt32.dll", "CertStrToNameW", 7,
        (uint64_t)dwCertEncodingType, (uint64_t)pszX500,
        (uint64_t)dwStrType, (uint64_t)pvReserved,
        (uint64_t)pbEncoded, (uint64_t)pcbEncoded, (uint64_t)ppszError);
}

uintptr_t CertCreateSelfSignCertificate(uintptr_t hCryptProvOrNCryptKey,
    uint32_t pSubjectIssuerBlob, uint32_t dwFlags,
    uint32_t pKeyProvInfo, uint32_t pSignatureAlgorithm,
    uint32_t pStartTime, uint32_t pEndTime, uint32_t pExtensions) {
    return (uintptr_t)wf_call("crypt32.dll", "CertCreateSelfSignCertificate", 8,
        (uint64_t)hCryptProvOrNCryptKey,
        (uint64_t)pSubjectIssuerBlob, (uint64_t)dwFlags,
        (uint64_t)pKeyProvInfo, (uint64_t)pSignatureAlgorithm,
        (uint64_t)pStartTime, (uint64_t)pEndTime, (uint64_t)pExtensions);
}

uint32_t CryptAcquireContextW(uint32_t phProv, uint32_t pszContainer,
    uint32_t pszProvider, uint32_t dwProvType, uint32_t dwFlags) {
    return (uint32_t)wf_call("advapi32.dll", "CryptAcquireContextW", 5,
        (uint64_t)phProv, (uint64_t)pszContainer, (uint64_t)pszProvider,
        (uint64_t)dwProvType, (uint64_t)dwFlags);
}

uint32_t CryptGenKey(uintptr_t hProv, uint32_t Algid, uint32_t dwFlags,
    uint32_t phKey) {
    return (uint32_t)wf_call("advapi32.dll", "CryptGenKey", 4,
        (uint64_t)hProv, (uint64_t)Algid, (uint64_t)dwFlags, (uint64_t)phKey);
}

// CertFreeCertificateContext, CryptDestroyKey, CryptReleaseContext are
// defined earlier in this file with uintptr_t signatures.

// ── BCrypt (CNG) P/Invoke wrappers for WfForge ────────────────────
//
// All wrappers with WASM pointer output args use wf_call_v2 with an
// out8_mask bit set for each output. The default wf_call protection
// saves/restores 4 bytes at addr+4 which corrupts:
//   - High 32 bits of an 8-byte BCRYPT_*_HANDLE (phAlgorithm, phKey)
//   - Bytes 4-7 of any output buffer larger than 4 bytes (pbOutput)
// 4-byte output slots like `pcbResult` (ULONG*) are NOT in the mask —
// the protection is harmless there because the API writes only 4 bytes.

WF_KEEP uint32_t BCryptOpenAlgorithmProvider(uint32_t phAlgorithm,
    uint32_t pszAlgId, uint32_t pszImplementation, uint32_t dwFlags) {
    // phAlgorithm (arg 0) is an `out BCRYPT_ALG_HANDLE` — 8-byte slot.
    return (uint32_t)wf_call_v2("bcrypt.dll", "BCryptOpenAlgorithmProvider", 4,
        /*out8_mask=*/ 0x1,
        (uint64_t)phAlgorithm, (uint64_t)pszAlgId,
        (uint64_t)pszImplementation, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptCloseAlgorithmProvider(uint64_t hAlgorithm, uint32_t dwFlags) {
    return (uint32_t)wf_call("bcrypt.dll", "BCryptCloseAlgorithmProvider", 2,
        hAlgorithm, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptGenerateKeyPair(uint64_t hAlgorithm, uint32_t phKey,
    uint32_t dwLength, uint32_t dwFlags) {
    // phKey (arg 1) is an `out BCRYPT_KEY_HANDLE` — 8-byte slot.
    return (uint32_t)wf_call_v2("bcrypt.dll", "BCryptGenerateKeyPair", 4,
        /*out8_mask=*/ 0x2,
        hAlgorithm, (uint64_t)phKey,
        (uint64_t)dwLength, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptFinalizeKeyPair(uint64_t hKey, uint32_t dwFlags) {
    return (uint32_t)wf_call("bcrypt.dll", "BCryptFinalizeKeyPair", 2,
        hKey, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptDestroyKey(uint64_t hKey) {
    return (uint32_t)wf_call("bcrypt.dll", "BCryptDestroyKey", 1, hKey);
}

WF_KEEP uint32_t BCryptExportKey(uint64_t hKey, uint64_t hExportKey,
    uint32_t pszBlobType, uint32_t pbOutput, uint32_t cbOutput,
    uint32_t pcbResult, uint32_t dwFlags) {
    // pbOutput (arg 3) is an output buffer >= 4 bytes — bytes 4-7 would
    // be corrupted by the default protection.
    return (uint32_t)wf_call_v2("bcrypt.dll", "BCryptExportKey", 7,
        /*out8_mask=*/ 0x8,
        hKey, hExportKey, (uint64_t)pszBlobType,
        (uint64_t)pbOutput, (uint64_t)cbOutput,
        (uint64_t)pcbResult, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptSignHash(uint64_t hKey, uint32_t pPaddingInfo,
    uint32_t pbInput, uint32_t cbInput, uint32_t pbOutput,
    uint32_t cbOutput, uint32_t pcbResult, uint32_t dwFlags) {
    // pbOutput (arg 4) is an output signature buffer >= 4 bytes.
    return (uint32_t)wf_call_v2("bcrypt.dll", "BCryptSignHash", 8,
        /*out8_mask=*/ 0x10,
        hKey, (uint64_t)pPaddingInfo,
        (uint64_t)pbInput, (uint64_t)cbInput,
        (uint64_t)pbOutput, (uint64_t)cbOutput,
        (uint64_t)pcbResult, (uint64_t)dwFlags);
}

WF_KEEP uint32_t BCryptHash(uint64_t hAlgorithm, uint32_t pbSecret, uint32_t cbSecret,
    uint32_t pbInput, uint32_t cbInput, uint32_t pbOutput, uint32_t cbOutput) {
    // pbOutput (arg 5) is an output hash buffer >= 4 bytes.
    return (uint32_t)wf_call_v2("bcrypt.dll", "BCryptHash", 7,
        /*out8_mask=*/ 0x20,
        hAlgorithm, (uint64_t)pbSecret, (uint64_t)cbSecret,
        (uint64_t)pbInput, (uint64_t)cbInput,
        (uint64_t)pbOutput, (uint64_t)cbOutput);
}

// ── bcrypt.dll prefix aliases ───────────────────────────────────────
//
// NativeAOT-LLVM's DirectPInvoke resolution for bcrypt.dll looks for
// symbols named `bcrypt_BCryptOpenAlgorithmProvider` (dll-prefix + '_'
// + function name) when the linker can't find the bare name. The bare
// exports above work for some configurations but not all — the WfCsr
// and WfForge code paths in Certify hit "Lazy PInvoke resolution is
// not supported" without these prefixed aliases. Adding both
// conventions makes resolution unambiguous.
//
// BCryptSetProperty is also declared so direct callers can use it even
// though WfCsr currently doesn't (might in future for IV setup).

uint32_t bcrypt_BCryptOpenAlgorithmProvider(uint32_t phAlgorithm,
    uint32_t pszAlgId, uint32_t pszImplementation, uint32_t dwFlags) {
    return BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
}
uint32_t bcrypt_BCryptCloseAlgorithmProvider(uint64_t hAlgorithm, uint32_t dwFlags) {
    return BCryptCloseAlgorithmProvider(hAlgorithm, dwFlags);
}
uint32_t bcrypt_BCryptGenerateKeyPair(uint64_t hAlgorithm, uint32_t phKey,
    uint32_t dwLength, uint32_t dwFlags) {
    return BCryptGenerateKeyPair(hAlgorithm, phKey, dwLength, dwFlags);
}
uint32_t bcrypt_BCryptFinalizeKeyPair(uint64_t hKey, uint32_t dwFlags) {
    return BCryptFinalizeKeyPair(hKey, dwFlags);
}
uint32_t bcrypt_BCryptDestroyKey(uint64_t hKey) {
    return BCryptDestroyKey(hKey);
}
uint32_t bcrypt_BCryptExportKey(uint64_t hKey, uint64_t hExportKey,
    uint32_t pszBlobType, uint32_t pbOutput, uint32_t cbOutput,
    uint32_t pcbResult, uint32_t dwFlags) {
    return BCryptExportKey(hKey, hExportKey, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags);
}
uint32_t bcrypt_BCryptSignHash(uint64_t hKey, uint32_t pPaddingInfo,
    uint32_t pbInput, uint32_t cbInput, uint32_t pbOutput, uint32_t cbOutput,
    uint32_t pcbResult, uint32_t dwFlags) {
    return BCryptSignHash(hKey, pPaddingInfo, pbInput, cbInput,
        pbOutput, cbOutput, pcbResult, dwFlags);
}
uint32_t bcrypt_BCryptHash(uint64_t hAlgorithm, uint32_t pbSecret, uint32_t cbSecret,
    uint32_t pbInput, uint32_t cbInput, uint32_t pbOutput, uint32_t cbOutput) {
    return BCryptHash(hAlgorithm, pbSecret, cbSecret,
        pbInput, cbInput, pbOutput, cbOutput);
}

// BCryptSetProperty (used by WfForge for hash padding modes).
WF_KEEP uint32_t BCryptSetProperty(uint64_t hObject, uint32_t pszProperty,
    uint32_t pbInput, uint32_t cbInput, uint32_t dwFlags) {
    return (uint32_t)wf_call("bcrypt.dll", "BCryptSetProperty", 5,
        hObject, (uint64_t)pszProperty, (uint64_t)pbInput,
        (uint64_t)cbInput, (uint64_t)dwFlags);
}
uint32_t bcrypt_BCryptSetProperty(uint64_t hObject, uint32_t pszProperty,
    uint32_t pbInput, uint32_t cbInput, uint32_t dwFlags) {
    return BCryptSetProperty(hObject, pszProperty, pbInput, cbInput, dwFlags);
}
