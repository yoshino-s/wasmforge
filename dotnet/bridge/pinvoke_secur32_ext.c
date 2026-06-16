// pinvoke_secur32_ext.c — secur32.dll P/Invoke bridge stubs for NativeAOT-WASI.
//
// Auto-discovered as undefined symbols when building Seatbelt against WasmForge.
// Each stub forwards to wf_call() which dispatches to the real Win32 API on the
// host. The unprefixed naming convention (e.g. LsaGetLogonSessionData, NOT
// secur32_LsaGetLogonSessionData) is what NativeAOT-LLVM expects when the .csproj
// contains <DirectPInvoke Include="secur32" />.
//
// All pointer arguments are uint64_t (WASM linear-memory offsets; the host bridge
// translates them to host pointers). Small scalars are uint32_t in the parameter
// list and cast to uint64_t at the wf_call site.

#include "wf_bridge.h"

// AcceptSecurityContext
// SECURITY_STATUS AcceptSecurityContext(
//   SEC_HANDLE *phCredential, SEC_HANDLE *phContext, SecBufferDesc *pInput,
//   ULONG fContextReq, ULONG TargetDataRep, SEC_HANDLE *phNewContext,
//   SecBufferDesc *pOutput, ULONG *pfContextAttr, TimeStamp *ptsExpiry)
uint32_t AcceptSecurityContext(uint32_t phCredential, uint32_t phContext, uint32_t pInput, uint32_t fContextReq, uint32_t TargetDataRep, uint32_t phNewContext, uint32_t pOutput, uint32_t pfContextAttr, uint32_t ptsExpiry) {
    return (uint32_t)wf_call("secur32.dll", "AcceptSecurityContext", 9,
        (uint64_t)phCredential, (uint64_t)phContext, (uint64_t)pInput,
        (uint64_t)fContextReq, (uint64_t)TargetDataRep, (uint64_t)phNewContext,
        (uint64_t)pOutput, (uint64_t)pfContextAttr, (uint64_t)ptsExpiry);
}

// AcquireCredentialsHandle
// SECURITY_STATUS AcquireCredentialsHandleW(
//   LPCWSTR pPrincipal, LPCWSTR pPackage, ULONG fCredentialUse,
//   void *pvLogonID, void *pAuthData, void *pGetKeyFn,
//   void *pvGetKeyArgument, SEC_HANDLE *phCredential, TimeStamp *ptsExpiry)
uint32_t AcquireCredentialsHandle(uint32_t pPrincipal, uint32_t pPackage, uint32_t fCredentialUse, uint32_t pvLogonID, uint32_t pAuthData, uint32_t pGetKeyFn, uint32_t pvGetKeyArgument, uint32_t phCredential, uint32_t ptsExpiry) {
    return (uint32_t)wf_call("secur32.dll", "AcquireCredentialsHandleW", 9,
        (uint64_t)pPrincipal, (uint64_t)pPackage, (uint64_t)fCredentialUse,
        (uint64_t)pvLogonID, (uint64_t)pAuthData, (uint64_t)pGetKeyFn,
        (uint64_t)pvGetKeyArgument, (uint64_t)phCredential, (uint64_t)ptsExpiry);
}

// EnumerateSecurityPackages
// SECURITY_STATUS EnumerateSecurityPackagesW(
//   ULONG *pcPackages, PSecPkgInfo *ppPackageInfo)
uint32_t EnumerateSecurityPackages(uint32_t pcPackages, uint32_t ppPackageInfo) {
    return (uint32_t)wf_call("secur32.dll", "EnumerateSecurityPackagesW", 2,
        (uint64_t)pcPackages, (uint64_t)ppPackageInfo);
}

// FreeContextBuffer
// SECURITY_STATUS FreeContextBuffer(void *pvContextBuffer)
uint32_t FreeContextBuffer(uint32_t pvContextBuffer) {
    return (uint32_t)wf_call("secur32.dll", "FreeContextBuffer", 1,
        (uint64_t)pvContextBuffer);
}

// InitializeSecurityContext
// SECURITY_STATUS InitializeSecurityContextW(
//   SEC_HANDLE *phCredential, SEC_HANDLE *phContext, LPCWSTR pTargetName,
//   ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
//   SecBufferDesc *pInput, ULONG Reserved2, SEC_HANDLE *phNewContext,
//   SecBufferDesc *pOutput, ULONG *pfContextAttr, TimeStamp *ptsExpiry)
uint32_t InitializeSecurityContext(uint32_t phCredential, uint32_t phContext, uint32_t pTargetName, uint32_t fContextReq, uint32_t Reserved1, uint32_t TargetDataRep, uint32_t pInput, uint32_t Reserved2, uint32_t phNewContext, uint32_t pOutput, uint32_t pfContextAttr, uint32_t ptsExpiry) {
    return (uint32_t)wf_call("secur32.dll", "InitializeSecurityContextW", 12,
        (uint64_t)phCredential, (uint64_t)phContext, (uint64_t)pTargetName,
        (uint64_t)fContextReq, (uint64_t)Reserved1, (uint64_t)TargetDataRep,
        (uint64_t)pInput, (uint64_t)Reserved2, (uint64_t)phNewContext,
        (uint64_t)pOutput, (uint64_t)pfContextAttr, (uint64_t)ptsExpiry);
}

// Gap 3 / Task 3.5 — Tier 1 SSPI tgtdeleg fix.
//
// WfSspi_InitializeSecurityContext_HostOutput: variant of
// InitializeSecurityContextW where pOutput is a HOST address
// (returned by WfHost.GetHostAddress on a SecBufferDesc allocated in
// host memory). The bare-typed `uint32_t pOutput` on the standard
// bridge truncates the upper 4 bytes of an x64 host address, dropping
// pointers above the 4GB boundary on the loader.
//
// All other args remain WASM pointers / scalars (translated normally
// by wf_call). pOutputHost passes through because values >= wasmMemSize
// are skipped by the WASM-pointer-translation pass — see
// internal/hostmod/win32_windows_dll.go:1121.
//
// C# helper signature:
//   uint WfSspi_InitializeSecurityContext_HostOutput(
//       IntPtr phCredential, IntPtr phContext, string pTargetName,
//       uint fContextReq, uint Reserved1, uint TargetDataRep,
//       IntPtr pInput, uint Reserved2, IntPtr phNewContext,
//       ulong pOutputHost,
//       out uint pfContextAttr, out long ptsExpiry);
uint32_t WfSspi_InitializeSecurityContext_HostOutput(
    uint32_t phCredential, uint32_t phContext, uint32_t pTargetName,
    uint32_t fContextReq, uint32_t Reserved1, uint32_t TargetDataRep,
    uint32_t pInput, uint32_t Reserved2, uint32_t phNewContext,
    uint64_t pOutputHost,
    uint32_t pfContextAttr, uint32_t ptsExpiry)
{
    return (uint32_t)wf_call("secur32.dll", "InitializeSecurityContextW", 12,
        (uint64_t)phCredential, (uint64_t)phContext, (uint64_t)pTargetName,
        (uint64_t)fContextReq, (uint64_t)Reserved1, (uint64_t)TargetDataRep,
        (uint64_t)pInput, (uint64_t)Reserved2, (uint64_t)phNewContext,
        pOutputHost,  // host address — already full 8 bytes
        (uint64_t)pfContextAttr, (uint64_t)ptsExpiry);
}

// LsaEnumerateLogonSessions
// NTSTATUS LsaEnumerateLogonSessions(
//   PULONG LogonSessionCount, PLUID *LogonSessionList)
uint32_t LsaEnumerateLogonSessions(uint32_t LogonSessionCount, uint32_t LogonSessionList) {
    return (uint32_t)wf_call("secur32.dll", "LsaEnumerateLogonSessions", 2,
        (uint64_t)LogonSessionCount, (uint64_t)LogonSessionList);
}

// LsaFreeReturnBuffer
// NTSTATUS LsaFreeReturnBuffer(PVOID Buffer)
uint32_t LsaFreeReturnBuffer(uint32_t Buffer) {
    return (uint32_t)wf_call("secur32.dll", "LsaFreeReturnBuffer", 1,
        (uint64_t)Buffer);
}

// LsaGetLogonSessionData
// NTSTATUS LsaGetLogonSessionData(
//   PLUID LogonId, PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData)
uint32_t LsaGetLogonSessionData(uint32_t LogonId, uint32_t ppLogonSessionData) {
    return (uint32_t)wf_call("secur32.dll", "LsaGetLogonSessionData", 2,
        (uint64_t)LogonId, (uint64_t)ppLogonSessionData);
}
