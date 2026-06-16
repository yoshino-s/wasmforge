// pinvoke_advapi32_ext.c — advapi32.dll P/Invoke bridge stubs for NativeAOT-WASI.
//
// Auto-discovered as undefined symbols when building Seatbelt against WasmForge.
// These stubs forward to wf_call() which dispatches to the real Win32 API on the
// host at runtime. The unprefixed naming convention (e.g. "CredEnumerate" not
// "advapi32_CredEnumerate") is what NativeAOT-LLVM expects when the csproj has
// <DirectPInvoke Include="advapi32" />.

#include "wf_bridge.h"

uint32_t ConvertSecurityDescriptorToStringSecurityDescriptor(uint32_t SecurityDescriptor, uint32_t RequestedStringSDRevision, uint32_t SecurityInformation, uint32_t StringSecurityDescriptor, uint32_t StringSecurityDescriptorLen) {
    return (uint32_t)wf_call(
        "advapi32.dll",
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        5,
        (uint64_t)SecurityDescriptor,
        (uint64_t)RequestedStringSDRevision,
        (uint64_t)SecurityInformation,
        (uint64_t)StringSecurityDescriptor,
        (uint64_t)StringSecurityDescriptorLen);
}

uint32_t ConvertSidToStringSid(uint32_t Sid, uint32_t StringSid) {
    return (uint32_t)wf_call("advapi32.dll", "ConvertSidToStringSidW", 2,
        (uint64_t)Sid, (uint64_t)StringSid);
}

uint32_t CredEnumerate(uint32_t Filter, uint32_t Flags, uint32_t Count, uint32_t Credentials) {
    return (uint32_t)wf_call("advapi32.dll", "CredEnumerateW", 4,
        (uint64_t)Filter,
        (uint64_t)Flags,
        (uint64_t)Count,
        (uint64_t)Credentials);
}

uint32_t CredFree(uint32_t Buffer) {
    return (uint32_t)wf_call("advapi32.dll", "CredFree", 1,
        (uint64_t)Buffer);
}

uint32_t CryptAcquireContext(uint32_t phProv, uint32_t szContainer, uint32_t szProvider, uint32_t dwProvType, uint32_t dwFlags) {
    return (uint32_t)wf_call("advapi32.dll", "CryptAcquireContextW", 5,
        (uint64_t)phProv,
        (uint64_t)szContainer,
        (uint64_t)szProvider,
        (uint64_t)dwProvType,
        (uint64_t)dwFlags);
}

uint32_t CryptCreateHash(uint32_t hProv, uint32_t Algid, uint32_t hKey, uint32_t dwFlags, uint32_t phHash) {
    return (uint32_t)wf_call("advapi32.dll", "CryptCreateHash", 5,
        (uint64_t)hProv,
        (uint64_t)Algid,
        (uint64_t)hKey,
        (uint64_t)dwFlags,
        (uint64_t)phHash);
}

uint32_t CryptDecrypt(uint32_t hKey, uint32_t hHash, uint32_t Final, uint32_t dwFlags, uint32_t pbData, uint32_t pdwDataLen) {
    return (uint32_t)wf_call("advapi32.dll", "CryptDecrypt", 6,
        (uint64_t)hKey,
        (uint64_t)hHash,
        (uint64_t)Final,
        (uint64_t)dwFlags,
        (uint64_t)pbData,
        (uint64_t)pdwDataLen);
}

uint32_t CryptDeriveKey(uint32_t hProv, uint32_t Algid, uint32_t hBaseData, uint32_t dwFlags, uint32_t phKey) {
    return (uint32_t)wf_call("advapi32.dll", "CryptDeriveKey", 5,
        (uint64_t)hProv,
        (uint64_t)Algid,
        (uint64_t)hBaseData,
        (uint64_t)dwFlags,
        (uint64_t)phKey);
}

uint32_t CryptDestroyHash(uint32_t hHash) {
    return (uint32_t)wf_call("advapi32.dll", "CryptDestroyHash", 1,
        (uint64_t)hHash);
}

uint32_t CryptDestroyKey(uint32_t hKey) {
    return (uint32_t)wf_call("advapi32.dll", "CryptDestroyKey", 1,
        (uint64_t)hKey);
}

uint32_t CryptHashData(uint32_t hHash, uint32_t pbData, uint32_t dwDataLen, uint32_t dwFlags) {
    return (uint32_t)wf_call("advapi32.dll", "CryptHashData", 4,
        (uint64_t)hHash,
        (uint64_t)pbData,
        (uint64_t)dwDataLen,
        (uint64_t)dwFlags);
}

uint32_t CryptReleaseContext(uint32_t hProv, uint32_t dwFlags) {
    return (uint32_t)wf_call("advapi32.dll", "CryptReleaseContext", 2,
        (uint64_t)hProv,
        (uint64_t)dwFlags);
}

uint32_t DuplicateToken(uint32_t ExistingTokenHandle, uint32_t ImpersonationLevel, uint32_t DuplicateTokenHandle) {
    return (uint32_t)wf_call("advapi32.dll", "DuplicateToken", 3,
        (uint64_t)ExistingTokenHandle,
        (uint64_t)ImpersonationLevel,
        (uint64_t)DuplicateTokenHandle);
}

uint32_t GetNamedSecurityInfoW(uint32_t pObjectName, uint32_t ObjectType, uint32_t SecurityInfo, uint32_t ppsidOwner, uint32_t ppsidGroup, uint32_t ppDacl, uint32_t ppSacl, uint32_t ppSecurityDescriptor) {
    return (uint32_t)wf_call("advapi32.dll", "GetNamedSecurityInfoW", 8,
        (uint64_t)pObjectName,
        (uint64_t)ObjectType,
        (uint64_t)SecurityInfo,
        (uint64_t)ppsidOwner,
        (uint64_t)ppsidGroup,
        (uint64_t)ppDacl,
        (uint64_t)ppSacl,
        (uint64_t)ppSecurityDescriptor);
}

uint32_t GetTokenInformation(uint32_t TokenHandle, uint32_t TokenInformationClass, uint32_t TokenInformation, uint32_t TokenInformationLength, uint32_t ReturnLength) {
    return (uint32_t)wf_call("advapi32.dll", "GetTokenInformation", 5,
        (uint64_t)TokenHandle,
        (uint64_t)TokenInformationClass,
        (uint64_t)TokenInformation,
        (uint64_t)TokenInformationLength,
        (uint64_t)ReturnLength);
}

uint32_t ImpersonateLoggedOnUser(uint32_t hToken) {
    return (uint32_t)wf_call("advapi32.dll", "ImpersonateLoggedOnUser", 1,
        (uint64_t)hToken);
}

uint32_t LookupAccountSid(uint32_t lpSystemName, uint32_t Sid, uint32_t Name, uint32_t cchName, uint32_t ReferencedDomainName, uint32_t cchReferencedDomainName, uint32_t peUse) {
    return (uint32_t)wf_call("advapi32.dll", "LookupAccountSidW", 7,
        (uint64_t)lpSystemName,
        (uint64_t)Sid,
        (uint64_t)Name,
        (uint64_t)cchName,
        (uint64_t)ReferencedDomainName,
        (uint64_t)cchReferencedDomainName,
        (uint64_t)peUse);
}

uint32_t LookupPrivilegeName(uint32_t lpSystemName, uint32_t lpLuid, uint32_t lpName, uint32_t cchName) {
    return (uint32_t)wf_call("advapi32.dll", "LookupPrivilegeNameW", 4,
        (uint64_t)lpSystemName,
        (uint64_t)lpLuid,
        (uint64_t)lpName,
        (uint64_t)cchName);
}

// LsaEnumerateAccountsWithUserRight: arg 2 (EnumerationBuffer) is an 8-byte
// host pointer OUT slot. out8_mask=0x4 protects it from the default 4-byte
// overflow-restore that would zero bytes 4-7 of the host pointer written by
// the API.
//
// IMPORTANT: arg 0 (PolicyHandle) declared as uint32_t in this wrapper means
// the caller-passed LSA_HANDLE is truncated to 32 bits before we wrap it
// in uint64_t. On Win11 we observed handles like 0x07290000 (32-bit) so this
// works in practice, but if LSA hands back a high address the truncation
// would silently corrupt the handle. Use LsaEnumerateAccountsWithUserRight_v2
// (declared further down in this file) when callers have the full uint64_t
// handle.
uint32_t LsaEnumerateAccountsWithUserRight(uint32_t PolicyHandle, uint32_t UserRights, uint32_t EnumerationBuffer, uint32_t CountReturned) {
    return (uint32_t)wf_call_v2("advapi32.dll", "LsaEnumerateAccountsWithUserRight", 4,
        /*out8_mask=*/ 0x4,
        (uint64_t)PolicyHandle,
        (uint64_t)UserRights,
        (uint64_t)EnumerationBuffer,
        (uint64_t)CountReturned);
}

// ── uint64_t-safe LSA wrappers (WfLsa.cs uses ulong for all args) ──────────
//
// NativeAOT-WASI compiles to wasm32: all pointers are 4 bytes in the WASM
// linear memory.  However WfLsa.cs declares these P/Invokes with `ulong`
// (8-byte) parameters so the ABI on the WASM→C boundary passes each arg as a
// 64-bit value.  The _v2 variants accept uint64_t directly and forward to
// wf_call / wf_call_v2 without truncating through uint32_t.

// LsaOpenPolicy_v2 — uint64_t-safe variant matching WfLsa.cs (ulong, ulong, uint, ulong).
// SystemName, ObjectAttributes, PolicyHandle are host pointers (8 bytes via host memory).
// DesiredAccess is a 32-bit access mask (uint).
uint32_t LsaOpenPolicy_v2(uint64_t SystemName, uint64_t ObjectAttributes, uint32_t DesiredAccess, uint64_t PolicyHandle) {
    return (uint32_t)wf_call_v2("advapi32.dll", "LsaOpenPolicy", 4, /*out8_mask=*/0x8,
        SystemName, ObjectAttributes, (uint64_t)DesiredAccess, PolicyHandle);
}

// LsaEnumerateAccountsWithUserRight_v2 — uint64_t-safe variant.
// PolicyHandle is the 8-byte LSA handle returned from LsaOpenPolicy_v2.
// UserRights, Buffer, CountReturned are host addresses.
uint32_t LsaEnumerateAccountsWithUserRight_v2(uint64_t PolicyHandle, uint64_t UserRights, uint64_t Buffer, uint64_t CountReturned) {
    return (uint32_t)wf_call_v2("advapi32.dll", "LsaEnumerateAccountsWithUserRight", 4, /*out8_mask=*/0xC,
        PolicyHandle, UserRights, Buffer, CountReturned);
}

// LsaFreeMemory_v2 — uint64_t-safe variant.
uint32_t LsaFreeMemory_v2(uint64_t Buffer) {
    return (uint32_t)wf_call("advapi32.dll", "LsaFreeMemory", 1, Buffer);
}

// LsaClose_v2 — uint64_t-safe variant.
uint32_t LsaClose_v2(uint64_t ObjectHandle) {
    return (uint32_t)wf_call("advapi32.dll", "LsaClose", 1, ObjectHandle);
}

// ConvertSidToStringSidW_v2 — uint64_t-safe variant. Sid is a host SID pointer
// (from the LSA enumeration buffer); StringSid is a host address of LPWSTR* output.
uint32_t ConvertSidToStringSidW_v2(uint64_t Sid, uint64_t StringSid) {
    return (uint32_t)wf_call_v2("advapi32.dll", "ConvertSidToStringSidW", 2, /*out8_mask=*/0x2,
        Sid, StringSid);
}

// kernel32_LocalFree_v2 — uint64_t-safe variant.
uint64_t kernel32_LocalFree_v2(uint64_t hMem) {
    return wf_call("kernel32.dll", "LocalFree", 1, hMem);
}

uint32_t I_QueryTagInformation(uint32_t MachineName, uint32_t InfoLevel, uint32_t Data) {
    return (uint32_t)wf_call("advapi32.dll", "I_QueryTagInformation", 3,
        (uint64_t)MachineName,
        (uint64_t)InfoLevel,
        (uint64_t)Data);
}

// SID-resolution bridge functions previously lived here but were unreachable —
// the C# DllImports in WfSec.cs target unprefixed entry names that NativeAOT's
// link-time resolution didn't pick up (the +49 DirectPInvoke entries are
// per-DLL not per-function). The proper place for these wrappers is
// pinvoke_nativeaot.c where the existing LookupAccountSidW lives and where
// the csproj template's NativeLibrary reference reliably picks them up. The
// previous experiment is documented in commit 06c7608; revert it here per
// "minimize host-side surface" guidance.
