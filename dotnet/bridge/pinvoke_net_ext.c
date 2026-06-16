/*
 * pinvoke_net_ext.c — Unprefixed C bridge stubs for NativeAOT-LLVM linker resolution.
 *
 * AUTO-DISCOVERED: These symbols appeared as undefined when building Seatbelt and other
 * C# tools against the WasmForge NativeAOT-WASI pipeline.
 *
 * DESIGN: Each stub forwards to wf_call(), which dispatches to the real Win32 API on
 * the host via SyscallN with linear-memory pointer translation.
 *
 * NAMING CONVENTION: Functions are UNPREFIXED (e.g., "NetUserEnum", not
 * "netapi32_NetUserEnum"). NativeAOT-LLVM resolves DllImport symbols by bare function
 * name when the csproj contains <DirectPInvoke Include="netapi32" /> etc. The prefixed
 * stubs in pinvoke_nativeaot.c serve the WfHostBridge.cs explicit EntryPoint path and
 * are a separate mechanism.
 *
 * POINTER ARGS: All pointer arguments are uint64_t (WASM linear-memory offset). The
 * host bridge translates these to real host addresses before each Win32 call.
 *
 * SCALAR ARGS: Small scalars (DWORD, BOOL, ULONG) use uint32_t in the function
 * signature but are widened to uint64_t at the wf_call() call site with an explicit
 * cast: (uint64_t)val.
 *
 * W-SUFFIX ALIASES: Where the undefined symbol name has no W suffix but the real
 * Win32 API is Unicode (e.g., RpcStringBindingCompose → RpcStringBindingComposeW),
 * the wf_call() target uses the W-suffixed name.
 *
 * Groups: iphlpapi.dll, netapi32.dll, rpcrt4.dll, vaultcli.dll, wtsapi32.dll
 */

#include "wf_bridge.h"

/* ── iphlpapi.dll ──────────────────────────────────────────────────────────── */

/*
 * DWORD GetExtendedTcpTable(
 *     PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder,
 *     ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved)
 */
uint32_t GetExtendedTcpTable(uint32_t pTcpTable, uint32_t pdwSize, uint32_t bOrder, uint32_t ulAf, uint32_t TableClass, uint32_t Reserved) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetExtendedTcpTable", 6,
        (uint64_t)pTcpTable, (uint64_t)pdwSize, (uint64_t)bOrder,
        (uint64_t)ulAf, (uint64_t)TableClass, (uint64_t)Reserved);
}

/*
 * DWORD GetExtendedUdpTable(
 *     PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder,
 *     ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved)
 */
uint32_t GetExtendedUdpTable(uint32_t pUdpTable, uint32_t pdwSize, uint32_t bOrder, uint32_t ulAf, uint32_t TableClass, uint32_t Reserved) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetExtendedUdpTable", 6,
        (uint64_t)pUdpTable, (uint64_t)pdwSize, (uint64_t)bOrder,
        (uint64_t)ulAf, (uint64_t)TableClass, (uint64_t)Reserved);
}

/* ── netapi32.dll ──────────────────────────────────────────────────────────── */

/*
 * void NetFreeAadJoinInformation(PDSREG_JOIN_INFO pJoinInfo)
 * Returns void; stub returns uint32_t to satisfy linker.
 */
uint32_t NetFreeAadJoinInformation(uint32_t pJoinInfo) {
    return (uint32_t)wf_call("netapi32.dll", "NetFreeAadJoinInformation", 1,
        (uint64_t)pJoinInfo);
}

/*
 * HRESULT NetGetAadJoinInformation(
 *     PCWSTR pcszTenantId, PDSREG_JOIN_INFO *ppJoinInfo)
 */
uint32_t NetGetAadJoinInformation(uint32_t pcszTenantId, uint32_t ppJoinInfo) {
    return (uint32_t)wf_call("netapi32.dll", "NetGetAadJoinInformation", 2,
        (uint64_t)pcszTenantId, (uint64_t)ppJoinInfo);
}

/*
 * NET_API_STATUS NetGetJoinInformation(
 *     LPCWSTR lpServer, LPWSTR *lpNameBuffer, PNETSETUP_JOIN_STATUS BufferType)
 */
uint32_t NetGetJoinInformation(uint32_t lpServer, uint32_t lpNameBuffer, uint32_t BufferType) {
    return (uint32_t)wf_call("netapi32.dll", "NetGetJoinInformation", 3,
        (uint64_t)lpServer, (uint64_t)lpNameBuffer, (uint64_t)BufferType);
}

/*
 * NET_API_STATUS NetLocalGroupEnum(
 *     LPCWSTR servername, DWORD level, LPBYTE *bufptr,
 *     DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries,
 *     PDWORD_PTR resumehandle)
 */
uint32_t NetLocalGroupEnum(uint32_t servername, uint32_t level, uint32_t bufptr, uint32_t prefmaxlen, uint32_t entriesread, uint32_t totalentries, uint32_t resumehandle) {
    return (uint32_t)wf_call("netapi32.dll", "NetLocalGroupEnum", 7,
        (uint64_t)servername, (uint64_t)level, (uint64_t)bufptr,
        (uint64_t)prefmaxlen, (uint64_t)entriesread, (uint64_t)totalentries, (uint64_t)resumehandle);
}

/*
 * NET_API_STATUS NetLocalGroupGetMembers(
 *     LPCWSTR servername, LPCWSTR localgroupname, DWORD level,
 *     LPBYTE *bufptr, DWORD prefmaxlen, LPDWORD entriesread,
 *     LPDWORD totalentries, PDWORD_PTR resumehandle)
 */
uint32_t NetLocalGroupGetMembers(uint32_t servername, uint32_t localgroupname, uint32_t level, uint32_t bufptr, uint32_t prefmaxlen, uint32_t entriesread, uint32_t totalentries, uint32_t resumehandle) {
    return (uint32_t)wf_call("netapi32.dll", "NetLocalGroupGetMembers", 8,
        (uint64_t)servername, (uint64_t)localgroupname, (uint64_t)level,
        (uint64_t)bufptr, (uint64_t)prefmaxlen, (uint64_t)entriesread,
        (uint64_t)totalentries, (uint64_t)resumehandle);
}

/*
 * NET_API_STATUS NetUserEnum(
 *     LPCWSTR servername, DWORD level, DWORD filter,
 *     LPBYTE *bufptr, DWORD prefmaxlen, LPDWORD entriesread,
 *     LPDWORD totalentries, LPDWORD resume_handle)
 */
uint32_t NetUserEnum(uint32_t servername, uint32_t level, uint32_t filter, uint32_t bufptr, uint32_t prefmaxlen, uint32_t entriesread, uint32_t totalentries, uint32_t resume_handle) {
    return (uint32_t)wf_call("netapi32.dll", "NetUserEnum", 8,
        (uint64_t)servername, (uint64_t)level, (uint64_t)filter,
        (uint64_t)bufptr, (uint64_t)prefmaxlen, (uint64_t)entriesread,
        (uint64_t)totalentries, (uint64_t)resume_handle);
}

/* ── rpcrt4.dll ────────────────────────────────────────────────────────────── */

/*
 * RPC_STATUS RpcBindingFromStringBinding(
 *     RPC_WSTR StringBinding, RPC_BINDING_HANDLE *Binding)
 * Undefined symbol: RpcBindingFromStringBinding → real API: RpcBindingFromStringBindingW
 */
uint32_t RpcBindingFromStringBinding(uint32_t StringBinding, uint32_t Binding) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcBindingFromStringBindingW", 2,
        (uint64_t)StringBinding, (uint64_t)Binding);
}

/*
 * RPC_STATUS RpcBindingToStringBinding(
 *     RPC_BINDING_HANDLE Binding, RPC_WSTR *StringBinding)
 * Undefined symbol: RpcBindingToStringBinding → real API: RpcBindingToStringBindingW
 */
uint32_t RpcBindingToStringBinding(uint32_t Binding, uint32_t StringBinding) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcBindingToStringBindingW", 2,
        (uint64_t)Binding, (uint64_t)StringBinding);
}

/*
 * RPC_STATUS RpcMgmtEpEltInqBegin(
 *     RPC_BINDING_HANDLE EpBinding, ULONG InquiryType, RPC_IF_ID *IfId,
 *     ULONG VersOption, UUID *ObjectUuid, RPC_EP_INQ_HANDLE *InquiryContext)
 */
uint32_t RpcMgmtEpEltInqBegin(uint32_t EpBinding, uint32_t InquiryType, uint32_t IfId, uint32_t VersOption, uint32_t ObjectUuid, uint32_t InquiryContext) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcMgmtEpEltInqBegin", 6,
        (uint64_t)EpBinding, (uint64_t)InquiryType, (uint64_t)IfId,
        (uint64_t)VersOption, (uint64_t)ObjectUuid, (uint64_t)InquiryContext);
}

/*
 * RPC_STATUS RpcMgmtEpEltInqDone(RPC_EP_INQ_HANDLE *InquiryContext)
 */
uint32_t RpcMgmtEpEltInqDone(uint32_t InquiryContext) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcMgmtEpEltInqDone", 1,
        (uint64_t)InquiryContext);
}

/*
 * RPC_STATUS RpcMgmtEpEltInqNext(
 *     RPC_EP_INQ_HANDLE InquiryContext, RPC_IF_ID *IfId,
 *     RPC_BINDING_HANDLE *Binding, UUID *ObjectUuid, RPC_WSTR *Annotation)
 */
uint32_t RpcMgmtEpEltInqNext(uint32_t InquiryContext, uint32_t IfId, uint32_t Binding, uint32_t ObjectUuid, uint32_t Annotation) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcMgmtEpEltInqNext", 5,
        (uint64_t)InquiryContext, (uint64_t)IfId, (uint64_t)Binding, (uint64_t)ObjectUuid, (uint64_t)Annotation);
}

/*
 * RPC_STATUS RpcStringBindingCompose(
 *     RPC_WSTR ObjUuid, RPC_WSTR Protseq, RPC_WSTR NetworkAddr,
 *     RPC_WSTR Endpoint, RPC_WSTR Options, RPC_WSTR *StringBinding)
 * Undefined symbol: RpcStringBindingCompose → real API: RpcStringBindingComposeW
 */
uint32_t RpcStringBindingCompose(uint32_t ObjUuid, uint32_t Protseq, uint32_t NetworkAddr, uint32_t Endpoint, uint32_t Options, uint32_t StringBinding) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcStringBindingComposeW", 6,
        (uint64_t)ObjUuid, (uint64_t)Protseq, (uint64_t)NetworkAddr, (uint64_t)Endpoint, (uint64_t)Options, (uint64_t)StringBinding);
}

/*
 * RPC_STATUS RpcStringFree(RPC_WSTR *String)
 * Undefined symbol: RpcStringFree → real API: RpcStringFreeW
 */
uint32_t RpcStringFree(uint32_t String) {
    return (uint32_t)wf_call("rpcrt4.dll", "RpcStringFreeW", 1,
        (uint64_t)String);
}

/* ── vaultcli.dll ──────────────────────────────────────────────────────────── */

/*
 * DWORD VaultCloseVault(VAULT_HANDLE *vaultHandle)
 */
uint32_t VaultCloseVault(uint32_t vaultHandle) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultCloseVault", 1,
        (uint64_t)vaultHandle);
}

/*
 * DWORD VaultEnumerateItems(
 *     VAULT_HANDLE vaultHandle, DWORD chunkSize,
 *     DWORD *vaultItemCount, PVAULT_ITEM *items)
 */
uint32_t VaultEnumerateItems(uint32_t vaultHandle, uint32_t chunkSize, uint32_t vaultItemCount, uint32_t items) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultEnumerateItems", 4,
        (uint64_t)vaultHandle, (uint64_t)chunkSize, (uint64_t)vaultItemCount, (uint64_t)items);
}

/*
 * DWORD VaultEnumerateVaults(DWORD dwFlags, DWORD *vaultCount, GUID **vaultGuid)
 */
uint32_t VaultEnumerateVaults(uint32_t dwFlags, uint32_t vaultCount, uint32_t vaultGuid) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultEnumerateVaults", 3,
        (uint64_t)dwFlags, (uint64_t)vaultCount, (uint64_t)vaultGuid);
}

/*
 * DWORD VaultFree(PVOID memory)
 */
uint32_t VaultFree(uint32_t memory) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultFree", 1,
        (uint64_t)memory);
}

/*
 * DWORD VaultGetItem(
 *     VAULT_HANDLE vaultHandle, GUID *schemaId,
 *     PVAULT_ITEM_ELEMENT pResource, PVAULT_ITEM_ELEMENT pIdentity,
 *     PVAULT_ITEM_ELEMENT pPackageSid, HWND hwndOwner,
 *     DWORD dwFlags, PVAULT_ITEM *ppItem)
 */
uint32_t VaultGetItem(uint32_t vaultHandle, uint32_t schemaId, uint32_t pResource, uint32_t pIdentity, uint32_t pPackageSid, uint32_t hwndOwner, uint32_t dwFlags, uint32_t ppItem) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultGetItem", 8,
        (uint64_t)vaultHandle, (uint64_t)schemaId, (uint64_t)pResource, (uint64_t)pIdentity,
        (uint64_t)pPackageSid, (uint64_t)hwndOwner, (uint64_t)dwFlags, (uint64_t)ppItem);
}

/*
 * DWORD VaultOpenVault(GUID *vaultGuid, DWORD dwFlags, VAULT_HANDLE *vaultHandle)
 */
uint32_t VaultOpenVault(uint32_t vaultGuid, uint32_t dwFlags, uint32_t vaultHandle) {
    return (uint32_t)wf_call("vaultcli.dll", "VaultOpenVault", 3,
        (uint64_t)vaultGuid, (uint64_t)dwFlags, (uint64_t)vaultHandle);
}

/* ── wtsapi32.dll ──────────────────────────────────────────────────────────── */

/*
 * void WTSCloseServer(HANDLE hServer)
 * Returns void; stub returns uint32_t to satisfy linker.
 */
uint32_t WTSCloseServer(uint32_t hServer) {
    return (uint32_t)wf_call("wtsapi32.dll", "WTSCloseServer", 1,
        (uint64_t)hServer);
}

/*
 * BOOL WTSEnumerateSessionsEx(
 *     HANDLE hServer, DWORD *pLevel, DWORD Filter,
 *     PWTS_SESSION_INFO_1W *ppSessionInfo, DWORD *pCount)
 * Undefined symbol: WTSEnumerateSessionsEx → real API: WTSEnumerateSessionsExW
 */
uint32_t WTSEnumerateSessionsEx(uint32_t hServer, uint32_t pLevel, uint32_t Filter, uint32_t ppSessionInfo, uint32_t pCount) {
    return (uint32_t)wf_call("wtsapi32.dll", "WTSEnumerateSessionsExW", 5,
        (uint64_t)hServer, (uint64_t)pLevel, (uint64_t)Filter, (uint64_t)ppSessionInfo, (uint64_t)pCount);
}

/*
 * void WTSFreeMemory(PVOID pMemory)
 * Returns void; stub returns uint32_t to satisfy linker.
 */
uint32_t WTSFreeMemory(uint32_t pMemory) {
    return (uint32_t)wf_call("wtsapi32.dll", "WTSFreeMemory", 1,
        (uint64_t)pMemory);
}

/*
 * HANDLE WTSOpenServer(LPWSTR pServerName)
 * Returns HANDLE (opaque 64-bit value on x64).
 * Undefined symbol: WTSOpenServer → real API: WTSOpenServerW
 */
uint32_t WTSOpenServer(uint32_t pServerName) {
    return (uint32_t)wf_call("wtsapi32.dll", "WTSOpenServerW", 1,
        (uint64_t)pServerName);
}
