// pinvoke_extras.c — second-pass stubs caught after case-normalization
// expanded the DirectPInvoke set.
//
// The first sweep (pinvoke_{secur32,kernel32,advapi32,net}_ext.c) closed
// out the originally-undefined symbol list. When the scanner started
// emitting original-case DLL spellings (User32.dll, Wlanapi.dll, …) the
// linker matched additional [DllImport] declarations that had previously
// fallen through to Lazy PInvoke. Those declarations don't change the
// overall ghostpack support story — they're the same kind of plain
// Win32 P/Invokes — they just weren't visible in the first pass.

#include "wf_bridge.h"

// ── user32.dll ─────────────────────────────────────────────────────

uint32_t GetLastInputInfo(uint32_t plii) {
    return (uint32_t)wf_call("user32.dll", "GetLastInputInfo", 1, (uint64_t)plii);
}

// ── iphlpapi.dll ───────────────────────────────────────────────────

uint32_t FreeMibTable(uint32_t Memory) {
    return (uint32_t)wf_call("iphlpapi.dll", "FreeMibTable", 1, (uint64_t)Memory);
}

uint32_t GetIpNetTable(uint32_t IpNetTable, uint32_t SizePointer, uint32_t Order) {
    return (uint32_t)wf_call("iphlpapi.dll", "GetIpNetTable", 3,
        (uint64_t)IpNetTable, (uint64_t)SizePointer, (uint64_t)Order);
}

// ── wlanapi.dll ────────────────────────────────────────────────────

uint32_t WlanOpenHandle(uint32_t dwClientVersion, uint32_t pReserved, uint32_t pdwNegotiatedVersion, uint32_t phClientHandle) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanOpenHandle", 4,
        (uint64_t)dwClientVersion, (uint64_t)pReserved,
        (uint64_t)pdwNegotiatedVersion, (uint64_t)phClientHandle);
}

uint32_t WlanCloseHandle(uint32_t hClientHandle, uint32_t pReserved) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanCloseHandle", 2,
        (uint64_t)hClientHandle, (uint64_t)pReserved);
}

uint32_t WlanEnumInterfaces(uint32_t hClientHandle, uint32_t pReserved, uint32_t ppInterfaceList) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanEnumInterfaces", 3,
        (uint64_t)hClientHandle, (uint64_t)pReserved, (uint64_t)ppInterfaceList);
}

uint32_t WlanFreeMemory(uint32_t pMemory) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanFreeMemory", 1, (uint64_t)pMemory);
}

uint32_t WlanGetProfileList(uint32_t hClientHandle, uint32_t pInterfaceGuid, uint32_t pReserved, uint32_t ppProfileList) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanGetProfileList", 4,
        (uint64_t)hClientHandle, (uint64_t)pInterfaceGuid, (uint64_t)pReserved, (uint64_t)ppProfileList);
}

uint32_t WlanGetProfile(uint32_t hClientHandle, uint32_t pInterfaceGuid, uint32_t strProfileName, uint32_t pReserved, uint32_t pstrProfileXml, uint32_t pdwFlags, uint32_t pdwGrantedAccess) {
    return (uint32_t)wf_call("wlanapi.dll", "WlanGetProfile", 7,
        (uint64_t)hClientHandle, (uint64_t)pInterfaceGuid, (uint64_t)strProfileName, (uint64_t)pReserved,
        (uint64_t)pstrProfileXml, (uint64_t)pdwFlags, (uint64_t)pdwGrantedAccess);
}

// ── wtsapi32.dll ───────────────────────────────────────────────────

uint32_t WTSQuerySessionInformation(uint32_t hServer, uint32_t SessionId, uint32_t WTSInfoClass, uint32_t ppBuffer, uint32_t pBytesReturned) {
    return (uint32_t)wf_call("wtsapi32.dll", "WTSQuerySessionInformationW", 5,
        (uint64_t)hServer, (uint64_t)SessionId, (uint64_t)WTSInfoClass,
        (uint64_t)ppBuffer, (uint64_t)pBytesReturned);
}
