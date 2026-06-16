// pinvoke_env_ext.c — vanilla-name wrappers for env-module host functions.
//
// wf_bridge.h declares the host imports under wasmforge's `wf_*` prefix
// (e.g., wf_wmi_query, wf_enum_user_rights). The Rubeus integration uses
// WfHostBridge.cs which declares each P/Invoke with explicit
// EntryPoint="wf_*" so those calls resolve to the prefixed names directly.
//
// Vanilla GhostPack sources (Seatbelt, SharpUp, …) — and any helper
// classes the migrate step generates without an explicit EntryPoint —
// reference these host functions by their bare names: [DllImport("env",
// EntryPoint = "wmi_query")] etc. The linker then looks for a concrete
// local symbol literally named "wmi_query", which wf_bridge.h does not
// provide.
//
// Each wrapper below is a concrete function with the bare name; the body
// forwards to the matching wf_* import declared in wf_bridge.h. Net cost
// is a single extra WASM call frame — negligible for these one-shot host
// helpers.

#include "wf_bridge.h"

// UTF-8 (ASCII subset) → UTF-16LE conversion into a static buffer. WASM is
// single-threaded so the static is safe. Hoisted before its first use so
// later functions (reg_open, fs_*, ver_info) can share the buffer.
#define WF_WIDE_BUF_LEN 2048
static uint16_t wf_wide_buf[WF_WIDE_BUF_LEN];
static int wf_utf8_to_wide_ascii(uint32_t path_ptr, uint32_t path_len) {
    if (path_len + 1 > WF_WIDE_BUF_LEN) return 0;
    const unsigned char* s = (const unsigned char*)(uintptr_t)path_ptr;
    for (uint32_t i = 0; i < path_len; i++) {
        unsigned char c = s[i];
        if (c & 0x80) return 0;
        wf_wide_buf[i] = c;
    }
    wf_wide_buf[path_len] = 0;
    return 1;
}

// ── Discovery / enumeration ─────────────────────────────────────────

// wmi_query / wmi_method: WASM-side stubs returning empty. Full WMI COM
// (CoCreateInstance + IWbemLocator/IWbemServices vtable navigation) needs
// COM-mirror infrastructure; the existing WfCom helper handles in-WASM COM
// vtables. Phase B returns empty — Seatbelt's WMI-dependent commands
// (AntiVirus, Patches, Processes) print degraded "no entries" output.
// Full WASM-side WMI via wf_call_ptr + WfCom comes later.
uint32_t wmi_query(uint32_t query_ptr, uint32_t query_len,
    uint32_t ns_ptr, uint32_t ns_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    (void)query_ptr; (void)query_len; (void)ns_ptr; (void)ns_len;
    (void)out_buf_ptr; (void)out_buf_len; return 0;
}

uint32_t wmi_method(uint32_t ns_ptr, uint32_t ns_len,
    uint32_t class_ptr, uint32_t class_len,
    uint32_t method_ptr, uint32_t method_len,
    uint32_t in_json_ptr, uint32_t in_json_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    (void)ns_ptr; (void)ns_len; (void)class_ptr; (void)class_len;
    (void)method_ptr; (void)method_len; (void)in_json_ptr; (void)in_json_len;
    (void)out_buf_ptr; (void)out_buf_len; return 0;
}

// net_adapters: iphlpapi!GetAdaptersInfo via wf_call. Returns adapter info as
// a wire format the C# consumer parses: per-adapter NUL-separated entries
// "name\tdescription\tmac_hex\tipv4_csv\n". Replaces wf_enum_network_adapters
// host import.
//
// IP_ADAPTER_INFO layout on x64 (offsets in bytes):
//   IP_ADAPTER_INFO* Next;            //   0  (8)
//   DWORD ComboIndex;                 //   8  (4)
//   char AdapterName[260];            //  12  (260)
//   char Description[132];            // 272  (132)
//   UINT AddressLength;               // 404  (4)
//   BYTE Address[8];                  // 408  (8)
//   DWORD Index;                      // 416  (4)
//   UINT Type;                        // 420  (4)
//   UINT DhcpEnabled;                 // 424  (4)
//   PIP_ADDR_STRING CurrentIpAddress; // 432  (8) — after 4 bytes pad
//   IP_ADDR_STRING IpAddressList;     // 440  (528)
//     char IpAddress[16];             //   :next(8)+context(4)+pad(4) = +16
//     ...
//   (total: 968)
#define WF_ADAPTER_INFO_SIZE 968

uint32_t net_adapters(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    // Query required size first. GetAdaptersInfo(NULL, &size) returns
    // ERROR_BUFFER_OVERFLOW=111 and fills size.
    uint32_t needed = 0;
    wf_call("iphlpapi.dll", "GetAdaptersInfo", 2,
        (uint64_t)0, (uint64_t)(uintptr_t)&needed);
    if (needed == 0 || needed > 1024*1024) return 0;

    // Allocate static buffer (WASM is single-threaded).
    static uint8_t adapt_buf[256 * 1024] __attribute__((aligned(8)));
    if (needed > sizeof(adapt_buf)) return 0;

    uint64_t status = wf_call_v2("iphlpapi.dll", "GetAdaptersInfo", 2, /*out8_mask=*/0x1,
        (uint64_t)(uintptr_t)adapt_buf,
        (uint64_t)(uintptr_t)&needed);
    if (status != 0) return 0;

    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t out_pos = 0;
    uint8_t* cur = adapt_buf;
    while (cur != NULL) {
        // Description at offset 272 (132 bytes, ASCII C string).
        const char* desc = (const char*)(cur + 272);
        // AdapterName at offset 12.
        const char* name = (const char*)(cur + 12);

        // Emit "name\tdescription\n"
        for (uint32_t i = 0; name[i] && i < 260; i++) {
            if (out_pos + 2 > out_buf_len) goto done;
            out[out_pos++] = (uint8_t)name[i];
        }
        if (out_pos + 2 > out_buf_len) goto done;
        out[out_pos++] = '\t';
        for (uint32_t i = 0; desc[i] && i < 132; i++) {
            if (out_pos + 2 > out_buf_len) goto done;
            out[out_pos++] = (uint8_t)desc[i];
        }
        if (out_pos + 1 > out_buf_len) goto done;
        out[out_pos++] = '\n';

        // Follow Next pointer at offset 0.
        uint8_t* next = *(uint8_t**)cur;
        cur = next;
    }
done:
    return out_pos;
}

// reg_enumvals: WASM-side advapi32 RegOpenKeyExW + RegEnumValueW + RegQueryValueExW
// chain. Wire format per value: "name\ttype\tdata_hex\n" or
// "name\ttype\tdata_string\n" depending on type. Replaces wf_enum_reg_values
// host import.
//
// hive_ptr in WASM linear memory holds a uint32 hive (HKEY_LOCAL_MACHINE etc.)
uint32_t reg_enumvals(uint32_t hive_ptr,
    uint32_t key_path_ptr, uint32_t key_path_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    static uint16_t path_wide[1024];
    if (key_path_len + 1 > sizeof(path_wide)/2) return 0;
    const unsigned char* p = (const unsigned char*)(uintptr_t)key_path_ptr;
    for (uint32_t i = 0; i < key_path_len; i++) {
        if (p[i] & 0x80) return 0;
        path_wide[i] = p[i];
    }
    path_wide[key_path_len] = 0;

    int32_t hkey = *(int32_t*)(uintptr_t)hive_ptr;
    const uint32_t KEY_READ = 0x20019;
    uint32_t hKey = 0;
    uint64_t status = wf_call_v2("advapi32.dll", "RegOpenKeyExW", 5, /*out8_mask=*/0x10,
        (uint64_t)(int64_t)hkey,
        (uint64_t)(uintptr_t)path_wide,
        (uint64_t)0,
        (uint64_t)KEY_READ,
        (uint64_t)(uintptr_t)&hKey);
    if (status != 0 || hKey == 0) return 0;

    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t out_pos = 0;
    static uint16_t name_buf[256];
    static uint8_t data_buf[4096];

    for (uint32_t idx = 0; out_pos + 1 < out_buf_len; idx++) {
        uint32_t name_len = sizeof(name_buf)/2;
        uint32_t value_type = 0;
        uint32_t data_size = sizeof(data_buf);
        // Use wf_call_v2 with out8_mask=0xfc (bits 2-7) to skip overflow
        // guard on ALL output args. The default wf_call save+restore of
        // bytes [addr+4..addr+7] reverts the host's writes to adjacent
        // stack slots: when name_len, value_type, data_size are declared
        // sequentially on the C stack, each guard for a DWORD's pointer
        // arg overwrites the next DWORD's slot. Result: value_type stays
        // 0 (hex-dump branch runs for everything), data_size stays at
        // initial cap. RegEnumValueW writes DWORDs (4 bytes), not QWORDs,
        // so there's no actual overflow to protect against — skipping is
        // safe and required.
        uint64_t r = wf_call_v2("advapi32.dll", "RegEnumValueW", 8, /*out8_mask=*/0xfc,
            (uint64_t)hKey,
            (uint64_t)idx,
            (uint64_t)(uintptr_t)name_buf,
            (uint64_t)(uintptr_t)&name_len,
            (uint64_t)0,                       // lpReserved
            (uint64_t)(uintptr_t)&value_type,
            (uint64_t)(uintptr_t)data_buf,
            (uint64_t)(uintptr_t)&data_size);
        if (r != 0) break; // ERROR_NO_MORE_ITEMS or other end-of-iter

        // Emit "name\tREG_<type-name>\tdata\0" — wire format matches what
        // WfRegistry.EnumValues() parses (splits records on NUL, splits
        // fields on TAB, calls ConvertValue(type_name, value_text)).
        //
        // Name: UTF-16 → ASCII (lossy but matches what most Win32 registry
        // value names use in practice; non-ASCII bytes get the low byte).
        for (uint32_t i = 0; i < name_len && out_pos + 1 < out_buf_len; i++) {
            out[out_pos++] = (uint8_t)(name_buf[i] & 0xff);
        }
        if (out_pos + 24 > out_buf_len) break;
        out[out_pos++] = '\t';
        // Type as REG_* name string. C# ConvertValue switches on these
        // exact spellings; unknown types degrade to bytes[].
        const char* tname = "REG_UNKNOWN";
        switch (value_type) {
            case 1:  tname = "REG_SZ"; break;
            case 2:  tname = "REG_EXPAND_SZ"; break;
            case 3:  tname = "REG_BINARY"; break;
            case 4:  tname = "REG_DWORD"; break;
            case 5:  tname = "REG_DWORD_BIG_ENDIAN"; break;
            case 6:  tname = "REG_LINK"; break;
            case 7:  tname = "REG_MULTI_SZ"; break;
            case 11: tname = "REG_QWORD"; break;
        }
        for (const char* tp = tname; *tp && out_pos + 1 < out_buf_len; tp++) {
            out[out_pos++] = (uint8_t)*tp;
        }
        out[out_pos++] = '\t';
        // Data value — match the format C#'s ConvertValue parses:
        //   REG_SZ / REG_EXPAND_SZ: UTF-8 string
        //   REG_DWORD / REG_QWORD: decimal digits
        //   REG_MULTI_SZ: '|' separator between strings
        //   REG_BINARY / others: hex-encoded bytes
        if ((value_type == 1 || value_type == 2) && data_size >= 2) {
            uint16_t* sw = (uint16_t*)data_buf;
            uint32_t schars = data_size / 2;
            for (uint32_t i = 0; i < schars && sw[i] != 0 && out_pos + 1 < out_buf_len; i++) {
                out[out_pos++] = (uint8_t)(sw[i] & 0xff);
            }
        } else if (value_type == 4 && data_size >= 4) { // REG_DWORD
            uint32_t v = *(uint32_t*)data_buf;
            char rev[12]; int rl = 0;
            if (v == 0) rev[rl++] = '0';
            else while (v > 0) { rev[rl++] = '0' + (v % 10); v /= 10; }
            while (rl > 0 && out_pos + 1 < out_buf_len) out[out_pos++] = rev[--rl];
        } else if (value_type == 11 && data_size >= 8) { // REG_QWORD
            uint64_t v = *(uint64_t*)data_buf;
            char rev[24]; int rl = 0;
            if (v == 0) rev[rl++] = '0';
            else while (v > 0) { rev[rl++] = '0' + (v % 10); v /= 10; }
            while (rl > 0 && out_pos + 1 < out_buf_len) out[out_pos++] = rev[--rl];
        } else if (value_type == 7 && data_size >= 2) { // REG_MULTI_SZ
            uint16_t* sw = (uint16_t*)data_buf;
            uint32_t schars = data_size / 2;
            int first = 1;
            uint32_t start = 0;
            for (uint32_t i = 0; i < schars; i++) {
                if (sw[i] == 0) {
                    if (i > start) {
                        if (!first && out_pos + 1 < out_buf_len) out[out_pos++] = '|';
                        for (uint32_t j = start; j < i && out_pos + 1 < out_buf_len; j++) {
                            out[out_pos++] = (uint8_t)(sw[j] & 0xff);
                        }
                        first = 0;
                    }
                    start = i + 1;
                }
            }
        } else {
            // Hex dump for REG_BINARY / REG_LINK / unknown types.
            static const char hex[] = "0123456789abcdef";
            for (uint32_t i = 0; i < data_size && out_pos + 2 < out_buf_len; i++) {
                out[out_pos++] = hex[(data_buf[i] >> 4) & 0xf];
                out[out_pos++] = hex[data_buf[i] & 0xf];
            }
        }
        // Record terminator: NUL (matches WfRegistry.EnumValues parser).
        if (out_pos < out_buf_len) out[out_pos++] = 0;
    }
    wf_call("advapi32.dll", "RegCloseKey", 1, (uint64_t)hKey);
    return out_pos;
}

// reg_open / reg_close / reg_enum — WASM-side advapi32!RegOpenKeyExW /
// RegCloseKey / RegEnumKeyExW chains via wf_call. Replace the
// wf_reg_open_key / wf_reg_close_key / wf_reg_enum_key host imports.
//
// hive_ptr is a pointer in WASM linear memory holding a uint32 hive value
// (HKEY_LOCAL_MACHINE=0x80000002 etc.). RegOpenKeyExW expects HKEY which is
// architecturally HANDLE (8 bytes) but the predefined HKEYs are signed 32-bit
// constants that the runtime treats as sign-extended pointers; we pass them
// through the wf_call uint64 arg as-is.
uint32_t reg_open(uint32_t hive_ptr, uint32_t path_ptr, uint32_t path_len,
    uint32_t out_handle_ptr) {
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0xFFFFFFFFu;
    int32_t hkey = *(int32_t*)(uintptr_t)hive_ptr;
    const uint32_t KEY_READ = 0x20019;
    uint32_t out_handle = 0;
    // RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    uint64_t status = wf_call_v2("advapi32.dll", "RegOpenKeyExW", 5, /*out8_mask=*/0x10,
        (uint64_t)(int64_t)hkey,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)0,
        (uint64_t)KEY_READ,
        (uint64_t)(uintptr_t)&out_handle);
    if (status == 0) {
        *(uint32_t*)(uintptr_t)out_handle_ptr = out_handle;
    }
    return (uint32_t)status;
}

uint32_t reg_close(uint32_t handle) {
    return (uint32_t)wf_call("advapi32.dll", "RegCloseKey", 1, (uint64_t)handle);
}

// reg_enum: RegEnumKeyExW(hKey, dwIndex, lpName, &lpcName, NULL, NULL, NULL, NULL)
// name_ptr receives wide chars; name_len_ptr both inputs the buffer capacity
// (in chars) and receives the actual length on output.
uint32_t reg_enum(uint32_t handle, uint32_t index,
    uint32_t name_ptr, uint32_t name_len_ptr) {
    // wf_call_v2 with out8_mask=0x0c bypasses the overflow guard for
    // both pointer args. The guard's save+restore corrupts buffer
    // contents (positions 4-7 of the output name buffer) and adjacent
    // DWORD slots — see reg_enumvals for the full rationale.
    uint64_t status = wf_call_v2("advapi32.dll", "RegEnumKeyExW", 8, /*out8_mask=*/0x0c,
        (uint64_t)handle,
        (uint64_t)index,
        (uint64_t)name_ptr,
        (uint64_t)name_len_ptr,
        (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint64_t)0);
    return (uint32_t)status;
}

// rpc_enumeps: WASM-side RpcMgmtEpEltInqBegin/Next chain via wf_call.
// Returns NUL-separated UTF-8 binding strings.
//
// RpcStringBindingComposeW(NULL, L"ncacn_ip_tcp", L"localhost", NULL, NULL,
//   &binding_str) then RpcBindingFromStringBindingW(binding_str, &binding)
// then RpcMgmtEpEltInqBegin(binding, ..., &inqContext) iterating with
// RpcMgmtEpEltInqNextW. For Phase B we provide an empty-result stub —
// Seatbelt's RPCMappedEndpoints command tolerates empty output and prints
// "[no endpoints found]" which matches the typical no-RPC-server case.
// Full chain can be added later with the same wf_call template.
uint32_t rpc_enumeps(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    (void)out_buf_ptr; (void)out_buf_len;
    return 0;
}

// ── Security descriptor / right enumeration ─────────────────────────

// sec_enumrights / sec_enumsessions: WASM-side stubs returning empty.
// LsaLookupPrivilegeName/LsaEnumerateLogonSessions chains have complex
// handle-based marshaling (LSA_HANDLE outputs, LSA_UNICODE_STRING
// struct pointer chains) that need richer wf_call_v2 expansion. For
// Phase B these return 0 — Seatbelt's LogonSessions / TokenPrivileges
// commands tolerate empty results.
uint32_t sec_enumrights(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    (void)out_buf_ptr; (void)out_buf_len; return 0;
}

// sec_parsesddl: ConvertStringSecurityDescriptorToSecurityDescriptorW chain
// converts an SDDL string into a SECURITY_DESCRIPTOR, then formats the DACL
// ACEs as a simple textual list "trustee_sid\trights\n". This replaces the
// wf_parse_sddl_acl host bridge which performed the same parse on the host.
//
// The host bridge did substantial work (resolving SIDs to names, formatting
// rights as text). For Phase B we provide a thin "raw SDDL passthrough" that
// preserves the input — Seatbelt's SDDL consumers tolerate either format.
// Full ACE walking can be added later via wf_call(advapi32!GetSecurityDescriptorDacl
// + GetAce loop) without re-introducing the host import.
uint32_t sec_parsesddl(uint32_t sddl_ptr, uint32_t sddl_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    if (sddl_len == 0 || sddl_len >= out_buf_len) return 0;
    const uint8_t* src = (const uint8_t*)(uintptr_t)sddl_ptr;
    uint8_t* dst = (uint8_t*)(uintptr_t)out_buf_ptr;
    for (uint32_t i = 0; i < sddl_len; i++) dst[i] = src[i];
    dst[sddl_len] = 0;
    return sddl_len;
}

// sec_sddl: WASM-side GetNamedSecurityInfoW + ConvertSecurityDescriptorTo-
// StringSecurityDescriptorW chain. path_ptr is a NUL-terminated UTF-8 path.
// Returns chars written to out_buf (NUL-terminated). Replaces wf_get_sddl.
//
// NOTE: this routine is intentionally NOT a 1:1 wf_get_sddl replacement — the
// previous host implementation paid extra attention to "TrustedInstaller" /
// elevation token quirks. Some Seatbelt callers tolerate empty SDDL strings.
// We return 0 on any failure path, which Seatbelt treats as "skip this row".
uint32_t sec_sddl(uint32_t path_ptr,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    // Determine length of NUL-terminated UTF-8 path.
    const unsigned char* p = (const unsigned char*)(uintptr_t)path_ptr;
    uint32_t path_len = 0;
    while (p[path_len] && path_len < WF_WIDE_BUF_LEN) path_len++;
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0;

    // GetNamedSecurityInfoW(pObjectName, ObjectType=SE_FILE_OBJECT=1,
    //   SecurityInfo=DACL_SECURITY_INFORMATION=4, ppsidOwner=NULL,
    //   ppsidGroup=NULL, ppDacl=NULL, ppSacl=NULL, ppSecurityDescriptor=&pSd)
    uint32_t pSd = 0;
    uint64_t status = wf_call("advapi32.dll", "GetNamedSecurityInfoW", 8,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)1,        // SE_FILE_OBJECT
        (uint64_t)4,        // DACL_SECURITY_INFORMATION
        (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint64_t)0,
        (uint64_t)(uintptr_t)&pSd);
    if (status != 0 || pSd == 0) return 0;

    // ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor,
    //   RequestedStringSDRevision=1, SecurityInformation=4,
    //   *StringSecurityDescriptor=&pSddl, *StringSecurityDescriptorLen=&len)
    uint32_t pSddl = 0;
    uint32_t sddl_len = 0;
    status = wf_call("advapi32.dll", "ConvertSecurityDescriptorToStringSecurityDescriptorW", 5,
        (uint64_t)pSd,
        (uint64_t)1,        // SDDL_REVISION_1
        (uint64_t)4,        // DACL_SECURITY_INFORMATION
        (uint64_t)(uintptr_t)&pSddl,
        (uint64_t)(uintptr_t)&sddl_len);

    // Free the SD from GetNamedSecurityInfo.
    wf_call("kernel32.dll", "LocalFree", 1, (uint64_t)pSd);

    if (status == 0 || pSddl == 0) return 0;

    // Copy UTF-16 SDDL to output buffer as ASCII (SDDL is ASCII-safe).
    const uint16_t* sddl_w = (const uint16_t*)(uintptr_t)pSddl;
    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t k = 0;
    while (sddl_w[k] != 0 && k + 1 < out_buf_len) {
        out[k] = (uint8_t)(sddl_w[k] & 0xff);
        k++;
    }
    out[k] = 0;
    wf_call("kernel32.dll", "LocalFree", 1, (uint64_t)pSddl);
    return k;
}

// sec_sddl_typed: variant that accepts SE_OBJECT_TYPE (1=SE_FILE_OBJECT,
// 5=SE_SERVICE_OBJECT). For services, pass just the service name (no leading
// slash). GetNamedSecurityInfoW with SE_SERVICE accepts "ServiceName" directly.
uint32_t sec_sddl_typed(uint32_t path_ptr, uint32_t object_type,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    const unsigned char* p = (const unsigned char*)(uintptr_t)path_ptr;
    uint32_t path_len = 0;
    while (p[path_len] && path_len < WF_WIDE_BUF_LEN) path_len++;
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0;

    uint32_t pSd = 0;
    uint64_t status = wf_call("advapi32.dll", "GetNamedSecurityInfoW", 8,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)object_type,    // 1=SE_FILE_OBJECT, 5=SE_SERVICE
        (uint64_t)4,              // DACL_SECURITY_INFORMATION
        (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint64_t)0,
        (uint64_t)(uintptr_t)&pSd);
    if (status != 0 || pSd == 0) return 0;

    uint32_t pSddl = 0;
    uint32_t sddl_len = 0;
    status = wf_call("advapi32.dll", "ConvertSecurityDescriptorToStringSecurityDescriptorW", 5,
        (uint64_t)pSd, (uint64_t)1, (uint64_t)4,
        (uint64_t)(uintptr_t)&pSddl,
        (uint64_t)(uintptr_t)&sddl_len);

    wf_call("kernel32.dll", "LocalFree", 1, (uint64_t)pSd);
    if (status == 0 || pSddl == 0) return 0;

    const uint16_t* sddl_w = (const uint16_t*)(uintptr_t)pSddl;
    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t k = 0;
    while (sddl_w[k] != 0 && k + 1 < out_buf_len) {
        out[k] = (uint8_t)(sddl_w[k] & 0xff);
        k++;
    }
    out[k] = 0;
    wf_call("kernel32.dll", "LocalFree", 1, (uint64_t)pSddl);
    return k;
}

// Filesystem helpers (sys_fileexists / sys_listdir) defined after fs_* below.

// fs_exists: replaces the wf_file_exists host import with a direct wf_call to
// kernel32!GetFileAttributesW. Returns 1 if attrs != INVALID_FILE_ATTRIBUTES.
uint32_t fs_exists(uint32_t path_ptr, uint32_t path_len) {
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0;
    uint64_t attrs = wf_call("kernel32.dll", "GetFileAttributesW", 1,
        (uint64_t)(uintptr_t)wf_wide_buf);
    return ((uint32_t)attrs != 0xFFFFFFFFu) ? 1u : 0u;
}

// fs_listdir: replaces wf_list_dir host import with FindFirstFileW/FindNextFileW
// chain via wf_call. Returns bytes_written; entries are NUL-separated UTF-8
// names. count_ptr receives the entry count.
//
// WIN32_FIND_DATAW size = 4 (dwFileAttributes)
//                       + 8*2 (3 FILETIMEs, each 8 bytes) = 28 wait, struct layout:
//   DWORD dwFileAttributes;          //  0  (4)
//   FILETIME ftCreationTime;         //  4  (8)
//   FILETIME ftLastAccessTime;       // 12  (8)
//   FILETIME ftLastWriteTime;        // 20  (8)
//   DWORD nFileSizeHigh;             // 28  (4)
//   DWORD nFileSizeLow;              // 32  (4)
//   DWORD dwReserved0;               // 36  (4)
//   DWORD dwReserved1;               // 40  (4)
//   WCHAR cFileName[MAX_PATH=260];   // 44  (520)
//   WCHAR cAlternateFileName[14];    // 564 (28)
//   Total: 592 bytes
#define WF_WIN32_FIND_DATA_SIZE 592
#define WF_WIN32_FIND_DATA_FILENAME_OFFSET 44
#define WF_WIN32_FIND_DATA_FILENAME_MAX 260

uint32_t fs_listdir(uint32_t path_ptr, uint32_t path_len,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    // Build search pattern "<path>\*" in wide buffer.
    if (path_len + 3 > WF_WIDE_BUF_LEN) return 0;
    const unsigned char* s = (const unsigned char*)(uintptr_t)path_ptr;
    uint32_t i = 0;
    for (; i < path_len; i++) {
        unsigned char c = s[i];
        if (c & 0x80) return 0;
        wf_wide_buf[i] = c;
    }
    // Strip trailing slash if present then append \*
    if (i > 0 && (wf_wide_buf[i-1] == '\\' || wf_wide_buf[i-1] == '/')) i--;
    wf_wide_buf[i++] = '\\';
    wf_wide_buf[i++] = '*';
    wf_wide_buf[i] = 0;

    // FindFirstFileW returns HANDLE. WIN32_FIND_DATAW must be 8-byte aligned.
    static uint8_t find_data[WF_WIN32_FIND_DATA_SIZE] __attribute__((aligned(8)));
    uint64_t hFind = wf_call("kernel32.dll", "FindFirstFileW", 2,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)(uintptr_t)find_data);
    if (hFind == 0 || hFind == 0xFFFFFFFFFFFFFFFFull) {
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }

    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint32_t out_pos = 0;
    uint32_t count = 0;
    uint64_t more = 1;
    while (more) {
        const uint16_t* name = (const uint16_t*)(find_data + WF_WIN32_FIND_DATA_FILENAME_OFFSET);
        // Skip "." and ".." entries.
        int skip = 0;
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) skip = 1;
        if (!skip) {
            // Write UTF-8 name (ASCII only) into output, then NUL separator.
            uint32_t k = 0;
            while (name[k] != 0 && k < WF_WIN32_FIND_DATA_FILENAME_MAX) {
                if (out_pos + 2 > buf_cap) goto done;
                out[out_pos++] = (uint8_t)(name[k] & 0xff);
                k++;
            }
            if (out_pos < buf_cap) out[out_pos++] = 0;
            count++;
        }
        more = wf_call("kernel32.dll", "FindNextFileW", 2,
            hFind, (uint64_t)(uintptr_t)find_data);
    }
done:
    wf_call("kernel32.dll", "FindClose", 1, hFind);
    *((uint32_t*)(uintptr_t)count_ptr) = count;
    return out_pos;
}

// sys_fileexists / sys_listdir — legacy export names that some callers
// still bind to. Forward to the new fs_* impls above.
uint32_t sys_fileexists(uint32_t path_ptr, uint32_t path_len) {
    return fs_exists(path_ptr, path_len);
}
uint32_t sys_listdir(uint32_t path_ptr, uint32_t path_len,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    return fs_listdir(path_ptr, path_len, buf_ptr, buf_cap, count_ptr);
}

// fs_pipes: WASM-side FindFirstFileW(\\\\.\\pipe\\*) chain via wf_call.
// Returns NUL-separated UTF-8 pipe names. Same WIN32_FIND_DATAW layout as
// fs_listdir; reuses the static find_data buffer pattern.
static const uint16_t WF_PIPES_PATTERN[] = {
    '\\','\\','.','\\','p','i','p','e','\\','*', 0
};
uint32_t fs_pipes(uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    static uint8_t pipe_find[WF_WIN32_FIND_DATA_SIZE] __attribute__((aligned(8)));
    uint64_t hFind = wf_call("kernel32.dll", "FindFirstFileW", 2,
        (uint64_t)(uintptr_t)WF_PIPES_PATTERN,
        (uint64_t)(uintptr_t)pipe_find);
    if (hFind == 0 || hFind == 0xFFFFFFFFFFFFFFFFull) {
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }
    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint32_t out_pos = 0;
    uint32_t count = 0;
    uint64_t more = 1;
    while (more) {
        const uint16_t* name = (const uint16_t*)(pipe_find + WF_WIN32_FIND_DATA_FILENAME_OFFSET);
        uint32_t k = 0;
        while (name[k] != 0 && k < WF_WIN32_FIND_DATA_FILENAME_MAX) {
            if (out_pos + 2 > buf_cap) goto pipes_done;
            out[out_pos++] = (uint8_t)(name[k] & 0xff);
            k++;
        }
        if (out_pos < buf_cap) out[out_pos++] = 0;
        count++;
        more = wf_call("kernel32.dll", "FindNextFileW", 2,
            hFind, (uint64_t)(uintptr_t)pipe_find);
    }
pipes_done:
    wf_call("kernel32.dll", "FindClose", 1, hFind);
    *((uint32_t*)(uintptr_t)count_ptr) = count;
    return out_pos;
}

// sys_printers / sec_pkgs / priv_rights / net_wifi: WASM-side stubs that
// return empty results (count=0). The underlying Win32 chains
// (EnumPrintersW, EnumerateSecurityPackagesW, LsaEnumerateAccountRights,
// WlanEnumInterfaces+WlanQueryInterface) involve handle-output marshaling
// that benefits from richer wf_call_v2 modeling. For Phase B we return
// empty — Seatbelt's PrintersCommand / SecPackagesCredentialsCommand /
// UserRightAssignmentsCommand / WifiProfileCommand print "no entries"
// which is acceptable degraded mode. Full chains can be added later
// without re-introducing host imports.
// sys_printers: winspool!EnumPrintersW size-twice pattern. PRINTER_LEVEL_4
// returns just printer name + server name + attributes. Wire: name\n per
// printer, count_ptr gets count.
//
// PRINTER_INFO_4W layout on x64:
//   0:  LPWSTR pPrinterName  (8)
//   8:  LPWSTR pServerName   (8)
//   16: DWORD  Attributes    (4)
#define WF_PRINTER_FLAGS_LOCAL    0x00000002
#define WF_PRINTER_FLAGS_CONNECTIONS 0x00000004
uint32_t sys_printers(uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    static uint8_t printer_buf[256 * 1024] __attribute__((aligned(8)));
    uint32_t needed = 0, returned = 0;
    // First call: size query (NULL buffer, 0 size)
    wf_call("winspool.drv", "EnumPrintersW", 7,
        (uint64_t)(WF_PRINTER_FLAGS_LOCAL | WF_PRINTER_FLAGS_CONNECTIONS),
        (uint64_t)0,            // Name
        (uint64_t)4,            // Level
        (uint64_t)0,            // pPrinterEnum
        (uint64_t)0,            // cbBuf
        (uint64_t)(uintptr_t)&needed,
        (uint64_t)(uintptr_t)&returned);
    if (needed == 0 || needed > sizeof(printer_buf)) {
        *(uint32_t*)(uintptr_t)count_ptr = 0;
        return 0;
    }
    uint64_t ok = wf_call_v2("winspool.drv", "EnumPrintersW", 7, /*out8_mask=*/0x8,
        (uint64_t)(WF_PRINTER_FLAGS_LOCAL | WF_PRINTER_FLAGS_CONNECTIONS),
        (uint64_t)0,
        (uint64_t)4,
        (uint64_t)(uintptr_t)printer_buf,
        (uint64_t)needed,
        (uint64_t)(uintptr_t)&needed,
        (uint64_t)(uintptr_t)&returned);
    if (!ok || returned == 0) {
        *(uint32_t*)(uintptr_t)count_ptr = 0;
        return 0;
    }

    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint32_t out_pos = 0;
    for (uint32_t i = 0; i < returned; i++) {
        uint8_t* entry = printer_buf + (i * 24); // sizeof(PRINTER_INFO_4W) on x64
        uint64_t pName = *(uint64_t*)entry;
        if (pName == 0) continue;
        const uint16_t* w = (const uint16_t*)(uintptr_t)pName;
        for (uint32_t k = 0; w[k] != 0 && out_pos + 1 < buf_cap; k++) {
            out[out_pos++] = (uint8_t)(w[k] & 0xff);
        }
        if (out_pos < buf_cap) out[out_pos++] = 0;
    }
    *(uint32_t*)(uintptr_t)count_ptr = returned;
    return out_pos;
}

// sec_pkgs: secur32!EnumerateSecurityPackagesW.
//   NTSTATUS EnumerateSecurityPackagesW(PULONG pcPackages, PSecPkgInfoW* ppPackageInfo);
// Returns NUL-separated package names.
//
// SecPkgInfoW layout on x64:
//   0:  ULONG fCapabilities (4)
//   4:  USHORT wVersion     (2)
//   6:  USHORT wRPCID       (2)
//   8:  ULONG cbMaxToken    (4)
//   12: pad                 (4)
//   16: SEC_WCHAR* Name     (8)
//   24: SEC_WCHAR* Comment  (8)
//   Total: 32 bytes
uint32_t sec_pkgs(uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    uint32_t count = 0;
    uint64_t pInfo = 0;
    uint64_t st = wf_call_v2("secur32.dll", "EnumerateSecurityPackagesW", 2, /*out8_mask=*/0x2,
        (uint64_t)(uintptr_t)&count,
        (uint64_t)(uintptr_t)&pInfo);
    if (st != 0 || count == 0 || pInfo == 0) {
        *(uint32_t*)(uintptr_t)count_ptr = 0;
        return 0;
    }
    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint32_t out_pos = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t* entry = (uint8_t*)(uintptr_t)(pInfo + (uint64_t)i * 32);
        uint64_t pName = *(uint64_t*)(entry + 16);
        if (pName == 0) continue;
        const uint16_t* w = (const uint16_t*)(uintptr_t)pName;
        for (uint32_t k = 0; w[k] != 0 && out_pos + 1 < buf_cap; k++) {
            out[out_pos++] = (uint8_t)(w[k] & 0xff);
        }
        if (out_pos < buf_cap) out[out_pos++] = 0;
    }
    wf_call("secur32.dll", "FreeContextBuffer", 1, pInfo);
    *(uint32_t*)(uintptr_t)count_ptr = count;
    return out_pos;
}

// priv_rights: enumerate well-known user rights via advapi32 LSA.
//
// Pipeline (deep-marshal aware):
//   1. LsaOpenPolicy(NULL, &attrs, ACCESS, &hPolicy)   out8_mask=0x8
//   2. For each well-known right:
//        Build wasm32 stack LSA_UNICODE_STRING with the wide-char buffer
//        adjacent on the same wasm32 stack so wf_call's pointer translation
//        produces a coherent host view (Buffer field is a uint32 wasm offset
//        in the low 4 bytes; high 4 zero — host reads the struct after its
//        own translation maps to wasmMemBase + wasm offset).
//        LsaEnumerateAccountsWithUserRight(hPolicy, &uniStr, &buf, &count)
//        out8_mask=0x4 (buf is 8-byte PLSA_ENUMERATION_INFORMATION* OUT)
//   3. For each returned account: read PSID via mod_hread, call
//      ConvertSidToStringSidW(psid, &sidW) with out8_mask=0x2, read the
//      wide SDDL with mod_hread, free with LocalFree.
//   4. Append "RightName|sid1,sid2,...\n" to the output buffer.
//   5. LsaFreeMemory(buf), LsaClose(hPolicy).
//
// Output format the C# consumer parses:
//   "<right>|<sid>,<sid>,...\n" per line, contiguous in the output buf.

// Matches the Seatbelt UserRightAssignmentsCommand `_defaultPrivileges`
// array (29 entries). Order is alphabetical because Seatbelt iterates the
// array in source order and that's what the parity baseline expects.
// Whenever Seatbelt's set grows we must extend this one — the env helper
// only enumerates rights it knows by name.
static const char* const WF_USER_RIGHTS[] = {
    "SeAssignPrimaryTokenPrivilege",
    "SeAuditPrivilege",
    "SeBackupPrivilege",
    "SeBatchLogonRight",
    "SeCreateSymbolicLinkPrivilege",
    "SeCreateTokenPrivilege",
    "SeDebugPrivilege",
    "SeDenyBatchLogonRight",
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyServiceLogonRight",
    "SeEnableDelegationPrivilege",
    "SeImpersonatePrivilege",
    "SeInteractiveLogonRight",
    "SeLoadDriverPrivilege",
    "SeNetworkLogonRight",
    "SeRelabelPrivilege",
    "SeRemoteInteractiveLogonRight",
    "SeRemoteShutdownPrivilege",
    "SeRestorePrivilege",
    "SeSecurityPrivilege",
    "SeServiceLogonRight",
    "SeShutdownPrivilege",
    "SeSyncAgentPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege",
    "SeTrustedCredManAccessPrivilege",
};
#define WF_USER_RIGHTS_COUNT (sizeof(WF_USER_RIGHTS)/sizeof(WF_USER_RIGHTS[0]))

// mod_hread is the env import for reading arbitrary host memory.
extern uint32_t mod_hread(uint64_t hostAddr, uint32_t len, uint32_t outBuf)
    __attribute__((import_module("env"), import_name("mod_hread")));

static int wf_append_str(uint8_t* outBuf, uint32_t outCap, uint32_t* offset, const char* s) {
    while (*s) {
        if (*offset >= outCap) return 0;
        outBuf[(*offset)++] = (uint8_t)*s++;
    }
    return 1;
}

#ifndef WF_KEEP
#define WF_KEEP __attribute__((used, visibility("default"), noinline))
#endif

// Deep-marshal helper: allocate a host-memory buffer containing both the
// LSA_UNICODE_STRING struct (16 bytes) AND its UTF-16 Buffer string, with
// the struct's Buffer field set to a HOST pointer (host_addr + 16). This
// way the Windows API sees a single coherent struct in host memory — no
// wf_call nested-pointer translation required.
//
// Returns the host address of the LSA_UNICODE_STRING (call wf_mem_free on
// the returned handle in *outHandle when done).
// MEM_COMMIT|MEM_RESERVE = 0x3000, PAGE_READWRITE = 4.
static uint64_t wf_alloc_lsa_unicode_string(const char* asciiName, int32_t* outHandle) {
    int wlen = 0;
    while (asciiName[wlen]) wlen++;
    uint32_t totalSize = 16 + (uint32_t)((wlen + 1) * 2);

    int32_t handle = 0;
    if (wf_mem_alloc(totalSize, 0x3000, 4, (uint32_t)(uintptr_t)&handle) != 0) return 0;
    if (handle == 0) return 0;

    uint64_t hostAddr = 0;
    if (wf_mem_addr(handle, (uint32_t)(uintptr_t)&hostAddr) != 0 || hostAddr == 0) {
        wf_mem_free(handle);
        return 0;
    }

    // Build the struct + wide string in a wasm-local buffer, then copy to host.
    uint8_t tmp[16 + 128 * 2];
    if (totalSize > sizeof(tmp)) { wf_mem_free(handle); return 0; }
    for (uint32_t i = 0; i < totalSize; i++) tmp[i] = 0;
    *((uint16_t*)(tmp + 0)) = (uint16_t)(wlen * 2);
    *((uint16_t*)(tmp + 2)) = (uint16_t)((wlen + 1) * 2);
    // Buffer points to host_addr + 16 (where the wide string lives).
    *((uint64_t*)(tmp + 8)) = hostAddr + 16;
    uint16_t* wide = (uint16_t*)(tmp + 16);
    for (int i = 0; i < wlen; i++) wide[i] = (uint16_t)asciiName[i];
    wide[wlen] = 0;

    if (wf_mem_write(handle, 0, tmp, totalSize) != 0) {
        wf_mem_free(handle);
        return 0;
    }
    *outHandle = handle;
    return hostAddr;
}

// Diagnostic helper: returns LSA pipeline status as fixed-layout struct.
// Output layout (must be >= 64 bytes):
//   [0..3]   alloc_rc   (uint32) — wf_mem_alloc rc
//   [4..7]   alloc_handle (int32) — mem_alloc handle returned
//   [8..15]  host_addr  (uint64) — wf_mem_addr returned (or 0)
//   [16..19] open_rc    (uint32) — LsaOpenPolicy rc
//   [20..27] hPolicy    (uint64) — opened LSA handle
//   [28..31] enum_rc    (uint32) — LsaEnumerateAccountsWithUserRight rc
//   [32..35] count      (uint32) — count returned
//   [36..43] enum_buf   (uint64) — enumeration buffer pointer
//   [44..47] errno_total — number of attempts
WF_KEEP uint32_t priv_rights_diag(uint32_t buf_ptr, uint32_t buf_cap) {
    if (buf_cap < 64) return 0;
    uint8_t* o = (uint8_t*)(uintptr_t)buf_ptr;
    for (int i = 0; i < 64; i++) o[i] = 0;

    // Try allocating a tiny host buffer first to verify mem_alloc works.
    int32_t handle = 0;
    uint32_t arc = wf_mem_alloc(64, 0x3000, 4, (uint32_t)(uintptr_t)&handle);
    *((uint32_t*)(o + 0)) = arc;
    *((int32_t*)(o + 4)) = handle;

    uint64_t hostAddr = 0;
    if (arc == 0 && handle != 0) {
        wf_mem_addr(handle, (uint32_t)(uintptr_t)&hostAddr);
        *((uint64_t*)(o + 8)) = hostAddr;
    }

    // Allocate OBJECT_ATTRIBUTES in host memory (LsaOpenPolicy does NOT
    // accept NULL — verified via diagnostic that returned 0xC0000005 when
    // we tried). Same deep-marshal approach as for LSA_UNICODE_STRING.
    int32_t oaHandle = 0;
    uint32_t oaArc = wf_mem_alloc(48, 0x3000, 4, (uint32_t)(uintptr_t)&oaHandle);
    uint64_t oaHostAddr = 0;
    if (oaArc == 0 && oaHandle != 0) {
        wf_mem_addr(oaHandle, (uint32_t)(uintptr_t)&oaHostAddr);
        uint8_t zeroed[48] = {0};
        *((uint32_t*)zeroed) = 48;
        wf_mem_write(oaHandle, 0, zeroed, 48);
    }

    uint64_t hPolicy = 0;
    uint32_t orc = (uint32_t)wf_call_v2("advapi32.dll", "LsaOpenPolicy", 4, /*out8_mask=*/ 0x8,
        (uint64_t)0,
        oaHostAddr,                                  // ObjectAttributes host ptr
        (uint64_t)0xF0FFF,                           // POLICY_ALL_ACCESS
        (uint64_t)(uintptr_t)&hPolicy);
    *((uint32_t*)(o + 16)) = orc;
    *((uint64_t*)(o + 20)) = hPolicy;
    if (oaHandle != 0) wf_mem_free(oaHandle);

    // Try enumerating SeBatchLogonRight using host-allocated LSA_UNICODE_STRING.
    if (orc == 0 && hPolicy != 0 && hostAddr != 0 && handle != 0) {
        const char* name = "SeBatchLogonRight";
        int wlen = 17;
        uint8_t buf[64];
        for (int i = 0; i < 64; i++) buf[i] = 0;
        *((uint16_t*)(buf + 0)) = (uint16_t)(wlen * 2);
        *((uint16_t*)(buf + 2)) = (uint16_t)((wlen + 1) * 2);
        *((uint64_t*)(buf + 8)) = hostAddr + 16;
        for (int i = 0; i < wlen; i++)
            *((uint16_t*)(buf + 16 + i * 2)) = (uint16_t)name[i];
        wf_mem_write(handle, 0, buf, 16 + (wlen + 1) * 2);

        // Allocate the OUTPUT enumBuf+count slots in HOST memory too,
        // so the host write goes to a real host pointer (not a wasm32
        // stack addr that wf_call would have to translate).
        int32_t outHandle = 0;
        wf_mem_alloc(16, 0x3000, 4, (uint32_t)(uintptr_t)&outHandle);
        uint64_t outHostAddr = 0;
        wf_mem_addr(outHandle, (uint32_t)(uintptr_t)&outHostAddr);

        uint32_t erc = (uint32_t)wf_call_v2("advapi32.dll",
            "LsaEnumerateAccountsWithUserRight", 4, /*out8_mask=*/ 0,
            hPolicy,
            hostAddr,
            outHostAddr,           // host ptr to PLSA_ENUMERATION_INFORMATION*
            outHostAddr + 8);      // host ptr to count (4 bytes)

        // Read back from host memory.
        uint8_t outBytes[16] = {0};
        wf_mem_read(outHandle, 0, outBytes, 16);
        uint64_t enumBuf = *((uint64_t*)(outBytes + 0));
        uint32_t countReturned = *((uint32_t*)(outBytes + 8));

        *((uint32_t*)(o + 28)) = erc;
        *((uint32_t*)(o + 32)) = countReturned;
        *((uint64_t*)(o + 36)) = enumBuf;

        if (enumBuf != 0) wf_call("advapi32.dll", "LsaFreeMemory", 1, enumBuf);
        wf_call("advapi32.dll", "LsaClose", 1, hPolicy);
        wf_mem_free(outHandle);
    }

    if (handle != 0) wf_mem_free(handle);
    return 64;
}

WF_KEEP uint32_t priv_rights(uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint32_t offset = 0;
    uint32_t totalEntries = 0;

    // Allocate OBJECT_ATTRIBUTES in HOST memory — LsaOpenPolicy rejects NULL
    // (verified via diagnostic).
    int32_t oaHandle = 0;
    if (wf_mem_alloc(48, 0x3000, 4, (uint32_t)(uintptr_t)&oaHandle) != 0 || oaHandle == 0) {
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }
    uint64_t oaHostAddr = 0;
    wf_mem_addr(oaHandle, (uint32_t)(uintptr_t)&oaHostAddr);
    {
        uint8_t zeroed[48] = {0};
        *((uint32_t*)zeroed) = 48;
        wf_mem_write(oaHandle, 0, zeroed, 48);
    }

    // Allocate the output PolicyHandle slot in HOST memory too — wasm32 stack
    // pointers don't work for advapi32 OUT slots (verified via diagnostic:
    // enumBuf returned 0x0 when slot was wasm32 stack, real host pointer
    // when slot was host memory).
    int32_t phHandle = 0;
    if (wf_mem_alloc(8, 0x3000, 4, (uint32_t)(uintptr_t)&phHandle) != 0 || phHandle == 0) {
        wf_mem_free(oaHandle);
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }
    uint64_t phHostAddr = 0;
    wf_mem_addr(phHandle, (uint32_t)(uintptr_t)&phHostAddr);

    uint32_t orc = (uint32_t)wf_call_v2("advapi32.dll", "LsaOpenPolicy", 4, /*out8_mask=*/ 0,
        (uint64_t)0,
        oaHostAddr,
        (uint64_t)0xF0FFF,
        phHostAddr);
    wf_mem_free(oaHandle);

    uint8_t phBytes[8] = {0};
    wf_mem_read(phHandle, 0, phBytes, 8);
    uint64_t hPolicy = *((uint64_t*)phBytes);
    wf_mem_free(phHandle);

    if (orc != 0 || hPolicy == 0) {
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }

    // Allocate the output slots (PLSA_ENUMERATION_INFORMATION* + ULONG count)
    // in HOST memory once, reuse across iterations.
    int32_t outHandle = 0;
    if (wf_mem_alloc(16, 0x3000, 4, (uint32_t)(uintptr_t)&outHandle) != 0 || outHandle == 0) {
        wf_call("advapi32.dll", "LsaClose", 1, hPolicy);
        *((uint32_t*)(uintptr_t)count_ptr) = 0;
        return 0;
    }
    uint64_t outHostAddr = 0;
    wf_mem_addr(outHandle, (uint32_t)(uintptr_t)&outHostAddr);

    for (unsigned i = 0; i < WF_USER_RIGHTS_COUNT; i++) {
        const char* rightName = WF_USER_RIGHTS[i];

        // Allocate the LSA_UNICODE_STRING + Buffer in HOST memory.
        int32_t lsaStrHandle = 0;
        uint64_t lsaStrHost = wf_alloc_lsa_unicode_string(rightName, &lsaStrHandle);
        if (lsaStrHost == 0) continue;

        // Zero the output slots before each call.
        uint8_t zeroOut[16] = {0};
        wf_mem_write(outHandle, 0, zeroOut, 16);

        uint32_t erc = (uint32_t)wf_call_v2("advapi32.dll",
            "LsaEnumerateAccountsWithUserRight", 4, /*out8_mask=*/ 0,
            hPolicy,
            lsaStrHost,
            outHostAddr,
            outHostAddr + 8);

        wf_mem_free(lsaStrHandle);

        uint8_t outBytes[16] = {0};
        wf_mem_read(outHandle, 0, outBytes, 16);
        uint64_t enumBuf = *((uint64_t*)outBytes);
        uint32_t countReturned = *((uint32_t*)(outBytes + 8));

        // Always emit the right name — even when LSA returns
        // STATUS_NO_MORE_ENTRIES (0x8000001A) which is the "no accounts
        // hold this right" status, not a hard failure. The C# map then
        // contains every right we enumerate and Seatbelt's formatter
        // emits headers for rights with no principals (matches native
        // baseline: SeCreateTokenPrivilege:, SeRelabelPrivilege:, etc
        // with no entries underneath). Treat STATUS_NO_MORE_ENTRIES and
        // STATUS_SUCCESS identically — both yield a valid empty result.
        // Skip only on actual error statuses (access denied, invalid
        // parameter, etc) where the right name shouldn't appear.
        // NTSTATUS bit layout: severity in high two bits.
        //   0x00000000-0x3FFFFFFF: STATUS_SUCCESS / STATUS_*
        //   0x40000000-0x7FFFFFFF: STATUS_INFORMATIONAL
        //   0x80000000-0xBFFFFFFF: STATUS_WARNING (includes NO_MORE_ENTRIES)
        //   0xC0000000-0xFFFFFFFF: STATUS_ERROR
        // We treat success + informational + warning as "right exists,
        // possibly empty"; only error severity skips the right entirely.
        if (erc >= 0xC0000000u) continue;

        if (!wf_append_str(out, buf_cap, &offset, rightName)) break;
        if (offset < buf_cap) out[offset++] = '|';

        if (countReturned == 0 || enumBuf == 0) {
            // Skip the per-PSID loop; emit the terminator and move on.
            // Free the enum buffer if LSA allocated one even with count==0
            // (rare but possible — the documented contract is that an
            // unused PLSA_ENUMERATION_INFORMATION* may still be allocated).
            if (offset < buf_cap) out[offset++] = '\n';
            totalEntries++;
            if (enumBuf != 0) wf_call("advapi32.dll", "LsaFreeMemory", 1, enumBuf);
            continue;
        }

        // Reuse outHandle's first 8 bytes for ConvertSidToStringSidW's sidW
        // output. Same host-memory pattern.
        for (uint32_t k = 0; k < countReturned; k++) {
            uint64_t psid = 0;
            mod_hread(enumBuf + k * 8, 8, (uint32_t)(uintptr_t)&psid);
            if (psid == 0) continue;

            // Zero outHandle's first 8 bytes before each ConvertSid call.
            uint8_t zero8[8] = {0};
            wf_mem_write(outHandle, 0, zero8, 8);

            // ConvertSidToStringSidW returns BOOL (nonzero = success), NOT
            // NTSTATUS. The earlier draft checked `crc == 0` which is the
            // NTSTATUS-success convention used by LsaOpenPolicy and
            // LsaEnumerateAccountsWithUserRight — that check silently
            // discarded every successfully-converted SID, leaving each
            // right name with an empty SID list. Per MSDN: "If the function
            // succeeds, the return value is nonzero."
            uint32_t crc = (uint32_t)wf_call_v2("advapi32.dll",
                "ConvertSidToStringSidW", 2, /*out8_mask=*/ 0,
                psid, outHostAddr);

            uint8_t sidWBytes[8] = {0};
            wf_mem_read(outHandle, 0, sidWBytes, 8);
            uint64_t sidW = *((uint64_t*)sidWBytes);

            if (crc != 0 && sidW != 0) {
                uint16_t sidBuf[256];
                for (int j = 0; j < 256; j++) sidBuf[j] = 0;
                mod_hread(sidW, 512, (uint32_t)(uintptr_t)sidBuf);
                if (k > 0 && offset < buf_cap) out[offset++] = ',';
                for (int j = 0; j < 255 && sidBuf[j] && offset < buf_cap; j++)
                    out[offset++] = (uint8_t)sidBuf[j];
                wf_call("kernel32.dll", "LocalFree", 1, sidW);
            }
        }
        if (offset < buf_cap) out[offset++] = '\n';
        totalEntries++;

        wf_call("advapi32.dll", "LsaFreeMemory", 1, enumBuf);
    }

    wf_call("advapi32.dll", "LsaClose", 1, hPolicy);
    wf_mem_free(outHandle);
    *((uint32_t*)(uintptr_t)count_ptr) = totalEntries;
    return offset;
}

// net_wifi: wlanapi!WlanOpenHandle + WlanEnumInterfaces + WlanGetProfileList.
// Returns "iface_name\tprofile_name\n" per profile. Output count = profile count.
//
// WLAN_INTERFACE_INFO layout on x64:
//   0:  GUID InterfaceGuid           (16)
//   16: WCHAR strInterfaceDescription[256]  (512)
//   528: WLAN_INTERFACE_STATE         (4)
//   Total: 532 → padded to 536
// WLAN_INTERFACE_INFO_LIST: DWORD dwNumberOfItems(4), DWORD dwIndex(4), array
//
// WLAN_PROFILE_INFO layout: WCHAR strProfileName[256] (512), DWORD flags(4) → 516 padded to 520
// WLAN_PROFILE_INFO_LIST: DWORD count(4), DWORD index(4), array
uint32_t net_wifi(uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr) {
    uint8_t* out = (uint8_t*)(uintptr_t)buf_ptr;
    uint64_t hClient = 0;
    uint32_t negotiatedVer = 0;
    uint64_t st = wf_call_v2("wlanapi.dll", "WlanOpenHandle", 4, /*out8_mask=*/0xC,
        (uint64_t)2,        // dwClientVersion
        (uint64_t)0,        // pReserved
        (uint64_t)(uintptr_t)&negotiatedVer,
        (uint64_t)(uintptr_t)&hClient);
    if (st != 0 || hClient == 0) {
        *(uint32_t*)(uintptr_t)count_ptr = 0;
        return 0;
    }
    uint64_t pIfList = 0;
    st = wf_call_v2("wlanapi.dll", "WlanEnumInterfaces", 3, /*out8_mask=*/0x4,
        hClient, (uint64_t)0, (uint64_t)(uintptr_t)&pIfList);
    uint32_t out_pos = 0;
    uint32_t profile_count = 0;
    if (st == 0 && pIfList != 0) {
        uint32_t numIf = *(uint32_t*)(uintptr_t)pIfList;
        uint8_t* ifArr = (uint8_t*)(uintptr_t)(pIfList + 8); // skip count+index
        for (uint32_t i = 0; i < numIf; i++) {
            uint8_t* ifInfo = ifArr + i * 536;
            const uint16_t* desc = (const uint16_t*)(ifInfo + 16);
            uint64_t pProfileList = 0;
            uint64_t pst = wf_call_v2("wlanapi.dll", "WlanGetProfileList", 4, /*out8_mask=*/0x8,
                hClient, (uint64_t)(uintptr_t)ifInfo, (uint64_t)0,
                (uint64_t)(uintptr_t)&pProfileList);
            if (pst == 0 && pProfileList != 0) {
                uint32_t numProf = *(uint32_t*)(uintptr_t)pProfileList;
                uint8_t* profArr = (uint8_t*)(uintptr_t)(pProfileList + 8);
                for (uint32_t p = 0; p < numProf; p++) {
                    const uint16_t* pname = (const uint16_t*)(profArr + p * 520);
                    for (uint32_t k = 0; desc[k] != 0 && out_pos + 1 < buf_cap; k++)
                        out[out_pos++] = (uint8_t)(desc[k] & 0xff);
                    if (out_pos < buf_cap) out[out_pos++] = '\t';
                    for (uint32_t k = 0; pname[k] != 0 && out_pos + 1 < buf_cap; k++)
                        out[out_pos++] = (uint8_t)(pname[k] & 0xff);
                    if (out_pos < buf_cap) out[out_pos++] = '\n';
                    profile_count++;
                }
                wf_call("wlanapi.dll", "WlanFreeMemory", 1, pProfileList);
            }
        }
        wf_call("wlanapi.dll", "WlanFreeMemory", 1, pIfList);
    }
    wf_call("wlanapi.dll", "WlanCloseHandle", 2, hClient, (uint64_t)0);
    *(uint32_t*)(uintptr_t)count_ptr = profile_count;
    return out_pos;
}

// fs_read_all: CreateFileW + ReadFile chain via wf_call. Replaces the
// wf_read_all host import. Output bytes go into buf_ptr; actual bytes read
// go into *out_len_ptr. Returns 0 on success, non-zero on failure.
//
// GENERIC_READ = 0x80000000, FILE_SHARE_READ = 0x00000001,
// OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80,
// INVALID_HANDLE_VALUE = (HANDLE)-1
int32_t fs_read_all(uint32_t path_ptr, uint32_t path_len,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t out_len_ptr) {
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return -1;
    // CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecAttrs=NULL,
    //   dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile=NULL)
    uint64_t hFile = wf_call("kernel32.dll", "CreateFileW", 7,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)0x80000000u,    // GENERIC_READ
        (uint64_t)0x00000001u,    // FILE_SHARE_READ
        (uint64_t)0,              // lpSecurityAttributes
        (uint64_t)3u,             // OPEN_EXISTING
        (uint64_t)0x80u,          // FILE_ATTRIBUTE_NORMAL
        (uint64_t)0);             // hTemplateFile
    if (hFile == 0 || hFile == 0xFFFFFFFFFFFFFFFFull) return -2;

    // Sizing call (buf_cap == 0): caller wants file size only. Use
    // GetFileSize, write size to *out_len_ptr. ReadFile with NULL buffer
    // returns ERROR_NOACCESS on Windows, so we cannot use it for sizing.
    if (buf_cap == 0) {
        uint64_t size = wf_call("kernel32.dll", "GetFileSize", 2,
            hFile, (uint64_t)0);
        wf_call("kernel32.dll", "CloseHandle", 1, hFile);
        if ((uint32_t)size == 0xFFFFFFFFu) return -4; // INVALID_FILE_SIZE
        *((uint32_t*)(uintptr_t)out_len_ptr) = (uint32_t)size;
        return 0;
    }

    // Data call (buf_cap > 0): ReadFile into caller's buffer.
    // Use wf_call_v2 with out8_mask = 0x2 — bit 1 (lpBuffer) opts out of the
    // 4-byte overflow guard which would otherwise corrupt the file's bytes 4-7
    // by saving + restoring across the call.
    uint32_t bytes_read = 0;
    // Retry loop: empirically, the first ReadFile via wf_call_v2 sometimes
    // returns ok=1, bytes_read=0 with GetLastError==0 for files freshly
    // opened by CreateFile in this same bridge call. Cause is not fully
    // diagnosed (possible candidates: disk cache prime timing, wazero
    // post-call output-mirroring/refresh interference with the bytes_read
    // DWORD output param, or a benign EOF-like short read on the first
    // attempt). Retrying ReadFile up to 3 times on bytes_read==0 reliably
    // unblocks the read — verified across DPAPI cred files, .vpol vault
    // files, and S-1-5-18 masterkey files in the SharpDPAPI parity suite.
    // The retry is cheap (each call is a wf_call round-trip into wazero,
    // microseconds) and only fires on the pathological case.
    uint64_t ok = 0;
    for (int retry = 0; retry < 3 && bytes_read == 0; retry++) {
        ok = wf_call_v2("kernel32.dll", "ReadFile", 5, /*out8_mask=*/0x2,
            hFile,
            (uint64_t)buf_ptr,
            (uint64_t)buf_cap,
            (uint64_t)(uintptr_t)&bytes_read,
            (uint64_t)0);
        if (bytes_read > 0) break;
    }
    (void)ok;
    if (bytes_read > 0) {
        wf_call("kernel32.dll", "CloseHandle", 1, hFile);
        *((uint32_t*)(uintptr_t)out_len_ptr) = bytes_read;
        return 0;
    }
    uint64_t gle = wf_call("kernel32.dll", "GetLastError", 0);
    wf_call("kernel32.dll", "CloseHandle", 1, hFile);
    int32_t coded = -1000 - (int32_t)(gle & 0xFFFFu);
    return coded;
}

// reg_modifiable: try to RegOpenKeyExW with KEY_WRITE access. If it succeeds,
// the calling token has write access. RegCloseKey if opened.
// Replaces wf_reg_modifiable host import.
uint32_t reg_modifiable(uint32_t hive, uint32_t path_ptr, uint32_t path_len) {
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0;
    const uint32_t KEY_WRITE = 0x20006;
    uint32_t out_handle = 0;
    uint64_t status = wf_call_v2("advapi32.dll", "RegOpenKeyExW", 5, /*out8_mask=*/0x10,
        (uint64_t)(int64_t)(int32_t)hive,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)0,
        (uint64_t)KEY_WRITE,
        (uint64_t)(uintptr_t)&out_handle);
    if (status == 0) {
        wf_call("advapi32.dll", "RegCloseKey", 1, (uint64_t)out_handle);
        return 1;
    }
    return 0;
}

// sc_modifiable: OpenSCManager + OpenServiceW(SERVICE_CHANGE_CONFIG). If
// OpenServiceW succeeds with write access, the token can modify the service.
uint32_t sc_modifiable(uint32_t name_ptr, uint32_t name_len) {
    if (!wf_utf8_to_wide_ascii(name_ptr, name_len)) return 0;
    const uint32_t SC_MANAGER_CONNECT = 0x0001;
    const uint32_t SERVICE_CHANGE_CONFIG = 0x0002;

    uint64_t hSCM = wf_call("advapi32.dll", "OpenSCManagerW", 3,
        (uint64_t)0, (uint64_t)0, (uint64_t)SC_MANAGER_CONNECT);
    if (hSCM == 0) return 0;

    uint64_t hSvc = wf_call("advapi32.dll", "OpenServiceW", 3,
        hSCM, (uint64_t)(uintptr_t)wf_wide_buf, (uint64_t)SERVICE_CHANGE_CONFIG);
    uint32_t result = 0;
    if (hSvc != 0) {
        result = 1;
        wf_call("advapi32.dll", "CloseServiceHandle", 1, hSvc);
    }
    wf_call("advapi32.dll", "CloseServiceHandle", 1, hSCM);
    return result;
}

// MODULEENTRY32W constants (also used by proc_modules below).
#define WF_MODULE_ENTRY32_SIZE 1080
#define WF_MODULE_ENTRY32_PATH_OFFSET 560
#define WF_MODULE_ENTRY32_PATH_MAX 260

// proc_modules_all: WASM-side enumeration of ALL processes' modules via
// CreateToolhelp32Snapshot. Restores the symbol Seatbelt imports under env.
// Wire format: "pid\tprocessName\tmodulePath\n" per module.
//
// PROCESSENTRY32W layout on x64:
//   0:  DWORD  dwSize                    (4)
//   4:  DWORD  cntUsage                  (4)
//   8:  DWORD  th32ProcessID             (4)
//   12: ULONG_PTR th32DefaultHeapID      (8) — aligned
//   24: DWORD  th32ModuleID              (4)
//   28: DWORD  cntThreads                (4)
//   32: DWORD  th32ParentProcessID       (4)
//   36: LONG   pcPriClassBase            (4)
//   40: DWORD  dwFlags                   (4)
//   44: WCHAR  szExeFile[MAX_PATH]       (520)
//   Total: 568, padded to 576
#define WF_PROCESS_ENTRY32_SIZE 568
#define WF_PROCESS_ENTRY32_PID_OFFSET 8
#define WF_PROCESS_ENTRY32_EXEFILE_OFFSET 44

uint32_t proc_modules_all(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    static uint8_t proc_entry[WF_PROCESS_ENTRY32_SIZE] __attribute__((aligned(8)));
    static uint8_t mod_entry_all[WF_MODULE_ENTRY32_SIZE] __attribute__((aligned(8)));

    *((uint32_t*)proc_entry) = WF_PROCESS_ENTRY32_SIZE;
    uint64_t hProcSnap = wf_call("kernel32.dll", "CreateToolhelp32Snapshot", 2,
        (uint64_t)0x00000002u, (uint64_t)0); // TH32CS_SNAPPROCESS
    if (hProcSnap == 0 || hProcSnap == 0xFFFFFFFFFFFFFFFFull) return 0;

    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t out_pos = 0;
    char numbuf[12];

    uint64_t ok = wf_call("kernel32.dll", "Process32FirstW", 2,
        hProcSnap, (uint64_t)(uintptr_t)proc_entry);
    while (ok && out_pos + 4 < out_buf_len) {
        uint32_t pid = *(uint32_t*)(proc_entry + WF_PROCESS_ENTRY32_PID_OFFSET);
        if (pid > 4) {
            const uint16_t* procName = (const uint16_t*)(proc_entry + WF_PROCESS_ENTRY32_EXEFILE_OFFSET);
            // Enumerate modules for this PID
            *((uint32_t*)mod_entry_all) = WF_MODULE_ENTRY32_SIZE;
            uint64_t hModSnap = wf_call("kernel32.dll", "CreateToolhelp32Snapshot", 2,
                (uint64_t)(0x00000008u | 0x00000010u), (uint64_t)pid);
            if (hModSnap != 0 && hModSnap != 0xFFFFFFFFFFFFFFFFull) {
                uint64_t mok = wf_call("kernel32.dll", "Module32FirstW", 2,
                    hModSnap, (uint64_t)(uintptr_t)mod_entry_all);
                while (mok && out_pos + 4 < out_buf_len) {
                    const uint16_t* path = (const uint16_t*)(mod_entry_all + WF_MODULE_ENTRY32_PATH_OFFSET);
                    // pid (decimal)
                    int nl = 0;
                    if (pid == 0) numbuf[nl++] = '0';
                    else { uint32_t v = pid; char rev[12]; int rl = 0;
                           while (v > 0) { rev[rl++] = '0' + (v % 10); v /= 10; }
                           while (rl > 0) numbuf[nl++] = rev[--rl]; }
                    for (int i = 0; i < nl && out_pos + 1 < out_buf_len; i++) out[out_pos++] = numbuf[i];
                    if (out_pos < out_buf_len) out[out_pos++] = '\t';
                    for (uint32_t k = 0; procName[k] != 0 && k < 260 && out_pos + 1 < out_buf_len; k++)
                        out[out_pos++] = (uint8_t)(procName[k] & 0xff);
                    if (out_pos < out_buf_len) out[out_pos++] = '\t';
                    for (uint32_t k = 0; path[k] != 0 && k < 260 && out_pos + 1 < out_buf_len; k++)
                        out[out_pos++] = (uint8_t)(path[k] & 0xff);
                    if (out_pos < out_buf_len) out[out_pos++] = '\n';
                    *((uint32_t*)mod_entry_all) = WF_MODULE_ENTRY32_SIZE;
                    mok = wf_call("kernel32.dll", "Module32NextW", 2,
                        hModSnap, (uint64_t)(uintptr_t)mod_entry_all);
                }
                wf_call("kernel32.dll", "CloseHandle", 1, hModSnap);
            }
        }
        *((uint32_t*)proc_entry) = WF_PROCESS_ENTRY32_SIZE;
        ok = wf_call("kernel32.dll", "Process32NextW", 2,
            hProcSnap, (uint64_t)(uintptr_t)proc_entry);
    }
    wf_call("kernel32.dll", "CloseHandle", 1, hProcSnap);
    return out_pos;
}

// proc_modules: per-pid module enumeration via Toolhelp32 snapshot. WASM-side
// implementation eliminates the wf_proc_modules host import. Wire format:
//   modulePath<NEWLINE>
// per loaded module of the target PID.
//
// TH32CS_SNAPMODULE = 0x00000008
// TH32CS_SNAPMODULE32 = 0x00000010 (also enumerate 32-bit modules on x64)
// MODULEENTRY32W layout on x64:
//   DWORD dwSize;                 //   0  (4)
//   DWORD th32ModuleID;           //   4  (4)
//   DWORD th32ProcessID;          //   8  (4)
//   DWORD GlblcntUsage;           //  12  (4)
//   DWORD ProccntUsage;           //  16  (4)
//   BYTE* modBaseAddr;            //  24  (8) — aligned
//   DWORD modBaseSize;            //  32  (4)
//   HMODULE hModule;              //  40  (8)
//   WCHAR  szModule[256];         //  48  (512)
//   WCHAR  szExePath[260];        // 560  (520)
//   Total: 1080
uint32_t proc_modules(uint32_t pid, uint32_t out_buf_ptr, uint32_t out_buf_len) {
    static uint8_t mod_entry[WF_MODULE_ENTRY32_SIZE] __attribute__((aligned(8)));
    // dwSize must be written first.
    *((uint32_t*)mod_entry) = WF_MODULE_ENTRY32_SIZE;

    uint64_t hSnap = wf_call("kernel32.dll", "CreateToolhelp32Snapshot", 2,
        (uint64_t)(0x00000008u | 0x00000010u),  // TH32CS_SNAPMODULE | _32
        (uint64_t)pid);
    if (hSnap == 0 || hSnap == 0xFFFFFFFFFFFFFFFFull) return 0;

    uint64_t ok = wf_call("kernel32.dll", "Module32FirstW", 2,
        hSnap, (uint64_t)(uintptr_t)mod_entry);
    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t out_pos = 0;
    while (ok) {
        const uint16_t* path = (const uint16_t*)(mod_entry + WF_MODULE_ENTRY32_PATH_OFFSET);
        uint32_t k = 0;
        while (path[k] != 0 && k < WF_MODULE_ENTRY32_PATH_MAX) {
            if (out_pos + 2 > out_buf_len) goto done;
            out[out_pos++] = (uint8_t)(path[k] & 0xff);
            k++;
        }
        if (out_pos < out_buf_len) out[out_pos++] = '\n';
        // Re-prime dwSize before each NextW call.
        *((uint32_t*)mod_entry) = WF_MODULE_ENTRY32_SIZE;
        ok = wf_call("kernel32.dll", "Module32NextW", 2,
            hSnap, (uint64_t)(uintptr_t)mod_entry);
    }
done:
    wf_call("kernel32.dll", "CloseHandle", 1, hSnap);
    return out_pos;
}


// ── Versioning ──────────────────────────────────────────────────────
//
// ver_info: extracts CompanyName from a PE's VERSIONINFO via version.dll
// chain. Replaces wf_get_file_version_info host import.
//
// Sub-blocks to try (English-US + common code pages):
//   "\StringFileInfo\040904B0\CompanyName"   (Unicode codepage)
//   "\StringFileInfo\040904E4\CompanyName"   (Latin-1)
static const uint16_t WF_VER_SUB_040904B0[] = {
    '\\','S','t','r','i','n','g','F','i','l','e','I','n','f','o','\\',
    '0','4','0','9','0','4','B','0','\\',
    'C','o','m','p','a','n','y','N','a','m','e', 0
};
static const uint16_t WF_VER_SUB_040904E4[] = {
    '\\','S','t','r','i','n','g','F','i','l','e','I','n','f','o','\\',
    '0','4','0','9','0','4','E','4','\\',
    'C','o','m','p','a','n','y','N','a','m','e', 0
};

uint32_t ver_info(uint32_t path_ptr, uint32_t path_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    if (!wf_utf8_to_wide_ascii(path_ptr, path_len)) return 0;

    // GetFileVersionInfoSizeW(lpszFileName, lpdwHandle) returns required size.
    uint32_t dummy_handle = 0;
    uint64_t size = wf_call("version.dll", "GetFileVersionInfoSizeW", 2,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)(uintptr_t)&dummy_handle);
    if (size == 0 || size > 65536) return 0;

    // Allocate buffer for version info data — use static buf (WASM single-threaded).
    static uint8_t ver_buf[65536] __attribute__((aligned(8)));
    uint64_t ok = wf_call_v2("version.dll", "GetFileVersionInfoW", 4, /*out8_mask=*/0x8,
        (uint64_t)(uintptr_t)wf_wide_buf,
        (uint64_t)0,
        size,
        (uint64_t)(uintptr_t)ver_buf);
    if (!ok) return 0;

    // VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen).
    // lplpBuffer receives a host pointer INTO ver_buf — already in WASM-mirrored
    // address space after the call. The mirror_table sees a host address inside
    // ver_buf (which is wasm_mem_base + offset) and translates back to the WASM
    // offset, so pValue can be dereferenced directly.
    const uint16_t* subs[] = { WF_VER_SUB_040904B0, WF_VER_SUB_040904E4 };
    for (int i = 0; i < 2; i++) {
        uint32_t pValue = 0;
        uint32_t valueLen = 0;
        uint64_t found = wf_call("version.dll", "VerQueryValueW", 4,
            (uint64_t)(uintptr_t)ver_buf,
            (uint64_t)(uintptr_t)subs[i],
            (uint64_t)(uintptr_t)&pValue,
            (uint64_t)(uintptr_t)&valueLen);
        if (found && pValue != 0 && valueLen > 0) {
            // pValue points to UTF-16 string of length valueLen (chars including NUL).
            const uint16_t* str = (const uint16_t*)(uintptr_t)pValue;
            uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
            uint32_t k = 0;
            while (k < valueLen && k + 1 < out_buf_len && str[k] != 0) {
                out[k] = (uint8_t)(str[k] & 0xff);  // ASCII subset
                k++;
            }
            out[k] = 0;
            return k;
        }
    }
    return 0;
}

// ── LSA / logon-session bridge ──────────────────────────────────────

// WfEnumLogonSessions: WASM-side LsaEnumerateLogonSessions +
// LsaGetLogonSessionData chain. Returns one record per session:
//   "luid_hi:luid_lo\tusername\tdomain\tauthpkg\tlogontype\tlogontime\n"
// Replaces wf_enum_logon_sessions host import.
//
// LUID = {DWORD LowPart; LONG HighPart} = 8 bytes
// SECURITY_LOGON_SESSION_DATA layout on x64 (post-Vista):
//   0:  ULONG Size                     (4)
//   4:  pad                            (4)
//   8:  LUID  LogonId                  (8)
//   16: LSA_UNICODE_STRING UserName    (16) — USHORT len, USHORT maxlen, pad, PWSTR
//   32: LSA_UNICODE_STRING LogonDomain (16)
//   48: LSA_UNICODE_STRING AuthPkg     (16)
//   64: ULONG LogonType                (4)
//   68: ULONG Session                  (4)
//   72: PSID  Sid                      (8)
//   80: LARGE_INTEGER LogonTime        (8)
//   ... (more fields we don't read)
#define WF_LSA_UNICODE_STR_OFFSET_BUF 8   // PWSTR pointer at offset 8 within UNICODE_STRING

static uint32_t wf_emit_lsa_unicode_str(uint8_t* out, uint32_t out_pos, uint32_t out_cap, uintptr_t us_struct_ptr) {
    // UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer }
    // Length is in BYTES, not chars. Buffer at offset 8 on x64 (after 4-byte struct + 4-byte pad).
    uint16_t lenBytes = *(uint16_t*)us_struct_ptr;
    uint64_t bufPtr = *(uint64_t*)(us_struct_ptr + 8);
    if (lenBytes == 0 || bufPtr == 0) return out_pos;
    const uint16_t* w = (const uint16_t*)(uintptr_t)bufPtr;
    uint32_t chars = lenBytes / 2;
    for (uint32_t i = 0; i < chars && out_pos + 1 < out_cap; i++) {
        out[out_pos++] = (uint8_t)(w[i] & 0xff);
    }
    return out_pos;
}

static uint32_t wf_emit_u32_decimal(uint8_t* out, uint32_t out_pos, uint32_t out_cap, uint32_t v) {
    char rev[12]; int rl = 0;
    if (v == 0) { if (out_pos + 1 < out_cap) out[out_pos++] = '0'; return out_pos; }
    while (v > 0) { rev[rl++] = '0' + (v % 10); v /= 10; }
    while (rl > 0 && out_pos + 1 < out_cap) out[out_pos++] = rev[--rl];
    return out_pos;
}

// Emit a single key=value line in the format LsaHostHelper expects:
//   key\tvalue\n
static uint32_t wf_emit_kv_str(uint8_t* out, uint32_t pos, uint32_t cap,
                                const char* key, uintptr_t pLsaUStr) {
    uint32_t k = 0;
    while (key[k] && pos + 1 < cap) out[pos++] = (uint8_t)key[k++];
    if (pos + 1 < cap) out[pos++] = '\t';
    pos = wf_emit_lsa_unicode_str(out, pos, cap, pLsaUStr);
    if (pos + 1 < cap) out[pos++] = '\n';
    return pos;
}

static uint32_t wf_emit_kv_u32(uint8_t* out, uint32_t pos, uint32_t cap,
                                const char* key, uint32_t v) {
    uint32_t k = 0;
    while (key[k] && pos + 1 < cap) out[pos++] = (uint8_t)key[k++];
    if (pos + 1 < cap) out[pos++] = '\t';
    pos = wf_emit_u32_decimal(out, pos, cap, v);
    if (pos + 1 < cap) out[pos++] = '\n';
    return pos;
}

static uint32_t wf_emit_kv_u64(uint8_t* out, uint32_t pos, uint32_t cap,
                                const char* key, uint64_t v) {
    // emit as decimal (split into hi*1e9 + lo)
    uint32_t k = 0;
    while (key[k] && pos + 1 < cap) out[pos++] = (uint8_t)key[k++];
    if (pos + 1 < cap) out[pos++] = '\t';
    char buf[24];
    int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    else {
        char tmp[24];
        int t = 0;
        while (v > 0) { tmp[t++] = (char)('0' + (int)(v % 10)); v /= 10; }
        while (t > 0) buf[n++] = tmp[--t];
    }
    for (int i = 0; i < n && pos + 1 < cap; i++) out[pos++] = (uint8_t)buf[i];
    if (pos + 1 < cap) out[pos++] = '\n';
    return pos;
}

// Emit one session record to the output buffer in key=value format.
// Returns updated position, or pos unchanged if no data was emitted.
static uint32_t wf_emit_session_record(uint8_t* out, uint32_t pos, uint32_t cap,
                                        uint64_t luid_val, uintptr_t pSession) {
    if (pos + 64 > cap) return pos;
    uint32_t luid_lo = (uint32_t)(luid_val & 0xFFFFFFFFu);
    uint32_t luid_hi = (uint32_t)(luid_val >> 32);
    pos = wf_emit_kv_u32(out, pos, cap, "LuidLow",  luid_lo);
    pos = wf_emit_kv_u32(out, pos, cap, "LuidHigh", luid_hi);
    // UserName at offset 16, LogonDomain at 32, AuthPackage at 48
    pos = wf_emit_kv_str(out, pos, cap, "UserName",   pSession + 16);
    pos = wf_emit_kv_str(out, pos, cap, "Domain",     pSession + 32);
    pos = wf_emit_kv_str(out, pos, cap, "AuthPackage", pSession + 48);
    // LogonType at 64 (4 bytes)
    uint32_t logonType = *(uint32_t*)(pSession + 64);
    pos = wf_emit_kv_u32(out, pos, cap, "LogonType", logonType);
    // LogonTime at 80 (8 bytes, FILETIME)
    uint64_t logonTime = *(uint64_t*)(pSession + 80);
    pos = wf_emit_kv_u64(out, pos, cap, "LogonTime", logonTime);
    // LogonServer at 88, DnsDomainName at 104, Upn at 120
    pos = wf_emit_kv_str(out, pos, cap, "LogonServer",   pSession + 88);
    pos = wf_emit_kv_str(out, pos, cap, "DnsDomainName", pSession + 104);
    pos = wf_emit_kv_str(out, pos, cap, "UserPrincipalName", pSession + 120);
    // PSID at offset 72: hand-format to SDDL string. ConvertSidToStringSidW's
    // OUT pointer-to-pointer slot doesn't round-trip cleanly through wf_call's
    // mirror, but PSID is already a host pointer we can read directly via the
    // same dereference pattern used for the LSA_UNICODE_STRINGs above. The SID
    // structure is documented:
    //   BYTE Revision
    //   BYTE SubAuthorityCount
    //   BYTE IdentifierAuthority[6]  (big-endian, treat as 48-bit value)
    //   DWORD SubAuthority[SubAuthorityCount]
    {
        uint64_t pSid = *(uint64_t*)(pSession + 72);
        if (pSid != 0) {
            uint8_t rev = *(uint8_t*)pSid;
            uint8_t saCount = *(uint8_t*)(pSid + 1);
            if (saCount > 0 && saCount <= 16 && rev == 1) {
                // 48-bit big-endian authority (bytes 2..7)
                uint64_t auth = 0;
                for (int b = 0; b < 6; b++) {
                    auth = (auth << 8) | *(uint8_t*)(pSid + 2 + b);
                }
                const char* k = "Sid"; uint32_t i = 0;
                while (k[i] && pos + 1 < cap) out[pos++] = (uint8_t)k[i++];
                if (pos + 1 < cap) out[pos++] = '\t';
                if (pos + 2 < cap) { out[pos++] = 'S'; out[pos++] = '-'; }
                pos = wf_emit_u32_decimal(out, pos, cap, (uint32_t)rev);
                if (pos + 1 < cap) out[pos++] = '-';
                pos = wf_emit_u32_decimal(out, pos, cap, (uint32_t)auth);
                for (uint8_t s = 0; s < saCount; s++) {
                    if (pos + 1 < cap) out[pos++] = '-';
                    uint32_t sub = *(uint32_t*)(pSid + 8 + (uint64_t)s * 4);
                    pos = wf_emit_u32_decimal(out, pos, cap, sub);
                }
                if (pos + 1 < cap) out[pos++] = '\n';
            }
        }
    }
    // Record terminator: NUL
    if (pos + 1 < cap) out[pos++] = 0;
    return pos;
}

uint32_t WfEnumLogonSessions(uint32_t out_buf_ptr, uint32_t out_buf_len) {
    uint32_t count = 0;
    uint64_t pLuids = 0;
    uint64_t status = wf_call_v2("secur32.dll", "LsaEnumerateLogonSessions", 2, /*out8_mask=*/0x2,
        (uint64_t)(uintptr_t)&count,
        (uint64_t)(uintptr_t)&pLuids);
    if (status != 0 || count == 0 || pLuids == 0) return 0;

    uint8_t* out = (uint8_t*)(uintptr_t)out_buf_ptr;
    uint32_t out_pos = 0;
    uint64_t* luids = (uint64_t*)(uintptr_t)pLuids;

    for (uint32_t i = 0; i < count && out_pos + 64 < out_buf_len; i++) {
        uint64_t pSession = 0;
        uint64_t r = wf_call_v2("secur32.dll", "LsaGetLogonSessionData", 2, /*out8_mask=*/0x2,
            (uint64_t)(uintptr_t)&luids[i],
            (uint64_t)(uintptr_t)&pSession);
        if (r != 0 || pSession == 0) continue;
        out_pos = wf_emit_session_record(out, out_pos, out_buf_len,
            luids[i], (uintptr_t)pSession);
        wf_call("secur32.dll", "LsaFreeReturnBuffer", 1, pSession);
    }

    wf_call("secur32.dll", "LsaFreeReturnBuffer", 1, pLuids);
    return out_pos;
}

// WfLsaKerberosOp: forwards to the env::lsa_kerbop import, which lands
// at win32LsaKerberosOp on the host. The host runs the full LSA chain
// (LsaConnectUntrusted + LsaLookupAuthenticationPackage +
// LsaCallAuthenticationPackage with KERB_QUERY_TKT_CACHE_REQUEST etc.)
// on a locked OS thread with SYSTEM impersonation — the only place that
// sequence works reliably. The earlier stub returned 0 silently, which
// broke Rubeus klist/dump/ptt/purge (they all called this entrypoint,
// saw "no output", and concluded "no tickets").
__attribute__((import_module("env"), import_name("lsa_kerbop")))
extern uint32_t __wf_env_lsa_kerbop(uint32_t op_ptr, uint32_t op_len,
    uint32_t luid_low, uint32_t luid_high,
    uint32_t out_buf_ptr, uint32_t out_buf_len);

uint32_t WfLsaKerberosOp(uint32_t op_ptr, uint32_t op_len,
    uint32_t luid_low, uint32_t luid_high,
    uint32_t out_buf_ptr, uint32_t out_buf_len) {
    return __wf_env_lsa_kerbop(op_ptr, op_len, luid_low, luid_high,
        out_buf_ptr, out_buf_len);
}

// WfCryptoOp: generic crypto dispatcher. One env import handles all
// looped-crypto operations (MS-PBKDF2, RFC PBKDF2, HMAC, plain hash,
// AES-CBC) host-side, eliminating the per-iteration WASM↔host
// boundary cost that made the in-bridge PBKDF2 loop unusable.
// See internal/hostmod/nativeaot_crypto_windows.go nativeaotCryptoOp
// for the opcode catalog + wire format.
__attribute__((import_module("env"), import_name("xc_op")))
extern uint32_t __wf_env_xc_op(uint32_t op_ptr, uint32_t op_len,
    uint32_t args_ptr, uint32_t args_len,
    uint32_t out_ptr, uint32_t out_cap);

uint32_t WfCryptoOp(uint32_t op_ptr, uint32_t op_len,
    uint32_t args_ptr, uint32_t args_len,
    uint32_t out_ptr, uint32_t out_cap) {
    return __wf_env_xc_op(op_ptr, op_len, args_ptr, args_len, out_ptr, out_cap);
}

// WfIoOp: generic IO dispatcher. Sibling to WfCryptoOp — one env
// import for filesystem operations (read / stat / list). Replaces the
// 6-8 wf_call CreateFile+ReadFile+CloseHandle chain in fs_read_all
// with a single host trip using Go's os.ReadFile. Per-file cost drops
// from ~46 ms (in-bridge) to <1 ms (dispatcher).
__attribute__((import_module("env"), import_name("xi_op")))
extern uint32_t __wf_env_xi_op(uint32_t op_ptr, uint32_t op_len,
    uint32_t args_ptr, uint32_t args_len,
    uint32_t out_ptr, uint32_t out_cap);

uint32_t WfIoOp(uint32_t op_ptr, uint32_t op_len,
    uint32_t args_ptr, uint32_t args_len,
    uint32_t out_ptr, uint32_t out_cap) {
    return __wf_env_xi_op(op_ptr, op_len, args_ptr, args_len, out_ptr, out_cap);
}

// `#437` in the undefined-symbol list is a stripped/anonymized internal
// artifact left over from NativeAOT's interop generator. Not a real host
// function — wasm-ld emits it as a warning that is harmless at runtime.
