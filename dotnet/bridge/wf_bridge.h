// wf_bridge.h — WasmForge NativeAOT-WASI bridge header.
//
// Declares the universal wf_call() bridge and direct host function imports.
// Used by pinvoke_nativeaot.c and hand-written P/Invoke implementations.
//
// The bridge solves the fundamental wasm32/x64 mismatch: NativeAOT compiles
// to wasm32 (4-byte pointers), but Windows APIs expect x64 (8-byte pointers).
// wf_call() provides overflow protection for output parameters.

#ifndef WF_BRIDGE_H
#define WF_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

// ── WasmForge host function imports ──────────────────────────────────
// These are WASM imports from the "env" module, provided by the WasmForge
// host binary (Go code in internal/hostmod/).

// mod_invoke: Universal SyscallN dispatcher.
// Loads a DLL proc and calls it with up to 15 arguments, handling WASM→host
// pointer translation, shadow memory, and mirror table operations.
//
// proc_handle: win32 handle table entry for the target proc
// nargs: number of arguments (0-15)
// a0..a14: arguments (WASM pointers auto-translated to host addresses)
// ret1_ptr: WASM pointer to write r1 return value
// err_ptr: WASM pointer to write errno
// Returns: r0
__attribute__((import_module("env"), import_name("mod_invoke")))
extern uint64_t wf_mod_invoke(
    uint64_t proc_handle, uint32_t nargs,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11,
    uint64_t a12, uint64_t a13, uint64_t a14,
    uint64_t ret1_ptr, uint64_t err_ptr);

// mod_load: LoadLibraryA — load a DLL by name.
// name_ptr: WASM pointer to null-terminated DLL name
// Returns: handle table entry, or 0 on failure
__attribute__((import_module("env"), import_name("mod_load")))
extern uint32_t wf_load_library(uint32_t name_ptr);

// mod_resolve: GetProcAddress — resolve a function by name.
// lib_handle: handle from wf_load_library
// name_ptr: WASM pointer to null-terminated function name
// Returns: handle table entry, or 0 on failure
__attribute__((import_module("env"), import_name("mod_resolve")))
extern uint32_t wf_get_proc_address(uint32_t lib_handle, uint32_t name_ptr);

// mod_free: FreeLibrary.
__attribute__((import_module("env"), import_name("mod_free")))
extern uint32_t wf_free_library(uint32_t lib_handle);

// mod_close: CloseHandle (generic).
__attribute__((import_module("env"), import_name("mod_close")))
extern uint32_t wf_close_handle(uint32_t handle);

// mod_regptr: Register a raw host function pointer (e.g. a COM vtable slot
// resolved via mirror traversal) as a synthetic proc handle with an explicit
// pointer mask. The returned handle plugs straight into wf_call_handle /
// wf_call_handle_v2 / wf_mod_invoke.
//
// funcptr: raw host function pointer (8 bytes; from a mirrored COM vtable)
// ptr_mask: bit N=1 means arg[N] is a WASM pointer that must be translated
//           to a host address before the call; bit N=0 means arg[N] is a
//           handle/scalar/size that must pass through unchanged
// Returns: handle table entry (>0) or 0 on failure
__attribute__((import_module("env"), import_name("mod_regptr")))
extern uint32_t wf_register_funcptr(uint64_t funcptr, uint32_t ptr_mask);


// ── NativeAOT-specific host function imports ─────────────────────────
// These bypass the SyscallN path entirely — complex operations run
// atomically on the host to avoid wasm32/x64 struct layout mismatches.

// sec_parsesddl import removed — WASM-side passthrough; richer parsing
// will use wf_call(advapi32!ConvertStringSDtoSD + GetAce) when needed.

// sec_sddl import removed — WASM-side via wf_call(advapi32!GetNamedSecurityInfoW
// + ConvertSecurityDescriptorToStringSecurityDescriptorW chain).

// sec_enumrights / sec_enumsessions imports removed — WASM-side stubs in
// pinvoke_env_ext.c. Full LsaLookupPrivilegeName / LsaEnumerateLogonSessions
// chains via wf_call to follow with wf_call_v2 handle-output marshaling.

// rpc_enumeps import removed — WASM-side stub (returns empty result) in
// pinvoke_env_ext.c. Full RpcMgmtEpEltInq chain via wf_call(rpcrt4.dll)
// can be added later.

// wmi_query / wmi_method imports removed — WASM-side stubs in
// pinvoke_env_ext.c. Full WMI COM chain via WfCom + wf_call_ptr later.

// wmi_query_r: host-side WMI for restricted namespaces (root\SecurityCenter2,
// ROOT\Subscription). Calls CoSetProxyBlanket on IWbemServices proxy so the
// WMI auth handshake never crosses the WASM FFI boundary (eliminates chanrecv2).
__attribute__((import_module("env"), import_name("wmi_query_r")))
extern uint32_t wf_wmi_query_restricted(uint32_t query_ptr, uint32_t query_len,
    uint32_t ns_ptr, uint32_t ns_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len);

// reg_search: host-side BFS walker for SharpDPAPI's `search` verb. Walks the
// supplied hive (HKEY constant: 0x80000002=HKLM, 0x80000003=HKU) and writes
// NUL-separated UTF-8 match lines to the output buffer. First record is the
// "Root: <prefix>\" header matching native FindRegistryBlobs; subsequent
// records are full match lines "<prefix>\\<subpath> ! <valueName>". See
// internal/hostmod/nativeaot_regsearch_windows.go for the walker + DPAPI
// signature catalog.
__attribute__((import_module("env"), import_name("reg_search")))
extern uint32_t wf_reg_search(uint32_t hive, uint32_t out_buf_ptr, uint32_t out_buf_cap);

// dpapi_bkey: host-side DsGetDcName + LsaOpenPolicy + LsaRetrievePrivateData
// chain for SharpDPAPI's `backupkey` verb. Returns a packed reply: status u32,
// dc_name length-prefixed, guid length-prefixed (16 bytes on success), key_blob
// length-prefixed. server_ptr/server_len may be empty to trigger DsGetDcName.
// See internal/hostmod/nativeaot_backupkey_windows.go for wire-format details.
__attribute__((import_module("env"), import_name("dpapi_bkey")))
extern uint32_t wf_dpapi_backupkey(uint32_t server_ptr, uint32_t server_len,
    uint32_t out_buf_ptr, uint32_t out_buf_cap);

// x509_match: host-side CurrentUser\MY + LocalMachine\MY walker for
// SharpDPAPI's machinetriage cert-matching path. Takes raw big-endian RSA
// modulus bytes (extracted by manual byte slicing of the decrypted blob),
// returns the matched cert's metadata + raw DER bytes packed as:
//   status u32 (0=match, 1=no match), then on match: 7× length-prefixed
//   records (thumbprint hex, issuer DN, subject DN, notBefore, notAfter,
//   semicolon-joined EKU "friendly|oid" pairs, cert DER bytes).
// See internal/hostmod/nativeaot_x509match_windows.go for details.
__attribute__((import_module("env"), import_name("x509_match")))
extern uint32_t wf_x509_match(uint32_t modulus_ptr, uint32_t modulus_len,
    uint32_t out_buf_ptr, uint32_t out_buf_cap);

// fs_listdir / fs_exists / fs_read_all imports removed — WASM-side via
// wf_call(kernel32.dll) FindFirstFileW / GetFileAttributesW / CreateFileW
// chains. See pinvoke_env_ext.c.

// fs_findfiles: one-shot recursive filesystem search. Host walks the tree
// natively (filepath.WalkDir) and returns matched paths in a NUL-separated
// UTF-8 buffer. Single WASM↔host crossing — vs the per-directory crossings
// the WASM-side fs_listdir approach incurs.
//
// root_ptr/root_len: UTF-8 root path (e.g., "C:\\ProgramData\\McAfee")
// pattern_ptr/pattern_len: UTF-8 case-insensitive substring match against basename
// max_depth: levels below root to descend (1 = immediate children only)
// max_matches: cap on result count (function returns early once reached)
// buf_ptr/buf_cap: WASM-side output buffer for NUL-separated paths
// count_ptr: WASM-side uint32 receiving the match count
// Returns: bytes_written into buf_ptr (0 on error, positive on success).
__attribute__((import_module("env"), import_name("fs_findfiles")))
extern int32_t fs_findfiles(
    uint32_t root_ptr, uint32_t root_len,
    uint32_t pattern_ptr, uint32_t pattern_len,
    int32_t max_depth, int32_t max_matches,
    uint32_t buf_ptr, uint32_t buf_cap, uint32_t count_ptr);

// reg_modifiable / sc_modifiable imports removed — WASM-side via wf_call
// (advapi32!RegOpenKeyExW with KEY_WRITE, OpenSCManagerW/OpenServiceW with
// SERVICE_CHANGE_CONFIG). See pinvoke_env_ext.c.

// proc_modules import removed — implemented WASM-side via wf_call(kernel32.dll)
// CreateToolhelp32Snapshot + Module32FirstW/NextW chain.


// net_adapters import removed — WASM-side via wf_call(iphlpapi!GetAdaptersInfo).

// ver_info import removed — WASM-side via wf_call(version.dll!Get/VerQueryW).

// reg_open / reg_close / reg_enum imports removed — WASM-side via
// wf_call(advapi32.dll!RegOpenKeyExW / RegCloseKey / RegEnumKeyExW)
// in pinvoke_env_ext.c.

// reg_enumvals import removed — WASM-side via wf_call(advapi32!RegOpenKeyExW +
// RegEnumValueW + RegCloseKey) in pinvoke_env_ext.c.

// lsa_kerbop import removed — WASM-side stub in pinvoke_env_ext.c
// (LSA Kerberos ticket ops degrade to empty pending SYSTEM impersonation
// design decision).

// crypto_kerbhash / crypto_kerbenc / crypto_kerbdec / crypto_kerbcksum
// env imports removed — WfKerberosHash/Encrypt/Decrypt/Checksum in
// pinvoke_nativeaot.c now implement these directly via BCrypt wf_call
// chains (hash) and CDLocateCSystem + wf_call_ptr_fixed8 (enc/dec/cksum).

// PBKDF2-HMAC-SHA1/256/512 imports removed — implemented WASM-side via
// wf_pbkdf2 (in pinvoke_nativeaot.c) using wf_call against
// bcrypt.dll!BCryptDeriveKeyPBKDF2.

// HMAC-SHA1/256/512: implemented WASM-side via wf_call(bcrypt.dll) chain.
// See wf_bcrypt_hash in pinvoke_nativeaot.c — no host import.

// All-process modules enumeration (no pid filter). Wire format:
//   pid<TAB>processName<TAB>modulePath<NEWLINE>
// per module of every accessible process. Returns bytes written.
__attribute__((import_module("env"), import_name("proc_modules_all")))
extern uint32_t proc_modules_all(uint32_t out_buf_ptr, uint32_t out_buf_len);

// AES-CBC decrypt — implemented WASM-side via wf_call(bcrypt.dll) chain.
// See WfAesCbcDecrypt in pinvoke_nativeaot.c. Host has no dedicated AES bridge.

// SHA1 / SHA256 / HMAC-* are NO LONGER imported from host.
// They're implemented WASM-side in pinvoke_nativeaot.c via wf_call against
// bcrypt.dll's BCryptOpenAlgorithmProvider/CreateHash/HashData/FinishHash
// chain. This eliminates the host's dedicated crypto exports and keeps the
// hashing logic inside the WASM payload.

// crypto_sha256 import removed — migrated to wf_call(bcrypt.dll) chain.

// net_tcpsendrecv env import removed — WfTcpSendRecv now implements
// TCP+KRB framing directly via wf_sock_* primitives in pinvoke_nativeaot.c.

__attribute__((import_module("env"), import_name("net_ldapsearch")))
extern uint32_t net_ldapsearch(
    uint32_t server_ptr, uint32_t server_len,
    uint32_t port,
    uint32_t base_dn_ptr, uint32_t base_dn_len,
    uint32_t filter_ptr, uint32_t filter_len,
    uint32_t attrs_ptr, uint32_t attrs_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len);

__attribute__((import_module("env"), import_name("net_ldapsearchext")))
extern uint32_t net_ldapsearchext(
    uint32_t server_ptr, uint32_t server_len,
    uint32_t port,
    uint32_t base_dn_ptr, uint32_t base_dn_len,
    uint32_t filter_ptr, uint32_t filter_len,
    uint32_t attrs_ptr, uint32_t attrs_len,
    uint32_t user_ptr, uint32_t user_len,
    uint32_t domain_ptr, uint32_t domain_len,
    uint32_t password_ptr, uint32_t password_len,
    uint32_t out_buf_ptr, uint32_t out_buf_len);

__attribute__((import_module("env"), import_name("net_getdc")))
extern uint32_t net_getdc(uint32_t domain_ptr, uint32_t domain_len,
    uint32_t flags,
    uint32_t out_buf_ptr, uint32_t out_buf_len);

__attribute__((import_module("env"), import_name("net_ldapmodify")))
extern uint32_t net_ldapmodify(
    uint32_t server_ptr, uint32_t server_len, uint32_t port,
    uint32_t dn_ptr, uint32_t dn_len,
    uint32_t attr_ptr, uint32_t attr_len,
    uint32_t val_ptr, uint32_t val_len,
    uint32_t op_code,
    uint32_t user_ptr, uint32_t user_len,
    uint32_t domain_ptr, uint32_t domain_len,
    uint32_t password_ptr, uint32_t password_len);

// ── Bridge API ───────────────────────────────────────────────────────

// WF_MAX_ARGS is the maximum number of arguments for wf_call.
#define WF_MAX_ARGS 15

// wf_call: Universal bridge from C P/Invoke to WasmForge host SyscallN.
//
// Resolves DLL+proc by name (cached), calls via mod_invoke with automatic
// overflow protection: saves 4 bytes after each WASM pointer output arg,
// restores after the call. This prevents x64 APIs from corrupting adjacent
// wasm32 stack data when writing 8-byte values to 4-byte slots.
//
// dll_name: e.g. "kernel32.dll"
// func_name: e.g. "CreateFileW"
// nargs: argument count
// ...: uint64_t arguments
// Returns: r0 (uint64_t)
uint64_t wf_call(const char* dll_name, const char* func_name, int nargs, ...);

// wf_call_handle: Like wf_call but takes a pre-resolved proc handle.
uint64_t wf_call_handle(uint32_t proc_handle, int nargs, ...);

// wf_call_v2: Like wf_call but takes an out8_mask bitmask of arguments
// whose pointed-to WASM slot is >= 8 bytes wide (e.g. an `out ulong` for
// a BCRYPT_*_HANDLE, or a freshly-allocated `byte[]` output buffer).
//
// For each arg with its bit set in out8_mask, the 4-byte overflow protection
// is SKIPPED. The default protection (wf_call) saves 4 bytes at addr+4 before
// the call and restores them after — which corrupts the high half of an
// 8-byte handle output, and zeros bytes 4-7 of any output buffer larger
// than 4 bytes.
//
// out8_mask is a bitmask where bit i corresponds to arg i (LSB = arg 0).
// nargs must still be <= WF_MAX_ARGS.
uint64_t wf_call_v2(const char* dll_name, const char* func_name,
    int nargs, uint32_t out8_mask, ...);

// wf_call_handle_v2: Like wf_call_v2 but with a pre-resolved proc handle.
uint64_t wf_call_handle_v2(uint32_t proc_handle, int nargs,
    uint32_t out8_mask, ...);

// wf_call_ptr: Invoke an arbitrary host function pointer (e.g. a COM
// vtable slot) with up to WF_MAX_ARGS arguments. The bridge registers
// the funcptr with the host on first use (per ptr_mask) and caches the
// resulting synthetic proc handle for subsequent calls.
//
// funcptr: raw host function pointer (from a mirrored COM vtable)
// nargs: argument count (0..WF_MAX_ARGS)
// ptr_mask: bit N=1 means arg[N] is a WASM pointer to translate
// out8_mask: bit N=1 means arg[N]'s WASM slot is >= 8 bytes wide
//            (skip the 4-byte overflow protection)
// ...: uint64_t arguments
// Returns: r0 (uint64_t)
uint64_t wf_call_ptr(uint64_t funcptr, int nargs,
    uint32_t ptr_mask, uint32_t out8_mask, ...);

// wf_get_last_error: Returns the errno from the most recent wf_call.
uint32_t wf_get_last_error(void);

// ── DLL/Proc cache ──────────────────────────────────────────────────

// wf_resolve_proc: Resolve a DLL+proc name pair, caching the result.
// Returns proc handle (>0) or 0 on failure.
uint32_t wf_resolve_proc(const char* dll_name, const char* func_name);

// wf_host_read_bytes: read `len` bytes from arbitrary host memory at
// `host_addr` into the WASM buffer at `out_buf`. Returns 0 on success.
// Used to dereference host pointers returned by Win32 APIs whose
// containing struct chain wasn't fully mirrored.
__attribute__((import_module("env"), import_name("mod_hread")))
extern uint32_t wf_host_read_bytes(uint64_t host_addr, uint32_t len, void* out_buf);

// ── Host-memory allocator env imports (for WfHost.HostAlloc/Free/etc) ──
// Required by WfFileVersionInfo, WfX509Store, WfSec, WfSspi, WfLsa et al.
// All map to win32_virtual_alloc family registered in internal/hostmod/win32.go.
// Without these declarations, NativeAOT-LLVM emits undefined_stub for
// DllImport("env", EntryPoint="mem_alloc") and the call traps at runtime.
__attribute__((import_module("env"), import_name("mem_alloc")))
extern uint32_t wf_mem_alloc(uint32_t size, uint32_t alloc_type, uint32_t protect, uint32_t handle_ptr);

__attribute__((import_module("env"), import_name("mem_free")))
extern uint32_t wf_mem_free(int32_t handle);

__attribute__((import_module("env"), import_name("mem_write")))
extern uint32_t wf_mem_write(int32_t handle, uint32_t offset, const void* data_ptr, uint32_t data_len);

__attribute__((import_module("env"), import_name("mem_read")))
extern uint32_t wf_mem_read(int32_t handle, uint32_t offset, void* buf_ptr, uint32_t buf_len);

__attribute__((import_module("env"), import_name("mem_write32")))
extern uint32_t wf_mem_write32(int32_t handle, uint32_t offset, uint32_t value);

__attribute__((import_module("env"), import_name("mem_write64")))
extern uint32_t wf_mem_write64(int32_t handle, uint32_t offset, uint32_t value_ptr);

__attribute__((import_module("env"), import_name("mem_read32")))
extern uint32_t wf_mem_read32(int32_t handle, uint32_t offset, uint32_t out_ptr);

__attribute__((import_module("env"), import_name("mem_read64")))
extern uint32_t wf_mem_read64(int32_t handle, uint32_t offset, uint32_t out_ptr);

__attribute__((import_module("env"), import_name("mem_addr")))
extern uint32_t wf_mem_addr(int32_t handle, uint32_t addr_ptr);

// fs_pipes / sys_printers / sec_pkgs / priv_rights / net_wifi imports removed —
// WASM-side via wf_call(kernel32!FindFirstFileW) for pipes; stub-empty for the
// rest pending wf_call_v2 expansion of EnumPrintersW / EnumerateSecurityPackagesW /
// LsaEnumerateAccountRights / WlanEnumInterfaces handle-output chains.

// ── WASI socket primitive env imports (for WfTcp.SendRecv) ──────────────
// WasmForge exposes a full WASI-style socket API in internal/hostmod/{tcp,io,
// dns}.go. Anonymized export names from internal/names/names.go:
//     sock_open        -> env.fd_open
//     sock_connect     -> env.fd_connect
//     sock_read        -> env.fd_read2
//     sock_write       -> env.fd_write2
//     sock_close       -> env.fd_close2
//     sock_getaddrinfo -> env.addr_resolve
// Used by dotnet/helpers/WfTcp.cs which is the wasm-side replacement for the
// broken net_tcpsendrecv env path. All pointer args are wasm32 offsets; the
// host translates via api.Module.Memory().
__attribute__((import_module("env"), import_name("fd_open")))
extern uint32_t wf_sock_open(int32_t domain, int32_t socktype, int32_t protocol, int32_t* fd_ptr);

__attribute__((import_module("env"), import_name("fd_connect")))
extern uint32_t wf_sock_connect(int32_t fd, const void* addr_ptr, uint32_t addr_len);

__attribute__((import_module("env"), import_name("fd_read2")))
extern uint32_t wf_sock_read(int32_t fd, void* buf_ptr, uint32_t buf_len, uint32_t* nread_ptr);

__attribute__((import_module("env"), import_name("fd_write2")))
extern uint32_t wf_sock_write(int32_t fd, const void* buf_ptr, uint32_t buf_len, uint32_t* nwritten_ptr);

__attribute__((import_module("env"), import_name("fd_close2")))
extern uint32_t wf_sock_close(int32_t fd);

__attribute__((import_module("env"), import_name("addr_resolve")))
extern uint32_t wf_sock_getaddrinfo(
    const void* name_ptr, uint32_t name_len,
    const void* svc_ptr, uint32_t svc_len,
    uint32_t hints,
    void* result_ptr, uint32_t max_results,
    uint32_t* n_ptr);

#endif // WF_BRIDGE_H
