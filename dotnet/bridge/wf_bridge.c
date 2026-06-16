// wf_bridge.c — WasmForge NativeAOT-WASI universal bridge.
//
// Provides wf_call() which bridges C# P/Invoke → WasmForge host SyscallN
// with automatic x64 overflow protection for wasm32 output parameters.
//
// THE PROBLEM:
// NativeAOT compiles to wasm32 (4-byte IntPtr). Windows x64 APIs write
// 8 bytes to `out IntPtr` / `out HANDLE` parameters. On wasm32, this
// overwrites 4 bytes of adjacent stack data, corrupting return addresses,
// other locals, or neighboring struct fields.
//
// THE FIX:
// For every argument that looks like a WASM pointer (value >= 0x10000 and
// < memory size), save the 4 bytes immediately following the pointed-to
// location BEFORE the call, then restore them AFTER. This is universal —
// it protects ALL output parameters without per-function knowledge.
//
// COMPILATION:
//   clang --target=wasm32-wasi -O2 -c wf_bridge.c -o wf_bridge.o

#include "wf_bridge.h"
#include <stdarg.h>
#include <string.h>
#include <errno.h>

// ── DLL/Proc cache ──────────────────────────────────────────────────

#define MAX_CACHED_PROCS 256

typedef struct {
    const char* dll_name;
    const char* func_name;
    uint32_t    handle;
} cached_proc_t;

static cached_proc_t proc_cache[MAX_CACHED_PROCS];
static int proc_cache_count = 0;

// Last errno from wf_call.
static uint32_t last_error = 0;

uint32_t wf_get_last_error(void) {
    return last_error;
}

uint32_t wf_resolve_proc(const char* dll_name, const char* func_name) {
    // Check cache first.
    for (int i = 0; i < proc_cache_count; i++) {
        if (proc_cache[i].dll_name == dll_name &&
            proc_cache[i].func_name == func_name) {
            return proc_cache[i].handle;
        }
    }

    // Load DLL.
    uint32_t dll_handle = wf_load_library((uint32_t)(uintptr_t)dll_name);
    if (dll_handle == 0) return 0;

    // Resolve proc.
    uint32_t proc_handle = wf_get_proc_address(dll_handle, (uint32_t)(uintptr_t)func_name);
    if (proc_handle == 0) return 0;

    // Cache it.
    if (proc_cache_count < MAX_CACHED_PROCS) {
        proc_cache[proc_cache_count].dll_name = dll_name;
        proc_cache[proc_cache_count].func_name = func_name;
        proc_cache[proc_cache_count].handle = proc_handle;
        proc_cache_count++;
    }

    return proc_handle;
}

// ── Overflow protection helpers ─────────────────────────────────────

// WASM linear memory bounds. On wasm32, memory starts at 0 and grows.
// We use __builtin_wasm_memory_size to get the current page count.
static inline uint32_t wasm_memory_size(void) {
    return (uint32_t)__builtin_wasm_memory_size(0) * 65536;
}

// is_wasm_ptr: Returns 1 if the value looks like a WASM linear memory pointer.
// Must be >= 0x10000 (above null page) and < current memory size.
static inline int is_wasm_ptr(uint64_t val) {
    uint32_t v = (uint32_t)val;
    return v >= 0x10000 && v < wasm_memory_size();
}

// Overflow guard: save/restore state for up to WF_MAX_ARGS args.
typedef struct {
    uint32_t addr;      // WASM address of the arg's pointed-to location
    uint32_t saved[1];  // 4 bytes saved from addr+4
    int      active;    // 1 if this slot is in use
} overflow_guard_t;

// ── wf_call implementation ──────────────────────────────────────────

uint64_t wf_call(const char* dll_name, const char* func_name, int nargs, ...) {
    uint32_t proc = wf_resolve_proc(dll_name, func_name);
    if (proc == 0) {
        last_error = 0x7F; // ERROR_PROC_NOT_FOUND
        return 0;
    }

    va_list ap;
    va_start(ap, nargs);

    uint64_t args[WF_MAX_ARGS];
    overflow_guard_t guards[WF_MAX_ARGS];
    memset(guards, 0, sizeof(guards));

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);

    // Fill remaining args with 0.
    for (int i = nargs; i < WF_MAX_ARGS; i++) {
        args[i] = 0;
    }

    // PRE-CALL: Save 4 bytes after each WASM pointer arg.
    // This protects against x64 API writes overflowing 4-byte wasm32 slots.
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (is_wasm_ptr(args[i])) {
            uint32_t addr = (uint32_t)args[i];
            // Save bytes at addr+4 (the 4 bytes that x64 would overflow into).
            // Only if addr+8 is within memory bounds.
            if (addr + 8 <= wasm_memory_size()) {
                guards[i].addr = addr;
                guards[i].saved[0] = *(uint32_t*)(uintptr_t)(addr + 4);
                guards[i].active = 1;
            }
        }
    }

    // Return values written by mod_invoke.
    uint64_t ret1_buf = 0;
    // err_buf MUST be uint64_t even though Win32 errnos are 32-bit:
    // the host's writeReturnValues writes 8 bytes to lastErrPtr via
    // PutUint64. If err_buf were uint32_t (4 bytes), the trailing 4
    // bytes would overflow into the adjacent ret1_buf, corrupting the
    // low 32 bits of any 8-byte return value (e.g. HCERTSTORE).
    // This was latent for BCrypt wrappers because they only consume
    // the low 32 bits of r0 (status code) — the handle comes via an
    // `out` param. Cert store / 8-byte-return APIs expose the bug.
    uint64_t err_buf = 0;

    // Call the host function via mod_invoke.
    uint64_t r0 = wf_mod_invoke(
        (uint64_t)proc, (uint32_t)nargs,
        args[0], args[1], args[2], args[3],
        args[4], args[5], args[6], args[7],
        args[8], args[9], args[10], args[11],
        args[12], args[13], args[14],
        (uint64_t)(uintptr_t)&ret1_buf,
        (uint64_t)(uintptr_t)&err_buf);

    // POST-CALL: Restore saved bytes to undo any overflow.
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (guards[i].active) {
            *(uint32_t*)(uintptr_t)(guards[i].addr + 4) = guards[i].saved[0];
        }
    }

    last_error = err_buf;
    // Propagate Win32 LastError to NativeAOT-WASI's Marshal.GetLastPInvokeError()
    // which reads `errno` on non-Windows runtimes. Without this, C# code paths
    // that check `Marshal.GetLastWin32Error()` after a `[DllImport(SetLastError=true)]`
    // call see 0 ("Success") even when the underlying Win32 API failed —
    // confuses BCL exception messages (Win32Exception(0)) and breaks code that
    // distinguishes ERROR_NO_MORE_ITEMS / ERROR_NOT_FOUND from real failures.
    errno = (int)err_buf;
    return r0;
}

uint64_t wf_call_handle(uint32_t proc_handle, int nargs, ...) {
    va_list ap;
    va_start(ap, nargs);

    uint64_t args[WF_MAX_ARGS];
    overflow_guard_t guards[WF_MAX_ARGS];
    memset(guards, 0, sizeof(guards));

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);

    for (int i = nargs; i < WF_MAX_ARGS; i++) {
        args[i] = 0;
    }

    // PRE-CALL overflow protection.
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (is_wasm_ptr(args[i])) {
            uint32_t addr = (uint32_t)args[i];
            if (addr + 8 <= wasm_memory_size()) {
                guards[i].addr = addr;
                guards[i].saved[0] = *(uint32_t*)(uintptr_t)(addr + 4);
                guards[i].active = 1;
            }
        }
    }

    uint64_t ret1_buf = 0;
    // err_buf MUST be uint64_t even though Win32 errnos are 32-bit:
    // the host's writeReturnValues writes 8 bytes to lastErrPtr via
    // PutUint64. If err_buf were uint32_t (4 bytes), the trailing 4
    // bytes would overflow into the adjacent ret1_buf, corrupting the
    // low 32 bits of any 8-byte return value (e.g. HCERTSTORE).
    // This was latent for BCrypt wrappers because they only consume
    // the low 32 bits of r0 (status code) — the handle comes via an
    // `out` param. Cert store / 8-byte-return APIs expose the bug.
    uint64_t err_buf = 0;

    uint64_t r0 = wf_mod_invoke(
        (uint64_t)proc_handle, (uint32_t)nargs,
        args[0], args[1], args[2], args[3],
        args[4], args[5], args[6], args[7],
        args[8], args[9], args[10], args[11],
        args[12], args[13], args[14],
        (uint64_t)(uintptr_t)&ret1_buf,
        (uint64_t)(uintptr_t)&err_buf);

    // POST-CALL restore.
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (guards[i].active) {
            *(uint32_t*)(uintptr_t)(guards[i].addr + 4) = guards[i].saved[0];
        }
    }

    last_error = err_buf;
    // Propagate Win32 LastError to NativeAOT-WASI's Marshal.GetLastPInvokeError()
    // which reads `errno` on non-Windows runtimes. Without this, C# code paths
    // that check `Marshal.GetLastWin32Error()` after a `[DllImport(SetLastError=true)]`
    // call see 0 ("Success") even when the underlying Win32 API failed —
    // confuses BCL exception messages (Win32Exception(0)) and breaks code that
    // distinguishes ERROR_NO_MORE_ITEMS / ERROR_NOT_FOUND from real failures.
    errno = (int)err_buf;
    return r0;
}

// ── wf_call_v2 / wf_call_handle_v2 — selective overflow protection ──
//
// Same as wf_call/wf_call_handle, but the caller passes an out8_mask
// bitmask of args whose pointed-to WASM slot is wider than 4 bytes
// (e.g. an `out ulong` for a BCRYPT_*_HANDLE, or a freshly-allocated
// `byte[]` output buffer). For each arg with its mask bit set, the
// 4-byte overflow protection is skipped.
//
// Rationale: the default wf_call protection saves bytes [addr+4..addr+7]
// before the call and restores them after. This is correct when the WASM
// slot is exactly 4 bytes (an `IntPtr` on wasm32) and the x64 API would
// write 8 bytes — the restore undoes the overflow into adjacent stack
// space. But when the WASM slot is 8+ bytes (a `ulong` or a wide buffer),
// the restore overwrites legitimate output: the high 32 bits of a handle,
// or bytes 4-7 of a structured blob.

uint64_t wf_call_v2(const char* dll_name, const char* func_name,
    int nargs, uint32_t out8_mask, ...) {
    uint32_t proc = wf_resolve_proc(dll_name, func_name);
    if (proc == 0) {
        last_error = 0x7F; // ERROR_PROC_NOT_FOUND
        return 0;
    }

    va_list ap;
    va_start(ap, out8_mask);

    uint64_t args[WF_MAX_ARGS];
    overflow_guard_t guards[WF_MAX_ARGS];
    memset(guards, 0, sizeof(guards));

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);

    for (int i = nargs; i < WF_MAX_ARGS; i++) {
        args[i] = 0;
    }

    // PRE-CALL: Save 4 bytes after each WASM pointer arg, EXCEPT args
    // whose bit is set in out8_mask (those slots are 8+ bytes wide).
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if ((out8_mask >> i) & 1U) continue;
        if (is_wasm_ptr(args[i])) {
            uint32_t addr = (uint32_t)args[i];
            if (addr + 8 <= wasm_memory_size()) {
                guards[i].addr = addr;
                guards[i].saved[0] = *(uint32_t*)(uintptr_t)(addr + 4);
                guards[i].active = 1;
            }
        }
    }

    uint64_t ret1_buf = 0;
    // err_buf MUST be uint64_t even though Win32 errnos are 32-bit:
    // the host's writeReturnValues writes 8 bytes to lastErrPtr via
    // PutUint64. If err_buf were uint32_t (4 bytes), the trailing 4
    // bytes would overflow into the adjacent ret1_buf, corrupting the
    // low 32 bits of any 8-byte return value (e.g. HCERTSTORE).
    // This was latent for BCrypt wrappers because they only consume
    // the low 32 bits of r0 (status code) — the handle comes via an
    // `out` param. Cert store / 8-byte-return APIs expose the bug.
    uint64_t err_buf = 0;

    uint64_t r0 = wf_mod_invoke(
        (uint64_t)proc, (uint32_t)nargs,
        args[0], args[1], args[2], args[3],
        args[4], args[5], args[6], args[7],
        args[8], args[9], args[10], args[11],
        args[12], args[13], args[14],
        (uint64_t)(uintptr_t)&ret1_buf,
        (uint64_t)(uintptr_t)&err_buf);

    // POST-CALL: Restore saved bytes. Args with mask bit set were not
    // guarded (active==0), so they are skipped here automatically.
    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (guards[i].active) {
            *(uint32_t*)(uintptr_t)(guards[i].addr + 4) = guards[i].saved[0];
        }
    }

    last_error = err_buf;
    errno = (int)err_buf;
    return r0;
}

// ── wf_call_ptr — COM vtable / arbitrary funcptr dispatch ──────────
//
// COM method dispatch needs to call a raw host function pointer (a
// vtable slot read from a mirrored COM object). We can't resolve it via
// DLL+name lookup. Instead, on first use we register the funcptr with
// the host through mod_regptr, which creates a synthetic proc handle
// with the supplied pointer mask, and cache the result. Subsequent
// calls reuse the cached handle for free.
//
// The cache is keyed by (funcptr, ptr_mask) so the same vtable slot
// invoked with different masks (e.g. for overloaded variants) doesn't
// collide.

#define MAX_FUNCPTR_CACHE 256
typedef struct {
    uint64_t funcptr;
    uint32_t ptr_mask;
    uint32_t handle;
} funcptr_cache_entry_t;
static funcptr_cache_entry_t funcptr_cache[MAX_FUNCPTR_CACHE];
static int funcptr_cache_count = 0;

static uint32_t resolve_funcptr(uint64_t funcptr, uint32_t ptr_mask) {
    for (int i = 0; i < funcptr_cache_count; i++) {
        if (funcptr_cache[i].funcptr == funcptr &&
            funcptr_cache[i].ptr_mask == ptr_mask) {
            return funcptr_cache[i].handle;
        }
    }
    uint32_t handle = wf_register_funcptr(funcptr, ptr_mask);
    if (handle == 0) return 0;
    if (funcptr_cache_count < MAX_FUNCPTR_CACHE) {
        funcptr_cache[funcptr_cache_count].funcptr  = funcptr;
        funcptr_cache[funcptr_cache_count].ptr_mask = ptr_mask;
        funcptr_cache[funcptr_cache_count].handle   = handle;
        funcptr_cache_count++;
    }
    // Cache saturation (>256 distinct funcptr/mask pairs in one session):
    // we silently re-register on every call. Host-side handle table entries
    // accumulate until module exit, which collects the entire context. No
    // OS handles are attached to handleProc entries, so this is bounded
    // memory growth within one session — acceptable for COM usage where a
    // single interface vtable has <30 methods.
    return handle;
}

uint64_t wf_call_ptr(uint64_t funcptr, int nargs,
    uint32_t ptr_mask, uint32_t out8_mask, ...) {
    uint32_t handle = resolve_funcptr(funcptr, ptr_mask);
    if (handle == 0) {
        last_error = 0x7F; // ERROR_PROC_NOT_FOUND
        return 0;
    }

    va_list ap;
    va_start(ap, out8_mask);

    uint64_t args[WF_MAX_ARGS];
    overflow_guard_t guards[WF_MAX_ARGS];
    memset(guards, 0, sizeof(guards));

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);

    for (int i = nargs; i < WF_MAX_ARGS; i++) {
        args[i] = 0;
    }

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if ((out8_mask >> i) & 1U) continue;
        if (is_wasm_ptr(args[i])) {
            uint32_t addr = (uint32_t)args[i];
            if (addr + 8 <= wasm_memory_size()) {
                guards[i].addr = addr;
                guards[i].saved[0] = *(uint32_t*)(uintptr_t)(addr + 4);
                guards[i].active = 1;
            }
        }
    }

    uint64_t ret1_buf = 0;
    // err_buf MUST be uint64_t even though Win32 errnos are 32-bit:
    // the host's writeReturnValues writes 8 bytes to lastErrPtr via
    // PutUint64. If err_buf were uint32_t (4 bytes), the trailing 4
    // bytes would overflow into the adjacent ret1_buf, corrupting the
    // low 32 bits of any 8-byte return value (e.g. HCERTSTORE).
    // This was latent for BCrypt wrappers because they only consume
    // the low 32 bits of r0 (status code) — the handle comes via an
    // `out` param. Cert store / 8-byte-return APIs expose the bug.
    uint64_t err_buf = 0;

    uint64_t r0 = wf_mod_invoke(
        (uint64_t)handle, (uint32_t)nargs,
        args[0], args[1], args[2], args[3],
        args[4], args[5], args[6], args[7],
        args[8], args[9], args[10], args[11],
        args[12], args[13], args[14],
        (uint64_t)(uintptr_t)&ret1_buf,
        (uint64_t)(uintptr_t)&err_buf);

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (guards[i].active) {
            *(uint32_t*)(uintptr_t)(guards[i].addr + 4) = guards[i].saved[0];
        }
    }

    last_error = err_buf;
    errno = (int)err_buf;
    return r0;
}

uint64_t wf_call_handle_v2(uint32_t proc_handle, int nargs,
    uint32_t out8_mask, ...) {
    va_list ap;
    va_start(ap, out8_mask);

    uint64_t args[WF_MAX_ARGS];
    overflow_guard_t guards[WF_MAX_ARGS];
    memset(guards, 0, sizeof(guards));

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        args[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);

    for (int i = nargs; i < WF_MAX_ARGS; i++) {
        args[i] = 0;
    }

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if ((out8_mask >> i) & 1U) continue;
        if (is_wasm_ptr(args[i])) {
            uint32_t addr = (uint32_t)args[i];
            if (addr + 8 <= wasm_memory_size()) {
                guards[i].addr = addr;
                guards[i].saved[0] = *(uint32_t*)(uintptr_t)(addr + 4);
                guards[i].active = 1;
            }
        }
    }

    uint64_t ret1_buf = 0;
    // err_buf MUST be uint64_t even though Win32 errnos are 32-bit:
    // the host's writeReturnValues writes 8 bytes to lastErrPtr via
    // PutUint64. If err_buf were uint32_t (4 bytes), the trailing 4
    // bytes would overflow into the adjacent ret1_buf, corrupting the
    // low 32 bits of any 8-byte return value (e.g. HCERTSTORE).
    // This was latent for BCrypt wrappers because they only consume
    // the low 32 bits of r0 (status code) — the handle comes via an
    // `out` param. Cert store / 8-byte-return APIs expose the bug.
    uint64_t err_buf = 0;

    uint64_t r0 = wf_mod_invoke(
        (uint64_t)proc_handle, (uint32_t)nargs,
        args[0], args[1], args[2], args[3],
        args[4], args[5], args[6], args[7],
        args[8], args[9], args[10], args[11],
        args[12], args[13], args[14],
        (uint64_t)(uintptr_t)&ret1_buf,
        (uint64_t)(uintptr_t)&err_buf);

    for (int i = 0; i < nargs && i < WF_MAX_ARGS; i++) {
        if (guards[i].active) {
            *(uint32_t*)(uintptr_t)(guards[i].addr + 4) = guards[i].saved[0];
        }
    }

    last_error = err_buf;
    errno = (int)err_buf;
    return r0;
}
