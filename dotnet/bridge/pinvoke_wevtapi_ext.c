// pinvoke_wevtapi_ext.c — wevtapi.dll P/Invoke bridge for NativeAOT-WASI.
// Forwards EvtQuery / EvtNext / EvtRender / EvtClose to wf_call.
//
// EVT_HANDLE is 8 bytes on x64 — these stubs return uint64_t (not
// uint32_t) so the high 32 bits of the handle survive the bridge.
// The C# DllImport declarations on the helper side declare `long`
// (mapped to wasi-wasm i64) instead of `IntPtr` (i32 on wasm32) to
// match.
//
// All Evt* exports are picked up by EmitDirectPInvokeProps which scans
// the helper's [DllImport("wevtapi.dll", ...)] attributes — no patcher
// rule required to wire the csproj.

#include "wf_bridge.h"

// EVT_HANDLE EvtQuery(EVT_HANDLE Session, LPCWSTR Path, LPCWSTR Query, DWORD Flags);
// Returns the 8-byte result-set handle. Session is normally NULL (0).
uint64_t EvtQuery(uint64_t Session, uint32_t Path, uint32_t Query, uint32_t Flags) {
    return wf_call("wevtapi.dll", "EvtQuery", 4,
        (uint64_t)Session, (uint64_t)Path, (uint64_t)Query, (uint64_t)Flags);
}

// BOOL EvtNext(EVT_HANDLE ResultSet, DWORD EventsSize, EVT_HANDLE* Events,
//              DWORD Timeout, DWORD Flags, DWORD* Returned);
// Events is array of EVT_HANDLE (8 bytes each on x64). The C# helper
// passes an 8-byte buffer via Marshal.AllocHGlobal(8); out8_mask bit 2
// skips the 4-byte overflow protection so the host can write all 8 bytes.
// Returns BOOL (1=success, 0=failure).
uint32_t EvtNext(uint64_t ResultSet, uint32_t EventsSize, uint32_t Events,
                 uint32_t Timeout, uint32_t Flags, uint32_t Returned) {
    return (uint32_t)wf_call_v2("wevtapi.dll", "EvtNext", 6,
        /*out8_mask*/ (1u<<2),
        (uint64_t)ResultSet, (uint64_t)EventsSize, (uint64_t)Events,
        (uint64_t)Timeout, (uint64_t)Flags, (uint64_t)Returned);
}

// BOOL EvtRender(EVT_HANDLE Context, EVT_HANDLE Fragment, DWORD Flags,
//                DWORD BufferSize, void* Buffer,
//                DWORD* BufferUsed, DWORD* PropertyCount);
// Context can be NULL (0). Fragment is the per-event handle.
// Buffer is a caller-allocated WASM byte buffer >= BufferSize bytes —
// use wf_call_v2 with out8_mask bit 4 set so the overflow guard does
// NOT save+restore bytes 4-7 of the buffer (otherwise EvtRender's
// rendered XML would be corrupted at chars 2-3).
uint32_t EvtRender(uint64_t Context, uint64_t Fragment, uint32_t Flags,
                   uint32_t BufferSize, uint32_t Buffer,
                   uint32_t BufferUsed, uint32_t PropertyCount) {
    return (uint32_t)wf_call_v2("wevtapi.dll", "EvtRender", 7,
        /*out8_mask*/ (1u<<4),  // Buffer is data output > 4 bytes
        (uint64_t)Context, (uint64_t)Fragment, (uint64_t)Flags,
        (uint64_t)BufferSize, (uint64_t)Buffer,
        (uint64_t)BufferUsed, (uint64_t)PropertyCount);
}

// BOOL EvtClose(EVT_HANDLE Object);
uint32_t EvtClose(uint64_t Object) {
    return (uint32_t)wf_call("wevtapi.dll", "EvtClose", 1, (uint64_t)Object);
}
