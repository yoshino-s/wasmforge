// pinvoke_winspool_ext.c — winspool.drv P/Invoke bridge for NativeAOT-WASI.
// Forwards EnumPrintersW to wf_call.
//
// Seatbelt's PrintersCommand was disabled via patcher rule
// ("Printers: disable (winspool bridge crash)") because the BCL
// DllImport path crashed during struct marshaling. With this bridge
// providing a typed wf_call entry, the patcher rule is removed in
// Task 5.2 and the C# EnumPrinters chain works against winspool.drv.
//
// The BCL P/Invoke is "EnumPrinters" (no W) — DllImport convention
// is unset CharSet→ANSI by default, but Seatbelt uses Unicode strings.
// We dispatch to "EnumPrintersW" on the host regardless.

#include "wf_bridge.h"

// BOOL EnumPrintersW(DWORD Flags, LPWSTR Name, DWORD Level,
//                    LPBYTE pPrinterEnum, DWORD cbBuf,
//                    LPDWORD pcbNeeded, LPDWORD pcReturned);
// pPrinterEnum is an output buffer (caller-allocated, cbBuf-sized) —
// 4-byte overflow protection is fine because the host writes contiguous
// PRINTER_INFO_* records that the caller's WASM-side buffer accommodates.
uint32_t EnumPrinters(uint32_t Flags, uint32_t Name, uint32_t Level,
                      uint32_t pPrinterEnum, uint32_t cbBuf,
                      uint32_t pcbNeeded, uint32_t pcReturned) {
    return (uint32_t)wf_call("winspool.drv", "EnumPrintersW", 7,
        (uint64_t)Flags, (uint64_t)Name, (uint64_t)Level,
        (uint64_t)pPrinterEnum, (uint64_t)cbBuf,
        (uint64_t)pcbNeeded, (uint64_t)pcReturned);
}
