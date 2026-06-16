# LSA Bridge Test Harness

Mirrors crypto-harness/ — minimal NativeAOT-WASI C# program that exercises
the Wf LSA wrappers. Use this to triage Seatbelt's UserRightAssignments
gap (LSA enumeration returning empty) without rebuilding Seatbelt.

## What it found

Two bridge bugs (fixed in this commit):

1. **`advapi32_LsaOpenPolicy` missing explicit uint64_t casts on varargs.**
   `wf_call_v2` reads via `va_arg(ap, uint64_t)`. uintptr_t is 4 bytes on
   wasm32 — without casts, va_arg reads 8 bytes from a 4-byte slot, pulling
   garbage into the high half of each arg. Symptom: 0xC0000005 read at
   0xFFFFFFFFFFFFFFFF deep inside advapi32.

2. **`LsaEnumerateAccountsWithUserRight` using `wf_call` instead of
   `wf_call_v2`** with out8_mask=0x4 (arg 2 = EnumerationBuffer is 8-byte
   host pointer output slot — without out8_mask the 4-byte overflow-restore
   zeros bytes 4-7 of the host pointer).

## What it still doesn't solve

LSA_UNICODE_STRING contains a nested Buffer pointer at offset 8 — a host
pointer to the actual UTF-16 string. wf_call's pointer translation only
handles TOP-LEVEL args; it doesn't know about pointers embedded inside
struct args. The next layer of fix needs a Wf-level helper that copies
the UTF-16 string into host memory (via WfHost.HostAlloc) and sets
Buffer to the real host address.

## Build

Same pattern as crypto-harness/README.md.
