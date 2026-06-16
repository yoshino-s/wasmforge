# Lazy PInvoke + Crypt32 Probe Harness

Probes Win32 P/Invokes used by Certify forge / SharpDPAPI master-key
decode / Rubeus crypto to identify:
1. Symbols that throw "Lazy PInvoke resolution is not supported when
   targeting WebAssembly" — these need WF_KEEP marker in the bridge
   AND a corresponding `<DirectPInvoke>` entry in the consumer's csproj.
2. Symbols that crash on call — bridge wrapper missing or arg shape wrong.

## Triage finding (2026-06-03)

```
OK         ntdll.dll!NtQuerySystemTime
Exception 0xc0000005 0x1 0x0 ...  ← CryptEncodeObjectEx
```

NtQuerySystemTime resolves cleanly. The CryptEncodeObjectEx call AVs
writing to NULL — bridge wrapper exists (so it's not Lazy PInvoke) but
arg marshaling is broken. Probably the `ref uint pcbEncoded` output
parameter isn't being honoured by wf_call's translation; Crypt32 writes
to NULL because the host-translated address is 0.

This is the EXACT same class of bug the LSA harness caught (wf_call_v2 +
out8_mask needed for output pointer slots). Forge's chain probably
involves several Crypt32 / NCrypt calls — each needs the same fix.

## Build
Same pattern as crypto-harness/.
