// WfSec.cs — WasmForge security helper: SDDL retrieval for files and services.
//
// Provides thin wrappers over sec_sddl_typed (pinvoke_env_ext.c) that route
// GetNamedSecurityInfoW calls through the bridge with the correct SE_OBJECT_TYPE.
//
// SE_FILE_OBJECT    = 1 — for binary path SDDL (ServicesCommand.TryGetBinaryPathSddl)
// SE_SERVICE_OBJECT = 5 — for service name SDDL (ServicesCommand.TryGetServiceSddl)

using System;
using System.Text;
using WasmForge.Bridge;

namespace WasmForge.Helpers
{
    // Preserve through NativeAOT trim. Without this, even though
    // LsaWrapper.ResolveAccountName calls WfSec.SidToAccountName via the
    // patcher rule, the trim analysis decides the call chain isn't
    // statically reachable (likely because the DllImports declare a
    // contract the linker can't fully resolve) and removes the entire
    // class. The annotation forces all members to be kept.
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
        System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public static unsafe class WfSec
    {
        public static string GetServiceSddl(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName)) return "";
            return GetSddlInternal(serviceName, /*SE_SERVICE_OBJECT=*/5);
        }

        public static string GetFileSddl(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            return GetSddlInternal(path, /*SE_FILE_OBJECT=*/1);
        }

        private static string GetSddlInternal(string name, uint objectType)
        {
            byte[] nameUtf8 = Encoding.UTF8.GetBytes(name + "\0");
            byte[] outBuf = new byte[1024];
            fixed (byte* npp = nameUtf8)
            fixed (byte* op = outBuf)
            {
                uint n = WfHostBridge.GetPathSddlTyped(npp, objectType, op, (uint)outBuf.Length);
                if (n == 0) return "";
                return Encoding.UTF8.GetString(outBuf, 0, (int)n);
            }
        }

        // ── Direct P/Invokes to advapi32 (resolved by the build to our C
        //    bridge functions in dotnet/bridge/pinvoke_nativeaot.c which
        //    route through wf_call_v2 with the correct out8_mask).
        // Use `long` (8 bytes) for the PSID out param even though it's
        // semantically a pointer. NativeAOT-WASI is wasm32 (4-byte IntPtr)
        // but the host x64 Win32 API writes 8 bytes to the out slot; using
        // IntPtr would let the 4 extra bytes overflow into adjacent stack
        // and corrupt locals. The 8-byte slot just receives the full host
        // pointer value which we then pass back through LookupAccountSidW
        // as-is (it's never dereferenced from WASM).
        // ── Direct P/Invokes to bridge functions in pinvoke_nativeaot.c ───
        // ConvertStringSidToSidW + LookupAccountSidW_8 live in the always-
        // included NativeLibrary so the linker reliably finds these symbols.
        // The _8 variant uses uint64_t for the PSID so the full host pointer
        // returned by ConvertStringSidToSidW survives the wasm32 boundary.
        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "ConvertStringSidToSidW", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int ConvertStringSidToSidW(
            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string StringSid,
            out long Sid);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "LookupAccountSidW_8", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int LookupAccountSidW_8(
            long Sid,
            byte[] Name,
            ref uint cchName,
            byte[] ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);

        // ── SidToAccountName ──────────────────────────────────────────────
        //
        // Resolves an SDDL-form SID ("S-1-5-21-...") to "DOMAIN\\user" via
        // ConvertStringSidToSidW + LookupAccountSidW_8. Returns "" on failure.
        // Drop-in for SecurityIdentifier.Translate(typeof(NTAccount)).Value
        // which throws PNS on NativeAOT-WASI. The PSID is passed as long
        // (8 bytes) so the full host pointer survives the wasm32 ABI; the
        // bridge wrapper LookupAccountSidW_8 reciprocates with uint64_t.
        public static string SidToAccountName(string sddlSid)
        {
            if (string.IsNullOrEmpty(sddlSid)) return "";
            try
            {
                long pSid;
                if (ConvertStringSidToSidW(sddlSid, out pSid) == 0 || pSid == 0)
                    return "";
                var nameBuf   = new byte[512];
                var domainBuf = new byte[512];
                uint cchName = 256, cchDomain = 256;
                int sidUse;
                if (LookupAccountSidW_8(pSid, nameBuf, ref cchName, domainBuf, ref cchDomain, out sidUse) == 0)
                    return "";
                string u = (cchName   > 0 && cchName   <= 255) ? System.Text.Encoding.Unicode.GetString(nameBuf,   0, (int)cchName   * 2) : "";
                string d = (cchDomain > 0 && cchDomain <= 255) ? System.Text.Encoding.Unicode.GetString(domainBuf, 0, (int)cchDomain * 2) : "";
                if (string.IsNullOrEmpty(u) && string.IsNullOrEmpty(d)) return "";
                if (string.IsNullOrEmpty(d)) return u;
                if (string.IsNullOrEmpty(u)) return d;
                return d + "\\" + u;
            }
            catch
            {
                return "";
            }
        }
    }
}
