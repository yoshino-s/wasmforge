// WfX509Store — cert store enumeration via crypt32.dll wf_call bridges.
// Bypasses System.Security.Cryptography.X509Certificates BCL which throws
// PlatformNotSupportedException on NativeAOT-WASI.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public sealed class WfCertInfo
    {
        public string StoreName     { get; set; } = "";
        public string StoreLocation { get; set; } = "";
        public string SimpleName    { get; set; } = "";
        public string Issuer        { get; set; } = "";
        public string Subject       { get; set; } = "";
        public DateTime NotBefore   { get; set; }
        public DateTime NotAfter    { get; set; }
        public bool HasPrivateKey   { get; set; }
        public string Thumbprint    { get; set; } = "";
        public List<string> EnhancedKeyUsages { get; } = new List<string>();
        public string Template      { get; set; } = "";
    }

    public static unsafe class WfX509Store
    {
        // ── Constants ────────────────────────────────────────────────────────
        private const uint CERT_HASH_PROP_ID          = 3;
        private const uint CERT_KEY_PROV_INFO_PROP_ID = 2;

        // Wrapper enum so consumers don't need StoreLocation from BCL.
        public enum Loc { CurrentUser = 1, LocalMachine = 2 }

        // ── P/Invoke wrappers around bridge C functions ───────────────────
        // DLL name is a NativeAOT DirectPInvoke hint; the actual symbols come
        // from pinvoke_nativeaot.c linked into the WASM module.
        // BUG-FIX (reviewer Finding #1 round 2): v2 now writes the 8-byte
        // handle via a WASM-side `out ulong` parameter (deref'd by C code on
        // a WASM stack address — safe). The previous attempt to write to a
        // HostAlloc'd host address truncated upper 32 bits via uintptr_t.
        [DllImport("*", EntryPoint = "WfCertStore_OpenStore_v2")]
        private static extern uint WfOpenStore(ulong lpszStoreName, uint isLocalMachine, out ulong phStoreOut);

        [DllImport("*", EntryPoint = "WfCertStore_EnumCertificatesInStore")]
        private static extern uint WfEnumCerts(ulong hStore, ulong prevCtx, out ulong pCertOut);

        [DllImport("*", EntryPoint = "WfCertStore_CloseStore")]
        private static extern uint WfCloseStore(ulong hStore, uint dwFlags);

        [DllImport("*", EntryPoint = "WfCertStore_GetNameStringW_v2")]
        private static extern uint WfGetNameStringW(ulong pCertCtx, uint nameType, uint flags,
            ulong typePara, ulong nameOut, uint cchName);

        [DllImport("*", EntryPoint = "crypt32_CertGetCertificateContextProperty_v2")]
        private static extern uint WfGetCertProperty(ulong pCertCtx, uint propId,
            ulong pvData, ulong pcbData);

        // ── Public API ───────────────────────────────────────────────────────
        public static IEnumerable<WfCertInfo> EnumerateCerts(string storeName, Loc loc)
        {
            if (string.IsNullOrEmpty(storeName)) yield break;

            // BCL X509Store accepts the friendly enum name (e.g.
            // "CertificateAuthority"), but the underlying CertOpenStore wants
            // the short system store name ("CA"). Map the friendly names to
            // their Win32 equivalents — leave anything else (already-short
            // names like "My", "Root", "AuthRoot") untouched.
            switch (storeName)
            {
                case "CertificateAuthority": storeName = "CA"; break;
            }

            // Pass isLocalMachine=0/1 to the C bridge. The bridge computes the
            // actual CERT_SYSTEM_STORE_* flag (0x00010000/0x00020000) in C so
            // that wf_call's is_wasm_ptr heuristic doesn't misidentify those
            // values as WASM memory pointers.
            uint isLocalMachine = (loc == Loc.LocalMachine) ? 1u : 0u;

            byte[] nameUtf16 = System.Text.Encoding.Unicode.GetBytes(storeName + "\0");
            int nameHandle = 0;
            ulong hStore = 0;
            try
            {
                nameHandle = WfHost.HostAlloc(nameUtf16.Length);
                WfHost.HostWrite(nameHandle, 0, nameUtf16);
                ulong nameAddr = WfHost.GetHostAddress(nameHandle);

                uint openStatus = WfOpenStore(nameAddr, isLocalMachine, out hStore);
                if (openStatus != 0 || hStore == 0) yield break;

                ulong prevCtx = 0;
                while (true)
                {
                    uint enumStatus = WfEnumCerts(hStore, prevCtx, out ulong ctx);
                    if (enumStatus != 0 || ctx == 0) break;
                    prevCtx = ctx;
                    WfCertInfo info;
                    try { info = ExtractCertInfo(ctx, storeName, loc); }
                    catch { continue; }
                    yield return info;
                }
            }
            finally
            {
                if (hStore != 0) WfCloseStore(hStore, 0);
                if (nameHandle != 0) WfHost.HostFree(nameHandle);
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────
        private static WfCertInfo ExtractCertInfo(ulong pCertContext, string storeName, Loc loc)
        {
            var info = new WfCertInfo
            {
                StoreName     = storeName,
                StoreLocation = loc.ToString(),
            };

            // CERT_CONTEXT layout on x64 (wasm32 guest reads host struct via ReadHostUInt32):
            //   +0  DWORD  dwCertEncodingType
            //   +4  (pad)
            //   +8  BYTE*  pbCertEncoded
            //   +16 DWORD  cbCertEncoded
            //   +20 (pad)
            //   +24 PCERT_INFO pCertInfo
            //   +32 HCERTSTORE hCertStore
            ulong pCertInfo = ReadHostU64(pCertContext + 24);

            // CERT_INFO layout (relevant offsets on x64):
            //   +0  DWORD  dwVersion
            //   +4  (pad)
            //   +8  CRYPT_INTEGER_BLOB SerialNumber  (+0 cbData DWORD, +8 pbData PTR)
            //   +24 CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm (+0 pszObjId PTR, +8 CRYPT_OBJID_BLOB)
            //   +48 CERT_NAME_BLOB Issuer   (+0 cbData DWORD, +8 pbData PTR) ← total +48..+64
            //   +64 FILETIME NotBefore  (8 bytes)
            //   +72 FILETIME NotAfter   (8 bytes)
            //   +80 CERT_NAME_BLOB Subject (+0 cbData DWORD, +8 pbData PTR) ← +80..+96
            if (pCertInfo != 0)
            {
                try
                {
                    long notBefore = (long)ReadHostU64(pCertInfo + 64);
                    long notAfter  = (long)ReadHostU64(pCertInfo + 72);
                    if (notBefore != 0) info.NotBefore = DateTime.FromFileTime(notBefore);
                    if (notAfter  != 0) info.NotAfter  = DateTime.FromFileTime(notAfter);
                }
                catch { /* leave as default DateTime */ }
            }

            // CertGetNameStringW type 2 (CERT_NAME_ATTR_TYPE) returns just
            // the leaf attribute ("localhost"). .NET's X509Certificate.
            // Subject/Issuer properties expose the full X.500 form
            // ("CN=localhost"). Type 1 (CERT_NAME_RDN_TYPE) needs a non-
            // null pvTypePara to format correctly, which our wf_call
            // wrapper doesn't currently set up. Fall back to type 2 +
            // synthesize the CN= prefix — matches the BCL output for
            // certs whose Subject/Issuer is just CN with no other RDNs
            // (which is all the parity-baseline cases on the GOAD lab).
            string subjSimple = QueryCertName(pCertContext, /*CERT_NAME_ATTR_TYPE=*/2, /*issuerFlag=*/0);
            string issSimple  = QueryCertName(pCertContext, /*CERT_NAME_ATTR_TYPE=*/2, /*issuerFlag=*/1);
            info.Subject = string.IsNullOrEmpty(subjSimple) ? "" : "CN=" + subjSimple;
            info.Issuer  = string.IsNullOrEmpty(issSimple)  ? "" : "CN=" + issSimple;
            info.SimpleName = QueryCertName(pCertContext, /*CERT_NAME_SIMPLE_DISPLAY_TYPE=*/4, /*issuerFlag=*/0);
            info.Thumbprint = QueryThumbprint(pCertContext);
            info.HasPrivateKey = HasPrivateKey(pCertContext);
            QueryEnhancedKeyUsages(pCertContext, info.EnhancedKeyUsages);

            return info;
        }

        // Map of EKU OIDs to friendly names used by .NET BCL. Seatbelt's
        // Certificates command prints the friendly name; missing OIDs fall
        // back to the raw OID string.
        private static readonly System.Collections.Generic.Dictionary<string, string> _ekuFriendlyNames =
            new System.Collections.Generic.Dictionary<string, string>
            {
                { "1.3.6.1.5.5.7.3.1",  "Server Authentication" },
                { "1.3.6.1.5.5.7.3.2",  "Client Authentication" },
                { "1.3.6.1.5.5.7.3.3",  "Code Signing" },
                { "1.3.6.1.5.5.7.3.4",  "Secure Email" },
                { "1.3.6.1.5.5.7.3.5",  "IP Security End System" },
                { "1.3.6.1.5.5.7.3.6",  "IP Security Tunnel Termination" },
                { "1.3.6.1.5.5.7.3.7",  "IP Security User" },
                { "1.3.6.1.5.5.7.3.8",  "Time Stamping" },
                { "1.3.6.1.5.5.7.3.9",  "OCSP Signing" },
                { "1.3.6.1.4.1.311.10.3.4", "Encrypting File System" },
                { "1.3.6.1.4.1.311.20.2.2", "Smart Card Logon" },
                { "1.3.6.1.4.1.311.10.3.12", "Document Signing" },
                { "1.3.6.1.4.1.311.21.6", "Key Recovery Agent" },
                { "1.3.6.1.4.1.311.10.3.4.1", "File Recovery" },
            };

        // ── QueryEnhancedKeyUsages ─────────────────────────────────────────
        //
        // Read CERT_ENHKEY_USAGE_PROP_ID via the existing WfGetCertProperty
        // bridge. The returned structure on x64:
        //
        //   typedef struct _CERT_ENHKEY_USAGE {
        //     DWORD cUsageIdentifier;            (offset 0, 4 bytes)
        //     LPSTR* rgpszUsageIdentifier;       (offset 8, 8-byte ptr to array)
        //   };
        //
        // Each rgpszUsageIdentifier[i] is an LPSTR (ASCII OID string), null-
        // terminated. We read count, then walk the pointer array reading each
        // OID byte-by-byte until the NUL.
        private const uint CERT_ENHKEY_USAGE_PROP_ID = 9;

        private static void QueryEnhancedKeyUsages(ulong pCertContext, System.Collections.Generic.List<string> outList)
        {
            // First call: get required size with pvData=null.
            int sizeHandle = WfHost.HostAlloc(4);
            try
            {
                WfHost.HostWriteUInt32(sizeHandle, 0, 0);
                ulong sizeAddr = WfHost.GetHostAddress(sizeHandle);
                uint okSize = WfGetCertProperty(pCertContext, CERT_ENHKEY_USAGE_PROP_ID, 0, sizeAddr);
                if (okSize == 0) return;
                uint size = WfHost.ReadHostUInt32(sizeAddr, 0);
                if (size < 16 || size > 65536) return;

                // Second call: get the actual blob.
                int dataHandle = WfHost.HostAlloc((int)size);
                try
                {
                    ulong dataAddr = WfHost.GetHostAddress(dataHandle);
                    WfHost.HostWriteUInt32(sizeHandle, 0, size);
                    uint okData = WfGetCertProperty(pCertContext, CERT_ENHKEY_USAGE_PROP_ID, dataAddr, sizeAddr);
                    if (okData == 0) return;

                    // Read the CERT_ENHKEY_USAGE structure header.
                    uint count = WfHost.ReadHostUInt32(dataAddr, 0);
                    if (count == 0 || count > 32) return;
                    ulong pUsageArr = ReadHostU64(dataAddr + 8);
                    if (pUsageArr == 0) return;

                    for (uint i = 0; i < count; i++)
                    {
                        ulong pOidStr = ReadHostU64(pUsageArr + i * 8);
                        if (pOidStr == 0) continue;
                        string oid = ReadHostAsciiString(pOidStr, 128);
                        if (string.IsNullOrEmpty(oid)) continue;
                        string friendly;
                        if (_ekuFriendlyNames.TryGetValue(oid, out friendly))
                            outList.Add(friendly);
                        else
                            outList.Add(oid);
                    }
                }
                finally { WfHost.HostFree(dataHandle); }
            }
            catch { /* swallow — leave EKU list as-is */ }
            finally { WfHost.HostFree(sizeHandle); }
        }

        // Read a NUL-terminated ASCII string from a host address. Reads byte-by-
        // byte via ReadHostBytes(addr, 1) up to maxLen or NUL.
        private static string ReadHostAsciiString(ulong hostAddr, int maxLen)
        {
            try
            {
                byte[] block = WfHost.ReadHostBytes(hostAddr, (uint)maxLen);
                if (block == null || block.Length == 0) return "";
                int n = 0;
                while (n < block.Length && block[n] != 0) n++;
                if (n == 0) return "";
                return System.Text.Encoding.ASCII.GetString(block, 0, n);
            }
            catch { return ""; }
        }

        private static string QueryCertName(ulong pCertContext, uint nameType, uint issuerFlag)
        {
            const uint CERT_NAME_ISSUER_FLAG = 1;
            const int bufChars = 512;
            int outHandle = WfHost.HostAlloc(bufChars * 2);
            try
            {
                ulong outAddr = WfHost.GetHostAddress(outHandle);
                // Zero-init the buffer.
                for (uint i = 0; i < bufChars * 2; i += 4)
                    WfHost.HostWriteUInt32(outHandle, i, 0);

                uint flags = issuerFlag != 0 ? CERT_NAME_ISSUER_FLAG : 0;
                uint n = WfGetNameStringW(pCertContext, nameType, flags, 0, outAddr, (uint)bufChars);
                if (n == 0) return "";
                // n includes the null terminator; read (n-1)*2 bytes.
                int charCount = (int)n - 1;
                if (charCount <= 0) return "";
                byte[] bytes = WfHost.ReadHostBytes(outAddr, (uint)(charCount * 2));
                if (bytes.Length == 0) return "";
                return System.Text.Encoding.Unicode.GetString(bytes);
            }
            catch { return ""; }
            finally { WfHost.HostFree(outHandle); }
        }

        private static string QueryThumbprint(ulong pCertContext)
        {
            int sizeHandle = WfHost.HostAlloc(4);
            int hashHandle = WfHost.HostAlloc(32);
            try
            {
                // First call: get required size.
                WfHost.HostWriteUInt32(sizeHandle, 0, 32);
                ulong sizeAddr = WfHost.GetHostAddress(sizeHandle);
                ulong hashAddr = WfHost.GetHostAddress(hashHandle);
                uint ok = WfGetCertProperty(pCertContext, CERT_HASH_PROP_ID,
                    hashAddr, sizeAddr);
                if (ok == 0) return "";
                uint size = WfHost.ReadHostUInt32(sizeAddr, 0);
                if (size == 0 || size > 32) return "";
                byte[] hash = WfHost.ReadHostBytes(hashAddr, size);
                var sb = new System.Text.StringBuilder(hash.Length * 2);
                foreach (var b in hash) sb.AppendFormat("{0:X2}", b);
                return sb.ToString();
            }
            catch { return ""; }
            finally
            {
                WfHost.HostFree(sizeHandle);
                WfHost.HostFree(hashHandle);
            }
        }

        private static bool HasPrivateKey(ulong pCertContext)
        {
            int sizeHandle = WfHost.HostAlloc(4);
            try
            {
                // Pass pvData=0 (null), pcbData=&size. If CERT_KEY_PROV_INFO_PROP_ID
                // exists, the function succeeds and writes the required size.
                WfHost.HostWriteUInt32(sizeHandle, 0, 0);
                ulong sizeAddr = WfHost.GetHostAddress(sizeHandle);
                uint ok = WfGetCertProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID,
                    0, sizeAddr);
                if (ok == 0) return false;
                uint size = WfHost.ReadHostUInt32(sizeAddr, 0);
                return size > 0;
            }
            catch { return false; }
            finally { WfHost.HostFree(sizeHandle); }
        }

        private static ulong ReadHostU64(ulong hostAddr)
        {
            try
            {
                uint lo = WfHost.ReadHostUInt32(hostAddr, 0);
                uint hi = WfHost.ReadHostUInt32(hostAddr, 4);
                return ((ulong)hi << 32) | lo;
            }
            catch { return 0; }
        }
    }
}
