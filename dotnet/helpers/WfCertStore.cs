// WfCertStore.cs — Local certificate store enumeration via crypt32.
// Drives the Certify manageself verb: enumerates the current user's MY
// store and prints subject names of certificates found.
//
// Avoids the wasm32/x64 CERT_CONTEXT struct layout problem by never
// dereferencing CERT_CONTEXT in managed code — instead it asks the API
// for the simple display name (a string) via CertGetNameStringW.
//
// Returns 0 on success, 1 if the store can't be opened. Counts
// certificates found and prints each subject name as a single line.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfCertStore
    {
        // 8-byte-return crypt32 wrappers. These are defined in
        // dotnet/bridge/pinvoke_nativeaot.c alongside BCrypt wrappers and
        // paired with pointer masks in semanticOverrides so the host
        // doesn't translate HCERTSTORE/PCCERT_CONTEXT (real host addrs)
        // as if they were WASM offsets.
        [DllImport("crypt32.dll", EntryPoint = "WfCertStore_OpenSystemStoreW")]
        private static extern uint WfOpenSystemStoreW(uint hProv, IntPtr lpszStoreName, out ulong phStoreOut);

        [DllImport("crypt32.dll", EntryPoint = "WfCertStore_EnumCertificatesInStore")]
        private static extern uint WfEnumCertificatesInStore(ulong hCertStore, ulong pPrevCertContext, out ulong pCertOut);

        [DllImport("crypt32.dll", EntryPoint = "WfCertStore_GetNameStringW")]
        private static extern uint WfGetNameStringW(ulong pCertContext, uint dwType, uint dwFlags,
            IntPtr pvTypePara, IntPtr pszNameString, uint cchNameString);

        [DllImport("crypt32.dll", EntryPoint = "WfCertStore_CloseStore")]
        private static extern uint WfCloseStore(ulong hCertStore, uint dwFlags);

        // CERT_NAME_* constants for CertGetNameStringW dwType.
        private const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
        private const uint CERT_NAME_ISSUER_FLAG         = 0x1;

        public static int ManageSelf()
        {
            Console.WriteLine();
            Console.WriteLine("[+] Listing personal certificates from CurrentUser\\MY:");
            Console.WriteLine();

            IntPtr storeName = Marshal.StringToHGlobalUni("MY");
            ulong hStore = 0;
            uint openStatus;
            try
            {
                openStatus = WfOpenSystemStoreW(0, storeName, out hStore);
            }
            finally
            {
                Marshal.FreeHGlobal(storeName);
            }
            if (openStatus != 0 || hStore == 0)
            {
                Console.WriteLine("[!] CertOpenSystemStoreW failed (status=0x{0:X}).", openStatus);
                return 1;
            }

            int count = 0;
            try
            {
                ulong pCert = 0;
                while (true)
                {
                    ulong nextCert = 0;
                    uint enumStatus = WfEnumCertificatesInStore(hStore, pCert, out nextCert);
                    if (enumStatus != 0 || nextCert == 0) break;
                    pCert = nextCert;
                    count++;

                    // Subject simple display name (max 256 chars).
                    string subject = GetNameString(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
                    // Issuer simple display name (CERT_NAME_ISSUER_FLAG).
                    string issuer = GetNameString(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);

                    Console.WriteLine("  [{0}] Subject:  {1}", count, subject);
                    Console.WriteLine("      Issuer:   {1}", count, issuer);
                    Console.WriteLine();
                }
            }
            finally
            {
                WfCloseStore(hStore, 0);
            }

            Console.WriteLine("[+] Found {0} certificate(s).", count);
            return 0;
        }

        private static string GetNameString(ulong pCert, uint type, uint flags)
        {
            char[] buf = new char[256];
            fixed (char* pBuf = buf)
            {
                uint n = WfGetNameStringW(pCert, type, flags, IntPtr.Zero,
                    (IntPtr)pBuf, (uint)buf.Length);
                if (n == 0) return "(none)";
                // Returned count includes the null terminator.
                int len = (int)n - 1;
                if (len < 0) len = 0;
                return new string(buf, 0, len);
            }
        }
    }
}
