// LazyPInvokeTest — probe Win32 DllImports used by Certify forge / SharpDPAPI /
// Rubeus to identify which trigger "Lazy PInvoke resolution is not supported".
//
// Each probe is wrapped in try/catch; the test reports OK / LazyPInvoke / Other
// for each DllImport so we can see which need WF_KEEP / bridge wrappers.

using System;
using System.Runtime.InteropServices;

namespace LazyPInvokeTest
{
    internal static unsafe class Probe
    {
        // ntdll
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemTime(out ulong systemTime);

        // crypt32 (forge cert encoding)
        [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptEncodeObjectEx(
            uint dwCertEncodingType,
            IntPtr lpszStructType,
            IntPtr pvStructInfo,
            uint dwFlags,
            IntPtr pEncodePara,
            IntPtr pvEncoded,
            ref uint pcbEncoded);

        // advapi32 — context for keys
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptAcquireContextW(
            ref ulong phProv,
            IntPtr pszContainer,
            IntPtr pszProvider,
            uint dwProvType,
            uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptReleaseContext(ulong hProv, uint dwFlags);

        // crypt32 — cert open
        [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CertOpenSystemStoreW(IntPtr hProv, IntPtr storeName);

        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        // ncrypt — modern crypto
        [DllImport("ncrypt.dll")]
        public static extern int NCryptOpenStorageProvider(
            out ulong phProvider, IntPtr pszProviderName, uint dwFlags);
    }

    internal static class Program
    {
        static int _ok = 0, _lazy = 0, _other = 0;

        static void Try(string name, Action action)
        {
            try
            {
                action();
                _ok++;
                Console.WriteLine($"OK         {name}");
            }
            catch (NotSupportedException ex) when (ex.Message.Contains("Lazy PInvoke"))
            {
                _lazy++;
                Console.WriteLine($"LazyPInvk  {name}");
            }
            catch (Exception ex)
            {
                _other++;
                Console.WriteLine($"Error      {name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        static unsafe int Main()
        {
            Console.WriteLine("=== Lazy PInvoke Triage ===");

            Try("ntdll.dll!NtQuerySystemTime", () => { ulong t; Probe.NtQuerySystemTime(out t); });

            Try("crypt32.dll!CryptEncodeObjectEx", () =>
            {
                uint sz = 0;
                Probe.CryptEncodeObjectEx(0, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, ref sz);
            });

            Try("advapi32.dll!CryptAcquireContextW", () =>
            {
                ulong h = 0;
                Probe.CryptAcquireContextW(ref h, IntPtr.Zero, IntPtr.Zero, 1, 0);
            });

            Try("advapi32.dll!CryptReleaseContext", () => Probe.CryptReleaseContext(0, 0));

            Try("crypt32.dll!CertOpenSystemStoreW", () => Probe.CertOpenSystemStoreW(IntPtr.Zero, IntPtr.Zero));

            Try("crypt32.dll!CertCloseStore", () => Probe.CertCloseStore(IntPtr.Zero, 0));

            Try("ncrypt.dll!NCryptOpenStorageProvider", () =>
            {
                ulong h;
                Probe.NCryptOpenStorageProvider(out h, IntPtr.Zero, 0);
            });

            Console.WriteLine($"=== Result: {_ok} OK, {_lazy} LazyPInvoke, {_other} other ===");
            return _lazy > 0 ? 1 : 0;
        }
    }
}
