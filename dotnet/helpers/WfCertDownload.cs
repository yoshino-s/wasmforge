// WfCertDownload.cs — Certify download verb implementation.
//
// Retrieves an already-issued certificate by request ID via
// ICertRequest3::RetrievePending + ICertRequest3::GetCertificate.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfCertDownload
    {
        public static int Execute(string ca, int requestId)
        {
            Console.WriteLine("[*] Action: Download a certificate");

            if (string.IsNullOrEmpty(ca))
            {
                Console.WriteLine("[X] /ca:<CONFIG> is required (e.g. SERVER\\CA-NAME).");
                return 1;
            }
            if (requestId <= 0)
            {
                Console.WriteLine("[X] /id:<N> is required (positive request ID).");
                return 1;
            }

            int hr = WfCom.Initialize();
            Console.WriteLine("[trace] CoInitializeEx hr=0x{0:X}", hr);

            IntPtr ifc = WfCertCli.CreateInstance();
            if (ifc == IntPtr.Zero)
            {
                Console.WriteLine("[X] Failed to create CCertRequest3 instance.");
                return 1;
            }
            Console.WriteLine("[*] WfCom: ifc (WASM mirror) = 0x{0:X}", ifc);

            uint disposition;
            uint rcHr = WfCertCli.RetrievePending(ifc, (uint)requestId, ca, out disposition);
            Console.WriteLine("[*] RetrievePending hr=0x{0:X} disposition={1}", rcHr, disposition);
            if (rcHr != 0)
            {
                Console.WriteLine("[X] RetrievePending failed.");
                return 1;
            }

            if (disposition != WfCertCli.CR_DISP_ISSUED &&
                disposition != WfCertCli.CR_DISP_ISSUED_OUT_OF_BAND)
            {
                Console.WriteLine("[!] Certificate not in issued state (disposition={0}).", disposition);
                return 1;
            }

            string certPem;
            uint gHr = WfCertCli.GetCertificate(ifc, WfCertCli.CR_OUT_BASE64HEADER, out certPem);
            Console.WriteLine("[*] GetCertificate hr=0x{0:X}", gHr);
            if (gHr != 0 || string.IsNullOrEmpty(certPem))
            {
                Console.WriteLine("[X] GetCertificate failed.");
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine("[+] Certificate (request ID {0}):", requestId);
            Console.WriteLine();
            Console.WriteLine(certPem);
            return 0;
        }
    }
}
