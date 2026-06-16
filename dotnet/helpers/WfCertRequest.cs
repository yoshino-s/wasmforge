// WfCertRequest.cs — Certify request verb implementation.
//
// Builds a PKCS#10 CSR via WfCsr, submits it through ICertRequest3 (vtable
// slot 7), and prints the issued cert. Used as the NativeAOT-WASI
// replacement for CertEnrollment.SendCertificateRequest + DownloadCert.

using System;
using System.Collections.Generic;

namespace WasmForge.Helpers
{
    public static class WfCertRequest
    {
        public sealed class Options
        {
            public string CertificateAuthority;
            public string TemplateName;
            public string SubjectName;
            public List<Tuple<string, string>> Sans = new List<Tuple<string, string>>();
            public string SidUrl;
            public List<string> ApplicationPolicies = new List<string>();
            public int KeySize = 2048;
            public bool OutputPem;
            public bool OutputCsr;
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate");
            if (string.IsNullOrEmpty(opts.CertificateAuthority) || !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] /ca:SERVER\\CA-NAME required.");
                return 1;
            }
            if (string.IsNullOrEmpty(opts.TemplateName))
            {
                Console.WriteLine("[X] /template:NAME required.");
                return 1;
            }

            string subject = opts.SubjectName;
            if (string.IsNullOrEmpty(subject)) subject = "CN=User";

            Console.WriteLine();
            Console.WriteLine("[*] Template                : {0}", opts.TemplateName);
            Console.WriteLine("[*] Subject                 : {0}", subject);
            if (opts.Sans.Count > 0)
            {
                var parts = new List<string>();
                foreach (var s in opts.Sans) parts.Add(s.Item2);
                Console.WriteLine("[*] Subject Alt Name(s)     : {0}", string.Join(", ", parts));
            }
            if (!string.IsNullOrEmpty(opts.SidUrl))
                Console.WriteLine("[*] Sid Extension           : {0}", opts.SidUrl);
            if (opts.ApplicationPolicies.Count > 0)
                Console.WriteLine("[*] Application Policies    : {0}", string.Join(", ", opts.ApplicationPolicies));

            WfCsr.Result csr;
            try
            {
                csr = WfCsr.Build(opts.TemplateName, subject, opts.Sans, opts.SidUrl,
                    opts.ApplicationPolicies, opts.KeySize);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] CSR generation failed: {0}", ex.Message);
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine("[*] Certificate Authority   : {0}", opts.CertificateAuthority);

            if (opts.OutputCsr)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Generate Certificate Signing Request (CSR)");
                Console.WriteLine("[+] Cert Signing Request    :");
                Console.WriteLine("-----BEGIN CERTIFICATE REQUEST-----");
                Console.WriteLine(csr.CsrBase64);
                Console.WriteLine("-----END CERTIFICATE REQUEST-----");
                Console.WriteLine();
                Console.WriteLine("[+] Private Key           :");
                Console.Write(csr.PrivateKeyPem);
                return 0;
            }

            int hr = WfCom.Initialize();
            Console.WriteLine("[trace] CoInitializeEx hr=0x{0:X}", hr);

            IntPtr ifc = WfCertCli.CreateInstance();
            if (ifc == IntPtr.Zero)
            {
                Console.WriteLine("[X] Failed to create CCertRequest3 instance.");
                return 1;
            }

            uint disposition;
            uint sHr = WfCertCli.Submit(ifc,
                WfCertCli.CR_IN_BASE64 | WfCertCli.CR_IN_FORMATANY,
                csr.CsrBase64, string.Empty, opts.CertificateAuthority, out disposition);
            Console.WriteLine("[trace] Submit hr=0x{0:X} disposition={1}", sHr, disposition);

            int requestId = 0;
            uint idHr = WfCertCli.GetRequestId(ifc, out requestId);
            Console.WriteLine("[trace] GetRequestId hr=0x{0:X} id={1}", idHr, requestId);

            if (disposition == WfCertCli.CR_DISP_ISSUED)
                Console.WriteLine("[*] CA Response             : The certificate has been issued.");
            else if (disposition == WfCertCli.CR_DISP_UNDER_SUBMISSION)
                Console.WriteLine("[*] CA Response             : The certificate is still pending.");
            else
            {
                string msg;
                WfCertCli.GetDispositionMessage(ifc, out msg);
                Console.WriteLine("[!] CA Response             : The submission failed: {0}", msg);
                int status;
                WfCertCli.GetLastStatus(ifc, out status);
                Console.WriteLine("[!] Last status             : 0x{0:X}", (uint)status);
                Console.WriteLine();
                Console.WriteLine("[*] Request ID              : {0}", requestId);
                Console.WriteLine();
                Console.WriteLine("[*] Private Key (PEM)       :");
                Console.WriteLine();
                Console.Write(csr.PrivateKeyPem);
                return 1;
            }

            Console.WriteLine("[*] Request ID              : {0}", requestId);
            Console.WriteLine();

            string pem;
            uint gHr = WfCertCli.GetCertificate(ifc, WfCertCli.CR_OUT_BASE64HEADER, out pem);
            if (gHr != 0 || string.IsNullOrEmpty(pem))
            {
                Console.WriteLine("[X] GetCertificate failed (hr=0x{0:X}).", gHr);
                Console.WriteLine();
                Console.Write(csr.PrivateKeyPem);
                return 1;
            }

            Console.WriteLine("[*] Certificate (PEM)       :");
            Console.WriteLine();
            Console.Write(csr.PrivateKeyPem);
            Console.WriteLine(pem);
            return 0;
        }
    }
}
