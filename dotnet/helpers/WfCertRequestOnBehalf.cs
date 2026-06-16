// WfCertRequestOnBehalf.cs — Certify requestonbehalf verb implementation.
//
// Native Certify uses CX509CertificateRequestPkcs7 + CSignerCertificate to
// wrap an inner PKCS#10 request and sign it with an Enrollment Agent
// certificate. The signed PKCS#7 is submitted under the EA's authority.
//
// NativeAOT-WASI cannot use CERTENROLLLib. As a working approximation,
// we issue a fresh PKCS#10 CSR for the target user's subject and submit
// it directly. The CA's EDITF_ATTRIBUTESUBJECTALTNAME2 / template
// configuration controls whether this succeeds; for templates that
// require enrollment-agent signing (e.g. EnrollmentAgent), this will
// fall back to the requesting user's authority.
//
// The inputs match native Certify's CLI so output text matches when the
// CA accepts the request.

using System;
using System.Collections.Generic;

namespace WasmForge.Helpers
{
    public static class WfCertRequestOnBehalf
    {
        public sealed class Options
        {
            public string CertificateAuthority;
            public string TemplateName;
            public string OnBehalfOf;            // "DOMAIN\\user"
            public string EnrollmentCertBase64;  // PFX (currently unused — see below)
            public string EnrollmentCertPass;
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate on behalf of another user");
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
            if (string.IsNullOrEmpty(opts.OnBehalfOf))
            {
                Console.WriteLine("[X] /onbehalfof:DOMAIN\\user required.");
                return 1;
            }

            // Map "DOMAIN\user" → CN=user subject for the CSR. Native Certify
            // sets RequesterName on the PKCS#7 to encode the on-behalf-of
            // identity; we can't construct that without CERTENROLLLib so we
            // place the target user in CN.
            string user = opts.OnBehalfOf;
            int slash = user.IndexOf('\\');
            if (slash > 0) user = user.Substring(slash + 1);
            string subject = "CN=" + user;

            Console.WriteLine();
            Console.WriteLine("[*] Template                : {0}", opts.TemplateName);
            Console.WriteLine("[*] On Behalf Of            : {0}", opts.OnBehalfOf);
            Console.WriteLine("[*] Subject                 : {0}", subject);
            Console.WriteLine("[*] Certificate Authority   : {0}", opts.CertificateAuthority);
            if (!string.IsNullOrEmpty(opts.EnrollmentCertBase64))
                Console.WriteLine("[!] Note: Enrollment agent PKCS#7 signing not yet bridged; submitting under current user.");

            WfCsr.Result csr;
            try
            {
                csr = WfCsr.Build(opts.TemplateName, subject,
                    /*sans=*/ null, /*sidUrl=*/ null,
                    /*applicationPolicies=*/ null, /*keySize=*/ 2048);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] CSR generation failed: {0}", ex.Message);
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

            uint disposition;
            uint sHr = WfCertCli.Submit(ifc,
                WfCertCli.CR_IN_BASE64 | WfCertCli.CR_IN_FORMATANY,
                csr.CsrBase64, string.Empty, opts.CertificateAuthority, out disposition);
            Console.WriteLine("[trace] Submit hr=0x{0:X} disposition={1}", sHr, disposition);

            int requestId = 0;
            WfCertCli.GetRequestId(ifc, out requestId);

            if (disposition != WfCertCli.CR_DISP_ISSUED)
            {
                string msg;
                WfCertCli.GetDispositionMessage(ifc, out msg);
                Console.WriteLine("[!] CA Response             : {0}", msg ?? "(no message)");
                Console.WriteLine("[*] Request ID              : {0}", requestId);
                Console.WriteLine();
                Console.WriteLine("[*] Private Key (PEM)       :");
                Console.WriteLine();
                Console.Write(csr.PrivateKeyPem);
                return 1;
            }

            Console.WriteLine("[*] CA Response             : The certificate has been issued.");
            Console.WriteLine("[*] Request ID              : {0}", requestId);
            Console.WriteLine();

            string pem;
            uint gHr = WfCertCli.GetCertificate(ifc, WfCertCli.CR_OUT_BASE64HEADER, out pem);
            if (gHr != 0 || string.IsNullOrEmpty(pem))
            {
                Console.WriteLine("[X] GetCertificate failed (hr=0x{0:X}).", gHr);
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
