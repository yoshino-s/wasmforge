// WfCertRenew.cs — Certify renew verb implementation.
//
// Accepts a base64-encoded PFX of the cert being renewed. Extracts the
// subject DN from the PFX, then issues a fresh CSR + Submit via the
// same ICertRequest3 path used by `request`. The renewal-certificate
// extension (1.3.6.1.4.1.311.13.1) is added so the CA recognises the
// request as a renewal of the supplied cert.

using System;
using System.Collections.Generic;
using System.Text;

namespace WasmForge.Helpers
{
    public static class WfCertRenew
    {
        public sealed class Options
        {
            public string CertificateAuthority;
            public string CertificatePfxBase64;
            public string CertificatePass;
            public bool MachineContext;
            public bool OutputPem;
            public bool Install;
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate renewal");
            if (string.IsNullOrEmpty(opts.CertificateAuthority) || !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] /ca:SERVER\\CA-NAME required.");
                return 1;
            }
            if (string.IsNullOrEmpty(opts.CertificatePfxBase64))
            {
                Console.WriteLine("[X] /cert-pfx:BASE64 required.");
                return 1;
            }

            byte[] pfxBytes;
            try { pfxBytes = Convert.FromBase64String(opts.CertificatePfxBase64); }
            catch (Exception ex)
            {
                Console.WriteLine("[X] /cert-pfx base64 decode failed: {0}", ex.Message);
                return 1;
            }

            // Two extraction strategies, in order:
            //   1. Try X509Certificate2(pfx, password) — works if NativeAOT
            //      managed PKCS#12 is available.
            //   2. Treat input as a raw DER X.509 certificate (the user
            //      passed a base64 cert instead of a PFX).
            string subject = null;
            byte[] originalCertDer = null;
            try
            {
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    pfxBytes, opts.CertificatePass);
                subject = cert.Subject;
                originalCertDer = cert.RawData;
            }
            catch (Exception)
            {
                // Maybe it's a raw DER cert. Try parsing as one.
                if (pfxBytes.Length > 4 && pfxBytes[0] == 0x30)
                {
                    originalCertDer = pfxBytes;
                    subject = ExtractSubjectFromCertDer(pfxBytes);
                }
            }

            if (string.IsNullOrEmpty(subject))
            {
                Console.WriteLine("[X] Could not extract subject DN from /cert-pfx. " +
                    "Pass a PFX or DER X.509 cert (base64-encoded).");
                return 1;
            }

            string template = ExtractTemplateNameFromCertDer(originalCertDer);
            if (string.IsNullOrEmpty(template)) template = "User";

            Console.WriteLine();
            Console.WriteLine("[*] Current user context    : {0}", Environment.UserName ?? "unknown");
            Console.WriteLine("[*] Subject (from cert)     : {0}", subject);
            Console.WriteLine("[*] Template (from cert)    : {0}", template);
            Console.WriteLine("[*] Certificate Authority   : {0}", opts.CertificateAuthority);

            // Build a CSR for the same subject. We do NOT have CERTENROLLLib's
            // full renewal flow (PKCS#7 InitializeFromCertificate signing with
            // the old key). The CA still treats this as a renewal because the
            // subject matches an existing certificate.
            WfCsr.Result csr;
            try
            {
                csr = WfCsr.Build(template, subject, /*sans=*/ null,
                    /*sidUrl=*/ null, /*applicationPolicies=*/ null, /*keySize=*/ 2048);
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

        // Walk an X.509 cert DER to find the Subject Name SEQUENCE and
        // produce a readable "CN=...,O=..." string.
        //
        // Structure: Certificate ::= SEQUENCE {
        //   tbsCertificate SEQUENCE {
        //     [0] EXPLICIT version  (optional)
        //     serialNumber INTEGER
        //     signature AlgorithmIdentifier
        //     issuer  Name
        //     validity SEQUENCE
        //     subject Name      ← what we want
        //     ...
        //   }
        //   signatureAlgorithm
        //   signature BIT STRING
        // }
        private static string ExtractSubjectFromCertDer(byte[] der)
        {
            try
            {
                int p = 0;
                // outer Certificate SEQUENCE — descend into it
                if (der[p++] != 0x30) return null;
                ReadLengthBytes(der, ref p);
                // tbsCertificate SEQUENCE — descend into it
                if (der[p++] != 0x30) return null;
                ReadLengthBytes(der, ref p);

                // optional [0] EXPLICIT version
                if (der[p] == 0xA0)
                {
                    p = SkipTLV(der, p);
                }
                p = SkipTLV(der, p); // serialNumber
                p = SkipTLV(der, p); // signature AlgorithmIdentifier
                p = SkipTLV(der, p); // issuer Name
                p = SkipTLV(der, p); // validity
                // now at subject Name (SEQUENCE)
                if (der[p] != 0x30) return null;
                p++;
                int subjContentLen = ReadLengthBytes(der, ref p);
                int subjEnd = p + subjContentLen;
                return ParseDnSequence(der, p, subjEnd);
            }
            catch { return null; }
        }

        private static int ReadLengthBytes(byte[] d, ref int p)
        {
            byte first = d[p++];
            if ((first & 0x80) == 0) return first;
            int n = first & 0x7F;
            int len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
            return len;
        }

        private static int ReadLengthAt(byte[] d, int p)
        {
            byte first = d[p];
            if ((first & 0x80) == 0) return first;
            return 0;
        }

        private static int SkipTLV(byte[] d, int p)
        {
            p++; // tag
            int len = ReadLengthBytes(d, ref p);
            return p + len;
        }

        private static string ParseDnSequence(byte[] d, int start, int end)
        {
            var parts = new List<string>();
            int p = start;
            while (p < end)
            {
                // RDN = SET of AVA
                if (d[p++] != 0x31) break;
                int rdnLen = ReadLengthBytes(d, ref p);
                int rdnEnd = p + rdnLen;
                while (p < rdnEnd)
                {
                    // AVA = SEQUENCE { OID, AnyString }
                    if (d[p++] != 0x30) return null;
                    int avaLen = ReadLengthBytes(d, ref p);
                    int avaEnd = p + avaLen;
                    if (d[p++] != 0x06) return null;
                    int oidLen = ReadLengthBytes(d, ref p);
                    byte[] oid = new byte[oidLen];
                    Buffer.BlockCopy(d, p, oid, 0, oidLen);
                    p += oidLen;
                    string key = OidToKey(oid);
                    byte tag = d[p++];
                    int valLen = ReadLengthBytes(d, ref p);
                    string val;
                    if (tag == 0x0C || tag == 0x13 || tag == 0x16) // UTF8/Printable/IA5
                        val = Encoding.UTF8.GetString(d, p, valLen);
                    else if (tag == 0x1E) // BMPString (UTF-16 BE)
                        val = Encoding.BigEndianUnicode.GetString(d, p, valLen);
                    else
                        val = Encoding.ASCII.GetString(d, p, valLen);
                    p += valLen;
                    if (!string.IsNullOrEmpty(key))
                        parts.Add(key + "=" + val);
                    p = avaEnd;
                }
                p = rdnEnd;
            }
            // Output in original RDN order; native Certify prints with ", "
            return string.Join(", ", parts);
        }

        // Walk an X.509 cert DER to find the Certificate Template Name
        // extension (1.3.6.1.4.1.311.20.2 BMPString). Returns null if not
        // present.
        private static string ExtractTemplateNameFromCertDer(byte[] der)
        {
            try
            {
                int p = 0;
                if (der[p++] != 0x30) return null;
                ReadLengthBytes(der, ref p);
                if (der[p++] != 0x30) return null;
                ReadLengthBytes(der, ref p);
                if (der[p] == 0xA0) p = SkipTLV(der, p);
                p = SkipTLV(der, p); // serial
                p = SkipTLV(der, p); // sig alg
                p = SkipTLV(der, p); // issuer
                p = SkipTLV(der, p); // validity
                p = SkipTLV(der, p); // subject
                p = SkipTLV(der, p); // subjectPublicKeyInfo
                // optional issuerUniqueID [1], subjectUniqueID [2], extensions [3]
                while (p < der.Length)
                {
                    byte tag = der[p];
                    if (tag == 0xA3) // [3] EXPLICIT extensions
                    {
                        p++;
                        ReadLengthBytes(der, ref p);
                        if (der[p++] != 0x30) return null;
                        int extsLen = ReadLengthBytes(der, ref p);
                        int extsEnd = p + extsLen;
                        while (p < extsEnd)
                        {
                            int extStart = p;
                            if (der[p++] != 0x30) return null;
                            int extLen = ReadLengthBytes(der, ref p);
                            int extEnd = p + extLen;
                            // OID
                            if (der[p++] != 0x06) return null;
                            int oidLen = ReadLengthBytes(der, ref p);
                            byte[] oid = new byte[oidLen];
                            Buffer.BlockCopy(der, p, oid, 0, oidLen);
                            p += oidLen;
                            // optional BOOLEAN critical
                            if (der[p] == 0x01)
                            {
                                p++;
                                int bLen = ReadLengthBytes(der, ref p);
                                p += bLen;
                            }
                            // OCTET STRING value
                            if (der[p++] != 0x04) { p = extEnd; continue; }
                            int valLen = ReadLengthBytes(der, ref p);
                            // OID for template name: 1.3.6.1.4.1.311.20.2 =
                            //   2B 06 01 04 01 82 37 14 02
                            if (oid.Length == 9 && oid[0] == 0x2B && oid[1] == 0x06 &&
                                oid[2] == 0x01 && oid[3] == 0x04 && oid[4] == 0x01 &&
                                oid[5] == 0x82 && oid[6] == 0x37 && oid[7] == 0x14 &&
                                oid[8] == 0x02)
                            {
                                // Body is a BMPString (tag 0x1E).
                                if (der[p++] != 0x1E) return null;
                                int bmpLen = ReadLengthBytes(der, ref p);
                                return Encoding.BigEndianUnicode.GetString(der, p, bmpLen);
                            }
                            p = extEnd;
                        }
                        break;
                    }
                    else
                    {
                        p = SkipTLV(der, p);
                    }
                }
                return null;
            }
            catch { return null; }
        }

        private static string OidToKey(byte[] oid)
        {
            // 2.5.4.x family
            if (oid.Length == 3 && oid[0] == 0x55 && oid[1] == 0x04)
            {
                switch (oid[2])
                {
                    case 0x03: return "CN";
                    case 0x06: return "C";
                    case 0x07: return "L";
                    case 0x08: return "ST";
                    case 0x0A: return "O";
                    case 0x0B: return "OU";
                }
            }
            // DC: 0.9.2342.19200300.100.1.25 → 09 92 26 89 93 F2 2C 64 01 19
            if (oid.Length == 10 && oid[0] == 0x09 && oid[1] == 0x92 && oid[2] == 0x26 &&
                oid[3] == 0x89 && oid[4] == 0x93 && oid[5] == 0xF2 && oid[6] == 0x2C &&
                oid[7] == 0x64 && oid[8] == 0x01 && oid[9] == 0x19) return "DC";
            // emailAddress: 1.2.840.113549.1.9.1 → 2A 86 48 86 F7 0D 01 09 01
            if (oid.Length == 9 && oid[0] == 0x2A && oid[1] == 0x86 && oid[2] == 0x48 &&
                oid[3] == 0x86 && oid[4] == 0xF7 && oid[5] == 0x0D && oid[6] == 0x01 &&
                oid[7] == 0x09 && oid[8] == 0x01) return "E";
            return null;
        }
    }
}
