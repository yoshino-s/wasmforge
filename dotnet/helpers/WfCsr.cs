// WfCsr.cs — Pure C# PKCS#10 CSR generation for Certify request/renew/
// requestonbehalf verbs under NativeAOT-WASI.
//
// Sidesteps CERTENROLLLib COM (CX509Enrollment, IX509CertificateRequestPkcs10,
// CX500DistinguishedName, etc.) which would require dozens of additional COM
// dispatches. Instead, builds the PKCS#10 CertificationRequest directly using
// the same BCrypt key generation + BigInteger.ModPow signing path that
// WfForge already validated for self-signed certs.

using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfCsr
    {
        // PKCS#1 v1.5 SHA-256 DigestInfo prefix.
        private static readonly byte[] SHA256_DIGEST_INFO_PREFIX = new byte[]
        {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        };

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct BCRYPT_RSAKEY_BLOB
        {
            public uint Magic;
            public uint BitLength;
            public uint cbPublicExp;
            public uint cbModulus;
            public uint cbPrime1;
            public uint cbPrime2;
        }

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptOpenAlgorithmProvider(out ulong phAlgorithm,
            IntPtr pszAlgId, IntPtr pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptCloseAlgorithmProvider(ulong hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptGenerateKeyPair(ulong hAlgorithm,
            out ulong phKey, uint dwLength, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptFinalizeKeyPair(ulong hKey, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptDestroyKey(ulong hKey);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptExportKey(ulong hKey, ulong hExportKey,
            IntPtr pszBlobType, byte* pbOutput, uint cbOutput,
            out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptHash(ulong hAlgorithm, IntPtr pbSecret, uint cbSecret,
            byte* pbInput, uint cbInput, byte* pbOutput, uint cbOutput);

        public sealed class Result
        {
            public string CsrBase64;       // base64 of DER PKCS#10
            public string PrivateKeyPem;   // PKCS#1 RSAPrivateKey PEM
        }

        // Build a PKCS#10 CertificationRequest for the given template/subject.
        // sans is a list of (kind,value) where kind is "dns","upn","email","url".
        public static Result Build(string templateName, string subject,
            System.Collections.Generic.IList<Tuple<string, string>> sans,
            string sidUrl, System.Collections.Generic.IList<string> applicationPolicies,
            int keySize)
        {
            if (string.IsNullOrEmpty(subject)) subject = "CN=User";
            if (keySize <= 0) keySize = 2048;

            ulong pAlgRsa = 0, pAlgSha256 = 0;
            IntPtr pAlgRsaPtr = Marshal.StringToHGlobalUni("RSA");
            IntPtr pAlgSha256Ptr = Marshal.StringToHGlobalUni("SHA256");
            IntPtr pBlobPub = Marshal.StringToHGlobalUni("RSAPUBLICBLOB");
            IntPtr pBlobPriv = Marshal.StringToHGlobalUni("RSAFULLPRIVATEBLOB");
            try
            {
                uint rc = BCryptOpenAlgorithmProvider(out pAlgRsa, pAlgRsaPtr, IntPtr.Zero, 0);
                if (rc != 0) throw new Exception($"BCryptOpenAlgorithmProvider(RSA) failed 0x{rc:X}");
                rc = BCryptOpenAlgorithmProvider(out pAlgSha256, pAlgSha256Ptr, IntPtr.Zero, 0);
                if (rc != 0) throw new Exception($"BCryptOpenAlgorithmProvider(SHA256) failed 0x{rc:X}");

                ulong hKey = 0;
                rc = BCryptGenerateKeyPair(pAlgRsa, out hKey, (uint)keySize, 0);
                if (rc != 0) throw new Exception($"BCryptGenerateKeyPair failed 0x{rc:X}");
                rc = BCryptFinalizeKeyPair(hKey, 0);
                if (rc != 0) throw new Exception($"BCryptFinalizeKeyPair failed 0x{rc:X}");

                try
                {
                    // Export public blob (n, e).
                    uint pubSize = 0;
                    rc = BCryptExportKey(hKey, 0UL, pBlobPub, (byte*)0, 0, out pubSize, 0);
                    if (rc != 0) throw new Exception($"BCryptExportKey(public) sizing failed 0x{rc:X}");
                    byte[] pubBlob = new byte[pubSize];
                    fixed (byte* pPub = pubBlob)
                        rc = BCryptExportKey(hKey, 0UL, pBlobPub, pPub, pubSize, out pubSize, 0);
                    if (rc != 0) throw new Exception($"BCryptExportKey(public) failed 0x{rc:X}");

                    var pubHdr = MemoryMarshal.Read<BCRYPT_RSAKEY_BLOB>(pubBlob);
                    int pubHdrSize = sizeof(BCRYPT_RSAKEY_BLOB);
                    byte[] e = new byte[pubHdr.cbPublicExp];
                    byte[] n = new byte[pubHdr.cbModulus];
                    Buffer.BlockCopy(pubBlob, pubHdrSize, e, 0, (int)pubHdr.cbPublicExp);
                    Buffer.BlockCopy(pubBlob, pubHdrSize + (int)pubHdr.cbPublicExp, n, 0, (int)pubHdr.cbModulus);

                    // Export full private blob.
                    uint privSize = 0;
                    rc = BCryptExportKey(hKey, 0UL, pBlobPriv, (byte*)0, 0, out privSize, 0);
                    if (rc != 0) throw new Exception($"BCryptExportKey(private) sizing failed 0x{rc:X}");
                    byte[] privBlob = new byte[privSize];
                    fixed (byte* pPriv = privBlob)
                        rc = BCryptExportKey(hKey, 0UL, pBlobPriv, pPriv, privSize, out privSize, 0);
                    if (rc != 0) throw new Exception($"BCryptExportKey(private) failed 0x{rc:X}");

                    // Parse RSAFULLPRIVATEBLOB.
                    var privHdr = MemoryMarshal.Read<BCRYPT_RSAKEY_BLOB>(privBlob);
                    int privHdrSize = sizeof(BCRYPT_RSAKEY_BLOB);
                    int cE = (int)privHdr.cbPublicExp;
                    int cN = (int)privHdr.cbModulus;
                    int cP1 = (int)privHdr.cbPrime1;
                    int offE = privHdrSize;
                    int offN = offE + cE;
                    int offP = offN + cN;
                    int offQ = offP + cP1;
                    int offDp = offQ + cP1;
                    int offDq = offDp + cP1;
                    int offIq = offDq + cP1;
                    int offD = offIq + cP1;
                    byte[] privN = new byte[cN]; Buffer.BlockCopy(privBlob, offN, privN, 0, cN);
                    byte[] privE = new byte[cE]; Buffer.BlockCopy(privBlob, offE, privE, 0, cE);
                    byte[] privD = new byte[cN]; Buffer.BlockCopy(privBlob, offD, privD, 0, cN);
                    byte[] primeP = new byte[cP1]; Buffer.BlockCopy(privBlob, offP, primeP, 0, cP1);
                    byte[] primeQ = new byte[cP1]; Buffer.BlockCopy(privBlob, offQ, primeQ, 0, cP1);
                    byte[] dp = new byte[cP1]; Buffer.BlockCopy(privBlob, offDp, dp, 0, cP1);
                    byte[] dq = new byte[cP1]; Buffer.BlockCopy(privBlob, offDq, dq, 0, cP1);
                    byte[] iq = new byte[cP1]; Buffer.BlockCopy(privBlob, offIq, iq, 0, cP1);

                    // Build CertificationRequestInfo.
                    byte[] version = TLV(0x02, new byte[] { 0x00 });
                    byte[] subjDer = BuildX500NameDer(subject);
                    byte[] spki = BuildSubjectPublicKeyInfo(n, e);
                    byte[] attrs = BuildAttributes(templateName, sans, sidUrl, applicationPolicies);
                    byte[] criInner = Concat(version, subjDer, spki, attrs);
                    byte[] cri = TLV(0x30, criInner);

                    // Hash and sign.
                    byte[] hash = new byte[32];
                    fixed (byte* pCri = cri)
                    fixed (byte* pHash = hash)
                    {
                        rc = BCryptHash(pAlgSha256, IntPtr.Zero, 0, pCri, (uint)cri.Length, pHash, 32);
                    }
                    if (rc != 0) throw new Exception($"BCryptHash failed 0x{rc:X}");

                    int modLen = cN;
                    int diLen = SHA256_DIGEST_INFO_PREFIX.Length + 32;
                    int psLen = modLen - 3 - diLen;
                    byte[] block = new byte[modLen];
                    block[0] = 0x00; block[1] = 0x01;
                    for (int i = 0; i < psLen; i++) block[2 + i] = 0xFF;
                    block[2 + psLen] = 0x00;
                    Buffer.BlockCopy(SHA256_DIGEST_INFO_PREFIX, 0, block, 2 + psLen + 1, SHA256_DIGEST_INFO_PREFIX.Length);
                    Buffer.BlockCopy(hash, 0, block, 2 + psLen + 1 + SHA256_DIGEST_INFO_PREFIX.Length, 32);

                    BigInteger bn = NewPositive(privN);
                    BigInteger bd = NewPositive(privD);
                    BigInteger bm = NewPositive(block);
                    BigInteger sBig = BigInteger.ModPow(bm, bd, bn);
                    byte[] sLE = sBig.ToByteArray();
                    byte[] sig = new byte[modLen];
                    int copyLen = Math.Min(sLE.Length, modLen);
                    for (int i = 0; i < copyLen; i++) sig[modLen - 1 - i] = sLE[i];

                    byte[] sigAlg = BuildSigAlgIdSha256Rsa();
                    byte[] sigBit = TLV(0x03, Concat(new byte[] { 0x00 }, sig));
                    byte[] csrDer = TLV(0x30, Concat(cri, sigAlg, sigBit));

                    return new Result
                    {
                        CsrBase64 = Convert.ToBase64String(csrDer, Base64FormattingOptions.InsertLineBreaks),
                        PrivateKeyPem = BuildPrivateKeyPem(privN, privE, privD, primeP, primeQ, dp, dq, iq),
                    };
                }
                finally
                {
                    BCryptDestroyKey(hKey);
                }
            }
            finally
            {
                if (pAlgRsa != 0) BCryptCloseAlgorithmProvider(pAlgRsa, 0);
                if (pAlgSha256 != 0) BCryptCloseAlgorithmProvider(pAlgSha256, 0);
                Marshal.FreeHGlobal(pAlgRsaPtr);
                Marshal.FreeHGlobal(pAlgSha256Ptr);
                Marshal.FreeHGlobal(pBlobPub);
                Marshal.FreeHGlobal(pBlobPriv);
            }
        }

        // ── ASN.1 helpers ────────────────────────────────────────────

        private static byte[] BuildSubjectPublicKeyInfo(byte[] mod, byte[] exp)
        {
            byte[] rsaOid = TLV(0x06, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 });
            byte[] algId = TLV(0x30, Concat(rsaOid, TLV(0x05, new byte[0])));
            byte[] modTlv = TLV(0x02, IntegerWithLeadingZero(mod));
            byte[] expTlv = TLV(0x02, IntegerWithLeadingZero(exp));
            byte[] rsaPub = TLV(0x30, Concat(modTlv, expTlv));
            byte[] bitStr = TLV(0x03, Concat(new byte[] { 0x00 }, rsaPub));
            return TLV(0x30, Concat(algId, bitStr));
        }

        private static byte[] BuildSigAlgIdSha256Rsa()
        {
            byte[] oid = TLV(0x06, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B });
            byte[] nul = TLV(0x05, new byte[0]);
            return TLV(0x30, Concat(oid, nul));
        }

        // Build PKCS#10 attributes [0] IMPLICIT SET with an extensionRequest.
        private static byte[] BuildAttributes(string templateName,
            System.Collections.Generic.IList<Tuple<string, string>> sans,
            string sidUrl,
            System.Collections.Generic.IList<string> applicationPolicies)
        {
            var extList = new System.Collections.Generic.List<byte[]>();

            // Certificate Template Name extension (1.3.6.1.4.1.311.20.2) — BMPString.
            // BMPString = UTF-16 BE.
            if (!string.IsNullOrEmpty(templateName))
            {
                byte[] tplBmp = Encoding.BigEndianUnicode.GetBytes(templateName);
                byte[] extVal = TLV(0x1E, tplBmp);
                byte[] extOid = TLV(0x06, new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02 });
                byte[] extOctet = TLV(0x04, extVal);
                extList.Add(TLV(0x30, Concat(extOid, extOctet)));
            }

            // SubjectAltName extension.
            if ((sans != null && sans.Count > 0) || !string.IsNullOrEmpty(sidUrl))
            {
                var sanInner = new System.Collections.Generic.List<byte[]>();
                if (sans != null)
                {
                    foreach (var s in sans)
                    {
                        string kind = s.Item1.ToLowerInvariant();
                        string val = s.Item2;
                        switch (kind)
                        {
                            case "dns":
                                sanInner.Add(TLV(0x82, Encoding.ASCII.GetBytes(val)));
                                break;
                            case "email":
                                sanInner.Add(TLV(0x81, Encoding.ASCII.GetBytes(val)));
                                break;
                            case "upn":
                                // [0] otherName { type-id OID 1.3.6.1.4.1.311.20.2.3, value [0] EXPLICIT UTF8String }
                                byte[] upnOid = TLV(0x06, new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 });
                                byte[] upnVal = TLV(0xA0, TLV(0x0C, Encoding.UTF8.GetBytes(val)));
                                sanInner.Add(TLVMulti(0xA0, Concat(upnOid, upnVal)));
                                break;
                            case "url":
                                // [0] otherName { type-id ms 1.3.6.1.4.1.311.25.2 (SID), value }
                                byte[] sidOid = TLV(0x06, new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02 });
                                byte[] sidVal = TLV(0xA0, TLV(0x0C, Encoding.UTF8.GetBytes(val)));
                                sanInner.Add(TLVMulti(0xA0, Concat(sidOid, sidVal)));
                                break;
                        }
                    }
                }
                byte[] sanSeq = TLV(0x30, Concat(sanInner.ToArray()));
                byte[] sanOid = TLV(0x06, new byte[] { 0x55, 0x1D, 0x11 });
                byte[] sanOctet = TLV(0x04, sanSeq);
                extList.Add(TLV(0x30, Concat(sanOid, sanOctet)));
            }

            // ApplicationPolicies (1.3.6.1.4.1.311.21.10) — SEQUENCE OF SEQUENCE { OID }.
            if (applicationPolicies != null && applicationPolicies.Count > 0)
            {
                var inner = new System.Collections.Generic.List<byte[]>();
                foreach (var p in applicationPolicies)
                {
                    byte[] policyOid = EncodeOid(p);
                    if (policyOid != null)
                        inner.Add(TLV(0x30, TLV(0x06, policyOid)));
                }
                byte[] polSeq = TLV(0x30, Concat(inner.ToArray()));
                byte[] polOid = TLV(0x06, new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0A });
                byte[] polOctet = TLV(0x04, polSeq);
                extList.Add(TLV(0x30, Concat(polOid, polOctet)));
            }

            if (extList.Count == 0)
                return TLV(0xA0, new byte[0]);

            byte[] extSeq = TLV(0x30, Concat(extList.ToArray()));
            byte[] extOidAttr = TLV(0x06, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E });
            byte[] extSet = TLV(0x31, extSeq);
            byte[] extRequest = TLV(0x30, Concat(extOidAttr, extSet));
            return TLV(0xA0, extRequest);
        }

        private static byte[] EncodeOid(string oid)
        {
            try
            {
                string[] parts = oid.Split('.');
                int[] arcs = new int[parts.Length];
                for (int i = 0; i < parts.Length; i++) arcs[i] = int.Parse(parts[i]);
                var ms = new System.IO.MemoryStream();
                ms.WriteByte((byte)(arcs[0] * 40 + arcs[1]));
                for (int i = 2; i < arcs.Length; i++)
                {
                    int v = arcs[i];
                    if (v == 0) { ms.WriteByte(0); continue; }
                    var stack = new System.Collections.Generic.Stack<byte>();
                    stack.Push((byte)(v & 0x7F));
                    v >>= 7;
                    while (v > 0)
                    {
                        stack.Push((byte)((v & 0x7F) | 0x80));
                        v >>= 7;
                    }
                    while (stack.Count > 0) ms.WriteByte(stack.Pop());
                }
                return ms.ToArray();
            }
            catch
            {
                return null;
            }
        }

        private static byte[] BuildX500NameDer(string subject)
        {
            // Parse comma-separated AVA pairs. Each becomes a separate RDN.
            var rdns = new System.Collections.Generic.List<byte[]>();
            string[] parts = subject.Split(',');
            foreach (var raw in parts)
            {
                string p = raw.Trim();
                if (p.Length == 0) continue;
                int eq = p.IndexOf('=');
                if (eq <= 0) continue;
                string key = p.Substring(0, eq).Trim().ToUpperInvariant();
                string val = p.Substring(eq + 1).Trim();
                byte[] oid;
                switch (key)
                {
                    case "CN": oid = new byte[] { 0x55, 0x04, 0x03 }; break;
                    case "O":  oid = new byte[] { 0x55, 0x04, 0x0A }; break;
                    case "OU": oid = new byte[] { 0x55, 0x04, 0x0B }; break;
                    case "L":  oid = new byte[] { 0x55, 0x04, 0x07 }; break;
                    case "ST": oid = new byte[] { 0x55, 0x04, 0x08 }; break;
                    case "C":  oid = new byte[] { 0x55, 0x04, 0x06 }; break;
                    case "DC": oid = new byte[] { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 }; break;
                    case "E":  oid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 }; break;
                    default: continue;
                }
                byte[] valTlv = TLV(0x0C, Encoding.UTF8.GetBytes(val));
                byte[] oidTlv = TLV(0x06, oid);
                byte[] atv = TLV(0x30, Concat(oidTlv, valTlv));
                rdns.Add(TLV(0x31, atv));
            }
            return TLV(0x30, Concat(rdns.ToArray()));
        }

        // PKCS#1 RSAPrivateKey PEM output.
        private static string BuildPrivateKeyPem(byte[] n, byte[] e, byte[] d,
            byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            byte[] ver = TLV(0x02, new byte[] { 0x00 });
            byte[] inner = Concat(
                ver,
                TLV(0x02, IntegerWithLeadingZero(n)),
                TLV(0x02, IntegerWithLeadingZero(e)),
                TLV(0x02, IntegerWithLeadingZero(d)),
                TLV(0x02, IntegerWithLeadingZero(p)),
                TLV(0x02, IntegerWithLeadingZero(q)),
                TLV(0x02, IntegerWithLeadingZero(dp)),
                TLV(0x02, IntegerWithLeadingZero(dq)),
                TLV(0x02, IntegerWithLeadingZero(iq)));
            byte[] der = TLV(0x30, inner);
            string b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
            return "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----\n";
        }

        private static BigInteger NewPositive(byte[] beBytes)
        {
            byte[] le = new byte[beBytes.Length + 1];
            for (int i = 0; i < beBytes.Length; i++) le[i] = beBytes[beBytes.Length - 1 - i];
            le[beBytes.Length] = 0x00;
            return new BigInteger(le);
        }

        private static byte[] IntegerWithLeadingZero(byte[] bytes)
        {
            if (bytes.Length == 0) return new byte[] { 0x00 };
            if ((bytes[0] & 0x80) != 0)
            {
                byte[] r = new byte[bytes.Length + 1];
                Buffer.BlockCopy(bytes, 0, r, 1, bytes.Length);
                return r;
            }
            return bytes;
        }

        private static byte[] TLV(byte tag, byte[] content)
        {
            byte[] lenBytes = DerLength(content.Length);
            byte[] result = new byte[1 + lenBytes.Length + content.Length];
            result[0] = tag;
            Buffer.BlockCopy(lenBytes, 0, result, 1, lenBytes.Length);
            Buffer.BlockCopy(content, 0, result, 1 + lenBytes.Length, content.Length);
            return result;
        }

        private static byte[] TLVMulti(byte tag, byte[] content) => TLV(tag, content);

        private static byte[] DerLength(int len)
        {
            if (len < 0x80) return new byte[] { (byte)len };
            if (len <= 0xFF) return new byte[] { 0x81, (byte)len };
            if (len <= 0xFFFF) return new byte[] { 0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
            return new byte[] { 0x83, (byte)((len >> 16) & 0xFF), (byte)((len >> 8) & 0xFF), (byte)(len & 0xFF) };
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            byte[] result = new byte[total];
            int offset = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, result, offset, p.Length);
                offset += p.Length;
            }
            return result;
        }
    }
}
