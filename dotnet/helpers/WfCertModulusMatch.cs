// WfCertModulusMatch.cs — RSA-modulus match against host X.509 stores.
//
// SharpDPAPI's DescribeCertificate walks CurrentUser\MY + LocalMachine\MY
// asking each cert for its public-key XML and substring-matching against
// the private key's XML. On wasm32 every link in that chain (X509Store /
// X509Certificate2 / cert.PublicKey.Key.ToXmlString) throws
// PlatformNotSupportedException; this helper takes raw modulus bytes the
// patched ParseDecCapiCertBlob extracted from the decrypted blob (no
// crypto on the C# side — just byte slicing) and asks the host bridge
// `x509_match` to do the walk natively.
//
// Wire format (input):   raw big-endian RSA modulus bytes
// Wire format (output):  u32 status (0 = match, 1 = no match), then on
//                        match: 7 length-prefixed records
//                        (thumbprint hex, issuer DN, subject DN,
//                         notBefore, notAfter, EKU list, cert DER).
//
// On a match the helper returns a populated MatchResult; otherwise null.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfCertModulusMatch
    {
        [DllImport("env", EntryPoint = "x509_match")]
        private static extern uint NativeX509Match(
            uint modulusPtr, uint modulusLen,
            uint outBufPtr, uint outBufCap);

        public struct EkuPair
        {
            public string FriendlyName;
            public string Oid;
        }

        public sealed class MatchResult
        {
            public string Thumbprint { get; set; } = "";
            public string Issuer     { get; set; } = "";
            public string Subject    { get; set; } = "";
            public string NotBefore  { get; set; } = "";
            public string NotAfter   { get; set; } = "";
            public List<EkuPair> EnhancedKeyUsages { get; set; } = new List<EkuPair>();
            public byte[] CertDER    { get; set; } = Array.Empty<byte>();
        }

        public static MatchResult Match(byte[] modulus)
        {
            if (modulus == null || modulus.Length == 0)
                return null;

            // Strip leading zero sign-byte if present so the host comparison
            // is invariant to whether the caller padded the modulus.
            int start = 0;
            while (start < modulus.Length && modulus[start] == 0)
                start++;
            if (start == modulus.Length) return null;

            // 64 KiB is generous — a typical 2048-bit cert is well under 2 KiB
            // (DER ~1 KiB + metadata strings ~256 B).
            const int outCap = 64 * 1024;
            byte[] outBuf = new byte[outCap];
            int modLen = modulus.Length - start;

            uint written;
            fixed (byte* mp = &modulus[start])
            fixed (byte* op = outBuf)
            {
                written = NativeX509Match(
                    (uint)(IntPtr)mp, (uint)modLen,
                    (uint)(IntPtr)op, (uint)outBuf.Length);
            }
            if (written < 4) return null;

            int off = 0;
            uint status = BitConverter.ToUInt32(outBuf, off); off += 4;
            if (status != 0) return null;

            var res = new MatchResult();
            res.Thumbprint = ReadRecord(outBuf, ref off, (int)written);
            res.Issuer     = ReadRecord(outBuf, ref off, (int)written);
            res.Subject    = ReadRecord(outBuf, ref off, (int)written);
            res.NotBefore  = ReadRecord(outBuf, ref off, (int)written);
            res.NotAfter   = ReadRecord(outBuf, ref off, (int)written);
            string ekuJoined = ReadRecord(outBuf, ref off, (int)written);
            res.CertDER    = ReadRecordBytes(outBuf, ref off, (int)written);

            if (!string.IsNullOrEmpty(ekuJoined))
            {
                foreach (var pair in ekuJoined.Split(';'))
                {
                    if (string.IsNullOrEmpty(pair)) continue;
                    int sep = pair.IndexOf('|');
                    if (sep < 0)
                    {
                        res.EnhancedKeyUsages.Add(new EkuPair { FriendlyName = "", Oid = pair });
                    }
                    else
                    {
                        res.EnhancedKeyUsages.Add(new EkuPair
                        {
                            FriendlyName = pair.Substring(0, sep),
                            Oid          = pair.Substring(sep + 1),
                        });
                    }
                }
            }
            return res;
        }

        private static string ReadRecord(byte[] buf, ref int off, int max)
        {
            byte[] raw = ReadRecordBytes(buf, ref off, max);
            return raw.Length == 0 ? "" : Encoding.UTF8.GetString(raw);
        }

        private static byte[] ReadRecordBytes(byte[] buf, ref int off, int max)
        {
            if (off + 4 > max) return Array.Empty<byte>();
            int len = (int)BitConverter.ToUInt32(buf, off);
            off += 4;
            if (len <= 0 || off + len > max) return Array.Empty<byte>();
            byte[] out_ = new byte[len];
            Array.Copy(buf, off, out_, 0, len);
            off += len;
            return out_;
        }
    }
}
