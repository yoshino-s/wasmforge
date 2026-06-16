// WfForge.cs — Pure C# self-signed certificate forging via BCrypt (CNG).
//
// Architecture per user directive: ALL implementation in WASM (C# code).
// The only host involvement is the universal SyscallN bridge (mod_invoke)
// that every other Win32 P/Invoke uses. No new Go-side feature code.
//
// Flow:
//   1. BCryptOpenAlgorithmProvider("RSA") → hAlg
//   2. BCryptGenerateKeyPair(hAlg, 2048) + BCryptFinalizeKeyPair → hKey
//   3. BCryptExportKey(BCRYPT_RSAPUBLIC_BLOB) → public key bytes
//   4. Manually DER-encode TBSCertificate (subject, validity, pubkey, etc.)
//   5. BCryptHash(SHA256, tbs) → hash
//   6. BCryptSignHash(hKey, hash, PKCS1) → signature
//   7. Wrap TBSCertificate + signature in outer Certificate SEQUENCE
//   8. Base64 + emit PEM
//   9. BCryptExportKey(BCRYPT_RSAFULLPRIVATE_BLOB) for private key PEM

using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfForge
    {
        // BCrypt constants
        private const uint BCRYPT_PAD_PKCS1 = 2;
        private const uint BCRYPT_PAD_NONE  = 1;
        // PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 8017 § 9.2).
        // OID 2.16.840.1.101.3.4.2.1 wrapped in the DigestInfo SEQUENCE.
        private static readonly byte[] SHA256_DIGEST_INFO_PREFIX = new byte[]
        {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        };
        private static readonly char[] BCRYPT_RSA_ALG = "RSA\0".ToCharArray();
        private static readonly char[] BCRYPT_SHA256_ALG = "SHA256\0".ToCharArray();
        private static readonly char[] BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB\0".ToCharArray();
        private static readonly char[] BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB\0".ToCharArray();

        // BCrypt P/Invokes — handles declared as ulong (8 bytes) instead of
        // IntPtr (4 bytes on wasm32) so the BCrypt API has a properly-sized
        // slot to write 64-bit handle values. The wf_call x64-overflow
        // protection only touches bytes ADJACENT to the WASM allocation;
        // an 8-byte ulong slot is fully inside the allocation so the high
        // 4 bytes of the handle are preserved.
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
        private static extern uint BCryptSignHash(ulong hKey, IntPtr pPaddingInfo,
            byte* pbInput, uint cbInput, byte* pbOutput, uint cbOutput,
            out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern uint BCryptHash(ulong hAlgorithm, IntPtr pbSecret, uint cbSecret,
            byte* pbInput, uint cbInput, byte* pbOutput, uint cbOutput);

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_PKCS1_PADDING_INFO
        {
            public IntPtr pszAlgId; // OID string for hash algorithm
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_RSAKEY_BLOB
        {
            public uint Magic;
            public uint BitLength;
            public uint cbPublicExp;
            public uint cbModulus;
            public uint cbPrime1;
            public uint cbPrime2;
        }

        // Convert a big-endian byte array (BCrypt RSA blob format) into a
        // positive BigInteger. BigInteger constructor expects little-endian;
        // we reverse and append a 0x00 byte to keep the sign positive.
        private static BigInteger NewPositive(byte[] beBytes)
        {
            byte[] le = new byte[beBytes.Length + 1];
            for (int i = 0; i < beBytes.Length; i++) le[i] = beBytes[beBytes.Length - 1 - i];
            le[beBytes.Length] = 0x00;
            return new BigInteger(le);
        }

        public static int Forge(string subject)
        {
            if (string.IsNullOrEmpty(subject)) subject = "CN=Administrator";

            ulong pAlgRsa = 0, pAlgSha256 = 0;
            IntPtr pAlgRsaPtr = Marshal.StringToHGlobalUni("RSA");
            IntPtr pAlgSha256Ptr = Marshal.StringToHGlobalUni("SHA256");
            IntPtr pBlobPub = Marshal.StringToHGlobalUni("RSAPUBLICBLOB");
            try
            {
                uint rc = BCryptOpenAlgorithmProvider(out pAlgRsa, pAlgRsaPtr, IntPtr.Zero, 0);
                if (rc != 0)
                {
                    Console.WriteLine("[X] BCryptOpenAlgorithmProvider(RSA) failed: 0x{0:X}", rc);
                    return 1;
                }
                rc = BCryptOpenAlgorithmProvider(out pAlgSha256, pAlgSha256Ptr, IntPtr.Zero, 0);
                if (rc != 0)
                {
                    Console.WriteLine("[X] BCryptOpenAlgorithmProvider(SHA256) failed: 0x{0:X}", rc);
                    return 1;
                }

                ulong hKey = 0;
                rc = BCryptGenerateKeyPair(pAlgRsa, out hKey, 2048, 0);
                if (rc != 0)
                {
                    Console.WriteLine("[X] BCryptGenerateKeyPair failed: 0x{0:X}", rc);
                    return 1;
                }
                rc = BCryptFinalizeKeyPair(hKey, 0);
                if (rc != 0)
                {
                    Console.WriteLine("[X] BCryptFinalizeKeyPair failed: 0x{0:X}", rc);
                    return 1;
                }
                try
                {
                    // Export public key blob
                    uint cbResult = 0;
                    rc = BCryptExportKey(hKey, 0UL, pBlobPub,
                        (byte*)0, 0, out cbResult, 0);
                    if (rc != 0)
                    {
                        Console.WriteLine("[X] BCryptExportKey (sizing) failed: 0x{0:X}", rc);
                        return 1;
                    }
                    byte[] pubBlob = new byte[cbResult];
                    fixed (byte* pPub = pubBlob)
                    {
                        rc = BCryptExportKey(hKey, 0UL, pBlobPub,
                            pPub, cbResult, out cbResult, 0);
                    }
                    if (rc != 0)
                    {
                        Console.WriteLine("[X] BCryptExportKey failed: 0x{0:X}", rc);
                        return 1;
                    }

                    // Parse RSA pub blob: { BCRYPT_RSAKEY_BLOB header, exp bytes, modulus bytes }
                    var hdr = MemoryMarshal.Read<BCRYPT_RSAKEY_BLOB>(pubBlob);
                    byte[] exp = new byte[hdr.cbPublicExp];
                    byte[] mod = new byte[hdr.cbModulus];
                    int hdrSize = sizeof(BCRYPT_RSAKEY_BLOB);
                    Buffer.BlockCopy(pubBlob, hdrSize, exp, 0, (int)hdr.cbPublicExp);
                    Buffer.BlockCopy(pubBlob, hdrSize + (int)hdr.cbPublicExp, mod, 0, (int)hdr.cbModulus);

                    // Build the cert
                    byte[] tbsCert = BuildTbsCertificate(subject, mod, exp);

                    // Hash TBS via BCryptHash
                    byte[] hash = new byte[32];
                    fixed (byte* pTbs = tbsCert)
                    fixed (byte* pHash = hash)
                    {
                        rc = BCryptHash(pAlgSha256, IntPtr.Zero, 0, pTbs, (uint)tbsCert.Length,
                            pHash, 32);
                    }
                    if (rc != 0)
                    {
                        Console.WriteLine("[X] BCryptHash failed: 0x{0:X}", rc);
                        return 1;
                    }

                    // RSA PKCS#1 v1.5 signing — done entirely in managed C# via
                    // BigInteger.ModPow. This avoids BCryptSignHash entirely,
                    // sidestepping the wasm32/x64 ABI mismatch on the
                    // BCRYPT_PKCS1_PADDING_INFO struct (its LPCWSTR field is
                    // 4 bytes on wasm32, 8 on x64, and the inner pointer is
                    // not translated by the host bridge before BCrypt
                    // dereferences it).
                    //
                    // We export RSAFULLPRIVATEBLOB to obtain (n, d) and compute
                    // signature = block^d mod n directly.
                    IntPtr pPrivBlob = Marshal.StringToHGlobalUni("RSAFULLPRIVATEBLOB");
                    uint privSize = 0;
                    rc = BCryptExportKey(hKey, 0UL, pPrivBlob, (byte*)0, 0, out privSize, 0);
                    if (rc != 0)
                    {
                        Console.WriteLine("[X] BCryptExportKey(FULLPRIVATE) sizing failed: 0x{0:X}", rc);
                        Marshal.FreeHGlobal(pPrivBlob);
                        return 1;
                    }
                    byte[] privBlob = new byte[privSize];
                    fixed (byte* pPriv = privBlob)
                    {
                        rc = BCryptExportKey(hKey, 0UL, pPrivBlob, pPriv, privSize, out privSize, 0);
                    }
                    Marshal.FreeHGlobal(pPrivBlob);
                    if (rc != 0)
                    {
                        Console.WriteLine("[X] BCryptExportKey(FULLPRIVATE) failed: 0x{0:X}", rc);
                        return 1;
                    }

                    // Parse RSAFULLPRIVATEBLOB layout (after BCRYPT_RSAKEY_BLOB header):
                    //   PublicExponent (cbPublicExp bytes, big-endian)
                    //   Modulus        (cbModulus bytes)
                    //   Prime1         (cbPrime1 bytes)
                    //   Prime2         (cbPrime2 bytes)
                    //   Exponent1      (cbPrime1 bytes)
                    //   Exponent2      (cbPrime1 bytes)
                    //   Coefficient    (cbPrime1 bytes)
                    //   PrivateExponent(cbModulus bytes)  ← d
                    var privHdr = MemoryMarshal.Read<BCRYPT_RSAKEY_BLOB>(privBlob);
                    int hdrSz = sizeof(BCRYPT_RSAKEY_BLOB);
                    int offN = hdrSz + (int)privHdr.cbPublicExp;
                    int offD = hdrSz + (int)privHdr.cbPublicExp + (int)privHdr.cbModulus
                             + 5 * (int)privHdr.cbPrime1;
                    int modLen = (int)privHdr.cbModulus;
                    byte[] nBytes = new byte[modLen];
                    byte[] dBytes = new byte[modLen];
                    Buffer.BlockCopy(privBlob, offN, nBytes, 0, modLen);
                    Buffer.BlockCopy(privBlob, offD, dBytes, 0, modLen);

                    // Build PKCS#1 v1.5 padded signature input:
                    //   00 01 FF...FF 00 DigestInfo Hash
                    int diLen = SHA256_DIGEST_INFO_PREFIX.Length + 32;
                    int psLen = modLen - 3 - diLen;
                    byte[] block = new byte[modLen];
                    block[0] = 0x00;
                    block[1] = 0x01;
                    for (int i = 0; i < psLen; i++) block[2 + i] = 0xFF;
                    block[2 + psLen] = 0x00;
                    Buffer.BlockCopy(SHA256_DIGEST_INFO_PREFIX, 0, block,
                        2 + psLen + 1, SHA256_DIGEST_INFO_PREFIX.Length);
                    Buffer.BlockCopy(hash, 0, block,
                        2 + psLen + 1 + SHA256_DIGEST_INFO_PREFIX.Length, 32);

                    // signature = block^d mod n. BCrypt blobs are big-endian.
                    // BigInteger uses little-endian byte order with an
                    // additional 0x00 byte to force positive sign.
                    BigInteger n = NewPositive(nBytes);
                    BigInteger d = NewPositive(dBytes);
                    BigInteger m = NewPositive(block);
                    BigInteger sBig = BigInteger.ModPow(m, d, n);
                    byte[] sLE = sBig.ToByteArray();
                    byte[] sig = new byte[modLen];
                    // Convert little-endian BigInteger bytes → big-endian, right-aligned.
                    int copyLen = Math.Min(sLE.Length, modLen);
                    for (int i = 0; i < copyLen; i++) sig[modLen - 1 - i] = sLE[i];

                    // Assemble final Certificate: SEQUENCE { tbsCert, sigAlgId, sigBitString }
                    byte[] sigAlgId = BuildSigAlgIdSha256Rsa();
                    byte[] sigBitString = TLV(0x03, Concat(new byte[] { 0x00 }, sig));
                    byte[] certInner = Concat(tbsCert, sigAlgId, sigBitString);
                    byte[] certDer = TLV(0x30, certInner);

                    Console.WriteLine("[*] Subject:    " + subject);
                    Console.WriteLine("[*] Issuer:     " + subject + " (self-signed)");
                    Console.WriteLine("[*] Size:       {0} bytes DER", certDer.Length);
                    Console.WriteLine();
                    Console.WriteLine("-----BEGIN CERTIFICATE-----");
                    Console.WriteLine(Convert.ToBase64String(certDer,
                        Base64FormattingOptions.InsertLineBreaks));
                    Console.WriteLine("-----END CERTIFICATE-----");
                    return 0;
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
            }
        }

        // ── ASN.1 DER builders ─────────────────────────────────────

        private static byte[] BuildTbsCertificate(string subject, byte[] modulus, byte[] publicExponent)
        {
            // Version [0] EXPLICIT INTEGER (v3 = 2)
            byte[] version = TLV(0xA0, TLV(0x02, new byte[] { 0x02 }));
            // SerialNumber INTEGER (random 8 bytes)
            byte[] serialBytes = new byte[8];
            var rng = new Random();
            rng.NextBytes(serialBytes);
            serialBytes[0] = (byte)(serialBytes[0] & 0x7F); // ensure positive
            byte[] serial = TLV(0x02, serialBytes);
            // Signature AlgorithmIdentifier (sha256WithRSAEncryption)
            byte[] sigAlg = BuildSigAlgIdSha256Rsa();
            // Issuer/Subject Name
            byte[] subjDer = BuildX500NameDer(subject);
            // Validity SEQUENCE { notBefore, notAfter }
            byte[] notBefore = BuildUtcTime(DateTime.UtcNow.AddHours(-1));
            byte[] notAfter = BuildUtcTime(DateTime.UtcNow.AddYears(1));
            byte[] validity = TLV(0x30, Concat(notBefore, notAfter));
            // SubjectPublicKeyInfo SEQUENCE { algId, BITSTRING { RSAPublicKey } }
            byte[] rsaAlgOid = TLV(0x06, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 });
            byte[] rsaAlgId = TLV(0x30, Concat(rsaAlgOid, TLV(0x05, new byte[0])));
            byte[] rsaPubKey = BuildRsaPubKey(modulus, publicExponent);
            byte[] pubKeyBitStr = TLV(0x03, Concat(new byte[] { 0x00 }, rsaPubKey));
            byte[] subjPubKeyInfo = TLV(0x30, Concat(rsaAlgId, pubKeyBitStr));

            byte[] tbsContent = Concat(version, serial, sigAlg, subjDer, validity, subjDer, subjPubKeyInfo);
            return TLV(0x30, tbsContent);
        }

        private static byte[] BuildSigAlgIdSha256Rsa()
        {
            byte[] oid = TLV(0x06, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B });
            byte[] nullParams = TLV(0x05, new byte[0]);
            return TLV(0x30, Concat(oid, nullParams));
        }

        private static byte[] BuildUtcTime(DateTime dt)
        {
            string s = dt.ToString("yyMMddHHmmss") + "Z";
            return TLV(0x17, Encoding.ASCII.GetBytes(s));
        }

        private static byte[] BuildRsaPubKey(byte[] modulus, byte[] exponent)
        {
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            byte[] modTlv = TLV(0x02, IntegerWithLeadingZero(modulus));
            byte[] expTlv = TLV(0x02, IntegerWithLeadingZero(exponent));
            return TLV(0x30, Concat(modTlv, expTlv));
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

        private static byte[] BuildX500NameDer(string subject)
        {
            string cnValue;
            int eq = subject.IndexOf('=');
            if (eq > 0 && eq < subject.Length - 1)
            {
                string prefix = subject.Substring(0, eq).Trim().ToUpperInvariant();
                cnValue = (prefix == "CN") ? subject.Substring(eq + 1).Trim() : subject;
            }
            else cnValue = subject;
            byte[] valBytes = Encoding.UTF8.GetBytes(cnValue);
            byte[] utf8Tlv = TLV(0x0C, valBytes);
            byte[] cnOidTlv = TLV(0x06, new byte[] { 0x55, 0x04, 0x03 });
            byte[] atvTlv = TLV(0x30, Concat(cnOidTlv, utf8Tlv));
            byte[] rdnTlv = TLV(0x31, atvTlv);
            return TLV(0x30, rdnTlv);
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
