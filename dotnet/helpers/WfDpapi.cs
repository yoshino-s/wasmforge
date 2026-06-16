// WfDpapi.cs — DPAPI master key derivation + decryption via wasmforge crypto bridges.
//
// SharpDPAPI's Dpapi.CalculateKeys and Dpapi.DecryptMasterKeyWithSha use
// System.Security.Cryptography.HMACSHA1/HMACSHA512/AesCryptoServiceProvider
// which throw PlatformNotSupportedException on NativeAOT-WASI. This helper
// mirrors the same crypto operations but routes through CryptoHostHelper
// which uses BCrypt CNG on the host side.
//
// Reference: github.com/GhostPack/SharpDPAPI Dpapi.cs:
//   GetMasterKey()             line 1740
//   CalculateKeys()            line 1755
//   DecryptMasterKeyWithSha()  line 1907
//   DerivePreKey()             line 1962
//   DecryptAes256HmacSha512()  line 1997

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WasmForge.Bridge
{
    public static unsafe class WfDpapi
    {
        // ── mod_invoke bridge primitives (WfNetapi.cs pattern) ───────────────────

        [DllImport("env", EntryPoint = "mod_load")]
        private static extern uint mod_load(uint namePtr);

        [DllImport("env", EntryPoint = "mod_resolve")]
        private static extern uint mod_resolve(uint libHandle, uint namePtr);

        [DllImport("env", EntryPoint = "mod_invoke")]
        private static extern ulong mod_invoke(
            ulong procHandle, uint nargs,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11,
            ulong a12, ulong a13, ulong a14,
            ulong ret1Ptr, ulong errPtr);

        private static uint _crypt32;
        private static uint _kernel32Dpapi;
        private static uint _ntdllDpapi;
        private static uint _hCryptUnprotectData;
        private static uint _hLocalFreeDpapi;
        private static uint _hVirtualAllocDpapi;
        private static uint _hVirtualFreeDpapi;
        private static uint _hRtlMoveMemoryDpapi;

        private static uint DpapiResolve(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
        {
            if (cachedProc != 0) return cachedProc;
            if (cachedLib == 0)
            {
                byte[] db = Encoding.ASCII.GetBytes(dll + "\0");
                fixed (byte* dp = db) cachedLib = mod_load((uint)(IntPtr)dp);
                if (cachedLib == 0) return 0;
            }
            byte[] fb = Encoding.ASCII.GetBytes(fn + "\0");
            fixed (byte* fp = fb) cachedProc = mod_resolve(cachedLib, (uint)(IntPtr)fp);
            return cachedProc;
        }

        private static ulong DpapiInvoke(uint proc, uint nargs,
            ulong a0=0, ulong a1=0, ulong a2=0, ulong a3=0,
            ulong a4=0, ulong a5=0, ulong a6=0, ulong a7=0)
        {
            ulong ret1=0, err=0;
            return mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // ── Unprotect (CryptUnprotectData) ────────────────────────────────────────
        //
        // Replaces System.Security.Cryptography.ProtectedData.Unprotect which
        // throws PlatformNotSupportedException on NativeAOT-WASI.
        //
        // DATA_BLOB in WASM (32-bit) = { uint cbData; uint pbData; } = 8 bytes.
        //
        // Strategy:
        //   1. Build input DATA_BLOB structs in WASM stackalloc memory.
        //      mod_invoke translates WASM pointers → host pointers automatically.
        //   2. Allocate 16-byte output DATA_BLOB on the HOST via VirtualAlloc so
        //      CryptUnprotectData can fill it with a LocalAlloc-owned buffer.
        //   3. After success, copy the decrypted bytes back via RtlMoveMemory
        //      then LocalFree the host buffer, VirtualFree the struct area.
        //
        // ptrmask 0x5f = args 0,1,2,3,4,6 are pointer args (ppszDataDescr at
        // arg1 is NULL so mod_invoke skips translation on 0 values).
        //
        // The DataProtectionScope parameter is accepted to match the BCL API
        // signature but ignored — CryptUnprotectData always uses the current
        // user's DPAPI context.

        public static byte[] Unprotect(byte[] data, byte[] optionalEntropy, int scope)
        {
            if (data == null || data.Length == 0) return Array.Empty<byte>();
            try
            {
                uint pCUD  = DpapiResolve("crypt32.dll",  ref _crypt32,        "CryptUnprotectData", ref _hCryptUnprotectData);
                uint pLF   = DpapiResolve("kernel32.dll", ref _kernel32Dpapi,  "LocalFree",          ref _hLocalFreeDpapi);
                uint pVA   = DpapiResolve("kernel32.dll", ref _kernel32Dpapi,  "VirtualAlloc",       ref _hVirtualAllocDpapi);
                uint pVF   = DpapiResolve("kernel32.dll", ref _kernel32Dpapi,  "VirtualFree",        ref _hVirtualFreeDpapi);
                uint pMove = DpapiResolve("ntdll.dll",    ref _ntdllDpapi,     "RtlMoveMemory",      ref _hRtlMoveMemoryDpapi);
                if (pCUD == 0 || pLF == 0 || pVA == 0 || pVF == 0) return Array.Empty<byte>();

                // Allocate host-side output DATA_BLOB (16 bytes for alignment).
                ulong hostOut = DpapiInvoke(pVA, 4, 0u, 16u, 0x3000u, 4u);
                if (hostOut == 0) return Array.Empty<byte>();

                try
                {
                    bool hasEnt = optionalEntropy != null && optionalEntropy.Length > 0;
                    ulong ok;

                    fixed (byte* pData = data)
                    {
                        // WASM-side DATA_BLOB: { cbData, pbData } each 4 bytes.
                        uint* inBlob = stackalloc uint[2];
                        inBlob[0] = (uint)data.Length;
                        inBlob[1] = (uint)(IntPtr)pData;

                        if (hasEnt)
                        {
                            fixed (byte* pEnt = optionalEntropy)
                            {
                                uint* entBlob = stackalloc uint[2];
                                entBlob[0] = (uint)optionalEntropy!.Length;
                                entBlob[1] = (uint)(IntPtr)pEnt;
                                ok = DpapiInvoke(pCUD, 7,
                                    (ulong)(uint)(IntPtr)inBlob,  // pDataIn  (WASM → translated)
                                    0,                             // ppszDataDescr = NULL
                                    (ulong)(uint)(IntPtr)entBlob, // pOptionalEntropy (WASM → translated)
                                    0,                             // pvReserved = NULL
                                    0,                             // pPromptStruct = NULL
                                    0,                             // dwFlags = 0
                                    hostOut);                      // pDataOut (host addr, passes through)
                            }
                        }
                        else
                        {
                            ok = DpapiInvoke(pCUD, 7,
                                (ulong)(uint)(IntPtr)inBlob,
                                0, 0, 0, 0, 0,
                                hostOut);
                        }
                    }

                    if (ok == 0) return Array.Empty<byte>();

                    // Read cbData (first 4 bytes) and pbData (next 4 bytes) from host struct.
                    uint outCb = 0;
                    uint outPb = 0;
                    if (pMove != 0)
                    {
                        DpapiInvoke(pMove, 3, (ulong)(uint)(IntPtr)(&outCb), hostOut,     4u);
                        DpapiInvoke(pMove, 3, (ulong)(uint)(IntPtr)(&outPb), hostOut + 4, 4u);
                    }
                    if (outCb == 0 || outPb == 0) return Array.Empty<byte>();

                    // Copy decrypted bytes from host buffer into WASM.
                    byte[] result = new byte[outCb];
                    fixed (byte* rp = result)
                    {
                        if (pMove != 0)
                            DpapiInvoke(pMove, 3, (ulong)(uint)(IntPtr)rp, outPb, outCb);
                    }

                    // Free the CryptUnprotectData-allocated output buffer.
                    DpapiInvoke(pLF, 1, outPb);
                    return result;
                }
                finally
                {
                    DpapiInvoke(pVF, 3, hostOut, 0u, 0x8000u); // MEM_RELEASE
                }
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }


        /// <summary>
        /// Mirrors SharpDPAPI's Dpapi.CalculateKeys (BCL version) for the
        /// password / ntlm / credkey paths. Returns the SHA bytes used as
        /// input to PBKDF2 during master key decryption.
        /// </summary>
        public static byte[] CalculateKeys(bool domain = true, string password = "", string ntlm = "", string credkey = "", string userSID = "", string directory = "")
        {
            if (!String.IsNullOrEmpty(password))
            {
                byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
                byte[] sha1pwd = CryptoHostHelper.Sha1(passwordBytes);
                if (sha1pwd == null) return null;
                byte[] saltBytes = Encoding.Unicode.GetBytes(userSID);
                return CryptoHostHelper.HmacSha1(sha1pwd, saltBytes);
            }
            if (!String.IsNullOrEmpty(ntlm))
            {
                byte[] ntlmBytes = HexToBytes(ntlm);
                byte[] saltBytes = Encoding.Unicode.GetBytes(userSID);
                return CryptoHostHelper.HmacSha1(ntlmBytes, saltBytes);
            }
            if (!String.IsNullOrEmpty(credkey))
            {
                byte[] credkeyBytes = HexToBytes(credkey);
                byte[] saltBytes = Encoding.Unicode.GetBytes(userSID);
                return CryptoHostHelper.HmacSha1(credkeyBytes, saltBytes);
            }
            Console.WriteLine("  [X] WfDpapi.CalculateKeys() error: either /password, /ntlm, or /credkey must be supplied");
            return null;
        }

        /// <summary>
        /// Mirrors SharpDPAPI's GetMasterKey (line 1740). Extracts the master
        /// key sub-blob from a master key file blob: skips 96-byte header,
        /// reads 8-byte sub-blob length, skips 4*8=32 bytes of length headers,
        /// returns the master key sub-blob.
        /// </summary>
        private static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            int offset = 96;
            if (offset + 8 > masterKeyBytes.Length) return null;
            long masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the 4 key length headers (8 bytes each)
            if (masterKeyLen <= 0 || offset + masterKeyLen > masterKeyBytes.Length) return null;
            byte[] sub = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, sub, 0, masterKeyLen);
            return sub;
        }

        /// <summary>
        /// Mirrors SharpDPAPI's Dpapi.DecryptMasterKeyWithSha (line 1907).
        ///
        /// Master key sub-blob layout (offsets relative to start of mkBytes):
        ///   +0   Version (4 bytes, skipped)
        ///   +4   Salt (16 bytes)
        ///   +20  Rounds (int32)
        ///   +24  AlgHash (int32) — 32782=SHA512, 32777/32772=SHA1
        ///   +28  AlgCrypt (int32) — 26128=AES-256, 26115=3DES
        ///   +32  EncData (rest)
        ///
        /// For AES-256+SHA512 (modern DPAPI):
        ///   pre = PBKDF2-HMAC-SHA512(shaBytes, salt, rounds, 48)
        ///   key = pre[0:32], iv = pre[32:48]
        ///   plain = AES-CBC-decrypt(encData, key, iv) with zero-padding
        ///   masterKeyFull = plain[-64:]
        ///   return (guid, hex(SHA1(masterKeyFull)))
        /// </summary>
        public static KeyValuePair<string, string> DecryptMasterKeyWithSha(byte[] masterKeyBytes, byte[] shaBytes)
        {
            try
            {
                if (masterKeyBytes == null || masterKeyBytes.Length < 96 + 32)
                    return default;

                // GUID is 36 chars UTF-16-LE at offset 12, length 72 bytes.
                string guidInner = Encoding.Unicode.GetString(masterKeyBytes, 12, 72);
                string guidMasterKey = "{" + guidInner.Replace("\0", "").Trim() + "}";

                byte[] mkBytes = GetMasterKey(masterKeyBytes);
                if (mkBytes == null || mkBytes.Length < 32) return default;

                int offset = 4; // skip version
                byte[] salt = SubArray(mkBytes, offset, 16);
                offset += 16;
                int rounds = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;
                int algHash = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;
                int algCrypt = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;

                byte[] encData = SubArray(mkBytes, offset, mkBytes.Length - offset);
                if (encData.Length == 0) return default;

                byte[] derivedPreKey = DerivePreKey(shaBytes, algHash, salt, rounds);
                if (derivedPreKey == null) return default;

                // CALG_AES_256 (26128) with CALG_SHA_512 (32782)
                if (algCrypt == 26128 && algHash == 32782)
                {
                    byte[] mkSha1 = DecryptAes256HmacSha512(shaBytes, derivedPreKey, encData);
                    if (mkSha1 == null) return default;
                    return new KeyValuePair<string, string>(guidMasterKey, BytesToHex(mkSha1));
                }

                // CALG_3DES (26115) — not implemented in bridge; SharpDPAPI handles
                // it but it requires DES key derivation we haven't wired yet.
                if (algCrypt == 26115)
                {
                    Console.WriteLine($"  [X] WfDpapi: 3DES master key decryption not yet supported for {guidMasterKey}");
                    return default;
                }

                Console.WriteLine($"  [X] WfDpapi: unsupported algCrypt={algCrypt:X} algHash={algHash:X}");
                return default;
            }
            catch (Exception e)
            {
                Console.WriteLine($"  [X] WfDpapi.DecryptMasterKeyWithSha exception: {e.Message}");
                return default;
            }
        }

        private static byte[] DerivePreKey(byte[] shaBytes, int algHash, byte[] salt, int rounds)
        {
            switch (algHash)
            {
                case 32782: // CALG_SHA_512
                    // Windows DPAPI uses the Microsoft-CryptoAPI PBKDF2 variant
                    // (mscrypto=true in SharpDPAPI's third-party Pbkdf2.cs), which
                    // deviates from RFC2898: after each iteration the accumulated
                    // XOR result is fed back into HMAC instead of the previous
                    // U_i. This is the "MS PBKDF2 bug" that Mimikatz / SharpDPAPI
                    // / impacket all replicate to match what Windows actually
                    // produces on disk. Real bcrypt!BCryptDeriveKeyPBKDF2 is
                    // RFC-compliant and produces different bytes; the WfHostBridge
                    // MsPbkdf2 helpers run the buggy loop entirely host-side via
                    // BCrypt HMAC for performance (8000 iterations per master
                    // key — running the loop in C# via the host bridge would
                    // require 40k+ wf_call round-trips per key).
                    // Route through the generic xc_op crypto dispatcher: one
                    // wf_call per master-key derivation, the entire iteration
                    // loop runs host-side via Go-native BCrypt.
                    return CryptoHostHelper.MsPbkdf2Sha512Op(shaBytes, salt, rounds, 48);
                case 32777: // CALG_HMAC
                case 32772: // CALG_SHA1
                    return CryptoHostHelper.MsPbkdf2Sha1Op(shaBytes, salt, rounds, 32);
                default:
                    Console.WriteLine($"  [X] WfDpapi.DerivePreKey: unsupported algHash={algHash:X}");
                    return null;
            }
        }

        /// <summary>
        /// Mirrors SharpDPAPI's DecryptAes256HmacSha512 (line 1997).
        /// key = derivedPreKey[0:32], iv = derivedPreKey[32:48].
        /// Zero-pad encData to a multiple of 16 bytes, AES-CBC-decrypt,
        /// take last 64 bytes as masterKeyFull, return SHA1(masterKeyFull).
        /// </summary>
        private static byte[] DecryptAes256HmacSha512(byte[] shaBytes, byte[] derivedPreKey, byte[] encData)
        {
            if (derivedPreKey == null || derivedPreKey.Length < 48) return null;
            byte[] key = SubArray(derivedPreKey, 0, 32);
            byte[] iv = SubArray(derivedPreKey, 32, 16);

            // Pad encData to multiple of 16 with zeros (matches PaddingMode.Zeros).
            int padLen = (16 - (encData.Length % 16)) % 16;
            byte[] padded = encData;
            if (padLen != 0)
            {
                padded = new byte[encData.Length + padLen];
                Array.Copy(encData, padded, encData.Length);
            }

            byte[] plain = CryptoHostHelper.AesCbcDecrypt(key, iv, padded);
            if (plain == null || plain.Length < 64) return null;

            // Native AesManaged with PaddingMode.Zeros, given encData not a
            // multiple of 16, returns plaintext of length encData.Length
            // (the last partial block decrypts plus zero-pad is stripped to
            // match the original input length). When we zero-pad encData
            // ourselves before BCrypt, we get an extra block of decrypted
            // padding at the end — masterKeyFull must skip that extra
            // block, not include it. Slice from (encData.Length - 64),
            // which equals (plain.Length - padLen - 64).
            int effLen = encData.Length;
            if (effLen < 64) return null;
            byte[] masterKeyFull = SubArray(plain, effLen - 64, 64);
            return CryptoHostHelper.Sha1(masterKeyFull);
        }

        // ── helpers ────────────────────────────────────────────────────

        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
            if (hex.Length % 2 != 0) return Array.Empty<byte>();
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        private static byte[] SubArray(byte[] src, int start, int len)
        {
            if (start < 0 || len < 0 || start + len > src.Length)
                return Array.Empty<byte>();
            byte[] dst = new byte[len];
            Array.Copy(src, start, dst, 0, len);
            return dst;
        }

        private static string BytesToHex(byte[] bytes)
        {
            // Uppercase to match SharpDPAPI's BitConverter.ToString format
            // (which produces uppercase hex separated by dashes; we drop the
            // dashes upstream).
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }

        /// <summary>
        /// Drop-in replacement for SharpDPAPI's Crypto.DeriveKey — Microsoft
        /// DPAPI session-key derivation. SharpDPAPI's BCL version calls
        /// HMACSHA512 / SHA1Managed via System.Security.Cryptography, both
        /// of which PNS on NativeAOT-WASI. We route to the HMAC/SHA host
        /// bridges instead.
        ///
        /// algHash: 32782 = CALG_SHA_512, 32772 = CALG_SHA_1
        /// entropy: optional, appended to salt (or to inner buffer for SHA1)
        /// per Microsoft's "magic" DPAPI session-key derivation.
        ///
        /// Returns the derived session key bytes — 64 for SHA512 path,
        /// 20*N for the SHA1 DeriveKeyRaw expansion which the caller will
        /// truncate to the required keyLen.
        /// </summary>
        public static byte[] DeriveKey(byte[] keyBytes, byte[] saltBytes, int algHash, byte[] entropy = null)
        {
            if (keyBytes == null || saltBytes == null)
                return Array.Empty<byte>();

            if (algHash == 32782) // CALG_SHA_512
            {
                byte[] data = entropy != null && entropy.Length > 0
                    ? Combine(saltBytes, entropy)
                    : saltBytes;
                return CryptoHostHelper.HmacSha512(keyBytes, data) ?? Array.Empty<byte>();
            }

            if (algHash == 32772) // CALG_SHA_1 — DPAPI's custom HMAC-like construction
            {
                // Mirror of Crypto.DeriveKey CALG_SHA1 branch (Crypto.cs:123-160).
                // Builds ipad/opad with magic '6'/'\\' bytes XOR'd with the key,
                // then SHA1(opad || SHA1(ipad || salt) [|| entropy]).
                byte[] ipad = new byte[64];
                byte[] opad = new byte[64];
                for (int i = 0; i < 64; i++) { ipad[i] = (byte)'6'; opad[i] = (byte)'\\'; }
                for (int i = 0; i < keyBytes.Length && i < 64; i++)
                {
                    ipad[i] ^= keyBytes[i];
                    opad[i] ^= keyBytes[i];
                }
                byte[] bufferI = Combine(ipad, saltBytes);
                byte[] sha1BufferI = CryptoHostHelper.Sha1(bufferI) ?? Array.Empty<byte>();
                byte[] bufferO = Combine(opad, sha1BufferI);
                if (entropy != null && entropy.Length > 0)
                    bufferO = Combine(bufferO, entropy);
                byte[] sha1Buffer0 = CryptoHostHelper.Sha1(bufferO) ?? Array.Empty<byte>();
                return DeriveKeyRaw(sha1Buffer0, algHash);
            }

            return Array.Empty<byte>();
        }

        // Mimikatz / Crypto.cs:DeriveKeyRaw — expands the 20-byte SHA1 result
        // into a 40-byte stream by SHA1(prefix || hash) with two magic prefixes.
        private static byte[] DeriveKeyRaw(byte[] hashBytes, int algHash)
        {
            byte[] ipad = new byte[64];
            byte[] opad = new byte[64];
            for (int i = 0; i < 64; i++) { ipad[i] = 0x36; opad[i] = 0x5c; }
            for (int i = 0; i < hashBytes.Length && i < 64; i++)
            {
                ipad[i] ^= hashBytes[i];
                opad[i] ^= hashBytes[i];
            }
            byte[] sha1Inner = CryptoHostHelper.Sha1(ipad) ?? Array.Empty<byte>();
            byte[] sha1Outer = CryptoHostHelper.Sha1(opad) ?? Array.Empty<byte>();
            byte[] result = new byte[sha1Inner.Length + sha1Outer.Length];
            Array.Copy(sha1Inner, 0, result, 0, sha1Inner.Length);
            Array.Copy(sha1Outer, 0, result, sha1Inner.Length, sha1Outer.Length);
            return result;
        }

        private static byte[] Combine(byte[] a, byte[] b)
        {
            if (a == null) return b ?? Array.Empty<byte>();
            if (b == null) return a;
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        /// <summary>
        /// Drop-in replacement for SharpDPAPI's Crypto.DecryptBlob. AesManaged
        /// and TripleDESCryptoServiceProvider both throw PlatformNotSupportedException
        /// on NativeAOT-WASI, so route through the AES-CBC host bridge for AES;
        /// 3DES not implemented in this bridge yet.
        ///
        /// algCrypt: 26128 = CALG_AES_256, 26115 = CALG_3DES
        /// paddingMode (matches SharpDPAPI): 0=Zeros, 1=PKCS7
        /// </summary>
        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt, int paddingMode = 0)
        {
            if (ciphertext == null || ciphertext.Length == 0) return Array.Empty<byte>();
            if (key == null || key.Length == 0) return Array.Empty<byte>();

            if (algCrypt == 26128) // CALG_AES_256
            {
                byte[] iv = new byte[16]; // zero IV per SharpDPAPI convention
                // Pad to block size with zeros (Mode.Zeros expectation).
                int padLen = (16 - (ciphertext.Length % 16)) % 16;
                byte[] padded = ciphertext;
                if (padLen != 0)
                {
                    padded = new byte[ciphertext.Length + padLen];
                    Array.Copy(ciphertext, padded, ciphertext.Length);
                }
                byte[] plain = CryptoHostHelper.AesCbcDecrypt(key, iv, padded);
                if (plain == null) return Array.Empty<byte>();
                // If PKCS7 padding, strip it.
                if (paddingMode == 1 && plain.Length > 0)
                {
                    int pad = plain[plain.Length - 1];
                    if (pad >= 1 && pad <= 16)
                    {
                        bool valid = true;
                        for (int i = plain.Length - pad; i < plain.Length; i++)
                            if (plain[i] != pad) { valid = false; break; }
                        if (valid)
                        {
                            byte[] trimmed = new byte[plain.Length - pad];
                            Array.Copy(plain, trimmed, trimmed.Length);
                            return trimmed;
                        }
                    }
                }
                return plain;
            }
            if (algCrypt == 26115) // CALG_3DES
            {
                Console.WriteLine($"[!] WfDpapi.DecryptBlob: CALG_3DES (26115) not yet supported on NativeAOT-WASI bridge");
                return Array.Empty<byte>();
            }
            Console.WriteLine($"[!] WfDpapi.DecryptBlob: unsupported algCrypt={algCrypt}");
            return Array.Empty<byte>();
        }
    }
}
