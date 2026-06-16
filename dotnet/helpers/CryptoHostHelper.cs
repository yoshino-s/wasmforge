// CryptoHostHelper.cs — C# wrapper for Kerberos hash host function.
//
// Bridges Rubeus's KerberosPasswordHash() to the WasmForge host function
// that calls CDLocateCSystem + KERB_ECRYPT on the host. The KERB_ECRYPT
// struct contains host function pointers that cannot be called from WASM,
// so the entire hash computation runs on the host side.

using System;
using System.Text;

namespace WasmForge.Bridge
{
    /// <summary>
    /// Bridges Rubeus Kerberos crypto to WasmForge host functions.
    /// </summary>
    public static class CryptoHostHelper
    {
        /// <summary>
        /// Compute a Kerberos password hash using the host's CDLocateCSystem.
        /// Drop-in replacement for Crypto.KerberosPasswordHash().
        /// Returns uppercase hex string matching Rubeus's BitConverter.ToString().Replace("-","") format.
        /// </summary>
        public static string KerberosPasswordHash(int etype, string password, string salt = "", int count = 4096)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password ?? "");
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt ?? "");
            byte[] outBuf = new byte[WfHostBridge.SmallBufSize];

            uint written;
            unsafe
            {
                fixed (byte* pwdPtr = passwordBytes)
                fixed (byte* sltPtr = saltBytes)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.KerberosHash(
                        (uint)etype,
                        pwdPtr, (uint)passwordBytes.Length,
                        sltPtr, (uint)saltBytes.Length,
                        (uint)count,
                        outPtr, (uint)outBuf.Length);
                }
            }

            if (written == 0) return "";

            // Host returns hex string; ensure uppercase for Rubeus parity
            return Encoding.UTF8.GetString(outBuf, 0, (int)written).ToUpper();
        }

        /// <summary>
        /// Encrypt data using Kerberos encryption (CDLocateCSystem on host).
        /// Drop-in replacement for Crypto.KerberosEncrypt().
        /// </summary>
        public static byte[] KerberosEncrypt(int eType, int keyUsage, byte[] key, byte[] data)
        {
            byte[] outBuf = new byte[data.Length + 256]; // extra for block padding + checksum
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = key)
                fixed (byte* dataPtr = data)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.KerberosEncrypt(
                        (uint)eType, (uint)keyUsage,
                        keyPtr, (uint)key.Length,
                        dataPtr, (uint)data.Length,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>
        /// Decrypt data using Kerberos decryption (CDLocateCSystem on host).
        /// Drop-in replacement for Crypto.KerberosDecrypt().
        /// </summary>
        public static byte[] KerberosDecrypt(int eType, int keyUsage, byte[] key, byte[] data)
        {
            byte[] outBuf = new byte[data.Length + 256];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = key)
                fixed (byte* dataPtr = data)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.KerberosDecrypt(
                        (uint)eType, (uint)keyUsage,
                        keyPtr, (uint)key.Length,
                        dataPtr, (uint)data.Length,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>
        /// Compute a Kerberos checksum (CDLocateCheckSum on host).
        /// Drop-in replacement for Crypto.KerberosChecksum().
        /// </summary>
        public static byte[] KerberosChecksum(byte[] key, byte[] data, int cksumType = -138, int keyUsage = 17)
        {
            byte[] outBuf = new byte[256];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = key)
                fixed (byte* dataPtr = data)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.KerberosChecksum(
                        (uint)cksumType, (uint)keyUsage,
                        keyPtr, (uint)key.Length,
                        dataPtr, (uint)data.Length,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>
        /// PBKDF2-HMAC-SHA1. Used by DPAPI master key derivation.
        /// </summary>
        public static byte[] Pbkdf2Sha1(byte[] password, byte[] salt, int iterations, int keyLength)
        {
            byte[] outBuf = new byte[keyLength];
            byte[] pwd = (password != null && password.Length > 0) ? password : new byte[1];
            byte[] slt = (salt != null && salt.Length > 0) ? salt : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* pwdPtr = pwd)
                fixed (byte* saltPtr = slt)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.Pbkdf2Sha1(
                        pwdPtr, (uint)(password?.Length ?? 0),
                        saltPtr, (uint)(salt?.Length ?? 0),
                        (uint)iterations, (uint)keyLength,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>PBKDF2-HMAC-SHA512. Used by AES-256 DPAPI master keys.</summary>
        public static byte[] Pbkdf2Sha512(byte[] password, byte[] salt, int iterations, int keyLength)
        {
            byte[] outBuf = new byte[keyLength];
            byte[] pwd = (password != null && password.Length > 0) ? password : new byte[1];
            byte[] slt = (salt != null && salt.Length > 0) ? salt : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* pwdPtr = pwd)
                fixed (byte* saltPtr = slt)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.Pbkdf2Sha512(
                        pwdPtr, (uint)(password?.Length ?? 0),
                        saltPtr, (uint)(salt?.Length ?? 0),
                        (uint)iterations, (uint)keyLength,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>
        /// PBKDF2-HMAC-SHA256. Used by newer DPAPI master keys.
        /// </summary>
        public static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int keyLength)
        {
            byte[] outBuf = new byte[keyLength];
            byte[] pwd = (password != null && password.Length > 0) ? password : new byte[1];
            byte[] slt = (salt != null && salt.Length > 0) ? salt : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* pwdPtr = pwd)
                fixed (byte* saltPtr = slt)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.Pbkdf2Sha256(
                        pwdPtr, (uint)(password?.Length ?? 0),
                        saltPtr, (uint)(salt?.Length ?? 0),
                        (uint)iterations, (uint)keyLength,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>HMAC-SHA1(key, data).</summary>
        public static byte[] HmacSha1(byte[] key, byte[] data)
        {
            byte[] outBuf = new byte[20];
            byte[] k = (key != null && key.Length > 0) ? key : new byte[1];
            byte[] d = (data != null && data.Length > 0) ? data : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = k)
                fixed (byte* dataPtr = d)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.HmacSha1(
                        keyPtr, (uint)(key?.Length ?? 0),
                        dataPtr, (uint)(data?.Length ?? 0),
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>HMAC-SHA256(key, data).</summary>
        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            byte[] outBuf = new byte[32];
            byte[] k = (key != null && key.Length > 0) ? key : new byte[1];
            byte[] d = (data != null && data.Length > 0) ? data : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = k)
                fixed (byte* dataPtr = d)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.HmacSha256(
                        keyPtr, (uint)(key?.Length ?? 0),
                        dataPtr, (uint)(data?.Length ?? 0),
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>HMAC-SHA512(key, data) → 64-byte MAC. Used by Microsoft
        /// DPAPI session-key derivation in SharpDPAPI credentials/vault parsers.</summary>
        public static byte[] HmacSha512(byte[] key, byte[] data)
        {
            byte[] outBuf = new byte[64];
            byte[] k = (key != null && key.Length > 0) ? key : new byte[1];
            byte[] d = (data != null && data.Length > 0) ? data : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = k)
                fixed (byte* dataPtr = d)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.HmacSha512(
                        keyPtr, (uint)(key?.Length ?? 0),
                        dataPtr, (uint)(data?.Length ?? 0),
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>SHA1(data).</summary>
        public static byte[] Sha1(byte[] data)
        {
            byte[] outBuf = new byte[20];
            byte[] d = (data != null && data.Length > 0) ? data : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* dataPtr = d)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.Sha1(dataPtr, (uint)(data?.Length ?? 0),
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA512 (the "MS PBKDF2 bug"). Required for
        /// Windows DPAPI master-key parity — see WfHostBridge.MsPbkdf2Sha512 rationale.</summary>
        public static byte[] MsPbkdf2Sha512(byte[] password, byte[] salt, int iterations, int keyLen)
        {
            if (password == null || salt == null || keyLen <= 0) return null;
            byte[] outBuf = new byte[keyLen];
            uint written;
            unsafe
            {
                fixed (byte* pwPtr = password)
                fixed (byte* sPtr = salt)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.MsPbkdf2Sha512(
                        pwPtr, (uint)password.Length,
                        sPtr, (uint)salt.Length,
                        (uint)iterations,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            if (written < (uint)keyLen)
            {
                byte[] trimmed = new byte[written];
                Array.Copy(outBuf, trimmed, written);
                return trimmed;
            }
            return outBuf;
        }

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA1 variant. See MsPbkdf2Sha512 for rationale.</summary>
        public static byte[] MsPbkdf2Sha1(byte[] password, byte[] salt, int iterations, int keyLen)
        {
            if (password == null || salt == null || keyLen <= 0) return null;
            byte[] outBuf = new byte[keyLen];
            uint written;
            unsafe
            {
                fixed (byte* pwPtr = password)
                fixed (byte* sPtr = salt)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.MsPbkdf2Sha1(
                        pwPtr, (uint)password.Length,
                        sPtr, (uint)salt.Length,
                        (uint)iterations,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            if (written < (uint)keyLen)
            {
                byte[] trimmed = new byte[written];
                Array.Copy(outBuf, trimmed, written);
                return trimmed;
            }
            return outBuf;
        }

        /// <summary>SHA256(data).</summary>
        public static byte[] Sha256(byte[] data)
        {
            byte[] outBuf = new byte[32];
            byte[] d = (data != null && data.Length > 0) ? data : new byte[1];
            uint written;
            unsafe
            {
                fixed (byte* dataPtr = d)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.Sha256(dataPtr, (uint)(data?.Length ?? 0),
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>
        /// AES-CBC decrypt (no padding). keyLength must be 16/24/32 bytes,
        /// IV must be 16 bytes, data length must be a multiple of 16.
        /// </summary>
        public static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32)) return null;
            if (iv == null || iv.Length != 16) return null;
            if (data == null || data.Length == 0 || data.Length % 16 != 0) return null;

            byte[] outBuf = new byte[data.Length];
            uint written;
            unsafe
            {
                fixed (byte* keyPtr = key)
                fixed (byte* ivPtr = iv)
                fixed (byte* dataPtr = data)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.AesCbcDecrypt(
                        keyPtr, (uint)key.Length,
                        ivPtr, (uint)iv.Length,
                        dataPtr, (uint)data.Length,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        // ────────────────────────────────────────────────────────────────
        // Generic crypto dispatcher (WfCryptoOp)
        //
        // Single host trip per operation. Used for primitives that would
        // otherwise pay per-iteration WASM↔host boundary cost (notably
        // MS-PBKDF2 — Windows DPAPI master-key derivation).
        //
        // Wire format: args = sequence of length-prefixed byte fields.
        //   Each field: uint32 little-endian length, then `length` bytes.
        //
        // Opcode strings are typed as constants below so a typo at a call
        // site becomes a compiler error rather than a silent null at
        // runtime (the Go-side dispatcher returns 0 for unknown opcodes).

        private const string OpSha1            = "sha1";
        private const string OpSha256          = "sha256";
        private const string OpSha512          = "sha512";
        private const string OpHmac1           = "hmac1";
        private const string OpHmac256         = "hmac256";
        private const string OpHmac512         = "hmac512";
        private const string OpPbkdf2_1        = "pbkdf2_1";
        private const string OpPbkdf2_256      = "pbkdf2_256";
        private const string OpPbkdf2_512      = "pbkdf2_512";
        private const string OpMsPbkdf2_1      = "mspbkdf2_1";
        private const string OpMsPbkdf2_512    = "mspbkdf2_512";
        private const string OpAesCbcDecrypt   = "aescbcdec";

        private static byte[] PackFields(params byte[][] fields)
        {
            int total = 0;
            foreach (var f in fields) total += 4 + (f?.Length ?? 0);
            byte[] buf = new byte[total];
            int o = 0;
            foreach (var f in fields)
            {
                int n = f?.Length ?? 0;
                buf[o + 0] = (byte)(n & 0xff);
                buf[o + 1] = (byte)((n >> 8) & 0xff);
                buf[o + 2] = (byte)((n >> 16) & 0xff);
                buf[o + 3] = (byte)((n >> 24) & 0xff);
                o += 4;
                if (n > 0) { Array.Copy(f, 0, buf, o, n); o += n; }
            }
            return buf;
        }

        private static byte[] Uint32LE(uint v)
        {
            return new byte[] { (byte)(v & 0xff), (byte)((v >> 8) & 0xff), (byte)((v >> 16) & 0xff), (byte)((v >> 24) & 0xff) };
        }

        private static byte[] InvokeCryptoOp(string op, byte[] args, int outCap)
        {
            byte[] opBytes = System.Text.Encoding.ASCII.GetBytes(op);
            byte[] outBuf = new byte[outCap];
            uint written;
            unsafe
            {
                fixed (byte* opPtr = opBytes)
                fixed (byte* argsPtr = args)
                fixed (byte* outPtr = outBuf)
                {
                    written = WfHostBridge.CryptoOp(
                        opPtr, (uint)opBytes.Length,
                        argsPtr, (uint)args.Length,
                        outPtr, (uint)outBuf.Length);
                }
            }
            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, written);
            return result;
        }

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA512 via generic dispatcher.
        /// Single host trip for the entire derivation — see WfHostBridge.CryptoOp.</summary>
        public static byte[] MsPbkdf2Sha512Op(byte[] password, byte[] salt, int iterations, int keyLen)
        {
            if (password == null || salt == null || keyLen <= 0) return null;
            byte[] args = PackFields(password, salt, Uint32LE((uint)iterations), Uint32LE((uint)keyLen));
            return InvokeCryptoOp(OpMsPbkdf2_512, args, keyLen);
        }

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA1 via generic dispatcher.</summary>
        public static byte[] MsPbkdf2Sha1Op(byte[] password, byte[] salt, int iterations, int keyLen)
        {
            if (password == null || salt == null || keyLen <= 0) return null;
            byte[] args = PackFields(password, salt, Uint32LE((uint)iterations), Uint32LE((uint)keyLen));
            return InvokeCryptoOp(OpMsPbkdf2_1, args, keyLen);
        }
    }
}
