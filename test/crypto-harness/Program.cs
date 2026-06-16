// CryptoTest — exercises Wf bcrypt.dll-routed crypto wrappers with known vectors.
//
// Build:
//   cd /tmp/wf-crypto-test
//   dotnet publish -c Release -r wasi-wasm
//   <wasmforge> build --wasm bin/Release/net10.0/wasi-wasm/native/CryptoTest.wasm \
//     --nativeaot --win32-apis --no-sign -o /tmp/cryptotest.exe
//
// Run on Win11:
//   cryptotest.exe
//
// Each test prints PASS/FAIL with hex of expected vs actual.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoTest
{
    internal static unsafe class Bridge
    {
        [DllImport("*", EntryPoint = "WfPbkdf2Sha1")]
        public static extern uint Pbkdf2Sha1(byte* pw, uint pwl, byte* salt, uint sl,
            uint iters, uint klen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfPbkdf2Sha256")]
        public static extern uint Pbkdf2Sha256(byte* pw, uint pwl, byte* salt, uint sl,
            uint iters, uint klen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfPbkdf2Sha512")]
        public static extern uint Pbkdf2Sha512(byte* pw, uint pwl, byte* salt, uint sl,
            uint iters, uint klen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfHmacSha1")]
        public static extern uint HmacSha1(byte* key, uint klen,
            byte* data, uint dlen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfHmacSha256")]
        public static extern uint HmacSha256(byte* key, uint klen,
            byte* data, uint dlen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfAesCbcDecrypt")]
        public static extern uint AesCbcDecrypt(byte* key, uint klen, byte* iv, uint ivl,
            byte* data, uint dlen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfSha1")]
        public static extern uint Sha1(byte* data, uint dlen, byte* outBuf, uint outBufLen);

        [DllImport("*", EntryPoint = "WfSha256")]
        public static extern uint Sha256(byte* data, uint dlen, byte* outBuf, uint outBufLen);
    }

    internal static class Program
    {
        static int _passes = 0, _fails = 0;

        static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        static byte[] FromHex(string h)
        {
            h = h.Replace(" ", "").Replace("\n", "");
            var r = new byte[h.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return r;
        }

        static void Check(string name, byte[] expected, byte[] actual)
        {
            string e = Hex(expected), a = Hex(actual);
            if (e == a) { _passes++; Console.WriteLine($"PASS {name}"); }
            else { _fails++; Console.WriteLine($"FAIL {name}\n  exp={e}\n  got={a}"); }
        }

        static unsafe void TestSha1()
        {
            // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
            var data = Encoding.ASCII.GetBytes("abc");
            var outBuf = new byte[20];
            fixed (byte* dp = data, op = outBuf)
                Bridge.Sha1(dp, (uint)data.Length, op, 20);
            Check("SHA1(\"abc\")",
                FromHex("a9993e364706816aba3e25717850c26c9cd0d89d"),
                outBuf);
        }

        static unsafe void TestSha256()
        {
            // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            var data = Encoding.ASCII.GetBytes("abc");
            var outBuf = new byte[32];
            fixed (byte* dp = data, op = outBuf)
                Bridge.Sha256(dp, (uint)data.Length, op, 32);
            Check("SHA256(\"abc\")",
                FromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                outBuf);
        }

        static unsafe void TestHmacSha1()
        {
            // RFC 2202 test case 1: key=20 bytes 0x0b, data="Hi There"
            // → b617318655057264e28bc0b6fb378c8ef146be00
            var key = FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var data = Encoding.ASCII.GetBytes("Hi There");
            var outBuf = new byte[20];
            fixed (byte* kp = key, dp = data, op = outBuf)
                Bridge.HmacSha1(kp, (uint)key.Length, dp, (uint)data.Length, op, 20);
            Check("HMAC-SHA1 RFC2202 #1",
                FromHex("b617318655057264e28bc0b6fb378c8ef146be00"),
                outBuf);
        }

        static unsafe void TestHmacSha256()
        {
            // RFC 4231 test case 1: key=20 bytes 0x0b, data="Hi There"
            // → b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
            var key = FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var data = Encoding.ASCII.GetBytes("Hi There");
            var outBuf = new byte[32];
            fixed (byte* kp = key, dp = data, op = outBuf)
                Bridge.HmacSha256(kp, (uint)key.Length, dp, (uint)data.Length, op, 32);
            Check("HMAC-SHA256 RFC4231 #1",
                FromHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                outBuf);
        }

        static unsafe void TestPbkdf2Sha1()
        {
            // RFC 6070 test 1: P="password", S="salt", c=1, dkLen=20
            // → 0c60c80f961f0e71f3a9b524af6012062fe037a6
            var pw = Encoding.ASCII.GetBytes("password");
            var salt = Encoding.ASCII.GetBytes("salt");
            var outBuf = new byte[20];
            fixed (byte* pp = pw, sp = salt, op = outBuf)
                Bridge.Pbkdf2Sha1(pp, (uint)pw.Length, sp, (uint)salt.Length, 1, 20, op, 20);
            Check("PBKDF2-SHA1 RFC6070 #1",
                FromHex("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
                outBuf);

            // RFC 6070 test 2: P="password", S="salt", c=2, dkLen=20
            // → ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
            var outBuf2 = new byte[20];
            fixed (byte* pp = pw, sp = salt, op = outBuf2)
                Bridge.Pbkdf2Sha1(pp, (uint)pw.Length, sp, (uint)salt.Length, 2, 20, op, 20);
            Check("PBKDF2-SHA1 RFC6070 #2",
                FromHex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
                outBuf2);
        }

        static unsafe void TestPbkdf2Sha256()
        {
            // RFC 7914 PBKDF2-SHA256 test:
            // P="passwd", S="salt", c=1, dkLen=64
            // → 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
            var pw = Encoding.ASCII.GetBytes("passwd");
            var salt = Encoding.ASCII.GetBytes("salt");
            var outBuf = new byte[64];
            fixed (byte* pp = pw, sp = salt, op = outBuf)
                Bridge.Pbkdf2Sha256(pp, (uint)pw.Length, sp, (uint)salt.Length, 1, 64, op, 64);
            Check("PBKDF2-SHA256 RFC7914 #1",
                FromHex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
                outBuf);
        }

        static unsafe void TestPbkdf2Sha512()
        {
            // NIST test: P="password", S="salt", c=1, dkLen=64
            // → 867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce
            var pw = Encoding.ASCII.GetBytes("password");
            var salt = Encoding.ASCII.GetBytes("salt");
            var outBuf = new byte[64];
            fixed (byte* pp = pw, sp = salt, op = outBuf)
                Bridge.Pbkdf2Sha512(pp, (uint)pw.Length, sp, (uint)salt.Length, 1, 64, op, 64);
            Check("PBKDF2-SHA512 NIST #1",
                FromHex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"),
                outBuf);
        }

        static unsafe void TestAesCbcDecrypt()
        {
            // NIST SP 800-38A F.2.1 AES-128-CBC:
            // Key=2b7e151628aed2a6abf7158809cf4f3c
            // IV=000102030405060708090a0b0c0d0e0f
            // Ciphertext=7649abac8119b246cee98e9b12e9197d (16 bytes — first block)
            // Plaintext=6bc1bee22e409f96e93d7e117393172a
            var key = FromHex("2b7e151628aed2a6abf7158809cf4f3c");
            var iv  = FromHex("000102030405060708090a0b0c0d0e0f");
            var ct  = FromHex("7649abac8119b246cee98e9b12e9197d");
            var outBuf = new byte[16];
            fixed (byte* kp = key, ip = iv, cp = ct, op = outBuf)
                Bridge.AesCbcDecrypt(kp, (uint)key.Length, ip, (uint)iv.Length,
                    cp, (uint)ct.Length, op, 16);
            Check("AES-128-CBC NIST F.2.1 block 1",
                FromHex("6bc1bee22e409f96e93d7e117393172a"),
                outBuf);
        }

        static int Main()
        {
            Console.WriteLine("=== Wf BCrypt Bridge Tests ===");
            try { TestSha1(); }            catch (Exception e) { _fails++; Console.WriteLine("FAIL SHA1 threw: " + e.Message); }
            try { TestSha256(); }          catch (Exception e) { _fails++; Console.WriteLine("FAIL SHA256 threw: " + e.Message); }
            try { TestHmacSha1(); }        catch (Exception e) { _fails++; Console.WriteLine("FAIL HmacSha1 threw: " + e.Message); }
            try { TestHmacSha256(); }      catch (Exception e) { _fails++; Console.WriteLine("FAIL HmacSha256 threw: " + e.Message); }
            try { TestPbkdf2Sha1(); }      catch (Exception e) { _fails++; Console.WriteLine("FAIL Pbkdf2Sha1 threw: " + e.Message); }
            try { TestPbkdf2Sha256(); }    catch (Exception e) { _fails++; Console.WriteLine("FAIL Pbkdf2Sha256 threw: " + e.Message); }
            try { TestPbkdf2Sha512(); }    catch (Exception e) { _fails++; Console.WriteLine("FAIL Pbkdf2Sha512 threw: " + e.Message); }
            try { TestAesCbcDecrypt(); }   catch (Exception e) { _fails++; Console.WriteLine("FAIL AesCbcDecrypt threw: " + e.Message); }
            Console.WriteLine($"=== Result: {_passes} PASS, {_fails} FAIL ===");
            return _fails == 0 ? 0 : 1;
        }
    }
}
