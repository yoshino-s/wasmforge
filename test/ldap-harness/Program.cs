// LdapTest — exercises WfLdapSearch / WfLdapSearchExt against the GOAD DC.
//
// Tests:
//   1. WfLdapSearch with a known DN + filter (no bind) — checks the
//      anonymous LDAP path.
//   2. WfLdapSearchExt with explicit user/domain/password — checks the
//      bind path used by Certify's enum-cas / enum-templates.
//
// Output format: "attr\tvalue\n" per attribute, '\0' between entries.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LdapTest
{
    internal static unsafe class Bridge
    {
        [DllImport("*", EntryPoint = "WfLdapSearch")]
        public static extern uint LdapSearch(
            byte* serverPtr, uint serverLen,
            uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* outBufPtr, uint outBufLen);

        [DllImport("*", EntryPoint = "WfLdapSearchExt")]
        public static extern uint LdapSearchExt(
            byte* serverPtr, uint serverLen, uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* userPtr, uint userLen,
            byte* domainPtr, uint domainLen,
            byte* passwordPtr, uint passwordLen,
            byte* outBufPtr, uint outBufLen);
    }

    internal static class Program
    {
        static unsafe int Main()
        {
            Console.WriteLine("=== LDAP Bridge Triage ===");

            // Test target: configured via WASMFORGE_PARITY_DC / WASMFORGE_PARITY_DOMAIN
            string server   = Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DC") ?? "dc01.example.local";
            string baseDN   = "DC=" + (Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DOMAIN") ?? "example.local").Replace(".", ",DC=");
            string filter   = "(objectClass=user)";
            string attrs    = "samAccountName\tdistinguishedName";  // tab-sep

            // 1) Anonymous LDAP search
            {
                var srvB = Encoding.UTF8.GetBytes(server);
                var bdnB = Encoding.UTF8.GetBytes(baseDN);
                var fltB = Encoding.UTF8.GetBytes(filter);
                var atrB = Encoding.UTF8.GetBytes(attrs);
                var outBuf = new byte[4096];
                uint rc;
                fixed (byte* sp = srvB, dp = bdnB, fp = fltB, ap = atrB, op = outBuf)
                    rc = Bridge.LdapSearch(
                        sp, (uint)srvB.Length, 389,
                        dp, (uint)bdnB.Length,
                        fp, (uint)fltB.Length,
                        ap, (uint)atrB.Length,
                        op, (uint)outBuf.Length);
                Console.WriteLine($"WfLdapSearch(anon) rc=0x{rc:x8} bytes_written={(rc <= outBuf.Length ? rc : 0)}");
                if (rc > 0 && rc <= outBuf.Length)
                {
                    // Show first 200 chars of output
                    string preview = Encoding.UTF8.GetString(outBuf, 0, Math.Min(200, (int)rc));
                    preview = preview.Replace('\0', '|').Replace('\t', '~');
                    Console.WriteLine($"  preview: {preview}");
                }
            }

            // 2) Bound LDAP search (kerberoast-style)
            {
                var srvB = Encoding.UTF8.GetBytes(server);
                var bdnB = Encoding.UTF8.GetBytes(baseDN);
                var fltB = Encoding.UTF8.GetBytes("(servicePrincipalName=*)");
                var atrB = Encoding.UTF8.GetBytes("samAccountName\tservicePrincipalName");
                var usrB = Encoding.UTF8.GetBytes("domainuser");
                var domB = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DOMAIN") ?? "example.local");
                var pwdB = Encoding.UTF8.GetBytes("password");
                var outBuf = new byte[4096];
                uint rc;
                fixed (byte* sp = srvB, dp = bdnB, fp = fltB, ap = atrB,
                              up = usrB, dmp = domB, pp = pwdB, op = outBuf)
                    rc = Bridge.LdapSearchExt(
                        sp, (uint)srvB.Length, 389,
                        dp, (uint)bdnB.Length,
                        fp, (uint)fltB.Length,
                        ap, (uint)atrB.Length,
                        up, (uint)usrB.Length,
                        dmp, (uint)domB.Length,
                        pp, (uint)pwdB.Length,
                        op, (uint)outBuf.Length);
                Console.WriteLine($"WfLdapSearchExt(bind) rc=0x{rc:x8} bytes_written={(rc <= outBuf.Length ? rc : 0)}");
                if (rc > 0 && rc <= outBuf.Length)
                {
                    string preview = Encoding.UTF8.GetString(outBuf, 0, Math.Min(200, (int)rc));
                    preview = preview.Replace('\0', '|').Replace('\t', '~');
                    Console.WriteLine($"  preview: {preview}");
                }
            }
            return 0;
        }
    }
}
