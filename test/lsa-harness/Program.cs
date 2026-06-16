// LSA Bridge Triage v3 — restore valid OBJECT_ATTRIBUTES, smaller access.
using System;
using System.Runtime.InteropServices;

namespace LsaTest
{
    internal static unsafe class Bridge
    {
        [DllImport("*", EntryPoint = "LsaOpenPolicy")]
        public static extern uint LsaOpenPolicy(uint systemName, uint objectAttributes,
            uint desiredAccess, uint policyHandle);

        [DllImport("*", EntryPoint = "LsaClose")]
        public static extern uint LsaClose(ulong policyHandle);

        [DllImport("*", EntryPoint = "LsaEnumerateAccountsWithUserRight")]
        public static extern uint LsaEnumerateAccountsWithUserRight(uint policyHandle,
            uint userRights, uint enumerationBuffer, uint countReturned);
    }

    internal static class Program
    {
        static unsafe int Main()
        {
            Console.WriteLine("=== LSA Bridge Triage v3 ===");

            // OBJECT_ATTRIBUTES (48 bytes x64): only Length field matters for LSA.
            byte* objAttrs = stackalloc byte[48];
            for (int i = 0; i < 48; i++) objAttrs[i] = 0;
            *((uint*)objAttrs) = 48;  // Length

            Console.WriteLine($"  objAttrs ptr=0x{((uint)(IntPtr)objAttrs):x8}");

            ulong hPolicy = 0;
            Console.WriteLine($"  &hPolicy=0x{((uint)(IntPtr)(&hPolicy)):x8}");
            uint orc = Bridge.LsaOpenPolicy(
                0,                              // SystemName = NULL
                (uint)(IntPtr)objAttrs,         // ObjectAttributes
                0x20800,                        // POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION
                (uint)(IntPtr)(&hPolicy));
            Console.WriteLine($"LsaOpenPolicy rc=0x{orc:x8} hPolicy=0x{hPolicy:x16}");
            if (orc != 0 || hPolicy == 0)
            {
                Console.WriteLine("  → OpenPolicy failed");
                return 1;
            }

            // LSA_UNICODE_STRING for "SeBatchLogonRight"
            const string rightName = "SeBatchLogonRight";
            int rightBytes = rightName.Length * 2;
            ushort* rightStr = stackalloc ushort[rightName.Length + 1];
            for (int i = 0; i < rightName.Length; i++) rightStr[i] = (ushort)rightName[i];
            rightStr[rightName.Length] = 0;

            byte* lsaStr = stackalloc byte[16];
            for (int i = 0; i < 16; i++) lsaStr[i] = 0;
            *((ushort*)(lsaStr + 0)) = (ushort)rightBytes;
            *((ushort*)(lsaStr + 2)) = (ushort)(rightBytes + 2);
            *((uint*)(lsaStr + 8))  = (uint)(IntPtr)rightStr;

            uint countReturned = 0;
            ulong enumBuf = 0;
            uint erc = Bridge.LsaEnumerateAccountsWithUserRight(
                (uint)hPolicy,
                (uint)(IntPtr)lsaStr,
                (uint)(IntPtr)(&enumBuf),
                (uint)(IntPtr)(&countReturned));
            Console.WriteLine($"LsaEnumerate rc=0x{erc:x8} count={countReturned} buf=0x{enumBuf:x16}");
            if (erc == 0)         Console.WriteLine("  → STATUS_SUCCESS");
            else if (erc == 0xC0000034) Console.WriteLine("  → STATUS_OBJECT_NAME_NOT_FOUND");
            else if (erc == 0xC0000022) Console.WriteLine("  → STATUS_ACCESS_DENIED");
            else if (erc == 0xC000000D) Console.WriteLine("  → STATUS_INVALID_PARAMETER");
            Bridge.LsaClose(hPolicy);
            return erc == 0 ? 0 : 1;
        }
    }
}
