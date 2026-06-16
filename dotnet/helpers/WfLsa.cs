// WfLsa.cs — WasmForge LSA helper: Kerberos ticket enumeration and
// user right assignment enumeration.
//
// Two capabilities are exposed:
//
//   1. WfLsa.EnumerateKerberosTickets()
//      Delegates to the existing WfLsaKerberosOp host bridge
//      ("enumerate_tickets" op), returning KerberosTicketCacheEntry records.
//      Used by SecurityPackagesCredentialsCommand.
//
//   2. WfLsa.EnumerateUserRightAssignments()
//      Calls the WASM-side LSA chain:
//        LsaOpenPolicy → LsaEnumerateAccountsWithUserRight (per right) →
//        ConvertSidToStringSidW → LsaFreeMemory → LsaClose
//      Each LSA_UNICODE_STRING and the LSA_OBJECT_ATTRIBUTES are allocated
//      entirely in host memory via WfHost.HostAlloc so that the nested
//      Buffer pointer is a real host address that survives the wf_call
//      boundary (values >= wasmMemSize are left untranslated by wf_call).
//      Used by UserRightAssignmentsCommand.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    // ── P/Invoke declarations for LSA and SID functions ──────────────────
    // These resolve to the bridge stubs in pinvoke_nativeaot.c and
    // pinvoke_advapi32_ext.c. The EntryPoint names match the exported C symbols.

    internal static unsafe class WfLsaNative
    {
        // advapi32_LsaOpenPolicy (nativeaot.c line ~576)
        // Signature: (SystemName, ObjectAttributes, DesiredAccess, PolicyHandle) → NTSTATUS
        // We pass host addresses for SystemName (NULL=0) and ObjectAttributes,
        // and a WASM address for PolicyHandle output.
        [DllImport("*", EntryPoint = "LsaOpenPolicy_v2")]
        public static extern uint LsaOpenPolicy(
            ulong SystemName,
            ulong ObjectAttributes,
            uint DesiredAccess,
            ulong PolicyHandle);

        // LsaEnumerateAccountsWithUserRight (pinvoke_advapi32_ext.c line ~154)
        // Signature: (PolicyHandle, UserRights, Buffer, CountReturned) → NTSTATUS
        // PolicyHandle: host handle value (uintptr on host — fits in ulong)
        // UserRights:   host address of LSA_UNICODE_STRING
        // Buffer:       host address of pointer-sized output slot
        // CountReturned: host address of ULONG output slot
        [DllImport("*", EntryPoint = "LsaEnumerateAccountsWithUserRight_v2")]
        public static extern uint LsaEnumerateAccountsWithUserRight(
            ulong PolicyHandle,
            ulong UserRights,
            ulong Buffer,
            ulong CountReturned);

        // LsaFreeMemory (nativeaot.c line ~588/803)
        [DllImport("*", EntryPoint = "LsaFreeMemory_v2")]
        public static extern uint LsaFreeMemory(ulong Buffer);

        // LsaClose (nativeaot.c line ~584/799)
        [DllImport("*", EntryPoint = "LsaClose_v2")]
        public static extern uint LsaClose(ulong ObjectHandle);

        // ConvertSidToStringSidW (pinvoke_advapi32_ext.c, also nativeaot.c ~1617)
        // Arg1: host SID pointer, Arg2: host address of LPWSTR* output
        [DllImport("*", EntryPoint = "ConvertSidToStringSidW_v2")]
        public static extern uint ConvertSidToStringSidW(ulong Sid, ulong StringSid);

        // LocalFree for the string allocated by ConvertSidToStringSidW
        [DllImport("*", EntryPoint = "kernel32_LocalFree_v2")]
        public static extern ulong LocalFree(ulong hMem);
    }

    // ── HostLsaUnicodeString ─────────────────────────────────────────────
    // Allocates an LSA_UNICODE_STRING entirely in host memory so that the
    // embedded Buffer pointer is a real x64 host address.
    //
    // LSA_UNICODE_STRING layout on x64:
    //   +0  USHORT Length         (2 bytes)
    //   +2  USHORT MaximumLength  (2 bytes)
    //   +4  4 bytes padding
    //   +8  PWSTR Buffer          (8 bytes — host VA of the UTF-16 string)
    //   Total struct: 16 bytes
    //
    // We allocate one block: 16 bytes (struct) + len(utf16) + 2 (NUL)
    // The UTF-16 chars are written at offset +16.
    // Buffer field (at +8) is set to hostAddress + 16.
    internal sealed class HostLsaUnicodeString : IDisposable
    {
        public int Handle { get; }
        public ulong HostAddress { get; }

        private bool _disposed;

        public HostLsaUnicodeString(string s)
        {
            byte[] utf16 = Encoding.Unicode.GetBytes(s ?? "");
            ushort len = (ushort)utf16.Length;
            ushort maxLen = (ushort)(utf16.Length + 2); // include NUL terminator space

            int total = 16 + utf16.Length + 2;
            Handle = WfHost.HostAlloc(total);
            HostAddress = WfHost.GetHostAddress(Handle);

            // Write Length (low 16) and MaximumLength (high 16) packed into uint32 at +0
            uint packed = (uint)len | ((uint)maxLen << 16);
            WfHost.HostWriteUInt32(Handle, 0, packed);

            // Padding at +4 (zero by HostAlloc; write explicitly for clarity)
            WfHost.HostWriteUInt32(Handle, 4, 0);

            // Buffer pointer at +8: points to HostAddress + 16 (where the UTF-16 data lives)
            WfHost.HostWriteUInt64(Handle, 8, HostAddress + 16);

            // Write the UTF-16 string data at +16 (NUL terminator is zero from HostAlloc)
            if (utf16.Length > 0)
                WfHost.HostWrite(Handle, 16, utf16);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (Handle != 0)
                WfHost.HostFree(Handle);
        }
    }

    // ── WfLsa ─────────────────────────────────────────────────────────────
    public static class WfLsa
    {
        // Well-known user rights — matches Seatbelt's _allPrivileges list.
        private static readonly string[] WellKnownRights = new[]
        {
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeBatchLogonRight", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege",
            "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege",
            "SeDenyBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyNetworkLogonRight",
            "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight",
            "SeEnableDelegationPrivilege", "SeImpersonatePrivilege",
            "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege", "SeInteractiveLogonRight",
            "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
            "SeManageVolumePrivilege", "SeNetworkLogonRight",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege",
            "SeRemoteInteractiveLogonRight", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeServiceLogonRight",
            "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege",
            "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege",
            "SeUnsolicitedInputPrivilege",
        };

        // STATUS_NO_MORE_ENTRIES — normal result when no accounts hold a right.
        private const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;

        // POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES
        private const uint POLICY_ACCESS = 0x00000801;

        // ── EnumerateKerberosTickets ─────────────────────────────────────
        // Returns Kerberos ticket cache entries for all logon sessions by
        // delegating to the WfLsaKerberosOp host bridge.
        public static List<WasmForge.Bridge.KerberosTicketCacheEntry> EnumerateKerberosTickets(
            uint luidLow = 0, uint luidHigh = 0)
        {
            return WasmForge.Bridge.LsaHostHelper.EnumerateTickets(luidLow, luidHigh);
        }

        // ── EnumerateUserRightAssignments ────────────────────────────────
        // Returns (rightName, sidString) pairs for all accounts holding each
        // well-known privilege or logon right.
        //
        // Architecture: all struct pointers are allocated in host memory via
        // WfHost.HostAlloc so that they survive the wf_call bridge boundary
        // without being mis-translated as WASM linear memory addresses.
        public static unsafe IEnumerable<(string Right, string Sid)> EnumerateUserRightAssignments()
        {
            var results = new List<(string, string)>();

            // Allocate LSA_OBJECT_ATTRIBUTES in host memory (48 bytes on x64, all zero except Length).
            int oaHandle = WfHost.HostAlloc(48);
            try
            {
                WfHost.HostWriteUInt32(oaHandle, 0, 48); // Length field
                ulong oaAddr = WfHost.GetHostAddress(oaHandle);

                // Allocate output slot for LsaOpenPolicy's PolicyHandle output (8 bytes = uintptr).
                int polHandleSlot = WfHost.HostAlloc(8);
                try
                {
                    ulong polHandleAddr = WfHost.GetHostAddress(polHandleSlot);

                    uint status = WfLsaNative.LsaOpenPolicy(0, oaAddr, POLICY_ACCESS, polHandleAddr);
                    if (status != 0)
                        return results;

                    // Read back the policy handle value (host pointer, 8 bytes).
                    ulong hPolicy = ReadHostUInt64(polHandleAddr);
                    if (hPolicy == 0)
                        return results;

                    try
                    {
                        results = EnumerateRightsWithPolicy(hPolicy);
                    }
                    finally
                    {
                        WfLsaNative.LsaClose(hPolicy);
                    }
                }
                finally
                {
                    WfHost.HostFree(polHandleSlot);
                }
            }
            finally
            {
                WfHost.HostFree(oaHandle);
            }

            return results;
        }

        private static unsafe List<(string, string)> EnumerateRightsWithPolicy(ulong hPolicy)
        {
            var results = new List<(string, string)>();

            // Allocate output slots once and reuse across iterations.
            int bufPtrSlot = WfHost.HostAlloc(8);   // output: host pointer to LSA_ENUMERATION_INFORMATION[]
            int countSlot = WfHost.HostAlloc(4);     // output: ULONG count

            try
            {
                ulong bufPtrAddr = WfHost.GetHostAddress(bufPtrSlot);
                ulong countAddr = WfHost.GetHostAddress(countSlot);

                foreach (string right in WellKnownRights)
                {
                    // Reset output slots.
                    WfHost.HostWriteUInt64(bufPtrSlot, 0, 0);
                    WfHost.HostWriteUInt32(countSlot, 0, 0);

                    using var rightStr = new HostLsaUnicodeString(right);

                    uint st = WfLsaNative.LsaEnumerateAccountsWithUserRight(
                        hPolicy,
                        rightStr.HostAddress,
                        bufPtrAddr,
                        countAddr);

                    // STATUS_NO_MORE_ENTRIES = no accounts have this right — normal.
                    if (st == STATUS_NO_MORE_ENTRIES)
                        continue;

                    if (st != 0)
                        continue; // Any other error — skip silently.

                    uint count = WfHost.ReadHostUInt32(countAddr, 0);
                    ulong bufHostAddr = ReadHostUInt64(bufPtrAddr);

                    if (count == 0 || bufHostAddr == 0)
                        continue;

                    // Each LSA_ENUMERATION_INFORMATION is a single PSID (8 bytes on x64).
                    const uint entrySize = 8;

                    // Allocate a slot to receive the LPWSTR* from ConvertSidToStringSidW.
                    int sidStrPtrSlot = WfHost.HostAlloc(8);
                    try
                    {
                        ulong sidStrPtrAddr = WfHost.GetHostAddress(sidStrPtrSlot);

                        for (uint i = 0; i < count; i++)
                        {
                            ulong entryAddr = bufHostAddr + i * entrySize;

                            // Read the SID host pointer from the entry.
                            ulong sidPtr = ReadHostUInt64(entryAddr);
                            if (sidPtr == 0)
                                continue;

                            // Reset SID string output slot.
                            WfHost.HostWriteUInt64(sidStrPtrSlot, 0, 0);

                            uint cvt = WfLsaNative.ConvertSidToStringSidW(sidPtr, sidStrPtrAddr);
                            if (cvt == 0)
                                continue;

                            ulong sidStrHostAddr = ReadHostUInt64(sidStrPtrAddr);
                            if (sidStrHostAddr == 0)
                                continue;

                            string sid = ReadHostUtf16(sidStrHostAddr);
                            WfLsaNative.LocalFree(sidStrHostAddr);

                            if (!string.IsNullOrEmpty(sid))
                                results.Add((right, sid));
                        }
                    }
                    finally
                    {
                        WfHost.HostFree(sidStrPtrSlot);
                    }

                    WfLsaNative.LsaFreeMemory(bufHostAddr);
                }
            }
            finally
            {
                WfHost.HostFree(bufPtrSlot);
                WfHost.HostFree(countSlot);
            }

            return results;
        }

        // ── Host memory read helpers ─────────────────────────────────────

        // Read a uint64 from an arbitrary host address using WfHost.ReadHostUInt32 twice.
        private static ulong ReadHostUInt64(ulong hostAddr)
        {
            uint lo = WfHost.ReadHostUInt32(hostAddr, 0);
            uint hi = WfHost.ReadHostUInt32(hostAddr + 4, 0);
            return (ulong)lo | ((ulong)hi << 32);
        }

        // Read a NUL-terminated UTF-16 string from an arbitrary host address.
        // Reads up to 512 UTF-16 code units (1024 bytes) to bound the scan.
        private static string ReadHostUtf16(ulong hostAddr)
        {
            if (hostAddr == 0)
                return string.Empty;

            // Find the length by scanning for the NUL terminator.
            int maxLen = 512;
            int charLen = 0;
            for (int i = 0; i < maxLen; i++)
            {
                // ReadHostUInt32 reads 4 bytes; we use offset within that for each UTF-16 char.
                uint chunk = WfHost.ReadHostUInt32(hostAddr + (ulong)(i * 2), 0);
                ushort ch = (ushort)(chunk & 0xFFFF);
                if (ch == 0)
                    break;
                charLen++;
            }

            if (charLen == 0)
                return string.Empty;

            // Read the UTF-16 bytes (charLen * 2 bytes).
            byte[] bytes = WfHost.ReadHostBytes(hostAddr, (uint)(charLen * 2));
            return Encoding.Unicode.GetString(bytes);
        }
    }
}
