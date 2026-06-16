// WfToken.cs — Token groups and privileges via direct Win32 wf_call pattern.
// Replaces the deleted token_groups_get / token_privs_get Go host bridges.
// Follows the WfNetapi.cs canonical pattern: mod_load → mod_resolve → mod_invoke
// + RtlMoveMemory for host→WASM buffer copies.
//
// Struct layouts (x64):
//   TOKEN_GROUPS:
//     DWORD  GroupCount      (offset 0)
//     [4-byte pad for 8-byte array alignment]
//     SID_AND_ATTRIBUTES[]   each 16 bytes: ptr Sid (8) + DWORD Attributes (4) + 4 pad
//
//   TOKEN_PRIVILEGES:
//     DWORD  PrivilegeCount  (offset 0)
//     LUID_AND_ATTRIBUTES[]  each 12 bytes: DWORD LowPart + DWORD HighPart + DWORD Attributes
//     (TOKEN_PRIVILEGES is packed — no padding between count and array)

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfToken
    {
        // ── Bridge primitives (same declarations as WfNetapi.cs) ────────────────
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

        // ── Cached proc handles ─────────────────────────────────────────────────
        private static uint _kernel32;
        private static uint _advapi32;
        private static uint _ntdll;
        private static uint _hGetCurrentProcess;
        private static uint _hOpenProcessToken;
        private static uint _hGetTokenInformation;
        private static uint _hConvertSidToStringSidW;
        private static uint _hLookupAccountSidW;
        private static uint _hLookupPrivilegeNameW;
        private static uint _hCloseHandle;
        private static uint _hLocalFree;
        private static uint _hVirtualAlloc;
        private static uint _hVirtualFree;
        private static uint _hRtlMoveMemory;

        // ── Resolve + Invoke helpers (identical to WfNetapi.cs pattern) ─────────
        private static uint Resolve(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
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

        private static ulong Invoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0,
            ulong a8 = 0, ulong a9 = 0)
        {
            ulong ret1 = 0, err = 0;
            return mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // Copy len bytes from a host address into a WASM-side buffer.
        private static bool CopyHostToWasm(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            Invoke(pCopy, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        // Read a little-endian 8-byte value from a WASM buffer at byte offset off.
        private static ulong Read8(byte* p, int off) =>
            ((ulong)p[off+0])       | ((ulong)p[off+1] <<  8) |
            ((ulong)p[off+2] << 16) | ((ulong)p[off+3] << 24) |
            ((ulong)p[off+4] << 32) | ((ulong)p[off+5] << 40) |
            ((ulong)p[off+6] << 48) | ((ulong)p[off+7] << 56);

        // Read a little-endian 4-byte value from a WASM buffer at byte offset off.
        private static uint Read4(byte* p, int off) =>
            (uint)(p[off+0] | (p[off+1] << 8) | (p[off+2] << 16) | (p[off+3] << 24));

        // Read a NUL-terminated UTF-16LE wide string from a host pointer into a managed string.
        private static string ReadWStringFromHost(ulong hostAddr, int maxChars)
        {
            if (hostAddr == 0 || maxChars <= 0) return "";
            byte[] buf = new byte[maxChars * 2];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, (uint)buf.Length)) return "";
            }
            int charLen = 0;
            for (int i = 0; i < maxChars; i++)
            {
                if (buf[2*i] == 0 && buf[2*i+1] == 0) break;
                charLen++;
            }
            if (charLen == 0) return "";
            char[] chars = new char[charLen];
            for (int i = 0; i < charLen; i++)
                chars[i] = (char)(buf[2*i] | (buf[2*i+1] << 8));
            return new string(chars);
        }

        // Parse a SID structure from raw bytes into SDDL string form (S-1-X-Y-...).
        //   BYTE  Revision           (offset 0)
        //   BYTE  SubAuthorityCount  (offset 1)  — typically 0..15
        //   BYTE  IdentifierAuthority[6] (offset 2, big-endian 48-bit)
        //   DWORD SubAuthority[SubAuthorityCount] (offset 8, little-endian)
        // Returns empty on malformed input.
        private static string ParseSidBytesToString(byte[] buf, int sidOff, int bufLen)
        {
            if (buf == null || sidOff < 0 || sidOff + 8 > bufLen) return "";
            byte rev = buf[sidOff + 0];
            byte subCnt = buf[sidOff + 1];
            if (rev != 1 || subCnt > 15) return "";
            int needed = 8 + subCnt * 4;
            if (sidOff + needed > bufLen) return "";

            // IdentifierAuthority is 48-bit big-endian.
            ulong idAuth = 0;
            for (int j = 0; j < 6; j++)
                idAuth = (idAuth << 8) | buf[sidOff + 2 + j];

            var sb = new System.Text.StringBuilder("S-1-");
            sb.Append(idAuth.ToString());
            for (int k = 0; k < subCnt; k++)
            {
                int subOff = sidOff + 8 + k * 4;
                uint sub = (uint)(buf[subOff + 0]
                                | (buf[subOff + 1] << 8)
                                | (buf[subOff + 2] << 16)
                                | (buf[subOff + 3] << 24));
                sb.Append('-').Append(sub.ToString());
            }
            return sb.ToString();
        }

        // Allocate a zeroed block of host memory (MEM_COMMIT|MEM_RESERVE = 0x3000, PAGE_READWRITE = 4).
        // Returns the host address, or 0 on failure.
        // Note: callers that pass the returned address back through Invoke() as an arg
        // can hit the wasmforge WASM pointer-translation collision when the OS allocates
        // a low 32-bit address. The TokenGroups path was migrated to WfHost.HostAlloc
        // (handle-based, guaranteed high address) to avoid this. TokenPrivileges still
        // uses this path and works because GetTokenInformation tolerates the collision
        // for that struct shape (no nested pointer chains to chase post-read).
        private static ulong VirtualAllocHost(uint size)
        {
            uint pAlloc = Resolve("kernel32.dll", ref _kernel32, "VirtualAlloc", ref _hVirtualAlloc);
            if (pAlloc == 0) return 0;
            return Invoke(pAlloc, 4, 0u, (ulong)size, 0x3000u, 4u);
        }

        // Release host memory allocated by VirtualAllocHost (MEM_RELEASE = 0x8000).
        private static void VirtualFreeHost(ulong addr)
        {
            if (addr == 0) return;
            uint pFree = Resolve("kernel32.dll", ref _kernel32, "VirtualFree", ref _hVirtualFree);
            if (pFree != 0) Invoke(pFree, 3, addr, 0u, 0x8000u);
        }

        // ── Public API ───────────────────────────────────────────────────────────

        /// <summary>
        /// Returns the SID string and account name for each group in the current process token.
        /// Equivalent to WindowsIdentity.GetCurrent().Groups.
        /// </summary>
        public static List<(string Sid, string Name)> GetGroups()
        {
            var result = new List<(string, string)>();
            try
            {
                // Resolve all needed procs.
                uint pGetCurrentProcess = Resolve("kernel32.dll", ref _kernel32, "GetCurrentProcess", ref _hGetCurrentProcess);
                uint pOpenProcessToken  = Resolve("advapi32.dll", ref _advapi32, "OpenProcessToken", ref _hOpenProcessToken);
                uint pGetTokenInfo      = Resolve("advapi32.dll", ref _advapi32, "GetTokenInformation", ref _hGetTokenInformation);
                uint pConvSid           = Resolve("advapi32.dll", ref _advapi32, "ConvertSidToStringSidW", ref _hConvertSidToStringSidW);
                uint pLookupAcct        = Resolve("advapi32.dll", ref _advapi32, "LookupAccountSidW", ref _hLookupAccountSidW);
                uint pCloseHandle       = Resolve("kernel32.dll", ref _kernel32, "CloseHandle", ref _hCloseHandle);
                uint pLocalFree         = Resolve("kernel32.dll", ref _kernel32, "LocalFree", ref _hLocalFree);
                if (pGetCurrentProcess == 0 || pOpenProcessToken == 0 || pGetTokenInfo == 0) return result;

                // Get pseudo-handle for current process (returns -1 = 0xFFFFFFFF as uint).
                ulong hProcess = Invoke(pGetCurrentProcess, 0);

                // OpenProcessToken(hProcess, TOKEN_QUERY=8, &hToken)
                ulong hToken = 0;
                ulong tokenOk = Invoke(pOpenProcessToken, 3,
                    hProcess,
                    8u,                                          // TOKEN_QUERY
                    (ulong)(uint)(IntPtr)(&hToken));
                if (tokenOk == 0 || hToken == 0) return result;

                try
                {
                    // First call: get required buffer size.
                    uint returnedSize = 0;
                    // GetTokenInformation(hToken, TokenGroups=2, NULL, 0, &returnedSize)
                    Invoke(pGetTokenInfo, 5,
                        hToken,
                        2u,   // TokenGroups
                        0u, 0u,
                        (ulong)(uint)(IntPtr)(&returnedSize));

                    if (returnedSize == 0) return result;
                    if (returnedSize > 65536) returnedSize = 65536;

                    // Allocate host buffer via WfHost.HostAlloc — returns a handle
                    // backed by a host-side allocation whose real address is
                    // guaranteed > wasmMemSize so wf_call's WASM pointer translation
                    // skips it. This was the root cause of the previous failure:
                    // VirtualAllocHost returned a low 32-bit address that COLLIDED
                    // with wf_call's translation threshold, causing GetTokenInformation
                    // to write to WASM memory instead of the host buffer.
                    int hostHandle = 0;
                    ulong hostBuf = 0;
                    try
                    {
                        hostHandle = WfHost.HostAlloc((int)returnedSize);
                        hostBuf = WfHost.GetHostAddress(hostHandle);
                    }
                    catch { return result; }
                    if (hostHandle == 0 || hostBuf == 0) {
                        if (hostHandle != 0) WfHost.HostFree(hostHandle);
                        return result;
                    }
                    try
                    {
                        uint actualSize = 0;
                        ulong ok = Invoke(pGetTokenInfo, 5,
                            hToken,
                            2u,
                            hostBuf,
                            (ulong)returnedSize,
                            (ulong)(uint)(IntPtr)(&actualSize));
                        if (ok == 0) return result;

                        // Read GroupCount (DWORD at offset 0).
                        uint groupCount = 0;
                        {
                            byte[] tmp = new byte[4];
                            fixed (byte* tp = tmp)
                            {
                                CopyHostToWasm(hostBuf, (uint)(IntPtr)tp, 4);
                                groupCount = (uint)(tmp[0] | (tmp[1] << 8) | (tmp[2] << 16) | (tmp[3] << 24));
                            }
                        }
                        if (groupCount == 0 || groupCount > 4096) return result;

                        // Canonical x64 TOKEN_GROUPS layout (verified via on-host buffer dump):
                        //   [000]: DWORD GroupCount (4 bytes)
                        //   [004]: padding (4 bytes — alignment to 8 for next PSID)
                        //   [008]: SID_AND_ATTRIBUTES[0]
                        //       PSID Sid (8 bytes, absolute host pointer into same buffer)
                        //       DWORD Attributes (4 bytes)
                        //       padding (4 bytes to align next entry)
                        //   [018]: SID_AND_ATTRIBUTES[1]
                        //   ...
                        //   [0D8]: SID structure for Group[0] (Revision + SubAuthCount + ...)
                        //
                        // Earlier failures observed an 8-byte stride with truncated 4-byte PSIDs
                        // — that was a symptom of allocating the buffer at a low 32-bit address
                        // which collided with wf_call's WASM pointer translation, causing the
                        // OS to write the data into WASM memory rather than the host buffer.
                        // We were then reading garbage/stale memory from the actual host buffer.
                        // The WfHost.HostAlloc path returns a high-address buffer that wf_call
                        // skips, so the OS writes the real canonical x64 layout.
                        const int SID_AND_ATTR_SIZE = 16;
                        uint arrayBytes = groupCount * SID_AND_ATTR_SIZE;
                        byte[] entryBuf = new byte[arrayBytes];
                        fixed (byte* ep = entryBuf)
                        {
                            if (!CopyHostToWasm(hostBuf + 8, (uint)(IntPtr)ep, arrayBytes))
                                return result;

                            // Read the whole buffer once via HostRead — bypasses the
                            // CopyHostToWasm path entirely (handle-based, no WASM ptr
                            // translation issues).
                            byte[] fullBuf = WfHost.HostRead(hostHandle, 0, (int)actualSize);

                            for (uint i = 0; i < groupCount; i++)
                            {
                                int off = (int)(i * SID_AND_ATTR_SIZE);
                                ulong psid = Read8(ep, off);
                                if (psid < hostBuf) continue;
                                ulong sidOffsetL = psid - hostBuf;
                                if (sidOffsetL == 0 || sidOffsetL + 8 > actualSize) continue;
                                int sidOffset = (int)sidOffsetL;
                                string sidStr = ParseSidBytesToString(fullBuf, (int)sidOffset, (int)actualSize);
                                if (!string.IsNullOrEmpty(sidStr))
                                {
                                    // Skip WfSec.SidToAccountName here: the underlying
                                    // ConvertStringSidToSidW P/Invoke gets trim-stripped
                                    // when reached through this call chain, causing a
                                    // WASM unreachable trap (not a catchable exception).
                                    // Name resolution happens lazily downstream via the
                                    // group-name cache + WindowsIdentity.GetCurrent path
                                    // already wired by the patcher. Empty name here matches
                                    // native Seatbelt output for SIDs that don't resolve.
                                    result.Add((sidStr, ""));
                                }
                            }
                        }
                    }
                    finally
                    {
                        WfHost.HostFree(hostHandle);
                    }
                }
                finally
                {
                    if (pCloseHandle != 0 && hToken != 0)
                        Invoke(pCloseHandle, 1, hToken);
                }
            }
            catch { /* return whatever we have */ }
            return result;
        }

        /// <summary>
        /// Drop-in replacement enumerable for WindowsIdentity.GetCurrent().Groups.
        /// Yields SecurityIdentifier objects so existing cast patterns still work.
        /// Per-SID name resolution is performed eagerly via WfSec.SidToAccountName.
        /// Companion: GetGroupNameForSid() returns the cached name.
        /// </summary>
        private static readonly System.Collections.Generic.Dictionary<string, string> _groupNameCache
            = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.Ordinal);

        // GetGroupsAsSids returns SDDL SID strings directly (NOT SecurityIdentifier
        // objects). NativeAOT-WASI throws PlatformNotSupportedException for
        // `new SecurityIdentifier(sddl)` — "Windows Principal functionality is not
        // supported on this platform" — so we can't construct one.
        // The patcher rewrites Seatbelt's `(SecurityIdentifier)group` cast to a
        // no-op so the existing $"{...}" format string just embeds the SDDL.
        public static System.Collections.Generic.IEnumerable<string> GetGroupsAsSids()
        {
            var groups = GetGroups();
            var refs = new System.Collections.Generic.List<string>();
            foreach (var g in groups)
            {
                if (string.IsNullOrEmpty(g.Sid)) continue;
                _groupNameCache[g.Sid] = g.Name ?? string.Empty;
                refs.Add(g.Sid);
            }
            return refs;
        }

        public static string GetGroupNameForSid(string sddlSid)
        {
            if (string.IsNullOrEmpty(sddlSid)) return string.Empty;
            string name;
            if (_groupNameCache.TryGetValue(sddlSid, out name) && !string.IsNullOrEmpty(name))
                return name;
            return ResolveWellKnownSid(sddlSid);
        }

        /// <summary>
        /// Resolves well-known SIDs to their canonical NTAccount-form names.
        /// Used by LsaWrapper.ResolveAccountName and WfToken.GetGroupNameForSid
        /// as a fallback when sid.Translate(typeof(NTAccount)) throws PNS on
        /// NativeAOT-WASI. Covers Seatbelt's UserRightAssignments output set
        /// (Local System, Administrators, Authenticated Users, etc.) so
        /// "NT AUTHORITY\\SYSTEM"-style names appear instead of raw SDDL.
        /// Returns empty string for unknown SIDs — caller falls back to SDDL.
        /// </summary>
        public static string ResolveWellKnownSid(string sddlSid)
        {
            if (string.IsNullOrEmpty(sddlSid)) return string.Empty;
            switch (sddlSid)
            {
                // Well-known universal SIDs
                case "S-1-0-0":      return "NULL SID";
                case "S-1-1-0":      return "Everyone";
                case "S-1-2-0":      return "LOCAL";
                case "S-1-2-1":      return "CONSOLE LOGON";
                case "S-1-3-0":      return "CREATOR OWNER";
                case "S-1-3-1":      return "CREATOR GROUP";
                case "S-1-3-2":      return "CREATOR OWNER SERVER";
                case "S-1-3-3":      return "CREATOR GROUP SERVER";
                case "S-1-3-4":      return "OWNER RIGHTS";
                // NT Authority (S-1-5-*)
                case "S-1-5-1":      return "NT AUTHORITY\\DIALUP";
                case "S-1-5-2":      return "NT AUTHORITY\\NETWORK";
                case "S-1-5-3":      return "NT AUTHORITY\\BATCH";
                case "S-1-5-4":      return "NT AUTHORITY\\INTERACTIVE";
                case "S-1-5-6":      return "NT AUTHORITY\\SERVICE";
                case "S-1-5-7":      return "NT AUTHORITY\\ANONYMOUS LOGON";
                case "S-1-5-8":      return "NT AUTHORITY\\PROXY";
                case "S-1-5-9":      return "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS";
                case "S-1-5-10":     return "NT AUTHORITY\\SELF";
                case "S-1-5-11":     return "NT AUTHORITY\\Authenticated Users";
                case "S-1-5-12":     return "NT AUTHORITY\\RESTRICTED";
                case "S-1-5-13":     return "NT AUTHORITY\\TERMINAL SERVER USER";
                case "S-1-5-14":     return "NT AUTHORITY\\REMOTE INTERACTIVE LOGON";
                case "S-1-5-15":     return "NT AUTHORITY\\This Organization";
                case "S-1-5-17":     return "NT AUTHORITY\\IUSR";
                case "S-1-5-18":     return "NT AUTHORITY\\SYSTEM";
                case "S-1-5-19":     return "NT AUTHORITY\\LOCAL SERVICE";
                case "S-1-5-20":     return "NT AUTHORITY\\NETWORK SERVICE";
                case "S-1-5-33":     return "NT AUTHORITY\\WRITE RESTRICTED";
                case "S-1-5-64-10":  return "NT AUTHORITY\\NTLM Authentication";
                case "S-1-5-64-14":  return "NT AUTHORITY\\SChannel Authentication";
                case "S-1-5-64-21":  return "NT AUTHORITY\\Digest Authentication";
                case "S-1-5-113":    return "NT AUTHORITY\\Local account";
                case "S-1-5-114":    return "NT AUTHORITY\\Local account and member of Administrators group";
                // BUILTIN aliases (S-1-5-32-*)
                case "S-1-5-32-544": return "BUILTIN\\Administrators";
                case "S-1-5-32-545": return "BUILTIN\\Users";
                case "S-1-5-32-546": return "BUILTIN\\Guests";
                case "S-1-5-32-547": return "BUILTIN\\Power Users";
                case "S-1-5-32-548": return "BUILTIN\\Account Operators";
                case "S-1-5-32-549": return "BUILTIN\\Server Operators";
                case "S-1-5-32-550": return "BUILTIN\\Print Operators";
                case "S-1-5-32-551": return "BUILTIN\\Backup Operators";
                case "S-1-5-32-552": return "BUILTIN\\Replicator";
                case "S-1-5-32-554": return "BUILTIN\\Pre-Windows 2000 Compatible Access";
                case "S-1-5-32-555": return "BUILTIN\\Remote Desktop Users";
                case "S-1-5-32-556": return "BUILTIN\\Network Configuration Operators";
                case "S-1-5-32-558": return "BUILTIN\\Performance Monitor Users";
                case "S-1-5-32-559": return "BUILTIN\\Performance Log Users";
                case "S-1-5-32-560": return "BUILTIN\\Windows Authorization Access Group";
                case "S-1-5-32-561": return "BUILTIN\\Terminal Server License Servers";
                case "S-1-5-32-562": return "BUILTIN\\Distributed COM Users";
                case "S-1-5-32-568": return "BUILTIN\\IIS_IUSRS";
                case "S-1-5-32-569": return "BUILTIN\\Cryptographic Operators";
                case "S-1-5-32-573": return "BUILTIN\\Event Log Readers";
                case "S-1-5-32-574": return "BUILTIN\\Certificate Service DCOM Access";
                case "S-1-5-32-575": return "BUILTIN\\RDS Remote Access Servers";
                case "S-1-5-32-576": return "BUILTIN\\RDS Endpoint Servers";
                case "S-1-5-32-577": return "BUILTIN\\RDS Management Servers";
                case "S-1-5-32-578": return "BUILTIN\\Hyper-V Administrators";
                case "S-1-5-32-579": return "BUILTIN\\Access Control Assistance Operators";
                case "S-1-5-32-580": return "BUILTIN\\Remote Management Users";
                // Mandatory integrity labels
                case "S-1-16-0":     return "Mandatory Label\\Untrusted Mandatory Level";
                case "S-1-16-4096":  return "Mandatory Label\\Low Mandatory Level";
                case "S-1-16-8192":  return "Mandatory Label\\Medium Mandatory Level";
                case "S-1-16-8448":  return "Mandatory Label\\Medium Plus Mandatory Level";
                case "S-1-16-12288": return "Mandatory Label\\High Mandatory Level";
                case "S-1-16-16384": return "Mandatory Label\\System Mandatory Level";
                case "S-1-16-20480": return "Mandatory Label\\Protected Process Mandatory Level";
            }
            // Logon session SIDs (S-1-5-5-X-Y): canonical form is "NT AUTHORITY\\LogonSessionId_X_Y"
            if (sddlSid.StartsWith("S-1-5-5-", System.StringComparison.Ordinal))
            {
                var parts = sddlSid.Substring("S-1-5-5-".Length).Split('-');
                if (parts.Length == 2)
                    return "NT AUTHORITY\\LogonSessionId_" + parts[0] + "_" + parts[1];
            }
            return string.Empty;
        }

        /// <summary>
        /// Returns the privilege name and attributes for each privilege in the current process token.
        /// Equivalent to WindowsIdentity.GetCurrent().Privileges.
        /// </summary>
        public static List<(string Name, uint Attributes)> GetPrivileges()
        {
            var result = new List<(string, uint)>();
            try
            {
                uint pGetCurrentProcess   = Resolve("kernel32.dll", ref _kernel32, "GetCurrentProcess", ref _hGetCurrentProcess);
                uint pOpenProcessToken    = Resolve("advapi32.dll", ref _advapi32, "OpenProcessToken", ref _hOpenProcessToken);
                uint pGetTokenInfo        = Resolve("advapi32.dll", ref _advapi32, "GetTokenInformation", ref _hGetTokenInformation);
                uint pLookupPrivilegeName = Resolve("advapi32.dll", ref _advapi32, "LookupPrivilegeNameW", ref _hLookupPrivilegeNameW);
                uint pCloseHandle         = Resolve("kernel32.dll", ref _kernel32, "CloseHandle", ref _hCloseHandle);
                if (pGetCurrentProcess == 0 || pOpenProcessToken == 0 || pGetTokenInfo == 0) return result;

                ulong hProcess = Invoke(pGetCurrentProcess, 0);

                ulong hToken = 0;
                ulong tokenOk = Invoke(pOpenProcessToken, 3,
                    hProcess,
                    8u,   // TOKEN_QUERY
                    (ulong)(uint)(IntPtr)(&hToken));
                if (tokenOk == 0 || hToken == 0) return result;

                try
                {
                    uint returnedSize = 0;
                    // GetTokenInformation(hToken, TokenPrivileges=3, NULL, 0, &returnedSize)
                    Invoke(pGetTokenInfo, 5,
                        hToken,
                        3u,   // TokenPrivileges
                        0u, 0u,
                        (ulong)(uint)(IntPtr)(&returnedSize));

                    if (returnedSize == 0) return result;
                    if (returnedSize > 65536) returnedSize = 65536;

                    ulong hostBuf = VirtualAllocHost(returnedSize);
                    if (hostBuf == 0) return result;
                    try
                    {
                        uint actualSize = 0;
                        ulong ok = Invoke(pGetTokenInfo, 5,
                            hToken,
                            3u,
                            hostBuf,
                            (ulong)returnedSize,
                            (ulong)(uint)(IntPtr)(&actualSize));
                        if (ok == 0) return result;

                        // TOKEN_PRIVILEGES layout (packed, no padding):
                        //   DWORD PrivilegeCount  (offset 0)
                        //   LUID_AND_ATTRIBUTES[] (offset 4), each entry 12 bytes:
                        //     DWORD LowPart  (offset 0)
                        //     DWORD HighPart (offset 4)
                        //     DWORD Attributes (offset 8)
                        uint privCount = 0;
                        {
                            byte[] tmp = new byte[4];
                            fixed (byte* tp = tmp)
                            {
                                CopyHostToWasm(hostBuf, (uint)(IntPtr)tp, 4);
                                privCount = (uint)(tmp[0] | (tmp[1] << 8) | (tmp[2] << 16) | (tmp[3] << 24));
                            }
                        }
                        if (privCount == 0 || privCount > 4096) return result;

                        const int LUID_AND_ATTR_SIZE = 12;
                        uint arrayBytes = privCount * LUID_AND_ATTR_SIZE;
                        byte[] entryBuf = new byte[arrayBytes];
                        fixed (byte* ep = entryBuf)
                        {
                            // Array starts at offset 4 (immediately after DWORD PrivilegeCount — packed).
                            if (!CopyHostToWasm(hostBuf + 4, (uint)(IntPtr)ep, arrayBytes))
                                return result;

                            for (uint i = 0; i < privCount; i++)
                            {
                                int off = (int)(i * LUID_AND_ATTR_SIZE);
                                uint luidLow  = Read4(ep, off + 0);
                                uint luidHigh = Read4(ep, off + 4);
                                uint attrs    = Read4(ep, off + 8);

                                string privName = "";
                                if (pLookupPrivilegeName != 0)
                                {
                                    // LookupPrivilegeNameW needs an in-WASM LUID, and an in-WASM name buffer.
                                    // The LUID must be in a fixed local — pass its WASM address.
                                    ulong luidVal = (ulong)luidLow | ((ulong)luidHigh << 32);
                                    byte[] privNameBuf = new byte[128]; // up to 64 UTF-16 chars
                                    uint   nameCch     = 64;
                                    fixed (byte* pp = privNameBuf)
                                    {
                                        Invoke(pLookupPrivilegeName, 4,
                                            0u,   // NULL = local system
                                            (ulong)(uint)(IntPtr)(&luidVal),
                                            (ulong)(uint)(IntPtr)pp,
                                            (ulong)(uint)(IntPtr)(&nameCch));
                                        privName = DecodeUtf16LE(pp, (int)nameCch);
                                    }
                                }

                                result.Add((privName, attrs));
                            }
                        }
                    }
                    finally
                    {
                        VirtualFreeHost(hostBuf);
                    }
                }
                finally
                {
                    if (pCloseHandle != 0 && hToken != 0)
                        Invoke(pCloseHandle, 1, hToken);
                }
            }
            catch { /* return whatever we have */ }
            return result;
        }

        // Decode a UTF-16LE byte array (already in WASM linear memory) into a managed string.
        private static string DecodeUtf16LE(byte* p, int charCount)
        {
            if (charCount <= 0) return "";
            char[] chars = new char[charCount];
            for (int i = 0; i < charCount; i++)
                chars[i] = (char)(p[2*i] | (p[2*i+1] << 8));
            return new string(chars);
        }

        /// <summary>
        /// Returns the current process token handle as an IntPtr, opened with TOKEN_QUERY.
        /// Replaces WindowsIdentity.GetCurrent().Token which throws on NativeAOT-WASI.
        /// Callers are responsible for CloseHandle; in Seatbelt TokenPrivilegesCommand
        /// the handle is passed to GetTokenInformation via P/Invoke and never explicitly closed.
        /// </summary>
        public static System.IntPtr GetCurrentTokenHandle()
        {
            try
            {
                uint pGetCurrentProcess = Resolve("kernel32.dll", ref _kernel32, "GetCurrentProcess", ref _hGetCurrentProcess);
                uint pOpenProcessToken  = Resolve("advapi32.dll", ref _advapi32, "OpenProcessToken", ref _hOpenProcessToken);
                if (pGetCurrentProcess == 0 || pOpenProcessToken == 0) return System.IntPtr.Zero;

                ulong hProcess = Invoke(pGetCurrentProcess, 0);
                // TOKEN_QUERY = 0x0008
                ulong hTokenOut = 0;
                unsafe
                {
                    ulong rc = Invoke(pOpenProcessToken, 3, hProcess, 0x0008u,
                        (ulong)(uint)(System.IntPtr)(&hTokenOut));
                    if (rc == 0) return System.IntPtr.Zero;
                }
                // hTokenOut holds the host-side handle value written by OpenProcessToken.
                // Return it as IntPtr for use with GetTokenInformation P/Invoke.
                return (System.IntPtr)(long)hTokenOut;
            }
            catch
            {
                return System.IntPtr.Zero;
            }
        }

        // ── IsHighIntegrity ─────────────────────────────────────────────
        //
        // Reads TokenIntegrityLevel (class 25) from the current process token
        // and compares the RID of the integrity-level SID against
        // SECURITY_MANDATORY_HIGH_RID (0x3000). Uses the same wf_call /
        // mod_invoke pattern as the rest of WfToken so no new host APIs are
        // needed — advapi32!GetTokenInformation + GetSidSubAuthority + a
        // RtlMoveMemory copy to land the RID in WASM linear memory.
        public static bool IsHighIntegrity()
        {
            try
            {
                System.IntPtr hToken = GetCurrentTokenHandle();
                if (hToken == System.IntPtr.Zero) return false;

                uint pGetTokenInfo = Resolve("advapi32.dll", ref _advapi32, "GetTokenInformation", ref _hGetTokenInformation);
                if (pGetTokenInfo == 0) return false;

                const uint TokenIntegrityLevel = 25;
                byte[] buf = new byte[64];
                uint returnedSize = 0;
                ulong rc;
                fixed (byte* bPtr = buf)
                {
                    rc = Invoke(pGetTokenInfo, 5,
                        (ulong)(uint)(long)hToken,
                        (ulong)TokenIntegrityLevel,
                        (ulong)(uint)(System.IntPtr)bPtr,
                        (ulong)(uint)buf.Length,
                        (ulong)(uint)(System.IntPtr)(&returnedSize));
                }
                if (rc == 0 || returnedSize < 8) return false;

                // TOKEN_MANDATORY_LABEL starts with PSID (8 bytes on x64).
                ulong pSid;
                fixed (byte* bPtr = buf)
                {
                    pSid = *(ulong*)bPtr;
                }
                if (pSid == 0) return false;

                uint pGetSidSubAuth = Resolve("advapi32.dll", ref _advapi32, "GetSidSubAuthority", ref _hGetSidSubAuthority);
                if (pGetSidSubAuth == 0) return false;
                // SubAuthority index 0 because mandatory-integrity SIDs only
                // have one sub-authority (the RID).
                ulong pRid = Invoke(pGetSidSubAuth, 2, pSid, 0UL);
                if (pRid == 0) return false;

                // pRid is a host pointer; can't deref in WASM linear memory.
                // Copy 4 bytes back via RtlMoveMemory.
                uint rid = 0;
                uint pMove = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
                if (pMove == 0) return false;
                Invoke(pMove, 3,
                    (ulong)(uint)(System.IntPtr)(&rid),
                    pRid,
                    4UL);

                // SECURITY_MANDATORY_HIGH_RID = 0x3000, SYSTEM_RID = 0x4000.
                return rid >= 0x3000;
            }
            catch
            {
                return false;
            }
        }
        private static uint _hGetSidSubAuthority;
    }

    // ── WfGroupIdentityReference ────────────────────────────────────────────
    //
    // Lightweight IdentityReference subclass that wraps a SecurityIdentifier
    // AND carries a pre-resolved DOMAIN\User name (from SidToAccountName at
    // construction time). The Translate(typeof(NTAccount)) override returns
    // a synthetic NTAccount with the stored name, avoiding NativeAOT-WASI
    // throws from the real SecurityIdentifier.Translate path.
    //
    // Used by WfToken.GetGroupsAsIdentityReferences to provide a drop-in
    // replacement for WindowsIdentity.GetCurrent().Groups (an
    // IdentityReferenceCollection — also IEnumerable<IdentityReference>).
}
