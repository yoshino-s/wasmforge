// WfNetapi.cs — managed helpers for netapi32 flat APIs.
//
// Reusable approach: all logic in C# (WASM), no host-side aggregator,
// no project-specific C bridge. Uses only the generic env primitives
// the wasmforge runtime already exposes: mod_load, mod_resolve,
// mod_invoke. NetLocalGroupEnum etc. are invoked via mod_invoke;
// host-side buffers are copied into WASM memory via mod_invoke
// against ntdll!RtlMoveMemory (a second syscall, NOT mod_hread —
// which triggers the cgocallback panic).
//
// Why RtlMoveMemory and not mod_hread: mod_invoke leaves the host
// goroutine in a transitional state after syscall.SyscallN returns.
// A subsequent env callback (mod_hread is implemented as a
// GoModuleFunc — direct Go function dispatch) re-enters cgocallbackg
// and calls runtime.exitsyscall which throws "syscall frame is no
// longer valid". A second mod_invoke (also via syscall.SyscallN)
// does its OWN enter/exit syscall pair and is fine — sequential
// syscalls don't conflict. RtlMoveMemory(dst, src, n) is the
// simplest Win32 primitive that lets us read from a host buffer
// into a WASM-side buffer through the syscall path.
//
// Patcher routes Seatbelt.Interop.Netapi32 helpers (GetLocalGroups,
// GetLocalGroupMembers, GetLocalUsers) to this class.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfNetapi
    {
        // ── env primitives ──────────────────────────────────────────────

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

        // ── Cached proc handles ────────────────────────────────────────

        private static uint _netapi32;
        private static uint _hLocalGroupEnum;
        private static uint _hLocalGroupGetMembers;
        private static uint _hUserEnum;
        private static uint _hApiBufferFree;
        private static uint _hGetAadJoinInfo;
        private static uint _hFreeAadJoinInfo;
        private static uint _advapi32;
        private static uint _hConvertSidToStringSidW;
        private static uint _kernel32;
        private static uint _hLocalFree;
        private static uint _ntdll;
        private static uint _hRtlMoveMemory;

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

        private static uint Invoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0)
        {
            ulong ret1 = 0, err = 0;
            ulong r0 = mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
            return (uint)r0;
        }

        // CopyHostToWasm: copy `len` bytes from a HOST address into a WASM
        // buffer at wasmPtr via ntdll!RtlMoveMemory.
        //
        // Pointer-mask handling: RtlMoveMemory isn't in
        // generated_ptrmasks.go, so wf_mod_invoke uses the heuristic —
        // values in WASM memory range get translated (wasmPtr → host),
        // values above memSize don't (hostAddr passes through). Both
        // conditions hold for our inputs.
        private static bool CopyHostToWasm(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            // RtlMoveMemory(dst, src, length)
            Invoke(pCopy, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        private static ulong ReadUInt64FromHost(ulong hostAddr)
        {
            byte[] buf = new byte[8];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, 8)) return 0;
            }
            return ((ulong)buf[0]) | ((ulong)buf[1] << 8) | ((ulong)buf[2] << 16) | ((ulong)buf[3] << 24)
                 | ((ulong)buf[4] << 32) | ((ulong)buf[5] << 40) | ((ulong)buf[6] << 48) | ((ulong)buf[7] << 56);
        }

        private static uint ReadUInt32FromHost(ulong hostAddr)
        {
            byte[] buf = new byte[4];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, 4)) return 0;
            }
            return (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
        }

        // Little-endian readers for fixed buffers. Inline to avoid lambdas
        // that would close over fixed locals (CS1764).
        private static ulong Read8(byte* p, int off)
        {
            return ((ulong)p[off+0])       | ((ulong)p[off+1] <<  8) |
                   ((ulong)p[off+2] << 16) | ((ulong)p[off+3] << 24) |
                   ((ulong)p[off+4] << 32) | ((ulong)p[off+5] << 40) |
                   ((ulong)p[off+6] << 48) | ((ulong)p[off+7] << 56);
        }

        private static uint Read4(byte* p, int off)
        {
            return (uint)(p[off+0] | (p[off+1] << 8) | (p[off+2] << 16) | (p[off+3] << 24));
        }

        // Read a NUL-terminated UTF-16 string from a host address.
        // Uses a single RtlMoveMemory for a fixed max length (faster than
        // chunked reads — we don't know the exact length but Win32 LPWSTR
        // for these APIs is always under 256 chars).
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
                if (buf[2*i] == 0 && buf[2*i + 1] == 0) break;
                charLen++;
            }
            if (charLen == 0) return "";
            char[] chars = new char[charLen];
            for (int i = 0; i < charLen; i++)
                chars[i] = (char)(buf[2*i] | (buf[2*i + 1] << 8));
            return new string(chars);
        }

        // ── Public types ────────────────────────────────────────────────

        public struct LocalGroup
        {
            public string Name;
            public string Comment;
        }

        public struct LocalGroupMember
        {
            public string DomainAndName;
            public string Sid;
            public uint SidUsage;
        }

        public struct LocalUser
        {
            public string Name;
            public string Comment;
            public string FullName;
            public uint Flags;
            public uint PasswordAge;
            public uint LastLogon;
            public uint NumLogons;
            public uint UserId;
            public uint Priv;  // USER_INFO_1.usri1_priv: 0=Guest, 1=User, 2=Admin
        }

        public struct AadJoinInfo
        {
            public uint JoinType;
            public string DeviceId;
            public string IdpDomain;
            public string TenantId;
            public string JoinUserEmail;
            public string TenantDisplayName;
        }

        // Pin a UTF-16LE WASM-side copy of `s` for a single Win32 call.
        private static IntPtr Utf16Alloc(string? s)
        {
            if (s == null) return IntPtr.Zero;
            byte[] bytes = new byte[(s.Length + 1) * 2];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bytes[2*i]     = (byte)(c & 0xff);
                bytes[2*i + 1] = (byte)((c >> 8) & 0xff);
            }
            IntPtr p = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, p, bytes.Length);
            return p;
        }

        // ── Public methods ──────────────────────────────────────────────

        public static List<LocalGroup> ListLocalGroups(string? computerName)
        {
            var result = new List<LocalGroup>();
            uint pEnum = Resolve("netapi32.dll", ref _netapi32, "NetLocalGroupEnum", ref _hLocalGroupEnum);
            uint pFree = Resolve("netapi32.dll", ref _netapi32, "NetApiBufferFree", ref _hApiBufferFree);
            if (pEnum == 0 || pFree == 0) return result;

            IntPtr server = Utf16Alloc(computerName);
            ulong bufHost = 0;
            uint entriesRead = 0, totalEntries = 0;
            ulong resume = 0;

            uint rc;
            try
            {
                rc = Invoke(pEnum, 7,
                    (ulong)(uint)server,
                    1u,
                    (ulong)(uint)(IntPtr)(&bufHost),
                    0xFFFFFFFFu,
                    (ulong)(uint)(IntPtr)(&entriesRead),
                    (ulong)(uint)(IntPtr)(&totalEntries),
                    (ulong)(uint)(IntPtr)(&resume));
            }
            finally
            {
                if (server != IntPtr.Zero) Marshal.FreeHGlobal(server);
            }
            if (rc != 0 || bufHost == 0) return result;
            if (entriesRead > 4096) entriesRead = 4096;

            // LOCALGROUP_INFO_1 (x64): LPWSTR name @0, LPWSTR comment @8. size=16.
            // Copy the entire entry array into WASM in one RtlMoveMemory call.
            byte[] entryBuf = new byte[entriesRead * 16];
            fixed (byte* ep = entryBuf)
            {
                if (!CopyHostToWasm(bufHost, (uint)(IntPtr)ep, (uint)entryBuf.Length))
                {
                    Invoke(pFree, 1, bufHost);
                    return result;
                }
                for (uint i = 0; i < entriesRead; i++)
                {
                    int off = (int)(i * 16);
                    ulong nameHost =
                        ((ulong)ep[off+0])       | ((ulong)ep[off+1] <<  8) |
                        ((ulong)ep[off+2] << 16) | ((ulong)ep[off+3] << 24) |
                        ((ulong)ep[off+4] << 32) | ((ulong)ep[off+5] << 40) |
                        ((ulong)ep[off+6] << 48) | ((ulong)ep[off+7] << 56);
                    ulong commentHost =
                        ((ulong)ep[off+ 8])       | ((ulong)ep[off+ 9] <<  8) |
                        ((ulong)ep[off+10] << 16) | ((ulong)ep[off+11] << 24) |
                        ((ulong)ep[off+12] << 32) | ((ulong)ep[off+13] << 40) |
                        ((ulong)ep[off+14] << 48) | ((ulong)ep[off+15] << 56);
                    result.Add(new LocalGroup
                    {
                        Name = ReadWStringFromHost(nameHost, 128),
                        Comment = ReadWStringFromHost(commentHost, 128)
                    });
                }
            }

            Invoke(pFree, 1, bufHost);
            return result;
        }

        public static List<LocalGroupMember> ListLocalGroupMembers(string? computerName, string groupName)
        {
            var result = new List<LocalGroupMember>();
            if (string.IsNullOrEmpty(groupName)) return result;
            uint pGet = Resolve("netapi32.dll", ref _netapi32, "NetLocalGroupGetMembers", ref _hLocalGroupGetMembers);
            uint pFree = Resolve("netapi32.dll", ref _netapi32, "NetApiBufferFree", ref _hApiBufferFree);
            uint pConv = Resolve("advapi32.dll", ref _advapi32, "ConvertSidToStringSidW", ref _hConvertSidToStringSidW);
            uint pLocalFree = Resolve("kernel32.dll", ref _kernel32, "LocalFree", ref _hLocalFree);
            if (pGet == 0 || pFree == 0) return result;

            IntPtr server = Utf16Alloc(computerName);
            IntPtr group = Utf16Alloc(groupName);
            ulong bufHost = 0;
            uint entriesRead = 0, totalEntries = 0;
            ulong resume = 0;

            uint rc;
            try
            {
                rc = Invoke(pGet, 8,
                    (ulong)(uint)server,
                    (ulong)(uint)group,
                    2u,
                    (ulong)(uint)(IntPtr)(&bufHost),
                    0xFFFFFFFFu,
                    (ulong)(uint)(IntPtr)(&entriesRead),
                    (ulong)(uint)(IntPtr)(&totalEntries),
                    (ulong)(uint)(IntPtr)(&resume));
            }
            finally
            {
                if (server != IntPtr.Zero) Marshal.FreeHGlobal(server);
                if (group != IntPtr.Zero) Marshal.FreeHGlobal(group);
            }
            if (rc != 0 || bufHost == 0) return result;
            if (entriesRead > 4096) entriesRead = 4096;

            // LOCALGROUP_MEMBERS_INFO_2 (x64): PSID @0, DWORD usage @8,
            //   LPWSTR domainandname @16. size = 24.
            byte[] entryBuf = new byte[entriesRead * 24];
            fixed (byte* ep = entryBuf)
            {
                if (!CopyHostToWasm(bufHost, (uint)(IntPtr)ep, (uint)entryBuf.Length))
                {
                    Invoke(pFree, 1, bufHost);
                    return result;
                }
                for (uint i = 0; i < entriesRead; i++)
                {
                    int off = (int)(i * 24);
                    ulong sidHost =
                        ((ulong)ep[off+0])       | ((ulong)ep[off+1] <<  8) |
                        ((ulong)ep[off+2] << 16) | ((ulong)ep[off+3] << 24) |
                        ((ulong)ep[off+4] << 32) | ((ulong)ep[off+5] << 40) |
                        ((ulong)ep[off+6] << 48) | ((ulong)ep[off+7] << 56);
                    uint usage = (uint)(ep[off+8] | (ep[off+9] << 8) | (ep[off+10] << 16) | (ep[off+11] << 24));
                    ulong nameHost =
                        ((ulong)ep[off+16])       | ((ulong)ep[off+17] <<  8) |
                        ((ulong)ep[off+18] << 16) | ((ulong)ep[off+19] << 24) |
                        ((ulong)ep[off+20] << 32) | ((ulong)ep[off+21] << 40) |
                        ((ulong)ep[off+22] << 48) | ((ulong)ep[off+23] << 56);

                    string sidStr = "";
                    if (sidHost != 0 && pConv != 0)
                    {
                        ulong sidWPtr = 0;
                        Invoke(pConv, 2, sidHost, (ulong)(uint)(IntPtr)(&sidWPtr));
                        if (sidWPtr != 0)
                        {
                            sidStr = ReadWStringFromHost(sidWPtr, 256);
                            if (pLocalFree != 0) Invoke(pLocalFree, 1, sidWPtr);
                        }
                    }
                    result.Add(new LocalGroupMember
                    {
                        DomainAndName = ReadWStringFromHost(nameHost, 260),
                        Sid = sidStr,
                        SidUsage = usage
                    });
                }
            }

            Invoke(pFree, 1, bufHost);
            return result;
        }

        public static List<LocalUser> ListLocalUsers(string? computerName)
        {
            var result = new List<LocalUser>();
            uint pEnum = Resolve("netapi32.dll", ref _netapi32, "NetUserEnum", ref _hUserEnum);
            uint pFree = Resolve("netapi32.dll", ref _netapi32, "NetApiBufferFree", ref _hApiBufferFree);
            if (pEnum == 0 || pFree == 0) return result;

            IntPtr server = Utf16Alloc(computerName);
            ulong bufHost = 0;
            uint entriesRead = 0, totalEntries = 0;
            ulong resume = 0;

            uint rc;
            try
            {
                // Level 1 (USER_INFO_1 = 56 bytes/entry on x64) gives us the
                // useful subset Seatbelt actually renders: name, comment, flags,
                // password_age. Level 3 (208 bytes/entry) crashes inside
                // netapi32.dll on this runtime — empirically host-side AV
                // during the API's domain-trust enumeration of the larger
                // struct on GOAD Win11. Level 1 avoids that path.
                //
                // USER_INFO_1 (x64):
                //   LPWSTR usri1_name           @  0  size 8
                //   LPWSTR usri1_password       @  8  size 8  (returned NULL)
                //   DWORD  usri1_password_age   @ 16  size 4
                //   DWORD  usri1_priv           @ 20  size 4
                //   LPWSTR usri1_home_dir       @ 24  size 8
                //   LPWSTR usri1_comment        @ 32  size 8
                //   DWORD  usri1_flags          @ 40  size 4
                //   _pad                        @ 44  size 4
                //   LPWSTR usri1_script_path    @ 48  size 8
                // Total: 56 bytes (8-byte aligned).
                rc = Invoke(pEnum, 8,
                    (ulong)(uint)server,
                    1u, // Level 1 → USER_INFO_1
                    2u, // FILTER_NORMAL_ACCOUNT
                    (ulong)(uint)(IntPtr)(&bufHost),
                    0xFFFFFFFFu,
                    (ulong)(uint)(IntPtr)(&entriesRead),
                    (ulong)(uint)(IntPtr)(&totalEntries),
                    (ulong)(uint)(IntPtr)(&resume));
            }
            finally
            {
                if (server != IntPtr.Zero) Marshal.FreeHGlobal(server);
            }
            if (rc != 0 || bufHost == 0) return result;
            if (entriesRead > 4096) entriesRead = 4096;

            const int USER1_SIZE = 56;
            byte[] entryBuf = new byte[entriesRead * USER1_SIZE];
            fixed (byte* ep = entryBuf)
            {
                if (!CopyHostToWasm(bufHost, (uint)(IntPtr)ep, (uint)entryBuf.Length))
                {
                    Invoke(pFree, 1, bufHost);
                    return result;
                }
                for (uint i = 0; i < entriesRead; i++)
                {
                    int b = (int)(i * USER1_SIZE);
                    ulong nameHost    = Read8(ep, b +  0);
                    uint  passwordAge = Read4(ep, b + 16);
                    uint  priv        = Read4(ep, b + 20);   // USER_INFO_1.usri1_priv
                    ulong commentHost = Read8(ep, b + 32);
                    uint  flags       = Read4(ep, b + 40);

                    string name = ReadWStringFromHost(nameHost, 260);
                    uint rid = LookupRidByName(name);

                    result.Add(new LocalUser
                    {
                        Name        = name,
                        Comment     = ReadWStringFromHost(commentHost, 260),
                        FullName    = "",
                        Flags       = flags,
                        PasswordAge = passwordAge,
                        LastLogon   = 0,
                        NumLogons   = 0,
                        UserId      = rid,
                        Priv        = priv
                    });
                }
            }

            Invoke(pFree, 1, bufHost);

            // Patch up Priv per user. NetUserEnum Level 1 returns priv=0
            // (USER_PRIV_GUEST) for every user on Vista+ — the field is
            // legacy. Level 3 has accurate priv but crashes inside
            // netapi32.dll on the Win11 GOAD lab during the larger struct's
            // domain-trust enumeration. So derive it from group membership
            // + well-known RIDs instead:
            //
            //   RID == 500           → Administrator (built-in admin)
            //   RID in {501,503,504} → Guest         (Guest / DefaultAccount / WDAGUtilityAccount)
            //   Other users:
            //     in "Administrators" group → Administrator
            //     else                       → User
            //
            // This matches native Seatbelt's per-user output exactly on
            // standard Windows installs. ListLocalGroupMembers can fail on
            // remote machines or restricted contexts — fall back to
            // RID-only classification if so.
            var admins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var m in ListLocalGroupMembers(computerName, "Administrators"))
                {
                    var nameOnly = m.DomainAndName;
                    int bs = nameOnly.LastIndexOf('\\');
                    if (bs >= 0 && bs + 1 < nameOnly.Length) nameOnly = nameOnly.Substring(bs + 1);
                    admins.Add(nameOnly);
                }
            }
            catch { /* RID-only fallback */ }

            // Rebuild list with patched Priv. We cannot mutate the LocalUser
            // value-type in place via `result[i] = u` because NativeAOT's
            // trimmer aggressively elides struct-field writes that aren't
            // observed by a "live" side-effecting consumer; the list-rebuild
            // pattern produces an obvious data dependency the trimmer can't
            // optimize away. Verified empirically on Win11 lab — in-place
            // mutation kept showing the original priv=0 in printed output.
            var patched = new List<LocalUser>(result.Count);
            foreach (var u in result)
            {
                uint priv;
                switch (u.UserId)
                {
                    case 500: priv = 2; break;          // built-in Administrator
                    case 501: case 503: case 504:
                        priv = 0; break;                // Guest / DefaultAccount / WDAGUtility
                    default:
                        priv = admins.Contains(u.Name) ? 2u : 1u;
                        break;
                }
                patched.Add(new LocalUser
                {
                    Name        = u.Name,
                    Comment     = u.Comment,
                    FullName    = u.FullName,
                    Flags       = u.Flags,
                    PasswordAge = u.PasswordAge,
                    LastLogon   = u.LastLogon,
                    NumLogons   = u.NumLogons,
                    UserId      = u.UserId,
                    Priv        = priv,
                });
            }
            return patched;
        }

        public static AadJoinInfo? GetAadJoinInformation()
        {
            uint pGet = Resolve("netapi32.dll", ref _netapi32, "NetGetAadJoinInformation", ref _hGetAadJoinInfo);
            uint pFree = Resolve("netapi32.dll", ref _netapi32, "NetFreeAadJoinInformation", ref _hFreeAadJoinInfo);
            if (pGet == 0) return null;

            ulong infoHost = 0;
            uint rc = Invoke(pGet, 2, 0u, (ulong)(uint)(IntPtr)(&infoHost));
            if (rc != 0 || infoHost == 0) return null;

            // DSREG_JOIN_INFO (x64). Read the head 56 bytes in one shot.
            byte[] head = new byte[56];
            fixed (byte* hp = head)
            {
                if (!CopyHostToWasm(infoHost, (uint)(IntPtr)hp, (uint)head.Length))
                {
                    if (pFree != 0) Invoke(pFree, 1, infoHost);
                    return null;
                }
                var info = new AadJoinInfo
                {
                    JoinType          = Read4(hp, 0),
                    DeviceId          = ReadWStringFromHost(Read8(hp, 16), 256),
                    IdpDomain         = ReadWStringFromHost(Read8(hp, 24), 256),
                    TenantId          = ReadWStringFromHost(Read8(hp, 32), 256),
                    JoinUserEmail     = ReadWStringFromHost(Read8(hp, 40), 256),
                    TenantDisplayName = ReadWStringFromHost(Read8(hp, 48), 256)
                };
                if (pFree != 0) Invoke(pFree, 1, infoHost);
                return info;
            }
        }

        // LookupRidByName — calls advapi32!LookupAccountNameW(NULL, name, ...)
        // and extracts the last SubAuthority of the returned SID, which is
        // the user/group RID. Returns 0 on failure. SID written directly
        // into a stack-allocated WASM byte array; wf_call's pointer
        // translation handles the wasm↔host transition.
        private static uint _hLookupAccountNameW;
        private static uint _hAdvapi32;
        public static uint LookupRidByName(string name)
        {
            if (string.IsNullOrEmpty(name)) return 0;
            try
            {
                uint pLookup = Resolve("advapi32.dll", ref _hAdvapi32, "LookupAccountNameW", ref _hLookupAccountNameW);
                if (pLookup == 0) return 0;

                byte[] nameUtf16 = Encoding.Unicode.GetBytes(name + "\0");
                byte[] sidBytes = new byte[256];
                byte[] domBuf = new byte[512];
                uint sidSize = 256;
                uint domSize = 256;
                uint use = 0;
                ulong rc;
                fixed (byte* np = nameUtf16)
                fixed (byte* sp = sidBytes)
                fixed (byte* dp = domBuf)
                {
                    rc = Invoke(pLookup, 7,
                        0UL,
                        (ulong)(uint)(IntPtr)np,
                        (ulong)(uint)(IntPtr)sp,
                        (ulong)(uint)(IntPtr)(&sidSize),
                        (ulong)(uint)(IntPtr)dp,
                        (ulong)(uint)(IntPtr)(&domSize),
                        (ulong)(uint)(IntPtr)(&use));
                }
                if (rc == 0 || sidSize < 12) return 0;

                // SID: Revision(1) + SubAuthCount(1) + IdentifierAuthority(6) +
                // SubAuthority[SubAuthCount] (4 each). RID = last SubAuthority.
                uint subAuthCount = sidBytes[1];
                if (subAuthCount == 0 || subAuthCount > 15) return 0;
                int ridOff = 8 + ((int)subAuthCount - 1) * 4;
                if (ridOff + 4 > sidBytes.Length) return 0;
                return (uint)(sidBytes[ridOff] |
                              (sidBytes[ridOff + 1] << 8) |
                              (sidBytes[ridOff + 2] << 16) |
                              (sidBytes[ridOff + 3] << 24));
            }
            catch { return 0; }
        }
    }
}
