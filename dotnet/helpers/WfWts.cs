// WfWts.cs — managed helpers for wtsapi32.dll (RDP session enumeration).
//
// Same Resolve→Invoke→CopyHostToWasm pattern as WfNetapi/WfVault. The
// consumer (RDPSessionsCommand) uses Marshal.PtrToStructure on host
// pointers which can't work on wasm32 (4-byte IntPtr truncates x64
// addresses). EnumerateSessions returns parsed RDPSessionData entries
// so the consumer can build its DTO directly.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfWts
    {
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

        // ── Cached library + proc handles ───────────────────────────────
        private static uint _wtsapi32;
        private static uint _hOpenServer;
        private static uint _hCloseServer;
        private static uint _hEnumSessionsEx;
        private static uint _hFreeMemory;
        private static uint _hQuerySessionInfo;
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

        private static bool CopyHostToWasm(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            Invoke(pCopy, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        private static uint Read4(byte* p, int off) =>
            (uint)(p[off+0] | (p[off+1] << 8) | (p[off+2] << 16) | (p[off+3] << 24));

        private static ulong Read8(byte* p, int off) =>
            ((ulong)p[off+0])       | ((ulong)p[off+1] <<  8) |
            ((ulong)p[off+2] << 16) | ((ulong)p[off+3] << 24) |
            ((ulong)p[off+4] << 32) | ((ulong)p[off+5] << 40) |
            ((ulong)p[off+6] << 48) | ((ulong)p[off+7] << 56);

        private static string ReadAnsiStringFromHost(ulong hostAddr, int maxChars)
        {
            if (hostAddr == 0 || maxChars <= 0) return "";
            byte[] buf = new byte[maxChars];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, (uint)buf.Length)) return "";
            }
            int len = 0;
            while (len < maxChars && buf[len] != 0) len++;
            if (len == 0) return "";
            return Encoding.ASCII.GetString(buf, 0, len);
        }

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

        // ── Public data types ───────────────────────────────────────────

        public class ClientDisplay
        {
            public int HorizontalResolution;
            public int VerticalResolution;
            public int ColorDepth;
        }

        public class RDPSessionData
        {
            public uint SessionID;
            public string SessionName = "";
            public string UserName = "";
            public string DomainName = "";
            public int State; // WTS_CONNECTSTATE_CLASS enum value
            public string HostName = "";
            public string FarmName = "";
            public long? LastInputTime;
            public byte[]? ClientAddressV4;   // 4 bytes for AF_INET
            public string? ClientHostname;
            public ClientDisplay? ClientResolution;
            public int? ClientBuild;
            public byte[]? ClientHardwareId;
            public string? ClientDirectory;
        }

        // WTS_INFO_CLASS values used.
        private const int WTSClientBuildNumber = 9;
        private const int WTSClientName        = 10;
        private const int WTSClientDirectory   = 11;
        private const int WTSClientAddress     = 14;
        private const int WTSClientDisplay     = 15;
        private const int WTSClientHardwareId  = 13;
        private const int WTSSessionInfo       = 24;

        public static List<RDPSessionData> EnumerateSessions(string computerName)
        {
            var results = new List<RDPSessionData>();

            uint pOpen   = Resolve("wtsapi32.dll", ref _wtsapi32, "WTSOpenServerA",            ref _hOpenServer);
            uint pClose  = Resolve("wtsapi32.dll", ref _wtsapi32, "WTSCloseServer",            ref _hCloseServer);
            uint pEnumEx = Resolve("wtsapi32.dll", ref _wtsapi32, "WTSEnumerateSessionsExA",   ref _hEnumSessionsEx);
            uint pFree   = Resolve("wtsapi32.dll", ref _wtsapi32, "WTSFreeMemory",             ref _hFreeMemory);
            uint pQuery  = Resolve("wtsapi32.dll", ref _wtsapi32, "WTSQuerySessionInformationW", ref _hQuerySessionInfo);
            if (pOpen == 0 || pEnumEx == 0) return results;

            // Open server (NULL for local, ANSI name for remote).
            ulong server = 0;
            if (string.IsNullOrEmpty(computerName) || computerName == "localhost")
            {
                // 0 == WTS_CURRENT_SERVER_HANDLE.
                server = 0;
            }
            else
            {
                byte[] nb = Encoding.ASCII.GetBytes(computerName + "\0");
                fixed (byte* np = nb) server = Invoke(pOpen, 1, (ulong)(uint)(IntPtr)np);
                if (server == 0) return results;
            }

            // Enumerate sessions (Level 1 → WTS_SESSION_INFO_1).
            int level = 1;
            ulong sessionArrayHost = 0;
            int sessionCount = 0;
            uint rc = Invoke(pEnumEx, 5,
                server,
                (ulong)(uint)(IntPtr)(&level),
                0u,
                (ulong)(uint)(IntPtr)(&sessionArrayHost),
                (ulong)(uint)(IntPtr)(&sessionCount));
            if (rc == 0 || sessionCount <= 0 || sessionArrayHost == 0)
            {
                CloseServer(pClose, server);
                return results;
            }
            if (sessionCount > 256) sessionCount = 256;

            // WTS_SESSION_INFO_1 x64 layout (LayoutKind.Sequential, no Pack):
            //   0:  uint ExecEnvId (4)
            //   4:  int  State     (4)
            //   8:  uint SessionID (4)
            //   12: padding to 8-byte align (4)
            //   16: LPSTR pSessionName (8)
            //   24: LPSTR pHostName    (8)
            //   32: LPSTR pUserName    (8)
            //   40: LPSTR pDomainName  (8)
            //   48: LPSTR pFarmName    (8)
            // Total: 56 bytes per entry.
            const int SESSION_INFO_1_SIZE = 56;
            byte[] entries = new byte[sessionCount * SESSION_INFO_1_SIZE];
            fixed (byte* ep = entries)
            {
                if (!CopyHostToWasm(sessionArrayHost, (uint)(IntPtr)ep, (uint)entries.Length))
                {
                    if (pFree != 0) Invoke(pFree, 1, sessionArrayHost);
                    CloseServer(pClose, server);
                    return results;
                }

                for (int i = 0; i < sessionCount; i++)
                {
                    int b = i * SESSION_INFO_1_SIZE;
                    var s = new RDPSessionData
                    {
                        State        = (int)Read4(ep, b + 4),
                        SessionID    = Read4(ep, b + 8),
                        SessionName  = ReadAnsiStringFromHost(Read8(ep, b + 16), 64),
                        HostName     = ReadAnsiStringFromHost(Read8(ep, b + 24), 256),
                        UserName     = ReadAnsiStringFromHost(Read8(ep, b + 32), 64),
                        DomainName   = ReadAnsiStringFromHost(Read8(ep, b + 40), 64),
                        FarmName     = ReadAnsiStringFromHost(Read8(ep, b + 48), 128),
                    };

                    if (pQuery != 0)
                    {
                        s.ClientAddressV4   = QueryAddressV4(pQuery, pFree, server, s.SessionID);
                        s.ClientHostname    = QueryWideString(pQuery, pFree, server, s.SessionID, WTSClientName, 64);
                        s.ClientDirectory   = QueryWideString(pQuery, pFree, server, s.SessionID, WTSClientDirectory, 260);
                        s.ClientBuild       = QueryInt32(pQuery, pFree, server, s.SessionID, WTSClientBuildNumber);
                        s.ClientResolution  = QueryClientDisplay(pQuery, pFree, server, s.SessionID);
                        s.ClientHardwareId  = QueryHardwareId(pQuery, pFree, server, s.SessionID);
                        s.LastInputTime     = QuerySessionInfoLastInput(pQuery, pFree, server, s.SessionID);
                    }

                    results.Add(s);
                }
            }

            if (pFree != 0) Invoke(pFree, 1, sessionArrayHost);
            CloseServer(pClose, server);
            return results;
        }

        private static void CloseServer(uint pClose, ulong server)
        {
            if (server != 0 && pClose != 0) Invoke(pClose, 1, server);
        }

        // QueryRaw: WTSQuerySessionInformationW returns hostPtr + byteLen via out
        // params. Returns the host buffer pointer (caller must free via pFree).
        // Out byteLen is written to *byteLenOut.
        private static ulong QueryRaw(uint pQuery, ulong server, uint sessionId, int infoClass, out uint byteLen)
        {
            ulong bufHost = 0;
            uint bytes = 0;
            byteLen = 0;
            uint rc = Invoke(pQuery, 5,
                server,
                (ulong)sessionId,
                (ulong)(uint)infoClass,
                (ulong)(uint)(IntPtr)(&bufHost),
                (ulong)(uint)(IntPtr)(&bytes));
            if (rc == 0 || bufHost == 0) return 0;
            byteLen = bytes;
            return bufHost;
        }

        private static byte[]? QueryAddressV4(uint pQuery, uint pFree, ulong server, uint sessionId)
        {
            ulong host = QueryRaw(pQuery, server, sessionId, WTSClientAddress, out _);
            if (host == 0) return null;
            // WTS_CLIENT_ADDRESS: AddressFamily(4) + Address[20].
            byte[] buf = new byte[24];
            fixed (byte* bp = buf) CopyHostToWasm(host, (uint)(IntPtr)bp, 24);
            if (pFree != 0) Invoke(pFree, 1, host);
            uint family = (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
            if (family != 2) return null;  // AF_INET only
            // IPv4 octets are at offset 2-5 within the 20-byte Address array,
            // which starts at byte offset 4 of the struct → struct offsets 6-9.
            return new byte[] { buf[6], buf[7], buf[8], buf[9] };
        }

        private static string? QueryWideString(uint pQuery, uint pFree, ulong server, uint sessionId, int infoClass, int maxChars)
        {
            ulong host = QueryRaw(pQuery, server, sessionId, infoClass, out _);
            if (host == 0) return null;
            string s = ReadWStringFromHost(host, maxChars);
            if (pFree != 0) Invoke(pFree, 1, host);
            return string.IsNullOrEmpty(s) ? null : s;
        }

        private static int? QueryInt32(uint pQuery, uint pFree, ulong server, uint sessionId, int infoClass)
        {
            ulong host = QueryRaw(pQuery, server, sessionId, infoClass, out _);
            if (host == 0) return null;
            byte[] buf = new byte[4];
            fixed (byte* bp = buf) CopyHostToWasm(host, (uint)(IntPtr)bp, 4);
            if (pFree != 0) Invoke(pFree, 1, host);
            return (int)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
        }

        private static ClientDisplay? QueryClientDisplay(uint pQuery, uint pFree, ulong server, uint sessionId)
        {
            ulong host = QueryRaw(pQuery, server, sessionId, WTSClientDisplay, out _);
            if (host == 0) return null;
            byte[] buf = new byte[12];
            fixed (byte* bp = buf) CopyHostToWasm(host, (uint)(IntPtr)bp, 12);
            if (pFree != 0) Invoke(pFree, 1, host);
            int h = (int)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
            int v = (int)(buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24));
            int d = (int)(buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24));
            return new ClientDisplay { HorizontalResolution = h, VerticalResolution = v, ColorDepth = d };
        }

        private static byte[]? QueryHardwareId(uint pQuery, uint pFree, ulong server, uint sessionId)
        {
            ulong host = QueryRaw(pQuery, server, sessionId, WTSClientHardwareId, out uint byteLen);
            if (host == 0) return null;
            if (byteLen == 0 || byteLen > 256) { if (pFree != 0) Invoke(pFree, 1, host); return null; }
            byte[] buf = new byte[byteLen];
            fixed (byte* bp = buf) CopyHostToWasm(host, (uint)(IntPtr)bp, byteLen);
            if (pFree != 0) Invoke(pFree, 1, host);
            return buf;
        }

        private static long? QuerySessionInfoLastInput(uint pQuery, uint pFree, ulong server, uint sessionId)
        {
            // WTSINFOW layout (CharSet.Auto → Unicode on modern .NET):
            //   0:   State (4) + SessionId (4) = 8
            //   8:   6 ints (24) → ends at 32
            //   32:  WinStationName[32 wchars] = 64 → ends at 96
            //   96:  Domain[17 wchars] = 34 → ends at 130
            //   130: UserName[21 wchars] = 42 → ends at 172
            //   176: ConnectTime (8) [padded to 8-byte boundary]
            //   184: DisconnectTime (8)
            //   192: LastInputTime (8)  ← what we want
            //   200: LogonTime (8)
            //   208: CurrentTime (8)
            //   Total: 216 bytes.
            ulong host = QueryRaw(pQuery, server, sessionId, WTSSessionInfo, out _);
            if (host == 0) return null;
            byte[] buf = new byte[216];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(host, (uint)(IntPtr)bp, 216))
                {
                    if (pFree != 0) Invoke(pFree, 1, host);
                    return null;
                }
                long li = (long)Read8(bp, 192);
                if (pFree != 0) Invoke(pFree, 1, host);
                return li;
            }
        }
    }
}
