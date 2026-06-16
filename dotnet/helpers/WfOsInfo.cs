// WfOsInfo.cs — kernel32-backed host info getters for NativeAOT-WASI.
//
// WASI's standard library exposes a sandboxed view of the host:
// Dns.GetHostName() returns "localhost", Environment.ProcessorCount
// returns 1, TimeZone.CurrentTimeZone falls back to UTC,
// IPGlobalProperties.DomainName returns "". For commands like
// Seatbelt's OSInfo that need the real Windows hostname, CPU count,
// joined domain DNS suffix, and timezone, we go through wf_call
// (mod_load + mod_resolve + mod_invoke) to invoke kernel32 / advapi32
// host-side and read the results back through Win32 RtlMoveMemory.
//
// Pattern mirrors WfNetapi.cs — see that file for the rationale
// against mod_hread (cgocallback re-entry panic).

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfOsInfo
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

        private static uint _kernel32;
        private static uint _hGetComputerNameW;
        private static uint _hGetComputerNameExW;
        private static uint _hGetUserNameW;
        private static uint _hGetSystemInfo;
        private static uint _hGetTimeZoneInformation;
        private static uint _hGetDynamicTimeZoneInformation;
        private static uint _hGetUserDefaultLocaleName;
        private static uint _hGetKeyboardLayoutNameW;
        private static uint _hGetTickCount64;
        private static uint _ntdll;
        private static uint _hRtlMoveMemory;
        private static uint _advapi32;
        private static uint _hGetUserNameWAdvapi;

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
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0)
        {
            ulong ret1 = 0, err = 0;
            return mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // Copy n bytes from host address src into the WASM-side buffer dstPtr.
        private static void CopyHostToWasm(ulong hostSrc, uint wasmDst, uint n)
        {
            uint mv = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (mv == 0) return;
            Invoke(mv, 3, (ulong)wasmDst, hostSrc, n);
        }

        // ── MachineName ────────────────────────────────────────────────
        //
        // Replaces Dns.GetHostName() / Environment.MachineName which return
        // "localhost" under wasip1. Uses kernel32!GetComputerNameW which
        // returns the local NetBIOS name.

        public static string MachineName()
        {
            // DNS hostname ("GOADf97252-GOAD-Win11") — what
            // IPGlobalProperties.HostName returns on real .NET, what Seatbelt
            // OSInfo's Hostname field expects. Falls back to GetComputerNameW
            // (NetBIOS) if Ex is unavailable.
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetComputerNameExW", ref _hGetComputerNameExW);
            if (proc != 0)
            {
                byte[] buf = new byte[512];
                uint sz = 256;
                ulong rc;
                fixed (byte* b = buf)
                {
                    // 1 = ComputerNameDnsHostname
                    rc = Invoke(proc, 3, 1u, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz));
                }
                if (rc != 0 && sz > 0 && sz <= 255)
                    return Encoding.Unicode.GetString(buf, 0, (int)sz * 2);
            }

            uint proc2 = Resolve("kernel32.dll", ref _kernel32, "GetComputerNameW", ref _hGetComputerNameW);
            if (proc2 == 0) return "localhost";

            byte[] buf2 = new byte[64];
            uint sz2 = 32;
            ulong rc2;
            fixed (byte* b = buf2)
            {
                rc2 = Invoke(proc2, 2, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz2));
            }
            if (rc2 == 0) return "localhost";
            int charCount = (int)sz2;
            if (charCount <= 0 || charCount > 31) return "localhost";
            return Encoding.Unicode.GetString(buf2, 0, charCount * 2);
        }

        // ── NetBiosName ─────────────────────────────────────────────────
        //
        // GetComputerNameW returns the NetBIOS computer name (uppercase, max
        // 15 chars). That's what `Environment.MachineName` returns on real
        // .NET, and what Seatbelt's LocalGroups / LocalUsers /
        // UserRightAssignments baselines expect as the local-account prefix.
        // Distinct from MachineName() which returns the DNS hostname.
        public static string NetBiosName()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetComputerNameW", ref _hGetComputerNameW);
            if (proc == 0) return "";
            byte[] buf = new byte[64];
            uint sz = 32;
            ulong rc;
            fixed (byte* b = buf)
            {
                rc = Invoke(proc, 2, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz));
            }
            if (rc == 0) return "";
            int n = (int)sz;
            if (n <= 0 || n > 31) return "";
            return Encoding.Unicode.GetString(buf, 0, n * 2);
        }

        // ── UserName ────────────────────────────────────────────────────
        //
        // advapi32!GetUserNameW. Fallback to USERNAME env var, then "unknown".

        public static string UserName()
        {
            uint proc = Resolve("advapi32.dll", ref _advapi32, "GetUserNameW", ref _hGetUserNameWAdvapi);
            if (proc != 0)
            {
                byte[] buf = new byte[512];
                uint sz = 256;
                ulong rc;
                fixed (byte* b = buf)
                {
                    rc = Invoke(proc, 2, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz));
                }
                // GetUserNameW returns sz including the null terminator.
                if (rc != 0 && sz > 1 && sz <= 256)
                {
                    return Encoding.Unicode.GetString(buf, 0, (int)(sz - 1) * 2);
                }
            }
            return Environment.GetEnvironmentVariable("USERNAME") ?? "unknown";
        }

        // ── WindowsIdentityName ────────────────────────────────────────
        //
        // Equivalent of WindowsIdentity.GetCurrent().Name — the
        // DOMAIN\username form. Uses secur32!GetUserNameExW(NameSamCompatible=2).

        private static uint _secur32;
        private static uint _hGetUserNameExW;

        public static string WindowsIdentityName()
        {
            uint proc = Resolve("secur32.dll", ref _secur32, "GetUserNameExW", ref _hGetUserNameExW);
            if (proc != 0)
            {
                byte[] buf = new byte[1024];
                uint sz = 512;
                ulong rc;
                fixed (byte* b = buf)
                {
                    // 2 = NameSamCompatible (DOMAIN\username)
                    rc = Invoke(proc, 3, 2u, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz));
                }
                if (rc != 0 && sz > 1 && sz <= 511)
                {
                    return Encoding.Unicode.GetString(buf, 0, (int)sz * 2);
                }
            }
            // Fallback: USERDOMAIN\USERNAME from env (works for SSH domain sessions).
            string dom = Environment.GetEnvironmentVariable("USERDOMAIN") ?? "";
            string usr = Environment.GetEnvironmentVariable("USERNAME") ?? UserName();
            if (!string.IsNullOrEmpty(dom)) return dom + "\\" + usr;
            return usr;
        }

        // ── ProcessorCount ─────────────────────────────────────────────
        //
        // GetSystemInfo writes a SYSTEM_INFO struct. Field offsets (x64):
        //   wProcessorArchitecture(2) @0
        //   wReserved(2)             @2
        //   dwPageSize(4)            @4
        //   lpMinimumApplicationAddress(8) @8
        //   lpMaximumApplicationAddress(8) @16
        //   dwActiveProcessorMask(8) @24
        //   dwNumberOfProcessors(4)  @32
        //   ...
        // We only need offset 32 (NumberOfProcessors).

        public static int ProcessorCount()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetSystemInfo", ref _hGetSystemInfo);
            if (proc == 0) return 1;

            // SYSTEM_INFO is 48 bytes on x64.
            byte[] buf = new byte[64];
            fixed (byte* b = buf)
            {
                Invoke(proc, 1, (ulong)(uint)(IntPtr)b);
            }
            // dwNumberOfProcessors is a 4-byte int at offset 32.
            int n = buf[32] | (buf[33] << 8) | (buf[34] << 16) | (buf[35] << 24);
            return n > 0 ? n : 1;
        }

        // ── DnsDomain ──────────────────────────────────────────────────
        //
        // GetComputerNameExW(ComputerNameDnsDomain=2, lpBuffer, lpnSize)
        // Returns the joined-domain DNS suffix, e.g. "sevenkingdoms.local".

        public static string DnsDomain()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetComputerNameExW", ref _hGetComputerNameExW);
            if (proc == 0) return "";

            byte[] buf = new byte[512];
            uint sz = 256;
            ulong rc;
            fixed (byte* b = buf)
            {
                // 2 = ComputerNameDnsDomain
                rc = Invoke(proc, 3, 2u, (ulong)(uint)(IntPtr)b, (ulong)(uint)(IntPtr)(&sz));
            }
            if (rc == 0 || sz == 0 || sz > 255) return "";
            return Encoding.Unicode.GetString(buf, 0, (int)sz * 2);
        }

        // ── TimeZoneId ─────────────────────────────────────────────────
        //
        // GetTimeZoneInformation returns a TIME_ZONE_INFORMATION struct.
        // We just want the StandardName (WCHAR[32] at offset 4).

        public static string TimeZoneId()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetTimeZoneInformation", ref _hGetTimeZoneInformation);
            if (proc == 0) return "UTC";

            // TIME_ZONE_INFORMATION is 172 bytes.
            byte[] buf = new byte[256];
            ulong rc;
            fixed (byte* b = buf)
            {
                rc = Invoke(proc, 1, (ulong)(uint)(IntPtr)b);
            }
            if (rc == 0xFFFFFFFF) return "UTC"; // TIME_ZONE_ID_INVALID
            // StandardName WCHAR[32] starts at offset 4.
            int nameOff = 4;
            int nameLen = 0;
            while (nameLen < 32 && (buf[nameOff + nameLen * 2] != 0 || buf[nameOff + nameLen * 2 + 1] != 0))
                nameLen++;
            if (nameLen == 0) return "UTC";
            return Encoding.Unicode.GetString(buf, nameOff, nameLen * 2);
        }

        // ── TimeZoneOffset ─────────────────────────────────────────────
        //
        // Returns the current Bias (in minutes) as a TimeSpan-formatted
        // string "-HH:MM:SS" matching the format Seatbelt's OSInfo expects.
        // GetTimeZoneInformation Bias is at offset 0 (LONG, signed 4 bytes).

        public static string TimeZoneOffset()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetTimeZoneInformation", ref _hGetTimeZoneInformation);
            if (proc == 0) return "00:00:00";

            byte[] buf = new byte[256];
            ulong rc;
            fixed (byte* b = buf)
            {
                rc = Invoke(proc, 1, (ulong)(uint)(IntPtr)b);
            }
            if (rc == 0xFFFFFFFF) return "00:00:00";
            // TIME_ZONE_INFORMATION layout:
            //   0:  LONG Bias
            //   4:  WCHAR StandardName[32]    (64 bytes)
            //   68: SYSTEMTIME StandardDate   (16 bytes)
            //   84: LONG StandardBias
            //   88: WCHAR DaylightName[32]    (64 bytes)
            //   152:SYSTEMTIME DaylightDate   (16 bytes)
            //   168:LONG DaylightBias
            //
            // Return value: 0 = unknown, 1 = standard time, 2 = daylight.
            // Effective offset = -(Bias + (currentBias)).
            int bias = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
            int extraBias = 0;
            if (rc == 1) // TIME_ZONE_ID_STANDARD
                extraBias = buf[84] | (buf[85] << 8) | (buf[86] << 16) | (buf[87] << 24);
            else if (rc == 2) // TIME_ZONE_ID_DAYLIGHT
                extraBias = buf[168] | (buf[169] << 8) | (buf[170] << 16) | (buf[171] << 24);
            int totalMinutes = -(bias + extraBias);
            int sign = totalMinutes < 0 ? -1 : 1;
            int abs = totalMinutes * sign;
            int h = abs / 60;
            int m = abs % 60;
            return string.Format("{0}{1:D2}:{2:D2}:00", sign < 0 ? "-" : "", h, m);
        }

        // ── BootTime ──────────────────────────────────────────────────
        //
        // GetTickCount64 returns ms since boot. Seatbelt computes
        // BootTimeUtc = UtcNow - TickCount.

        public static long TickCount64()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetTickCount64", ref _hGetTickCount64);
            if (proc == 0) return 0;
            return (long)Invoke(proc, 0);
        }

        // ── UserDefaultLocaleName ───────────────────────────────────────
        //
        // GetUserDefaultLocaleName(buf, LOCALE_NAME_MAX_LENGTH=85).
        // Returns e.g. "en-US". Used to back CultureInfo.InstalledUICulture.

        public static string UserLocale()
        {
            uint proc = Resolve("kernel32.dll", ref _kernel32, "GetUserDefaultLocaleName", ref _hGetUserDefaultLocaleName);
            if (proc == 0) return "en-US";

            byte[] buf = new byte[256];
            ulong charCount;
            fixed (byte* b = buf)
            {
                charCount = Invoke(proc, 2, (ulong)(uint)(IntPtr)b, 85u);
            }
            if (charCount == 0 || charCount > 85) return "en-US";
            // Returned count includes the null terminator.
            int n = (int)(charCount - 1);
            return n > 0 ? Encoding.Unicode.GetString(buf, 0, n * 2) : "en-US";
        }

        // ── TimeZone shim ───────────────────────────────────────────────
        //
        // Target of the MemberChainRewrite TimeZone.CurrentTimeZone → WfOsInfo.TimeZone.
        // Exposed as a singleton instance (not a static class) so calling
        // patterns like `var tz = TimeZone.CurrentTimeZone; tz.StandardName`
        // continue to compile after the rewrite. StandardName and
        // GetUtcOffset() proxy to the kernel32-backed values.

        public sealed class TimeZoneShim
        {
            public string StandardName => TimeZoneId();
            public string DaylightName => TimeZoneId();
            public System.TimeSpan GetUtcOffset(System.DateTime _ignored)
            {
                string s = TimeZoneOffset();
                if (System.TimeSpan.TryParse(s, out var ts)) return ts;
                return System.TimeSpan.Zero;
            }

            // ToLocalTime: convert a UTC DateTime to local time. Required so
            // the MemberChainRewrite "TimeZone.CurrentTimeZone.* → WfOsInfo.TimeZone"
            // produces compiling code for the .ToLocalTime(dt) chain. Without
            // this method we collided with a legacy text rule that rewrote
            // the whole "TimeZone.CurrentTimeZone.ToLocalTime(" invocation to
            // WfSidShim.ToLocalTimeSafe — both rules wanted to edit the same
            // byte span (the AST rule covered the receiver prefix [7393,7417);
            // the legacy rule covered prefix-plus-method [7393,7430)), which
            // tripped the EditList.ApplyBottomUp overlap detector. Folding
            // the safe-fallback logic into the shim eliminates the conflict.
            public System.DateTime ToLocalTime(System.DateTime dt)
            {
                try
                {
                    return System.TimeZoneInfo.ConvertTime(dt, System.TimeZoneInfo.Local);
                }
                catch { return dt; }
            }
        }

        private static readonly TimeZoneShim _tzInstance = new TimeZoneShim();
        public static TimeZoneShim TimeZone => _tzInstance;

        // ── GlobalProperties shim ──────────────────────────────────────
        //
        // Target of InvocationRewrite IPGlobalProperties.GetIPGlobalProperties()
        // → WfOsInfo.GlobalProperties.Get(). Exposes the small subset of
        // System.Net.NetworkInformation.IPGlobalProperties that the
        // GhostPack tools actually read: HostName, DomainName.

        public sealed class GlobalProperties
        {
            public string HostName { get; private set; }
            public string DomainName { get; private set; }

            public static GlobalProperties Get()
            {
                return new GlobalProperties
                {
                    HostName   = MachineName(),
                    DomainName = DnsDomain(),
                };
            }
        }

        // ── InputLanguageLayoutName ────────────────────────────────
        //
        // Returns the active keyboard layout's friendly name (e.g. "US",
        // "United States-International") to match
        // System.Windows.Forms.InputLanguage.CurrentInputLanguage.LayoutName.
        //
        // Uses GetKeyboardLayoutNameW to get the 8-char KLID hex string, then
        // reads HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\<KLID>
        // "Layout Text" → the human-readable name. Falls back to "" or to
        // the raw KLID if registry read fails.
        public static string InputLanguageLayoutName()
        {
            try
            {
                uint proc = Resolve("user32.dll", ref _user32, "GetKeyboardLayoutNameW", ref _hGetKeyboardLayoutNameW);
                if (proc == 0) return "";

                byte[] buf = new byte[64];
                ulong rc;
                fixed (byte* b = buf)
                {
                    rc = Invoke(proc, 1, (ulong)(uint)(IntPtr)b);
                }
                if (rc == 0) return "";

                string klid = Encoding.Unicode.GetString(buf, 0, 16);
                int nul = klid.IndexOf('\0');
                if (nul >= 0) klid = klid.Substring(0, nul);
                if (string.IsNullOrEmpty(klid)) return "";

                try
                {
                    var v = WfRegistry.GetStringValue(Microsoft.Win32.RegistryHive.LocalMachine,
                        @"SYSTEM\CurrentControlSet\Control\Keyboard Layouts\" + klid,
                        "Layout Text");
                    if (!string.IsNullOrEmpty(v)) return v;
                }
                catch { /* fall through */ }
                return klid;
            }
            catch
            {
                return "";
            }
        }
        private static uint _user32;
    }
}
