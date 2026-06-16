// WfRegistry.cs — managed registry-read helper backed by the wasmforge host.
//
// NativeAOT-WASI ships without a working Microsoft.Win32.RegistryKey
// implementation — every call to RegistryKey.OpenBaseKey throws
// `PlatformNotSupportedException: Registry is not supported on this
// platform`. That breaks ~20 GhostPack/Seatbelt commands that read the
// registry to enumerate values (LSASettings, InternetSettings, AutoRuns,
// AntiVirus, AppLocker, AuditPolicyRegistry, CredGuard, DotNet, …).
//
// WasmForge's host already exposes a registry enumerator as the
// `reg_enumvals` env-import (see internal/hostmod/nativeaot_security_windows.go).
// This helper wraps that import in a managed C# API that matches the
// shape Seatbelt's RegistryUtil expects: `EnumValues(hive, path) →
// Dictionary<string, object>`.
//
// Host wire format (parsed below):
//
//   record := name "\t" type "\t" value "\0"
//   names: arbitrary unicode (UTF-8 on the wire)
//   types: REG_SZ | REG_EXPAND_SZ | REG_DWORD | REG_QWORD | REG_MULTI_SZ |
//          REG_BINARY | REG_<n>
//   values:
//     REG_SZ / REG_EXPAND_SZ        — plain string
//     REG_DWORD                     — decimal integer as string
//     REG_QWORD                     — decimal integer as string
//     REG_MULTI_SZ                  — '|' separated entries
//     REG_BINARY                    — hex digits (max 64 bytes)
//     other                         — "<binary N bytes>"
//
// The helper returns each value typed approximately as the BCL would have:
// strings as System.String, DWORDs as System.Int32, QWORDs as System.Int64,
// MULTI_SZ as String[], BINARY as Byte[], anything else as the raw string.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace WasmForge.Helpers
{
    public static unsafe class WfRegistry
    {
        // reg_enumvals: hive_ptr → uint32 hive value at that pointer,
        // path_ptr/len → UTF-8 path bytes, out_buf → host writes records.
        [DllImport("env", EntryPoint = "reg_enumvals")]
        private static extern uint reg_enumvals(uint hivePtr, uint pathPtr, uint pathLen,
            uint outBufPtr, uint outBufLen);

        // Maps RegistryHive enum values to the Win32 HKEY_* constants the host expects.
        private static uint HiveToHkey(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:     return 0x80000000u;
                case RegistryHive.CurrentUser:     return 0x80000001u;
                case RegistryHive.LocalMachine:    return 0x80000002u;
                case RegistryHive.Users:           return 0x80000003u;
                case RegistryHive.PerformanceData: return 0x80000004u;
                case RegistryHive.CurrentConfig:   return 0x80000005u;
                default:                           return 0x80000002u; // safe default: HKLM
            }
        }

        // Single-value lookups built on EnumValues — avoids needing distinct
        // host functions per value type. Returns null if the path or value
        // doesn't exist.
        public static string GetStringValue(RegistryHive hive, string path, string valueName)
        {
            var values = EnumValues(hive, path);
            return values.TryGetValue(valueName, out var v) ? v?.ToString() : null;
        }

        public static uint? GetDwordValue(RegistryHive hive, string path, string valueName)
        {
            var values = EnumValues(hive, path);
            if (!values.TryGetValue(valueName, out var v) || v == null) return null;
            if (v is int i) return (uint)i;
            if (v is long l) return (uint)l;
            if (v is uint u) return u;
            if (uint.TryParse(v.ToString(), out uint parsed)) return parsed;
            return null;
        }

        // Subkey enumeration via reg_open / reg_enum_key / reg_close round-trip.
        // The host's reg_open returns an opaque handle; reg_enum_key fills a
        // caller-provided buffer with the subkey name at the given index.
        [DllImport("env", EntryPoint = "reg_open")]
        private static extern uint reg_open(uint hivePtr, uint pathPtr, uint pathLen, uint outHandlePtr);

        [DllImport("env", EntryPoint = "reg_close")]
        private static extern uint reg_close(uint handle);

        [DllImport("env", EntryPoint = "reg_enum")]
        private static extern uint reg_enum(uint handle, uint index, uint namePtr, uint nameLenPtr);

        public static string[] GetSubkeyNames(RegistryHive hive, string path)
        {
            var names = new List<string>();
            // Empty path is intentional for hive-root enumeration — the host
            // bridge (reg_open) passes the path verbatim to RegOpenKeyExW which
            // treats an empty subkey as "open the hive itself". Callers that
            // pass null get a defensive empty result; an empty string is a
            // valid request (e.g. SearchRegistry walking from HKEY_USERS\).
            if (path == null) return names.ToArray();
            uint hkey = HiveToHkey(hive);
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            uint handle;
            uint open;
            fixed (byte* pathPtr = pathBytes)
            {
                open = reg_open((uint)(IntPtr)(&hkey), (uint)(IntPtr)pathPtr, (uint)pathBytes.Length, (uint)(IntPtr)(&handle));
            }
            if (open != 0 || handle == 0) return names.ToArray();
            try
            {
                // RegEnumKeyExW writes UTF-16LE wide chars; lpcchName is the
                // CHAR count (in chars, not bytes) — input is buffer capacity
                // in chars, output is the actual char count written.
                // Capacity here: 512-byte buffer = 256 wide chars.
                const int BufBytes = 512;
                const uint BufChars = BufBytes / 2;
                byte[] nameBuf = new byte[BufBytes];
                for (uint i = 0; i < 4096; i++)
                {
                    uint nameLen = BufChars;
                    uint rc;
                    fixed (byte* nb = nameBuf)
                    {
                        rc = reg_enum(handle, i, (uint)(IntPtr)nb, (uint)(IntPtr)(&nameLen));
                    }
                    if (rc != 0 || nameLen == 0 || nameLen > BufChars) break;
                    // Decode UTF-16LE — RegEnumKeyExW always writes wide chars
                    // regardless of system locale; reading as UTF-8 produces
                    // the interleaved-NUL artefact seen in lab debug capture.
                    names.Add(Encoding.Unicode.GetString(nameBuf, 0, (int)nameLen * 2));
                }
            }
            finally { reg_close(handle); }
            return names.ToArray();
        }

        public static Dictionary<string, object> EnumValues(RegistryHive hive, string path)
        {
            var result = new Dictionary<string, object>();
            // Empty path == enumerate values directly under the hive root (rare
            // but valid for SearchRegistry-style recursive walks). Null path
            // remains a no-op for defensive callers.
            if (path == null)
                return result;

            uint hkey = HiveToHkey(hive);
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            // Output buffer sized for typical registry keys (a few KB of
            // enumerated values). 64 KB is generous; the host truncates if
            // its own scratch is smaller and we won't overflow this.
            byte[] outBuf = new byte[64 * 1024];

            uint written;
            fixed (byte* pathPtr = pathBytes)
            fixed (byte* outPtr = outBuf)
            {
                // hkey lives on the C# stack; pass its address as the hive_ptr.
                written = reg_enumvals(
                    (uint)(IntPtr)(&hkey),
                    (uint)(IntPtr)pathPtr, (uint)pathBytes.Length,
                    (uint)(IntPtr)outPtr, (uint)outBuf.Length);
            }

            if (written == 0 || written > outBuf.Length)
                return result;

            // Parse null-separated records: name\ttype\tvalue\0
            int start = 0;
            for (int i = 0; i < (int)written; i++)
            {
                if (outBuf[i] != 0) continue;
                if (i > start)
                {
                    string record = Encoding.UTF8.GetString(outBuf, start, i - start);
                    var parts = record.Split('\t');
                    if (parts.Length >= 3)
                    {
                        string name = parts[0];
                        string type = parts[1];
                        string value = parts[2];
                        result[name] = ConvertValue(type, value);
                    }
                }
                start = i + 1;
            }
            return result;
        }

        private static object ConvertValue(string regType, string raw)
        {
            switch (regType)
            {
                case "REG_DWORD":
                case "REG_DWORD_BIG_ENDIAN":
                    if (int.TryParse(raw, out int iv)) return iv;
                    if (uint.TryParse(raw, out uint uv)) return unchecked((int)uv);
                    return raw;
                case "REG_QWORD":
                    if (long.TryParse(raw, out long lv)) return lv;
                    if (ulong.TryParse(raw, out ulong ulv)) return unchecked((long)ulv);
                    return raw;
                case "REG_MULTI_SZ":
                    return raw.Split('|');
                case "REG_BINARY":
                    if ((raw.Length & 1) != 0) return raw;
                    byte[] bytes = new byte[raw.Length / 2];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        int hi = HexDigit(raw[i * 2]);
                        int lo = HexDigit(raw[i * 2 + 1]);
                        if (hi < 0 || lo < 0) return raw;
                        bytes[i] = (byte)((hi << 4) | lo);
                    }
                    return bytes;
                case "REG_SZ":
                case "REG_EXPAND_SZ":
                    return raw;
                default:
                    return raw;
            }
        }

        private static int HexDigit(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        // ── GetSubkeyClass — read the undocumented class string from
        //    LSA subkeys (JD/Skew1/GBG/Data). Used by Seatbelt's
        //    LSADump.GetBootKey to assemble the boot key from the
        //    scrambled 4-char class strings on those subkeys.
        //
        //    Wraps RegEnumKeyExW which is bridged via
        //    pinvoke_nativeaot.c:1586. Unlike GetSubkeyNames (which
        //    discards lpClass), this passes a stack-allocated
        //    class-string buffer and reads it back.

        private const uint KEY_READ = 0x20019;
        private const int  ERROR_SUCCESS = 0;
        private const int  ERROR_NO_MORE_ITEMS = 259;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey,
            uint ulOptions, uint samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int RegEnumKeyExW(IntPtr hKey, uint dwIndex,
            IntPtr lpName, ref uint lpcName,
            IntPtr lpReserved, IntPtr lpClass, ref uint lpcClass,
            IntPtr lpftLastWriteTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        public static string GetSubkeyClass(RegistryHive hive, string parentPath, string subkeyName)
        {
            if (string.IsNullOrEmpty(subkeyName)) return null;

            IntPtr rootHandle = (IntPtr)HiveToHkey(hive);
            IntPtr hKey = IntPtr.Zero;
            if (RegOpenKeyExW(rootHandle, parentPath ?? "", 0, KEY_READ, out hKey) != ERROR_SUCCESS
                || hKey == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                // Find the subkey index by enumerating names.
                IntPtr nameBuf  = Marshal.AllocHGlobal(260 * 2);   // 260 WCHARs
                IntPtr classBuf = Marshal.AllocHGlobal(260 * 2);
                IntPtr ftBuf    = Marshal.AllocHGlobal(16);
                try
                {
                    for (uint i = 0; i < 1024; i++)
                    {
                        uint nameLen = 260;
                        uint classLen = 260;

                        // Zero out buffers each iteration.
                        for (int z = 0; z < 260; z++)
                            Marshal.WriteInt16(nameBuf, z * 2, 0);
                        for (int z = 0; z < 260; z++)
                            Marshal.WriteInt16(classBuf, z * 2, 0);

                        int rc = RegEnumKeyExW(hKey, i, nameBuf, ref nameLen,
                            IntPtr.Zero, classBuf, ref classLen, ftBuf);
                        if (rc == ERROR_NO_MORE_ITEMS) return null;
                        if (rc != ERROR_SUCCESS) return null;

                        string enumeratedName = Marshal.PtrToStringUni(nameBuf, (int)nameLen);
                        if (string.Equals(enumeratedName, subkeyName,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            return Marshal.PtrToStringUni(classBuf, (int)classLen);
                        }
                    }
                    return null;
                }
                finally
                {
                    Marshal.FreeHGlobal(nameBuf);
                    Marshal.FreeHGlobal(classBuf);
                    Marshal.FreeHGlobal(ftBuf);
                }
            }
            finally
            {
                RegCloseKey(hKey);
            }
        }
    }
}
