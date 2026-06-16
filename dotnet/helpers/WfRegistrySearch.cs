// WfRegistrySearch.cs — DPAPI-blob hunter over Microsoft.Win32 hives.
//
// Routes the entire BFS to the wasmforge host via `reg_search` (Category C
// host export, see docs/refactor/host-api-contract.md). Doing the walk in
// WASM via per-key wf_calls is O(depth) per call and exceeds the lab's
// 5-minute exec budget on HKLM (~500K keys). The host-side walker uses
// parent-handle propagation at native Win32 speed and completes both
// hives in seconds.
//
// Wire format from the host (NUL-separated UTF-8 records):
//
//   Root: HKEY_USERS\
//   HKEY_USERS\\<subpath> ! <valueName>
//   HKEY_USERS\\<subpath> ! Default       (when valueName == "")
//
// The double backslash on subkey lines mirrors what .NET RegistryKey.Name
// emits when the root was opened as Registry.Users.OpenSubKey("\\") —
// root.Name ends with a backslash, then BFS-joining children appends
// another. See testdata/parity-baselines/sharpdpapi/search.golden for the
// exact byte sequence (offset 0x140: "HKEY_USERS\\S-1-5-...").

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace WasmForge.Helpers
{
    public static unsafe class WfRegistrySearch
    {
        // Host bridge — see internal/hostmod/nativeaot_regsearch_windows.go.
        // Returns bytes written into out_buf, or 0 on error / buffer too small.
        [DllImport("env", EntryPoint = "reg_search")]
        private static extern uint NativeRegSearch(uint hive, uint outBufPtr, uint outBufCap);

        // Initial scratch buffer. Most hives produce far less than this even
        // with several thousand matches (~80 bytes/line). The host returns 0
        // if the buffer is too small; we grow and retry up to a hard ceiling
        // matching the host's internal expectations.
        private const int InitialBufBytes = 1 << 20;  // 1 MiB
        private const int MaxBufBytes     = 64 << 20; // 64 MiB

        /// <summary>
        /// Walk the given hive and return one line per matching value plus a
        /// leading "Root: &lt;hive-prefix&gt;\" header. The walk runs entirely
        /// host-side (see reg_search in internal/hostmod/nativeaot_regsearch_windows.go);
        /// the subpath argument is reserved for future use — the host walker
        /// currently always starts at the hive root, matching SharpDPAPI's
        /// usage in SearchRegistry which never passes a subpath when invoked
        /// without the /path argument.
        /// </summary>
        public static List<string> FindDpapiBlobs(RegistryHive hive, string subpath)
        {
            var results = new List<string>();
            uint hiveConst = HiveConst(hive);
            if (hiveConst == 0)
            {
                results.Add("Root: " + HivePrefix(hive));
                return results;
            }

            // Grow the buffer until the host fits its full output. 0 from
            // NativeRegSearch is ambiguous (could be "no data" or "buffer
            // too small") so we conservatively retry on 0 once, doubling
            // each iteration, until we exceed MaxBufBytes.
            int cap = InitialBufBytes;
            uint written = 0;
            byte[] buf = null;
            for (; cap <= MaxBufBytes; cap *= 2)
            {
                buf = new byte[cap];
                fixed (byte* p = buf)
                {
                    written = NativeRegSearch(hiveConst, (uint)(IntPtr)p, (uint)cap);
                }
                if (written != 0) break;
                // written == 0 → host either had no matches (unlikely for a
                // real hive on Windows) or wrote nothing because cap was
                // too small. Try one more time at the next cap step; if it
                // still returns 0 we accept that there are simply no matches.
                if (cap > InitialBufBytes) break;
            }

            if (buf == null || written == 0)
            {
                // No matches at all (e.g. host stub on non-Windows). Emit the
                // Root header so callers still see structurally-valid output.
                results.Add("Root: " + HivePrefix(hive));
                return results;
            }

            // Parse NUL-separated UTF-8 records.
            int start = 0;
            for (int i = 0; i < (int)written; i++)
            {
                if (buf[i] != 0) continue;
                if (i > start)
                {
                    string record = Encoding.UTF8.GetString(buf, start, i - start);
                    results.Add(record);
                }
                start = i + 1;
            }
            // Trailing record without NUL terminator (defensive).
            if (start < (int)written)
            {
                string tail = Encoding.UTF8.GetString(buf, start, (int)written - start);
                if (tail.Length > 0) results.Add(tail);
            }
            return results;
        }

        private static uint HiveConst(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:     return 0x80000000;
                case RegistryHive.CurrentUser:     return 0x80000001;
                case RegistryHive.LocalMachine:    return 0x80000002;
                case RegistryHive.Users:           return 0x80000003;
                case RegistryHive.CurrentConfig:   return 0x80000005;
                default: return 0;
            }
        }

        private static string HivePrefix(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.LocalMachine:    return "HKEY_LOCAL_MACHINE\\";
                case RegistryHive.Users:           return "HKEY_USERS\\";
                case RegistryHive.CurrentUser:     return "HKEY_CURRENT_USER\\";
                case RegistryHive.ClassesRoot:     return "HKEY_CLASSES_ROOT\\";
                case RegistryHive.CurrentConfig:   return "HKEY_CURRENT_CONFIG\\";
                case RegistryHive.PerformanceData: return "HKEY_PERFORMANCE_DATA\\";
                default: return hive.ToString() + "\\";
            }
        }
    }
}
