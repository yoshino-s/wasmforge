// WfPipes.cs — Host-bridge replacement for FindFirstFile(\\.\pipe\*)
// which crashes the NativeAOT-WASI bridge due to WIN32_FIND_DATA struct
// marshaling. Routes through env.fs_pipes (host CreateToolhelp32Snapshot-
// alternative via FindFirstFileW on the host side).

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WasmForge.Bridge
{
    public static class WfPipes
    {
        [DllImport("env", EntryPoint = "fs_pipes")]
        private static extern uint fs_pipes(uint bufPtr, uint bufCap, uint countPtr);

        /// <summary>Enumerate Windows named pipes via the fs_pipes host bridge.
        /// Wire format: NUL-separated UTF-8 names in the output buffer.</summary>
        public static List<string> EnumerateNamedPipes()
        {
            var result = new List<string>();
            byte[] buf = new byte[256 * 1024];
            uint count = 0;
            uint written;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    written = fs_pipes((uint)(IntPtr)p, (uint)buf.Length, (uint)(IntPtr)(&count));
                }
            }
            if (written == 0 || written > buf.Length) return result;

            int start = 0;
            for (int i = 0; i < (int)written; i++)
            {
                if (buf[i] == 0)
                {
                    if (i > start)
                        result.Add(System.Text.Encoding.UTF8.GetString(buf, start, i - start));
                    start = i + 1;
                }
            }
            return result;
        }
    }
}
