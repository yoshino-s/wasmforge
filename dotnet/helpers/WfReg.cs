// WfReg.cs — Win32 registry security helpers backed by wasmforge host functions.
//
// Replaces .NET BCL patterns that require WindowsIdentity / NTAccount /
// RegistrySecurity (all PNS under NativeAOT-WASI) with host-side ACL checks
// using the calling process's primary token.
//
// The host's reg_modifiable function calls RegOpenKeyEx with KEY_SET_VALUE |
// KEY_CREATE_SUB_KEY. If that succeeds, the current token has at least one
// form of write access to the key — which is what SharpUp.IsModifiableKey
// determines by parsing the DACL and comparing against identity.Groups.
// Both approaches yield the same boolean answer, but the host bridge needs
// neither WindowsIdentity nor RegistryAccessRule / RegistryRights.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfReg
    {
        [DllImport("env", EntryPoint = "reg_modifiable")]
        private static extern uint reg_modifiable(uint hive, uint pathPtr, uint pathLen);

        private const uint HIVE_HKLM = 0;
        private const uint HIVE_HKCU = 1;
        private const uint HIVE_HKU  = 2;

        public static bool IsModifiableLocalMachineKey(string path)
        {
            return Modifiable(HIVE_HKLM, path);
        }

        public static bool IsModifiableCurrentUserKey(string path)
        {
            return Modifiable(HIVE_HKCU, path);
        }

        private static bool Modifiable(uint hive, string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            byte[] pb = Encoding.UTF8.GetBytes(path);
            fixed (byte* pp = pb)
            {
                return reg_modifiable(hive, (uint)(IntPtr)pp, (uint)pb.Length) != 0;
            }
        }

        [DllImport("env", EntryPoint = "sc_modifiable")]
        private static extern uint sc_modifiable(uint namePtr, uint nameLen);

        /// <summary>Returns true if the calling token has SERVICE_CHANGE_CONFIG
        /// (or any other modify right) on the named service.</summary>
        public static bool IsModifiableService(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            byte[] nb = Encoding.UTF8.GetBytes(name);
            fixed (byte* np = nb)
            {
                return sc_modifiable((uint)(IntPtr)np, (uint)nb.Length) != 0;
            }
        }

        [DllImport("env", EntryPoint = "proc_modules")]
        private static extern uint proc_modules(uint pid, uint outBufPtr, uint outBufLen);

        public sealed class ProcessModuleInfo
        {
            public string Name { get; set; }
            public string FileName { get; set; }
        }

        /// <summary>Enumerates loaded modules for a process by PID. Replaces
        /// process.Modules (PNS under NativeAOT-WASI). Uses EnumProcessModulesEx
        /// on the host side. Returns null if access denied.</summary>
        public static System.Collections.Generic.List<ProcessModuleInfo> EnumProcessModules(uint pid)
        {
            byte[] buf = new byte[256 * 1024];
            uint written;
            fixed (byte* bp = buf)
            {
                written = proc_modules(pid, (uint)(IntPtr)bp, (uint)buf.Length);
            }
            if (written == 0 || written > buf.Length) return null;
            string json = System.Text.Encoding.UTF8.GetString(buf, 0, (int)written);
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var list = new System.Collections.Generic.List<ProcessModuleInfo>();
                if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array) return list;
                foreach (var entry in doc.RootElement.EnumerateArray())
                {
                    string name = "";
                    string fileName = "";
                    if (entry.TryGetProperty("Name", out var n)) name = n.GetString() ?? "";
                    if (entry.TryGetProperty("FileName", out var f)) fileName = f.GetString() ?? "";
                    list.Add(new ProcessModuleInfo { Name = name, FileName = fileName });
                }
                return list;
            }
            catch { return null; }
        }
    }
}
