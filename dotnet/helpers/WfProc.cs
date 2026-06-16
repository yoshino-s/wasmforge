// WfProc.cs — Host-bridge alternative to System.Diagnostics.Process for
// NativeAOT-WASI. The BCL Process class PNS on this runtime, but SharpUp's
// ProcessDLLHijack just needs (pid, name, [{module path}]) — we route to a
// CreateToolhelp32Snapshot enumeration on the host.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WasmForge.Bridge
{
    public sealed class WfProcModule
    {
        public string Name { get; set; } = "";
        public string FileName { get; set; } = "";
        public string ModuleName => Name;
    }

    public sealed class WfProcess
    {
        public int Id { get; set; }
        public string ProcessName { get; set; } = "";
        public List<WfProcModule> ModuleList { get; } = new List<WfProcModule>();
        public List<WfProcModule> Modules => ModuleList;
    }

    public static class WfProc
    {
        /// <summary>Enumerate all accessible processes with their loaded
        /// modules via the host CreateToolhelp32Snapshot bridge. Returns
        /// an empty list on non-Windows hosts or if the snapshot fails.</summary>
        public static List<WfProcess> GetProcessesWithModules()
        {
            var result = new List<WfProcess>();
            byte[] outBuf = new byte[1024 * 1024]; // 1MB — Windows desktops typically produce ~200KB
            uint written;
            unsafe
            {
                fixed (byte* p = outBuf)
                {
                    written = WfHostBridge.ProcModulesAll(p, (uint)outBuf.Length);
                }
            }
            if (written == 0 || written > outBuf.Length) return result;

            string raw = System.Text.Encoding.UTF8.GetString(outBuf, 0, (int)written);
            // Wire format: pid\tname\tpath\n per line
            var byPid = new Dictionary<int, WfProcess>();
            foreach (var line in raw.Split('\n'))
            {
                if (string.IsNullOrEmpty(line)) continue;
                var fields = line.Split('\t');
                if (fields.Length < 3) continue;
                if (!int.TryParse(fields[0], out int pid)) continue;
                string name = fields[1];
                string path = fields[2];
                if (!byPid.TryGetValue(pid, out var proc))
                {
                    proc = new WfProcess { Id = pid, ProcessName = StripExe(name) };
                    byPid[pid] = proc;
                    result.Add(proc);
                }
                proc.ModuleList.Add(new WfProcModule
                {
                    Name = ExtractBasename(path),
                    FileName = path,
                });
            }
            return result;
        }

        private static string StripExe(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            int dot = name.LastIndexOf('.');
            return dot > 0 ? name.Substring(0, dot) : name;
        }

        private static string ExtractBasename(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int slash = path.LastIndexOfAny(new[] { '\\', '/' });
            return slash >= 0 && slash + 1 < path.Length ? path.Substring(slash + 1) : path;
        }

        // ── Task 2.9: CreateNetOnly ───────────────────────────────────────────

        /// <summary>
        /// Creates a new process using CreateProcessWithLogonW with network-only
        /// credentials (LOGON_NETCREDENTIALS_ONLY). Returns the new process ID on
        /// success, or 0 on failure. Used by Rubeus createnetonly.
        /// </summary>
        // ── Bridge primitives (mod_load / mod_resolve / mod_invoke pattern) ────
        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_load")]
        private static extern uint mod_load(uint namePtr);

        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_resolve")]
        private static extern uint mod_resolve(uint libHandle, uint namePtr);

        [System.Runtime.InteropServices.DllImport("env", EntryPoint = "mod_invoke")]
        private static extern ulong mod_invoke(
            ulong procHandle, uint nargs,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11,
            ulong a12, ulong a13, ulong a14,
            ulong ret1Ptr, ulong errPtr);

        private static uint _kernel32Proc;
        private static uint _advapi32Proc;
        private static uint _ntdllProc;
        private static uint _hVirtualAlloc;
        private static uint _hVirtualFree;
        private static uint _hCloseHandle;
        private static uint _hCreateProcessWithLogonW;
        private static uint _hRtlMoveMemory;
        private static uint _hRtlZeroMemory;

        private static uint ResolveProc(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
        {
            if (cachedProc != 0) return cachedProc;
            if (cachedLib == 0)
            {
                byte[] db = System.Text.Encoding.ASCII.GetBytes(dll + "\0");
                unsafe { fixed (byte* dp = db) cachedLib = mod_load((uint)(IntPtr)dp); }
                if (cachedLib == 0) return 0;
            }
            byte[] fb = System.Text.Encoding.ASCII.GetBytes(fn + "\0");
            unsafe { fixed (byte* fp = fb) cachedProc = mod_resolve(cachedLib, (uint)(IntPtr)fp); }
            return cachedProc;
        }

        private static ulong InvokeProc(uint proc, uint nargs,
            ulong a0=0, ulong a1=0, ulong a2=0, ulong a3=0,
            ulong a4=0, ulong a5=0, ulong a6=0, ulong a7=0,
            ulong a8=0, ulong a9=0, ulong a10=0)
        {
            ulong ret1=0, err=0;
            unsafe { return mod_invoke((ulong)proc, nargs,
                a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,0,0,0,0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err)); }
        }

        private static bool CopyHostToWasmProc(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint pCopy = ResolveProc("ntdll.dll", ref _ntdllProc, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            InvokeProc(pCopy, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        // Build a UTF-16LE string into a managed byte[] including NUL terminator.
        private static byte[] ToUtf16(string? s)
        {
            if (string.IsNullOrEmpty(s)) return new byte[2]; // just NUL
            byte[] bytes = new byte[(s!.Length + 1) * 2];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bytes[2*i]   = (byte)(c & 0xff);
                bytes[2*i+1] = (byte)((c >> 8) & 0xff);
            }
            return bytes;
        }

        /// <summary>
        /// Creates a new process using CreateProcessWithLogonW so the process runs
        /// with the supplied network credentials (LOGON_NETCREDENTIALS_ONLY by default).
        /// Returns the new process PID on success, or 0 on failure.
        ///
        /// Replaces the deleted proc_create_with_logon Go host bridge.
        /// Follows the WfNetapi.cs canonical wf_call pattern.
        ///
        /// STARTUPINFOW (x64, 104 bytes):
        ///   cb(4)@0, reserved(8)@8, lpDesktop(8)@16, lpTitle(8)@24,
        ///   dwX(4)@32, dwY(4)@36, dwXSize(4)@40, dwYSize(4)@44,
        ///   dwXCountChars(4)@48, dwYCountChars(4)@52, dwFillAttribute(4)@56,
        ///   dwFlags(4)@60, wShowWindow(2)@64, cbReserved2(2)@66, [pad 4]@68,
        ///   lpReserved2(8)@72, hStdInput(8)@80, hStdOutput(8)@88, hStdError(8)@96
        ///
        /// PROCESS_INFORMATION (24 bytes):
        ///   hProcess(8)@0, hThread(8)@8, dwProcessId(4)@16, dwThreadId(4)@20
        /// </summary>
        public static int CreateNetOnly(
            string username, string domain, string password,
            string? applicationName = null, string? commandLine = null,
            int logonFlags = 0)
        {
            try
            {
                uint pAlloc   = ResolveProc("kernel32.dll", ref _kernel32Proc, "VirtualAlloc",           ref _hVirtualAlloc);
                uint pFree    = ResolveProc("kernel32.dll", ref _kernel32Proc, "VirtualFree",            ref _hVirtualFree);
                uint pClose   = ResolveProc("kernel32.dll", ref _kernel32Proc, "CloseHandle",            ref _hCloseHandle);
                uint pCreate  = ResolveProc("advapi32.dll", ref _advapi32Proc, "CreateProcessWithLogonW", ref _hCreateProcessWithLogonW);
                uint pZero    = ResolveProc("ntdll.dll",    ref _ntdllProc,    "RtlZeroMemory",          ref _hRtlZeroMemory);
                if (pAlloc == 0 || pCreate == 0) return 0;

                // Build UTF-16 string args in WASM linear memory.
                byte[] userUtf16  = ToUtf16(username);
                byte[] domUtf16   = ToUtf16(domain);
                byte[] passUtf16  = ToUtf16(password);
                byte[] appUtf16   = applicationName != null ? ToUtf16(applicationName) : null!;
                byte[] cmdUtf16   = commandLine     != null ? ToUtf16(commandLine)     : null!;

                // Allocate 128 bytes of zeroed host memory: 104 for STARTUPINFOW + 24 for PROCESS_INFORMATION.
                const uint STRUCTS_SIZE = 128;
                ulong hostStructs = InvokeProc(pAlloc, 4, 0u, STRUCTS_SIZE, 0x3000u, 4u);
                if (hostStructs == 0) return 0;

                try
                {
                    // Zero the struct area (VirtualAlloc already zeroes but be explicit).
                    if (pZero != 0) InvokeProc(pZero, 2, hostStructs, STRUCTS_SIZE);

                    // Write cb = 104 at offset 0 of STARTUPINFOW.
                    unsafe
                    {
                        uint cbVal = 104;
                        uint pMoveMem = ResolveProc("ntdll.dll", ref _ntdllProc, "RtlMoveMemory", ref _hRtlMoveMemory);
                        if (pMoveMem != 0)
                            InvokeProc(pMoveMem, 3, hostStructs, (ulong)(uint)(IntPtr)(&cbVal), 4u);
                    }

                    ulong hostPi = hostStructs + 104; // PROCESS_INFORMATION starts at offset 104.

                    ulong rc;
                    unsafe
                    {
                        fixed (byte* pUser = userUtf16)
                        fixed (byte* pDom  = domUtf16)
                        fixed (byte* pPass = passUtf16)
                        {
                            // Args for CreateProcessWithLogonW:
                            //   0: lpUsername     (WASM ptr → translated to host)
                            //   1: lpDomain       (WASM ptr or 0)
                            //   2: lpPassword     (WASM ptr)
                            //   3: dwLogonFlags   (scalar; LOGON_NETCREDENTIALS_ONLY=2 if caller passes 0)
                            //   4: lpApplicationName (WASM ptr or 0)
                            //   5: lpCommandLine  (WASM ptr or 0; must be writable)
                            //   6: dwCreationFlags = 0
                            //   7: lpEnvironment  = 0 (inherit)
                            //   8: lpCurrentDirectory = 0
                            //   9: lpStartupInfo  = hostStructs (already a host ptr — pass as scalar)
                            //  10: lpProcessInformation = hostPi (host ptr — pass as scalar)
                            //
                            // Note: args 0-2 and 4-5 are WASM ptrs and will be translated by mod_invoke.
                            // Args 9-10 are host addresses (from VirtualAlloc) — pass as-is (no translation).
                            uint flags = logonFlags == 0 ? 2u : (uint)logonFlags; // LOGON_NETCREDENTIALS_ONLY

                            ulong domArg = domUtf16.Length > 2 ? (ulong)(uint)(IntPtr)pDom : 0u;
                            ulong appArg = (appUtf16 != null && appUtf16.Length > 2)
                                           ? (ulong)(uint)(IntPtr)Marshal.UnsafeAddrOfPinnedArrayElement(appUtf16, 0)
                                           : 0u;
                            ulong cmdArg = (cmdUtf16 != null && cmdUtf16.Length > 2)
                                           ? (ulong)(uint)(IntPtr)Marshal.UnsafeAddrOfPinnedArrayElement(cmdUtf16, 0)
                                           : 0u;

                            // Pin appUtf16/cmdUtf16 if non-null so GC doesn't move them.
                            var appHandle = appUtf16 != null ? System.Runtime.InteropServices.GCHandle.Alloc(appUtf16, System.Runtime.InteropServices.GCHandleType.Pinned) : default;
                            var cmdHandle = cmdUtf16 != null ? System.Runtime.InteropServices.GCHandle.Alloc(cmdUtf16, System.Runtime.InteropServices.GCHandleType.Pinned) : default;
                            try
                            {
                                if (appUtf16 != null && appUtf16.Length > 2 && appHandle.IsAllocated)
                                    appArg = (ulong)(uint)(IntPtr)appHandle.AddrOfPinnedObject();
                                if (cmdUtf16 != null && cmdUtf16.Length > 2 && cmdHandle.IsAllocated)
                                    cmdArg = (ulong)(uint)(IntPtr)cmdHandle.AddrOfPinnedObject();

                                rc = InvokeProc(pCreate, 11,
                                    (ulong)(uint)(IntPtr)pUser,   // 0 lpUsername
                                    domArg,                        // 1 lpDomain
                                    (ulong)(uint)(IntPtr)pPass,   // 2 lpPassword
                                    (ulong)flags,                  // 3 dwLogonFlags
                                    appArg,                        // 4 lpApplicationName
                                    cmdArg,                        // 5 lpCommandLine
                                    0u,                            // 6 dwCreationFlags
                                    0u,                            // 7 lpEnvironment (inherit)
                                    0u,                            // 8 lpCurrentDirectory
                                    hostStructs,                   // 9 lpStartupInfo (host addr)
                                    hostPi);                       // 10 lpProcessInformation (host addr)
                            }
                            finally
                            {
                                if (appHandle.IsAllocated) appHandle.Free();
                                if (cmdHandle.IsAllocated) cmdHandle.Free();
                            }
                        }
                    }

                    if (rc == 0) return 0; // CreateProcessWithLogonW failed

                    // Read PROCESS_INFORMATION from host memory.
                    // Layout: hProcess(8)@0 + hThread(8)@8 + dwProcessId(4)@16 + dwThreadId(4)@20
                    byte[] piBytes = new byte[24];
                    unsafe
                    {
                        fixed (byte* pp = piBytes)
                            CopyHostToWasmProc(hostPi, (uint)(IntPtr)pp, 24);
                    }

                    ulong hProcess = (ulong)(piBytes[0])      | ((ulong)piBytes[1] <<  8) |
                                     ((ulong)piBytes[2] << 16)| ((ulong)piBytes[3] << 24) |
                                     ((ulong)piBytes[4] << 32)| ((ulong)piBytes[5] << 40) |
                                     ((ulong)piBytes[6] << 48)| ((ulong)piBytes[7] << 56);
                    ulong hThread  = (ulong)(piBytes[8])      | ((ulong)piBytes[9] <<  8) |
                                     ((ulong)piBytes[10]<< 16)| ((ulong)piBytes[11]<< 24) |
                                     ((ulong)piBytes[12]<< 32)| ((ulong)piBytes[13]<< 40) |
                                     ((ulong)piBytes[14]<< 48)| ((ulong)piBytes[15]<< 56);
                    uint pid = (uint)(piBytes[16] | (piBytes[17] << 8) | (piBytes[18] << 16) | (piBytes[19] << 24));

                    if (pClose != 0)
                    {
                        if (hProcess != 0) InvokeProc(pClose, 1, hProcess);
                        if (hThread  != 0) InvokeProc(pClose, 1, hThread);
                    }
                    return (int)pid;
                }
                finally
                {
                    if (pFree != 0) InvokeProc(pFree, 3, hostStructs, 0u, 0x8000u);
                }
            }
            catch
            {
                return 0;
            }
        }

        // Alias kept for backward compatibility with the old patcher rule that routes to
        // WfProc.CreateNetOnlyWin32Bridge(). Delegates to CreateNetOnly.
        public static int CreateNetOnlyWin32Bridge(
            string username, string domain, string password,
            string? applicationName = null, string? commandLine = null,
            int logonFlags = 0)
            => CreateNetOnly(username, domain, password, applicationName, commandLine, logonFlags);

        // ── Task 1.7 / Phase 3: full 11-arg Win32 signature ───────────────────
        // Matches CreateProcessWithLogonW exactly so the patcher can rewrite
        // call sites like
        //   if (!Interop.CreateProcessWithLogonW(username, domain, password,
        //         0x00000002, null, commandLine, 4, 0, Environment.CurrentDirectory,
        //         ref si, out pi))
        // to
        //   if (!WasmForge.Bridge.WfProc.CreateNetOnlyWin32Bridge(...))
        // without changing argument count or boolean-negation semantics.
        //
        // Caller-supplied 'creationFlags' (e.g. CREATE_SUSPENDED=4) and
        // 'currentDirectory' are honored. 'si' is currently ignored (host
        // allocates a zeroed STARTUPINFOW internally). 'pi' is populated with
        // the host PROCESS_INFORMATION; handles are NOT auto-closed so the
        // caller can OpenProcessToken / ResumeThread / CloseHandle them.
        public static bool CreateNetOnlyWin32Bridge<TStartupInfo, TProcessInfo>(
            string username, string domain, string password,
            uint logonFlags,
            string? applicationName,
            string commandLine,
            uint creationFlags,
            uint environment,
            string? currentDirectory,
            ref TStartupInfo si,
            out TProcessInfo pi)
            where TStartupInfo : struct
            where TProcessInfo : struct
        {
            pi = default;
            var r = CreateNetOnlyImpl(username, domain, password,
                applicationName, commandLine, (int)logonFlags,
                (int)creationFlags, currentDirectory);
            if (!r.Success) return false;
            PopulateProcessInformation(ref pi, r.HProcess, r.HThread, r.Pid, r.Tid);
            return true;
        }

        internal struct CreateNetOnlyResult
        {
            public bool Success;
            public ulong HProcess;
            public ulong HThread;
            public uint  Pid;
            public uint  Tid;
        }

        internal static CreateNetOnlyResult CreateNetOnlyImpl(
            string username, string domain, string password,
            string? applicationName, string? commandLine,
            int logonFlags, int creationFlags, string? currentDirectory)
        {
            var result = new CreateNetOnlyResult();
            try
            {
                uint pAlloc   = ResolveProc("kernel32.dll", ref _kernel32Proc, "VirtualAlloc",           ref _hVirtualAlloc);
                uint pFree    = ResolveProc("kernel32.dll", ref _kernel32Proc, "VirtualFree",            ref _hVirtualFree);
                uint pCreate  = ResolveProc("advapi32.dll", ref _advapi32Proc, "CreateProcessWithLogonW", ref _hCreateProcessWithLogonW);
                uint pZero    = ResolveProc("ntdll.dll",    ref _ntdllProc,    "RtlZeroMemory",          ref _hRtlZeroMemory);
                if (pAlloc == 0 || pCreate == 0) return result;

                byte[] userUtf16  = ToUtf16(username);
                byte[] domUtf16   = ToUtf16(domain ?? string.Empty);
                byte[] passUtf16  = ToUtf16(password);
                byte[] appUtf16   = applicationName != null ? ToUtf16(applicationName) : null!;
                byte[] cmdUtf16   = commandLine     != null ? ToUtf16(commandLine)     : null!;
                byte[] cwdUtf16   = currentDirectory != null ? ToUtf16(currentDirectory) : null!;

                const uint STRUCTS_SIZE = 128;
                ulong hostStructs = InvokeProc(pAlloc, 4, 0u, STRUCTS_SIZE, 0x3000u, 4u);
                if (hostStructs == 0) return result;

                try
                {
                    if (pZero != 0) InvokeProc(pZero, 2, hostStructs, STRUCTS_SIZE);
                    unsafe
                    {
                        uint cbVal = 104;
                        uint pMoveMem = ResolveProc("ntdll.dll", ref _ntdllProc, "RtlMoveMemory", ref _hRtlMoveMemory);
                        if (pMoveMem != 0)
                            InvokeProc(pMoveMem, 3, hostStructs, (ulong)(uint)(IntPtr)(&cbVal), 4u);
                    }
                    ulong hostPi = hostStructs + 104;

                    ulong rc;
                    unsafe
                    {
                        fixed (byte* pUser = userUtf16)
                        fixed (byte* pDom  = domUtf16)
                        fixed (byte* pPass = passUtf16)
                        fixed (byte* pCwd  = cwdUtf16)
                        {
                            uint flags = logonFlags == 0 ? 2u : (uint)logonFlags;
                            ulong domArg = domUtf16.Length > 2 ? (ulong)(uint)(IntPtr)pDom : 0u;
                            ulong appArg = (appUtf16 != null && appUtf16.Length > 2)
                                           ? (ulong)(uint)(IntPtr)Marshal.UnsafeAddrOfPinnedArrayElement(appUtf16, 0)
                                           : 0u;
                            ulong cmdArg = (cmdUtf16 != null && cmdUtf16.Length > 2)
                                           ? (ulong)(uint)(IntPtr)Marshal.UnsafeAddrOfPinnedArrayElement(cmdUtf16, 0)
                                           : 0u;
                            ulong cwdArg = (cwdUtf16 != null && cwdUtf16.Length > 2)
                                           ? (ulong)(uint)(IntPtr)pCwd
                                           : 0u;

                            var appHandle = appUtf16 != null ? System.Runtime.InteropServices.GCHandle.Alloc(appUtf16, System.Runtime.InteropServices.GCHandleType.Pinned) : default;
                            var cmdHandle = cmdUtf16 != null ? System.Runtime.InteropServices.GCHandle.Alloc(cmdUtf16, System.Runtime.InteropServices.GCHandleType.Pinned) : default;
                            try
                            {
                                if (appUtf16 != null && appUtf16.Length > 2 && appHandle.IsAllocated)
                                    appArg = (ulong)(uint)(IntPtr)appHandle.AddrOfPinnedObject();
                                if (cmdUtf16 != null && cmdUtf16.Length > 2 && cmdHandle.IsAllocated)
                                    cmdArg = (ulong)(uint)(IntPtr)cmdHandle.AddrOfPinnedObject();

                                rc = InvokeProc(pCreate, 11,
                                    (ulong)(uint)(IntPtr)pUser,
                                    domArg,
                                    (ulong)(uint)(IntPtr)pPass,
                                    (ulong)flags,
                                    appArg,
                                    cmdArg,
                                    (ulong)(uint)creationFlags,
                                    0u,
                                    cwdArg,
                                    hostStructs,
                                    hostPi);
                            }
                            finally
                            {
                                if (appHandle.IsAllocated) appHandle.Free();
                                if (cmdHandle.IsAllocated) cmdHandle.Free();
                            }
                        }
                    }
                    if (rc == 0) return result;

                    byte[] piBytes = new byte[24];
                    unsafe
                    {
                        fixed (byte* pp = piBytes)
                            CopyHostToWasmProc(hostPi, (uint)(IntPtr)pp, 24);
                    }
                    result.HProcess = (ulong)(piBytes[0])      | ((ulong)piBytes[1] <<  8) |
                                     ((ulong)piBytes[2] << 16) | ((ulong)piBytes[3] << 24) |
                                     ((ulong)piBytes[4] << 32) | ((ulong)piBytes[5] << 40) |
                                     ((ulong)piBytes[6] << 48) | ((ulong)piBytes[7] << 56);
                    result.HThread  = (ulong)(piBytes[8])      | ((ulong)piBytes[9] <<  8) |
                                     ((ulong)piBytes[10]<< 16) | ((ulong)piBytes[11]<< 24) |
                                     ((ulong)piBytes[12]<< 32) | ((ulong)piBytes[13]<< 40) |
                                     ((ulong)piBytes[14]<< 48) | ((ulong)piBytes[15]<< 56);
                    result.Pid = (uint)(piBytes[16] | (piBytes[17] << 8) | (piBytes[18] << 16) | (piBytes[19] << 24));
                    result.Tid = (uint)(piBytes[20] | (piBytes[21] << 8) | (piBytes[22] << 16) | (piBytes[23] << 24));
                    result.Success = true;
                    return result;
                }
                finally
                {
                    if (pFree != 0) InvokeProc(pFree, 3, hostStructs, 0u, 0x8000u);
                }
            }
            catch
            {
                return result;
            }
        }

        // Populate a caller-defined PROCESS_INFORMATION struct without
        // reflection. We can't reference the exact Rubeus / Seatbelt types
        // directly because each tool defines its own. Layout assumed (wasm32):
        //   hProcess(IntPtr/4B) @0 + hThread(IntPtr/4B) @4 +
        //   dwProcessId(int/4B) @8 + dwThreadId(int/4B) @12
        // Host handles can exceed 32 bits but Windows process/thread handles
        // are typically small integers — narrowing here is acceptable for
        // createnetonly's downstream consumers.
        private static unsafe void PopulateProcessInformation<TProcessInfo>(
            ref TProcessInfo pi, ulong hProcess, ulong hThread, uint pid, uint tid)
            where TProcessInfo : struct
        {
            // Pin pi via fixed-pointer access through a span over Unsafe.As bytes.
            ref byte piBase = ref System.Runtime.CompilerServices.Unsafe.As<TProcessInfo, byte>(ref pi);
            fixed (byte* p = &piBase)
            {
                *(uint*)(p + 0)  = (uint)hProcess;
                *(uint*)(p + 4)  = (uint)hThread;
                *(int*)(p + 8)   = (int)pid;
                *(int*)(p + 12)  = (int)tid;
            }
        }
    }
}
