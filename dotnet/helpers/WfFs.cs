// WfFs.cs — managed filesystem helpers backed by wasmforge host functions.
//
// .NET's System.IO.Directory.GetDirectories / Environment.GetEnvironmentVariable
// don't behave correctly under WASI on Windows hosts: SystemDrive returns
// empty, paths get re-mapped through WASI preopens, and Directory.Enumerate
// aborts on missing preopens. Routing through fs_listdir / fs_exists
// sidesteps the WASI path machinery entirely — the host receives a Windows
// path string and uses native ReadDirectoryChanges / GetFileAttributes.
//
// Host wire format for fs_listdir (matches sys_listdir in nativeaot.go):
//   path_ptr, path_len → bytes representing the host path (Windows-style OK)
//   buf_ptr, buf_cap   → caller-allocated buffer for null-separated names
//   count_ptr          → out-parameter, host writes number of names written
//   returns: total bytes written (not counting trailing nulls)

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfFs
    {
        [DllImport("env", EntryPoint = "fs_listdir")]
        private static extern uint fs_listdir(uint pathPtr, uint pathLen,
            uint bufPtr, uint bufCap, uint countPtr);

        [DllImport("env", EntryPoint = "fs_exists")]
        private static extern uint fs_exists(uint pathPtr, uint pathLen);

        public static bool Exists(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            byte[] pb = Encoding.UTF8.GetBytes(path);
            fixed (byte* pp = pb)
            {
                return fs_exists((uint)(IntPtr)pp, (uint)pb.Length) != 0;
            }
        }

        public static string[] ListDirectory(string path)
        {
            return List(path, includeFiles: true, includeDirs: true);
        }

        public static string[] ListDirectoriesOnly(string path)
        {
            // The host returns mixed entries; we can't tell types apart from
            // the wire format alone, so return everything and let the caller
            // filter. Most Seatbelt code only walks subdir names anyway.
            return List(path, includeFiles: true, includeDirs: true);
        }

        // Mirrors Directory.GetDirectories(string path, string searchPattern)
        // — patcher rewrites it here. Pattern matching is delegated to the
        // existing glob matcher used by FindFiles (* and ? wildcards).
        public static string[] ListDirectoriesOnly(string path, string searchPattern)
        {
            var all = ListDirectoriesOnly(path);
            if (string.IsNullOrEmpty(searchPattern) || searchPattern == "*") return all;
            var matched = new List<string>(all.Length);
            foreach (var p in all)
            {
                string name = p;
                int slash = name.LastIndexOfAny(new[] { '\\', '/' });
                if (slash >= 0) name = name.Substring(slash + 1);
                if (GlobMatch(name, searchPattern)) matched.Add(p);
            }
            return matched.ToArray();
        }

        // Minimal glob matcher: * matches 0+ chars, ? matches one. Used by
        // the searchPattern parameter on ListDirectoriesOnly. Pattern matching
        // is case-insensitive to align with Win32 FindFirstFileW semantics.
        private static bool GlobMatch(string name, string pattern)
        {
            int ni = 0, pi = 0, niStar = -1, piStar = -1;
            string n = name.ToLowerInvariant();
            string p = pattern.ToLowerInvariant();
            while (ni < n.Length)
            {
                if (pi < p.Length && (p[pi] == '?' || p[pi] == n[ni])) { ni++; pi++; }
                else if (pi < p.Length && p[pi] == '*') { piStar = pi++; niStar = ni; }
                else if (piStar != -1) { pi = piStar + 1; ni = ++niStar; }
                else return false;
            }
            while (pi < p.Length && p[pi] == '*') pi++;
            return pi == p.Length;
        }

        private static string[] List(string path, bool includeFiles, bool includeDirs)
        {
            if (string.IsNullOrEmpty(path)) return Array.Empty<string>();
            byte[] pb = Encoding.UTF8.GetBytes(path);
            byte[] buf = new byte[64 * 1024];
            uint count = 0;
            uint written;
            fixed (byte* pp = pb)
            fixed (byte* bp = buf)
            {
                written = fs_listdir(
                    (uint)(IntPtr)pp, (uint)pb.Length,
                    (uint)(IntPtr)bp, (uint)buf.Length,
                    (uint)(IntPtr)(&count));
            }
            if (written == 0 || count == 0) return Array.Empty<string>();

            // Parse null-separated names.
            var result = new List<string>((int)count);
            int start = 0;
            int max = (int)Math.Min(written, (uint)buf.Length);
            for (int i = 0; i < max; i++)
            {
                if (buf[i] != 0) continue;
                if (i > start)
                    result.Add(Encoding.UTF8.GetString(buf, start, i - start));
                start = i + 1;
            }
            // Return full paths (the host gives just names; prepend the
            // input path with a trailing separator).
            string baseDir = path.TrimEnd('\\', '/');
            char sep = path.Contains('\\') ? '\\' : '/';
            for (int i = 0; i < result.Count; i++)
                result[i] = baseDir + sep + result[i];
            return result.ToArray();
        }

        // ReadAllBytes via Win32 CreateFileW/ReadFile path. The BCL's
        // File.ReadAllBytes routes through WASI which prepends '/' to absolute
        // Windows paths → DirectoryNotFoundException. This bypass uses the
        // working Win32 file I/O bridge.
        [DllImport("env", EntryPoint = "fs_read_all")]
        private static extern int fs_read_all(uint pathPtr, uint pathLen,
            uint bufPtr, uint bufCap, uint outLenPtr);

        public static byte[] ReadAllBytes(string path)
        {
            if (string.IsNullOrEmpty(path)) return Array.Empty<byte>();
            // Fast path: route through the io_op host dispatcher (one wf_call
            // per file vs 6-8 in the legacy fs_read_all bridge chain).
            // Per IoBench harness: ~46ms → <1ms per file.
            byte[] tryOp = TryIoOpRead(path);
            if (tryOp != null) return tryOp;

            // Fallback: legacy WASM-side CreateFile+ReadFile chain.
            byte[] pb = Encoding.UTF8.GetBytes(path);
            uint outLen = 0;
            int rc;
            fixed (byte* pp = pb)
            {
                uint* op = &outLen;
                rc = fs_read_all((uint)(IntPtr)pp, (uint)pb.Length, 0, 0, (uint)(IntPtr)op);
            }
            if (rc < 0) throw new System.IO.FileNotFoundException("WfFs.ReadAllBytes(size,rc=" + rc + "): " + path);
            if (outLen == 0) return Array.Empty<byte>();
            byte[] buf = new byte[outLen];
            uint dummy = 0;
            fixed (byte* pp = pb)
            {
                fixed (byte* bp = buf)
                {
                    uint* dp = &dummy;
                    rc = fs_read_all((uint)(IntPtr)pp, (uint)pb.Length, (uint)(IntPtr)bp, outLen, (uint)(IntPtr)dp);
                }
            }
            if (rc < 0) throw new System.IO.FileNotFoundException("WfFs.ReadAllBytes(data,rc=" + rc + "): " + path);
            return buf;
        }

        // TryIoOpRead — fast path via the io_op host dispatcher. Stat-probe
        // first to learn file size; then a single read into a perfectly-sized
        // buffer. Returns null on any error so the legacy fallback runs.
        private static byte[] TryIoOpRead(string path)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            byte[] args = new byte[4 + pathBytes.Length];
            args[0] = (byte)(pathBytes.Length & 0xff);
            args[1] = (byte)((pathBytes.Length >> 8) & 0xff);
            args[2] = (byte)((pathBytes.Length >> 16) & 0xff);
            args[3] = (byte)((pathBytes.Length >> 24) & 0xff);
            Array.Copy(pathBytes, 0, args, 4, pathBytes.Length);

            byte[] statOp = Encoding.ASCII.GetBytes("stat");
            byte[] statOut = new byte[8];
            uint statWritten;
            fixed (byte* opPtr = statOp)
            fixed (byte* argsPtr = args)
            fixed (byte* outPtr = statOut)
            {
                statWritten = WasmForge.Bridge.WfHostBridge.IoOp(
                    opPtr, (uint)statOp.Length,
                    argsPtr, (uint)args.Length,
                    outPtr, (uint)statOut.Length);
            }
            if (statWritten != 8) return null;
            uint size = (uint)statOut[0] | ((uint)statOut[1] << 8) | ((uint)statOut[2] << 16) | ((uint)statOut[3] << 24);
            uint exists = (uint)statOut[4];
            if (exists == 0) return null;
            if (size == 0) return Array.Empty<byte>();

            byte[] readOp = Encoding.ASCII.GetBytes("read");
            byte[] result = new byte[size];
            uint readWritten;
            fixed (byte* opPtr = readOp)
            fixed (byte* argsPtr = args)
            fixed (byte* outPtr = result)
            {
                readWritten = WasmForge.Bridge.WfHostBridge.IoOp(
                    opPtr, (uint)readOp.Length,
                    argsPtr, (uint)args.Length,
                    outPtr, (uint)result.Length);
            }
            if (readWritten != size) return null;
            return result;
        }

        // ReadAllText: UTF-8 decode the bytes returned by ReadAllBytes. Same
        // rationale — bypasses WASI path mapping (which can't see Windows
        // drives) by going directly through the fs_read_all host bridge.
        public static string ReadAllText(string path)
        {
            byte[] bytes = ReadAllBytes(path);
            if (bytes.Length == 0) return string.Empty;
            // Strip BOM if present (Chromium Bookmarks files are UTF-8, no BOM,
            // but Slack/OneNote configs may have one).
            int offset = 0;
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                offset = 3;
            return Encoding.UTF8.GetString(bytes, offset, bytes.Length - offset);
        }

        // ── FindFiles ─────────────────────────────────────────────────
        //
        // One-shot recursive filesystem search. The host env import does the
        // entire walk natively (Go filepath.WalkDir) — single WASM↔host
        // crossing for the whole tree traversal vs the per-directory crossings
        // a WASM-side fs_listdir loop would incur. Same architecture as
        // mod_load / mod_invoke / mod_resolve.
        //
        // [WasmImportLinkage] tells NativeAOT-LLVM to emit a WASM import for
        // this DllImport instead of routing through DirectPInvoke. The host's
        // env module provides the matching export — see
        // internal/hostmod/win32.go and internal/hostmod/win32_windows_file.go.
        //
        // Returns full absolute paths. Empty list on any error / cap hit.
        [System.Runtime.InteropServices.WasmImportLinkage]
        [DllImport("env", EntryPoint = "fs_findfiles")]
        private static extern int fs_findfiles(
            uint rootPtr, uint rootLen,
            uint patternPtr, uint patternLen,
            int maxDepth, int maxMatches,
            uint bufPtr, uint bufCap, uint countPtr);

        public static System.Collections.Generic.List<string> FindFiles(
            string root, string filenamePattern,
            int maxDepth = 4, int maxMatches = 64)
        {
            var results = new System.Collections.Generic.List<string>();
            if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(filenamePattern))
                return results;

            byte[] rb = Encoding.UTF8.GetBytes(root);
            byte[] pb = Encoding.UTF8.GetBytes(filenamePattern);
            byte[] buf = new byte[256 * 1024]; // 256KB — fits ~3000 typical paths
            uint count = 0;
            int written;
            fixed (byte* rp = rb)
            fixed (byte* pp = pb)
            fixed (byte* bp = buf)
            {
                written = fs_findfiles(
                    (uint)(IntPtr)rp, (uint)rb.Length,
                    (uint)(IntPtr)pp, (uint)pb.Length,
                    maxDepth, maxMatches,
                    (uint)(IntPtr)bp, (uint)buf.Length,
                    (uint)(IntPtr)(&count));
            }
            if (written <= 0 || count == 0) return results;

            // Parse null-separated full paths from host buffer.
            int start = 0;
            int max = Math.Min(written, buf.Length);
            for (int i = 0; i < max && results.Count < maxMatches; i++)
            {
                if (buf[i] != 0) continue;
                if (i > start)
                    results.Add(Encoding.UTF8.GetString(buf, start, i - start));
                start = i + 1;
            }
            return results;
        }

        // ── GlobFiles ──────────────────────────────────────────────────
        //
        // Non-recursive equivalent of Directory.GetFiles(path, pattern,
        // SearchOption.TopDirectoryOnly). Routes through fs_findfiles with
        // maxDepth=0 so the host only looks at the top directory.
        // Returns a string[] matching the BCL API expected by SharpUp's
        // FileUtils.FindFiles.
        public static string[] GlobFiles(string path, string pattern)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(pattern))
                return Array.Empty<string>();
            var list = FindFiles(path, pattern, maxDepth: 0, maxMatches: 512);
            return list.ToArray();
        }

        // Mirrors Directory.GetFiles(string path) — patcher rewrites it here.
        public static string[] GlobFiles(string path)
        {
            return GlobFiles(path, "*");
        }

        // Mirrors Directory.GetFiles(string path, string pattern, SearchOption).
        // AllDirectories is bounded conservatively (depth=4, maxMatches=1024)
        // because each level costs a host round-trip via os_list_dir; the
        // typical GhostPack consumer (SharpUp FileUtils.FindFiles) does its
        // own recursion through ListDirectoriesOnly, so this overload only
        // fires when the caller explicitly asks for AllDirectories.
        public static string[] GlobFiles(string path, string pattern, System.IO.SearchOption searchOption)
        {
            if (searchOption == System.IO.SearchOption.AllDirectories)
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(pattern))
                    return Array.Empty<string>();
                var list = FindFiles(path, pattern, maxDepth: 4, maxMatches: 1024);
                return list.ToArray();
            }
            return GlobFiles(path, pattern);
        }

        // ── IsModifiable ───────────────────────────────────────────────
        //
        // Returns true if the calling process can write to path.
        // Replaces SharpUp's FileUtils.CheckModifiableAccess, which uses
        // WindowsIdentity.GetCurrent() + ACL enumeration — neither
        // available in NativeAOT-WASI.
        //
        // Implementation: open path (or its parent dir) with GENERIC_WRITE
        // and FILE_SHARE_READ|FILE_SHARE_WRITE via kernel32!CreateFileW,
        // then close the handle. If CreateFileW returns INVALID_HANDLE_VALUE
        // (0xFFFFFFFF) the path is not writable.
        //
        // For paths that don't exist yet we probe the parent directory.
        [DllImport("env", EntryPoint = "mod_load")]
        private static extern uint _fs_mod_load(uint namePtr);

        [DllImport("env", EntryPoint = "mod_resolve")]
        private static extern uint _fs_mod_resolve(uint libHandle, uint namePtr);

        [DllImport("env", EntryPoint = "mod_invoke")]
        private static extern ulong _fs_mod_invoke(
            ulong procHandle, uint nargs,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11,
            ulong a12, ulong a13, ulong a14,
            ulong ret1Ptr, ulong errPtr);

        private static uint _fsKernel32;
        private static uint _hCreateFileW;
        private static uint _hCloseHandle;

        private static uint FsResolve(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
        {
            if (cachedProc != 0) return cachedProc;
            if (cachedLib == 0)
            {
                byte[] db = Encoding.ASCII.GetBytes(dll + "\0");
                fixed (byte* dp = db) cachedLib = _fs_mod_load((uint)(IntPtr)dp);
                if (cachedLib == 0) return 0;
            }
            byte[] fb = Encoding.ASCII.GetBytes(fn + "\0");
            fixed (byte* fp = fb) cachedProc = _fs_mod_resolve(cachedLib, (uint)(IntPtr)fp);
            return cachedProc;
        }

        private static uint FsInvoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0)
        {
            ulong ret1 = 0, err = 0;
            ulong r0 = _fs_mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
            return (uint)r0;
        }

        public static bool IsModifiable(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            // Probe the path itself; if it doesn't exist, fall back to parent.
            string probePath = path;
            if (!Exists(path))
            {
                string parent = System.IO.Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(parent)) return false;
                probePath = parent;
            }

            uint hCF = FsResolve("kernel32.dll", ref _fsKernel32, "CreateFileW", ref _hCreateFileW);
            uint hCH = FsResolve("kernel32.dll", ref _fsKernel32, "CloseHandle", ref _hCloseHandle);
            if (hCF == 0 || hCH == 0) return false;

            // Encode path as UTF-16LE + null terminator for the host.
            byte[] wb = Encoding.Unicode.GetBytes(probePath + "\0");
            fixed (byte* wp = wb)
            {
                // CreateFileW(lpFileName, GENERIC_WRITE=0x40000000,
                //   FILE_SHARE_READ|FILE_SHARE_WRITE=3,
                //   lpSecurityAttributes=NULL,
                //   OPEN_EXISTING=3,
                //   FILE_FLAG_BACKUP_SEMANTICS=0x02000000 (needed for dirs),
                //   hTemplateFile=NULL)
                uint handle = FsInvoke(hCF, 7,
                    (ulong)(uint)(IntPtr)wp,  // lpFileName
                    0x40000000,               // GENERIC_WRITE
                    3,                        // FILE_SHARE_READ | FILE_SHARE_WRITE
                    0,                        // lpSecurityAttributes
                    3,                        // OPEN_EXISTING
                    0x02000000,               // FILE_FLAG_BACKUP_SEMANTICS
                    0);                       // hTemplateFile
                if (handle == 0 || handle == 0xFFFFFFFF) return false;
                FsInvoke(hCH, 1, handle);
                return true;
            }
        }
    }
}
