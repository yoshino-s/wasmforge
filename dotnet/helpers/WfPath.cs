using System;

namespace WasmForge.Helpers
{
    // WfPath: Windows-aware path manipulation for NativeAOT-WASI.
    //
    // The NativeAOT-WASI runtime sets Path.DirectorySeparatorChar = '/' and
    // Path.AltDirectorySeparatorChar = '/' (the wasi-wasm runtime uses Linux
    // semantics, with no knowledge of Windows backslash). As a result the
    // BCL Path.GetFileName / Path.GetDirectoryName / Path.GetExtension
    // helpers only split on '/' and leave Windows-style paths unchanged —
    // a call like Path.GetFileName(@"C:\Users\foo\bar.txt") returns the
    // entire input string instead of "bar.txt".
    //
    // This breaks any ported Windows tool that processes real Win32 paths.
    // The fix is a small basename helper that splits on EITHER '\' or '/'
    // so a Windows path is correctly broken into directory + filename.
    //
    // The patcher rewrites every Path.GetFileName / Path.GetDirectoryName /
    // Path.GetExtension call site to the equivalent WfPath method. See
    // internal/patch/rules/rules.go for the rewrite rules.
    public static class WfPath
    {
        // GetFileName: returns the bare filename (everything after the
        // last directory separator). Splits on both '\' and '/' to handle
        // Windows paths even though the runtime's separator is '/'.
        //
        // Mirrors BCL Path.GetFileName semantics:
        //   - null input  → null
        //   - empty       → empty
        //   - no separator → path unchanged
        //   - trailing separator → empty string ("C:\dir\" → "")
        public static string GetFileName(string path)
        {
            if (path == null) return null;
            if (path.Length == 0) return path;
            int sep = LastSeparatorIndex(path);
            if (sep < 0) return path;
            return path.Substring(sep + 1);
        }

        // GetDirectoryName: returns everything up to (but not including)
        // the last separator. Mirrors BCL Path.GetDirectoryName:
        //   - null input  → null
        //   - no separator → empty (BCL returns "" not null)
        //   - root-only ("C:\") → root unchanged
        public static string GetDirectoryName(string path)
        {
            if (path == null) return null;
            if (path.Length == 0) return path;
            int sep = LastSeparatorIndex(path);
            if (sep < 0) return string.Empty;
            // If the only separator is at index 0 OR after a drive letter (C:\), keep it.
            if (sep == 0) return path.Substring(0, 1);
            if (sep == 2 && path.Length >= 3 && path[1] == ':') return path.Substring(0, 3);
            return path.Substring(0, sep);
        }

        // GetExtension: returns the extension including the dot, or "" if
        // there is none. Walks back from end of filename to find the last
        // '.'; returns "" if the dot is before any separator, or if the
        // filename starts with '.' (hidden file, no extension).
        public static string GetExtension(string path)
        {
            if (path == null) return null;
            if (path.Length == 0) return string.Empty;
            int sep = LastSeparatorIndex(path);
            int fileStart = sep + 1;
            int dot = path.LastIndexOf('.');
            if (dot < fileStart || dot == fileStart) return string.Empty;
            // BCL returns ".ext" with leading dot.
            return path.Substring(dot);
        }

        // GetFileNameWithoutExtension: GetFileName + strip extension.
        public static string GetFileNameWithoutExtension(string path)
        {
            string name = GetFileName(path);
            if (string.IsNullOrEmpty(name)) return name;
            int dot = name.LastIndexOf('.');
            if (dot < 0) return name;
            return name.Substring(0, dot);
        }

        // Combine: join two paths with the appropriate Windows separator.
        // BCL Path.Combine handles a lot of edge cases (rooted second arg
        // wins, etc.); this is a minimal version that covers the common
        // case of joining a directory + filename. Falls back to BCL for
        // unrooted joins when the inputs are already separator-free.
        public static string Combine(string a, string b)
        {
            if (string.IsNullOrEmpty(a)) return b;
            if (string.IsNullOrEmpty(b)) return a;
            // If b is rooted (starts with '\' or '/' or 'X:'), return as-is.
            if (b.Length > 0 && (b[0] == '\\' || b[0] == '/')) return b;
            if (b.Length >= 2 && b[1] == ':') return b;
            char last = a[a.Length - 1];
            if (last == '\\' || last == '/') return a + b;
            return a + "\\" + b;
        }

        private static int LastSeparatorIndex(string path)
        {
            int last = -1;
            for (int i = path.Length - 1; i >= 0; i--)
            {
                char c = path[i];
                if (c == '\\' || c == '/')
                {
                    last = i;
                    break;
                }
            }
            return last;
        }
    }
}
