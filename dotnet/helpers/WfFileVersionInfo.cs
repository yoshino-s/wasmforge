// WfFileVersionInfo — VS_VERSIONINFO query via version.dll.
// Pattern: host-memory allocation + wf_call bridges, no BCL FileVersionInfo.
// Drop-in replacement for System.Diagnostics.FileVersionInfo.GetVersionInfo(path)
// which throws PlatformNotSupportedException on NativeAOT-WASI.
using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public sealed unsafe class WfFileVersionInfo
    {
        public string ProductVersion { get; }
        public string FileVersion { get; }
        public string CompanyName { get; }
        public string ProductName { get; }

        private WfFileVersionInfo(string pv, string fv, string cn, string pn)
        {
            ProductVersion = pv;
            FileVersion = fv;
            CompanyName = cn;
            ProductName = pn;
        }

        // Drop-in replacement for FileVersionInfo.GetVersionInfo(path).
        public static WfFileVersionInfo GetVersionInfo(string path)
        {
            if (string.IsNullOrEmpty(path)) return Empty();

            int pathHandle = 0, sizeHandle = 0, blobHandle = 0, valuePtrHandle = 0, valueLenHandle = 0;
            try
            {
                byte[] pathUtf16 = System.Text.Encoding.Unicode.GetBytes(path + "\0");
                pathHandle = WfHost.HostAlloc(pathUtf16.Length);
                WfHost.HostWrite(pathHandle, 0, pathUtf16);
                ulong pathAddr = WfHost.GetHostAddress(pathHandle);

                // GetFileVersionInfoSizeW writes the dwHandle (unused) to lpdwHandle.
                // We pass a small host buffer for it; the returned DWORD is the size.
                sizeHandle = WfHost.HostAlloc(4);
                WfHost.HostWriteUInt32(sizeHandle, 0, 0);
                ulong sizeAddr = WfHost.GetHostAddress(sizeHandle);

                uint size = version_GetFileVersionInfoSizeW(pathAddr, sizeAddr);
                if (size == 0 || size > (16 * 1024 * 1024)) return Empty();

                blobHandle = WfHost.HostAlloc((int)size);
                ulong blobAddr = WfHost.GetHostAddress(blobHandle);
                uint ok = version_GetFileVersionInfoW(pathAddr, 0, size, blobAddr);
                if (ok == 0) return Empty();

                valuePtrHandle = WfHost.HostAlloc(8);
                WfHost.HostWriteUInt64(valuePtrHandle, 0, 0);
                valueLenHandle = WfHost.HostAlloc(4);
                WfHost.HostWriteUInt32(valueLenHandle, 0, 0);

                // Probe common language/codepage combos.
                string[] languages = { "040904B0", "040904E4", "040904b0", "000004B0", "000004E4" };
                string productVersion = "", fileVersion = "", companyName = "", productName = "";
                foreach (var lang in languages)
                {
                    productVersion = QueryString(blobAddr, valuePtrHandle, valueLenHandle, lang, "ProductVersion");
                    if (!string.IsNullOrEmpty(productVersion))
                    {
                        fileVersion  = QueryString(blobAddr, valuePtrHandle, valueLenHandle, lang, "FileVersion");
                        companyName  = QueryString(blobAddr, valuePtrHandle, valueLenHandle, lang, "CompanyName");
                        productName  = QueryString(blobAddr, valuePtrHandle, valueLenHandle, lang, "ProductName");
                        break;
                    }
                }
                return new WfFileVersionInfo(productVersion, fileVersion, companyName, productName);
            }
            catch { return Empty(); }
            finally
            {
                if (pathHandle      != 0) WfHost.HostFree(pathHandle);
                if (sizeHandle      != 0) WfHost.HostFree(sizeHandle);
                if (blobHandle      != 0) WfHost.HostFree(blobHandle);
                if (valuePtrHandle  != 0) WfHost.HostFree(valuePtrHandle);
                if (valueLenHandle  != 0) WfHost.HostFree(valueLenHandle);
            }
        }

        private static string QueryString(ulong blobAddr, int valuePtrHandle, int valueLenHandle,
            string lang, string field)
        {
            string sub = "\\StringFileInfo\\" + lang + "\\" + field;
            byte[] subUtf16 = System.Text.Encoding.Unicode.GetBytes(sub + "\0");
            int subHandle = WfHost.HostAlloc(subUtf16.Length);
            try
            {
                WfHost.HostWrite(subHandle, 0, subUtf16);
                ulong subAddr    = WfHost.GetHostAddress(subHandle);
                ulong valuePtrAddr = WfHost.GetHostAddress(valuePtrHandle);
                ulong valueLenAddr = WfHost.GetHostAddress(valueLenHandle);

                WfHost.HostWriteUInt64(valuePtrHandle, 0, 0);
                WfHost.HostWriteUInt32(valueLenHandle, 0, 0);
                uint ok = version_VerQueryValueW(blobAddr, subAddr,
                    valuePtrAddr, valueLenAddr);
                if (ok == 0) return "";

                // VerQueryValueW writes the string pointer into *lplpBuffer and the
                // character count into *puLen. Both are in host address space.
                uint lo = WfHost.ReadHostUInt32(valuePtrAddr, 0);
                uint hi = WfHost.ReadHostUInt32(valuePtrAddr, 4);
                ulong strAddr = ((ulong)hi << 32) | lo;
                uint strLen   = WfHost.ReadHostUInt32(valueLenAddr, 0);
                if (strAddr == 0 || strLen == 0 || strLen > 4096) return "";
                // strLen is character count — convert to bytes (UTF-16).
                uint byteLen = strLen * 2;
                byte[] strBytes = WfHost.ReadHostBytes(strAddr, byteLen);
                int actualBytes = strBytes.Length;
                // Trim trailing null characters.
                while (actualBytes >= 2 && strBytes[actualBytes - 1] == 0 && strBytes[actualBytes - 2] == 0)
                    actualBytes -= 2;
                if (actualBytes <= 0) return "";
                return System.Text.Encoding.Unicode.GetString(strBytes, 0, actualBytes);
            }
            catch { return ""; }
            finally
            {
                WfHost.HostFree(subHandle);
            }
        }

        private static WfFileVersionInfo Empty() => new WfFileVersionInfo("", "", "", "");

        // DLL name is a NativeAOT DirectPInvoke hint; the actual symbols come
        // from pinvoke_nativeaot.c linked into the WASM module.
        [DllImport("*", EntryPoint = "version_GetFileVersionInfoSizeW_v2")]
        private static extern uint version_GetFileVersionInfoSizeW(ulong path, ulong dwHandleOut);

        [DllImport("*", EntryPoint = "version_GetFileVersionInfoW_v2")]
        private static extern uint version_GetFileVersionInfoW(ulong path, uint dwHandle, uint dwLen, ulong blobOut);

        [DllImport("*", EntryPoint = "version_VerQueryValueW_v2")]
        private static extern uint version_VerQueryValueW(ulong blob, ulong subBlock, ulong valuePtrOut, ulong valueLenOut);
    }
}
