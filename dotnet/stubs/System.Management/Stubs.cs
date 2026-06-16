// WasmForge stub for System.Management.
//
// The real System.Management package ships for wasi-wasm but every call
// throws PlatformNotSupportedException: "System.Management currently is
// only supported for Windows desktop applications." This stub replaces
// it with a managed implementation that delegates ExecQuery-style WQL
// queries to WasmForge's wf_wmi_query env-import.
//
// The host returns query results as a JSON array of objects:
//   [{ "PropName": "value", ... }, ...]
//
// Property values come back as strings (or numbers, in which case
// json.Marshal serializes them as bare numerics — we parse them back into
// typed objects). Consumer code like Seatbelt indexes the result with
// `obj["PropName"]` and treats it as object; we return whatever the JSON
// parser produces (string, double, bool, IDictionary, IList<object>).
//
// Methods covered (matching the API surface Seatbelt and friends actually
// use; everything else throws NotSupportedException):
//   - ManagementObjectSearcher(string nspace, string query)
//   - ManagementObjectSearcher.Get() → ManagementObjectCollection
//   - ManagementObjectCollection : IEnumerable<ManagementBaseObject>
//   - ManagementBaseObject[string]  → object value
//   - ManagementBaseObject.Properties → IEnumerable<PropertyData>
//   - ManagementClass(string path) — stubbed minimally
//   - ManagementClass.GetMethodParameters(string method) — returns empty
//
// Anything that isn't read-only WQL (process Create, remote authentication,
// schema modification) throws.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace System.Management
{
    // ─────────────────────────────────────────────────────────────────
    // WfWmiCom — generalizable WMI driver via direct COM vtable dispatch.
    //
    // Mirrors how Go (go-ole / hcsshim) drives WMI: read vtable pointer
    // from interface, index by slot, call funcptr via wf_call_ptr.
    //
    // No host-side wmi_query stub. Pure CoCreateInstance + IWbemServices
    // chain runs inside WASM. Each method call dispatches through
    // wf_call_ptr to the actual host function pointer the host resolved.
    //
    // Chain:
    //   CoInitializeEx(NULL, COINIT_MULTITHREADED)
    //   CoCreateInstance(CLSID_WbemLocator, NULL, INPROC, IID_IWbemLocator, &pLoc)
    //   pLoc->ConnectServer(...) -> pSvc
    //   pSvc->ExecQuery("WQL", wql, flags, NULL, &pEnum)
    //   loop pEnum->Next -> pObj
    //     pObj->BeginEnumeration → loop pObj->Next(name, val) → pObj->EndEnumeration
    //     pObj->Release
    //   pEnum->Release / pSvc->Release / pLoc->Release
    // ─────────────────────────────────────────────────────────────────
    internal static unsafe class WfWmiCom
    {
        static readonly byte[] CLSID_WbemLocator_GUID = new Guid("4590f811-1d3a-11d0-891f-00aa004b2e24").ToByteArray();
        static readonly byte[] IID_IWbemLocator_GUID  = new Guid("dc12a687-737f-11cf-884d-00aa004b2e24").ToByteArray();

        const int IWbemLocator_ConnectServer = 3;
        const int IWbemServices_ExecQuery = 20;
        const int IEnumWbemClassObject_Next = 4;
        const int IWbemClassObject_BeginEnumeration = 8;
        const int IWbemClassObject_Next = 9;
        const int IWbemClassObject_EndEnumeration = 10;
        const int IUnknown_Release = 2;

        const uint WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
        const uint WBEM_FLAG_FORWARD_ONLY       = 0x20;
        const uint WBEM_FLAG_NONSYSTEM_ONLY     = 0x40;
        const uint WBEM_INFINITE                = 0xFFFFFFFF;
        const uint WBEM_S_NO_MORE_DATA          = 0x40005;
        const uint CLSCTX_INPROC_SERVER         = 0x1;
        const uint COINIT_APARTMENTTHREADED     = 0x2;

        // ── Host bridge env imports ──────────────────────────────────
        [DllImport("env", EntryPoint = "mod_hread")]
        static extern uint mod_hread(ulong hostAddr, uint len, void* outBuf);

        [DllImport("env", EntryPoint = "wf_call_ptr_fixed8")]
        static extern ulong wf_call_ptr_fixed8(ulong funcptr, int nargs,
            uint ptrMask, uint out8Mask,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7);

        [DllImport("env", EntryPoint = "wf_call_ptr_fixed12")]
        static extern ulong wf_call_ptr_fixed12(ulong funcptr, int nargs,
            uint ptrMask, uint out8Mask,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11);

        // ── ole32 / oleaut32 ─────────────────────────────────────────
        [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);
        [DllImport("ole32.dll")] static extern int CoCreateInstance(IntPtr rclsid, IntPtr pUnkOuter, uint dwClsContext, IntPtr riid, out IntPtr ppv);
        [DllImport("oleaut32.dll")] static extern void SysFreeString(ulong bstr);
        // SysAllocString — see WfCom.cs for the rationale. NativeAOT-LLVM/wasm-ld
        // generates a 2-arg wrapper for [MarshalAs(LPWStr)] string parameters that
        // mismatches the C bridge's 1-arg signature, replaced with undefined_stub.
        [DllImport("oleaut32.dll")] static extern ulong SysAllocString(IntPtr wstrPtr);
        static unsafe ulong AllocBstr(string s)
        {
            if (s == null) return 0;
            fixed (char* p = s) { return SysAllocString((IntPtr)p); }
        }
        [DllImport("oleaut32.dll")] static extern int VariantClear(IntPtr pVar);

        // ── Helpers ──────────────────────────────────────────────────
        static byte[] ReadHostBytes(ulong hostAddr, uint nbytes)
        {
            if (hostAddr == 0 || nbytes == 0) return Array.Empty<byte>();
            if (nbytes > 4096) nbytes = 4096;
            byte[] buf = new byte[nbytes];
            fixed (byte* p = buf)
            {
                if (mod_hread(hostAddr, nbytes, p) != 0) return Array.Empty<byte>();
            }
            return buf;
        }

        static uint ReadHostU32(ulong hostAddr)
        {
            byte[] b = ReadHostBytes(hostAddr, 4);
            return b.Length == 4 ? BitConverter.ToUInt32(b, 0) : 0;
        }

        static string BstrToString(ulong hostBstr)
        {
            if (hostBstr == 0) return null;
            uint byteLen = ReadHostU32(hostBstr - 4);
            if (byteLen == 0 || byteLen > 4096) return string.Empty;
            byte[] data = ReadHostBytes(hostBstr, byteLen);
            if (data.Length == 0) return string.Empty;
            int n = (int)(byteLen / 2);
            char[] c = new char[n];
            for (int i = 0; i < n; i++) c[i] = (char)(data[2*i] | (data[2*i+1] << 8));
            return new string(c);
        }

        static ulong ReadVtableSlot(IntPtr ifc, int index)
        {
            if (ifc == IntPtr.Zero) return 0;
            ulong* vtbl = (ulong*)ifc;
            ulong vtMirror = *vtbl;
            if (vtMirror == 0) return 0;
            ulong* vt = (ulong*)(IntPtr)(uint)vtMirror;
            return vt[index];
        }

        // VARIANT (24 bytes — 64-bit Windows COM layout)
        const int VARIANT_SIZE = 24;
        static IntPtr AllocVariant()
        {
            IntPtr p = Marshal.AllocHGlobal(VARIANT_SIZE);
            byte* bp = (byte*)p;
            for (int i = 0; i < VARIANT_SIZE; i++) bp[i] = 0;
            return p;
        }

        static object VariantToObject(IntPtr pVar)
        {
            if (pVar == IntPtr.Zero) return null;
            byte* bp = (byte*)pVar;
            ushort vt = (ushort)(bp[0] | (bp[1] << 8));
            byte* val = bp + 8;
            switch (vt)
            {
                case 0: case 1: return null;                                  // VT_EMPTY / VT_NULL
                case 2: return (short)(val[0] | (val[1] << 8));               // VT_I2
                case 3: case 22: return val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24);  // VT_I4 / VT_INT
                case 18: return (ushort)(val[0] | (val[1] << 8));             // VT_UI2
                case 19: case 23: return (uint)(val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24));  // VT_UI4 / VT_UINT
                case 20:                                                       // VT_I8
                {
                    long l = 0; for (int i = 0; i < 8; i++) l |= ((long)val[i]) << (i*8); return l;
                }
                case 21:                                                       // VT_UI8
                {
                    ulong u = 0; for (int i = 0; i < 8; i++) u |= ((ulong)val[i]) << (i*8); return u;
                }
                case 4: { byte[] b = new byte[4]; for (int i=0;i<4;i++) b[i]=val[i]; return BitConverter.ToSingle(b,0); }
                case 5: case 7:
                { byte[] b = new byte[8]; for (int i=0;i<8;i++) b[i]=val[i]; return BitConverter.ToDouble(b,0); }
                case 11: { short b = (short)(val[0]|(val[1]<<8)); return b != 0; }  // VT_BOOL
                case 8:                                                        // VT_BSTR
                {
                    ulong bstrHost = 0;
                    for (int i = 0; i < 8; i++) bstrHost |= ((ulong)val[i]) << (i*8);
                    return BstrToString(bstrHost);
                }
                case 16: return (sbyte)val[0];                                 // VT_I1
                case 17: return val[0];                                        // VT_UI1
                default: return "VT(0x" + vt.ToString("X4") + ")";
            }
        }

        // CoCreateInstance wrapper — pins GUIDs, returns mirror addr or IntPtr.Zero.
        static IntPtr CreateInstance(byte[] clsid, byte[] iid)
        {
            IntPtr ppv = IntPtr.Zero;
            IntPtr buf = Marshal.AllocHGlobal(32);
            try
            {
                Marshal.Copy(clsid, 0, buf, 16);
                Marshal.Copy(iid,   0, buf + 16, 16);
                int hr = CoCreateInstance(buf, IntPtr.Zero,
                    CLSCTX_INPROC_SERVER, buf + 16, out ppv);
                if (hr != 0) return IntPtr.Zero;
            }
            finally { Marshal.FreeHGlobal(buf); }
            return ppv;
        }

        static bool _initialized = false;
        static void EnsureInitialized()
        {
            if (_initialized) return;
            CoInitializeEx(IntPtr.Zero, COINIT_APARTMENTTHREADED);
            _initialized = true;
        }

        static void ReleaseCom(IntPtr ifc)
        {
            if (ifc == IntPtr.Zero) return;
            ulong fnRelease = ReadVtableSlot(ifc, IUnknown_Release);
            if (fnRelease == 0) return;
            wf_call_ptr_fixed8(fnRelease, 1, 0x01, 0, (ulong)(uint)ifc, 0, 0, 0, 0, 0, 0, 0);
        }

        /// <summary>
        /// Execute a WQL query and return matching rows as List&lt;Dict&lt;string,object&gt;&gt;.
        /// Returns empty list on any failure. Errors logged to Console.
        /// </summary>
        public static List<Dictionary<string, object>> Query(string nspace, string wql)
        {
            var results = new List<Dictionary<string, object>>();
            if (string.IsNullOrEmpty(wql)) return results;
            EnsureInitialized();

            IntPtr pLoc = CreateInstance(CLSID_WbemLocator_GUID, IID_IWbemLocator_GUID);
            if (pLoc == IntPtr.Zero)
            {
                Console.WriteLine("[!] WfWmiCom: CoCreateInstance(WbemLocator) failed");
                return results;
            }

            ulong bstrRes  = AllocBstr(nspace ?? "root\\cimv2");
            ulong bstrLang = AllocBstr("WQL");
            ulong bstrQuery = 0;
            IntPtr pSvc = IntPtr.Zero;
            IntPtr pEnum = IntPtr.Zero;

            try
            {
                // ConnectServer: 9 args (this + 8) → needs fixed12
                ulong fnConnect = ReadVtableSlot(pLoc, IWbemLocator_ConnectServer);
                if (fnConnect == 0) return results;

                IntPtr ppSvc = Marshal.AllocHGlobal(8);
                *((ulong*)ppSvc) = 0;
                // ptrMask: this(0)=1 + ppSvc(8)=1<<8 = 0x101
                // out8Mask: ppSvc(8) = 0x100
                ulong hrC = wf_call_ptr_fixed12(fnConnect, 9, /*ptrMask*/ 0x101, /*out8Mask*/ 0x100,
                    (ulong)(uint)pLoc,    // this
                    bstrRes, 0, 0, 0,     // strRes, strUser, strPassword, strLocale
                    0, 0, 0,              // lSecurityFlags, strAuthority, pCtx
                    (ulong)(uint)ppSvc,   // ppNamespace OUT
                    0, 0, 0);
                if ((uint)hrC != 0)
                {
                    Marshal.FreeHGlobal(ppSvc);
                    Console.WriteLine("[!] WfWmiCom.ConnectServer hr=0x" + ((uint)hrC).ToString("X"));
                    return results;
                }
                pSvc = (IntPtr)(*((uint*)ppSvc));
                Marshal.FreeHGlobal(ppSvc);
                if (pSvc == IntPtr.Zero) return results;

                // ExecQuery: 6 args (this + 5) → fits fixed8
                ulong fnExec = ReadVtableSlot(pSvc, IWbemServices_ExecQuery);
                if (fnExec == 0) return results;
                bstrQuery = AllocBstr(wql);
                IntPtr ppEnum = Marshal.AllocHGlobal(8);
                *((ulong*)ppEnum) = 0;
                // ptrMask: this(0) + ppEnum(5) = 0x21
                // out8Mask: ppEnum(5) = 0x20
                ulong hrE = wf_call_ptr_fixed8(fnExec, 6, /*ptrMask*/ 0x21, /*out8Mask*/ 0x20,
                    (ulong)(uint)pSvc,
                    bstrLang, bstrQuery,
                    WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                    0,                         // pCtx
                    (ulong)(uint)ppEnum,
                    0, 0);                     // unused slot pad
                if ((uint)hrE != 0)
                {
                    Marshal.FreeHGlobal(ppEnum);
                    Console.WriteLine("[!] WfWmiCom.ExecQuery hr=0x" + ((uint)hrE).ToString("X"));
                    return results;
                }
                pEnum = (IntPtr)(*((uint*)ppEnum));
                Marshal.FreeHGlobal(ppEnum);
                if (pEnum == IntPtr.Zero) return results;

                // Enumerate
                ulong fnNext = ReadVtableSlot(pEnum, IEnumWbemClassObject_Next);
                if (fnNext == 0) return results;

                int safetyMax = 4096;
                while (safetyMax-- > 0)
                {
                    IntPtr ppObj = Marshal.AllocHGlobal(8);
                    *((ulong*)ppObj) = 0;
                    IntPtr pUret = Marshal.AllocHGlobal(4);
                    *((uint*)pUret) = 0;
                    // Next(timeout, uCount, &apObjects, &puReturned)
                    // ptrMask: this(0) + apObjects(3) + puReturned(4) = 0x19
                    // out8Mask: apObjects(3) = 0x08
                    ulong hrN = wf_call_ptr_fixed8(fnNext, 5, /*ptrMask*/ 0x19, /*out8Mask*/ 0x08,
                        (ulong)(uint)pEnum,
                        WBEM_INFINITE,
                        1,
                        (ulong)(uint)ppObj,
                        (ulong)(uint)pUret,
                        0, 0, 0);
                    uint uReturned = *((uint*)pUret);
                    IntPtr pObj = (IntPtr)(*((uint*)ppObj));
                    Marshal.FreeHGlobal(ppObj);
                    Marshal.FreeHGlobal(pUret);

                    if (uReturned == 0 || pObj == IntPtr.Zero) break;
                    var row = ExtractProperties(pObj);
                    if (row != null) results.Add(row);
                    ReleaseCom(pObj);
                    if ((uint)hrN == WBEM_S_NO_MORE_DATA) break;
                    if ((uint)hrN != 0) break;
                }
            }
            finally
            {
                if (bstrRes != 0)   SysFreeString(bstrRes);
                if (bstrLang != 0)  SysFreeString(bstrLang);
                if (bstrQuery != 0) SysFreeString(bstrQuery);
                ReleaseCom(pEnum);
                ReleaseCom(pSvc);
                ReleaseCom(pLoc);
            }

            return results;
        }

        static Dictionary<string, object> ExtractProperties(IntPtr pObj)
        {
            var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            ulong fnBegin = ReadVtableSlot(pObj, IWbemClassObject_BeginEnumeration);
            ulong fnNext  = ReadVtableSlot(pObj, IWbemClassObject_Next);
            ulong fnEnd   = ReadVtableSlot(pObj, IWbemClassObject_EndEnumeration);
            if (fnBegin == 0 || fnNext == 0 || fnEnd == 0) return row;

            // BeginEnumeration(flags)
            ulong hr0 = wf_call_ptr_fixed8(fnBegin, 2, 0x01, 0,
                (ulong)(uint)pObj, WBEM_FLAG_NONSYSTEM_ONLY, 0, 0, 0, 0, 0, 0);
            if ((uint)hr0 != 0) return row;

            int safetyMax = 1024;
            while (safetyMax-- > 0)
            {
                IntPtr ppName = Marshal.AllocHGlobal(8);
                *((ulong*)ppName) = 0;
                IntPtr pVar = AllocVariant();
                // Next(flags, &strName, &varVal, &type, &flavor)
                // ptrMask: this(0) + ppName(2) + pVar(3) = 0x0D
                // out8Mask: ppName(2) + pVar(3) = 0x0C
                ulong hrN = wf_call_ptr_fixed8(fnNext, 6, /*ptrMask*/ 0x0D, /*out8Mask*/ 0x0C,
                    (ulong)(uint)pObj,
                    0,
                    (ulong)(uint)ppName,
                    (ulong)(uint)pVar,
                    0, 0, 0, 0);
                if ((uint)hrN != 0)
                {
                    Marshal.FreeHGlobal(ppName);
                    VariantClear(pVar); Marshal.FreeHGlobal(pVar);
                    break;
                }
                ulong bstrHost = *((ulong*)ppName);
                string propName = BstrToString(bstrHost);
                object value = VariantToObject(pVar);
                if (!string.IsNullOrEmpty(propName))
                    row[propName] = value;
                if (bstrHost != 0) SysFreeString(bstrHost);
                Marshal.FreeHGlobal(ppName);
                VariantClear(pVar); Marshal.FreeHGlobal(pVar);
            }

            wf_call_ptr_fixed8(fnEnd, 1, 0x01, 0, (ulong)(uint)pObj, 0, 0, 0, 0, 0, 0, 0);
            return row;
        }
    }

    /// <summary>Bridge: imports wf_wmi_query and wf_wmi_method from the WasmForge host.</summary>
    internal static unsafe class WfWmiBridge
    {
        [DllImport("env", EntryPoint = "wmi_query")]
        internal static extern uint wmi_query(
            uint queryPtr, uint queryLen,
            uint nsPtr, uint nsLen,
            uint outBufPtr, uint outBufLen);

        [DllImport("env", EntryPoint = "wmi_method")]
        internal static extern uint wmi_method(
            uint nsPtr, uint nsLen,
            uint classPtr, uint classLen,
            uint methodPtr, uint methodLen,
            uint inJsonPtr, uint inJsonLen,
            uint outBufPtr, uint outBufLen);

        internal static string Query(string nspace, string query)
        {
            if (string.IsNullOrEmpty(query)) return "[]";
            byte[] nsBytes = Encoding.UTF8.GetBytes(nspace ?? "root\\cimv2");
            byte[] qBytes = Encoding.UTF8.GetBytes(query);
            byte[] outBuf = new byte[1024 * 1024]; // 1 MB

            uint written;
            fixed (byte* nsPtr = nsBytes)
            fixed (byte* qPtr = qBytes)
            fixed (byte* outPtr = outBuf)
            {
                written = wmi_query(
                    (uint)(IntPtr)qPtr, (uint)qBytes.Length,
                    (uint)(IntPtr)nsPtr, (uint)nsBytes.Length,
                    (uint)(IntPtr)outPtr, (uint)outBuf.Length);
            }
            if (written == 0 || written > outBuf.Length) return "[]";
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>
        /// Invoke a WMI method on a class (IWbemServices::ExecMethod).
        /// Returns the output-parameter JSON object, or "{}" on failure.
        /// </summary>
        internal static string InvokeMethod(string nspace, string className,
            string methodName, string inputJson)
        {
            if (string.IsNullOrEmpty(className) || string.IsNullOrEmpty(methodName))
                return "{}";
            byte[] nsBytes = Encoding.UTF8.GetBytes(nspace ?? "root\\cimv2");
            byte[] cBytes = Encoding.UTF8.GetBytes(className);
            byte[] mBytes = Encoding.UTF8.GetBytes(methodName);
            byte[] iBytes = Encoding.UTF8.GetBytes(inputJson ?? "");
            byte[] outBuf = new byte[256 * 1024]; // 256 KB — outparam payloads are tiny

            uint written;
            fixed (byte* nsPtr = nsBytes)
            fixed (byte* cPtr = cBytes)
            fixed (byte* mPtr = mBytes)
            fixed (byte* iPtr = iBytes)
            fixed (byte* outPtr = outBuf)
            {
                written = wmi_method(
                    (uint)(IntPtr)nsPtr, (uint)nsBytes.Length,
                    (uint)(IntPtr)cPtr, (uint)cBytes.Length,
                    (uint)(IntPtr)mPtr, (uint)mBytes.Length,
                    (uint)(IntPtr)iPtr, (uint)iBytes.Length,
                    (uint)(IntPtr)outPtr, (uint)outBuf.Length);
            }
            if (written == 0 || written > outBuf.Length) return "{}";
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>Splits a path like "root\\cimv2:Win32_Process" into (ns, class).</summary>
        internal static (string ns, string cls) SplitPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return ("root\\cimv2", "");
            int colon = path.LastIndexOf(':');
            if (colon < 0) return ("root\\cimv2", path);
            string ns = path.Substring(0, colon);
            string cls = path.Substring(colon + 1);
            // Strip trailing instance qualifier like "Win32_Process.Handle='1234'"
            int dot = cls.IndexOf('.');
            if (dot >= 0) cls = cls.Substring(0, dot);
            // If ns looks like a class name (no backslash), it's actually the class.
            if (!ns.Contains('\\')) { cls = ns; ns = "root\\cimv2"; }
            return (ns, cls);
        }

        /// <summary>Serializes a property dictionary as a flat JSON object.
        /// Hand-rolled to avoid NativeAOT reflection-based JsonSerializer.</summary>
        internal static string PropsToJson(Dictionary<string, object> props)
        {
            if (props == null || props.Count == 0) return "{}";
            var sb = new StringBuilder("{");
            bool first = true;
            foreach (var kv in props)
            {
                if (kv.Value == null) continue;
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(EscapeJsonString(kv.Key)).Append("\":");
                AppendJsonValue(sb, kv.Value);
            }
            sb.Append('}');
            return sb.ToString();
        }

        private static string EscapeJsonString(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            var sb = new StringBuilder(s.Length + 4);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        private static void AppendJsonValue(StringBuilder sb, object v)
        {
            if (v == null) { sb.Append("null"); return; }
            switch (v)
            {
                case string s:
                    sb.Append('"').Append(EscapeJsonString(s)).Append('"');
                    return;
                case bool b:
                    sb.Append(b ? "true" : "false"); return;
                case int i: sb.Append(i); return;
                case uint u: sb.Append(u); return;
                case long l: sb.Append(l); return;
                case ulong ul: sb.Append(ul); return;
                case short sh: sb.Append(sh); return;
                case ushort us: sb.Append(us); return;
                case byte by: sb.Append(by); return;
                case sbyte sb2: sb.Append(sb2); return;
                case double d: sb.Append(d); return;
                case float f: sb.Append(f); return;
                default:
                    // Fall back to ToString quoted as string. Avoids reflection.
                    sb.Append('"').Append(EscapeJsonString(v.ToString())).Append('"');
                    return;
            }
        }
    }

    /// <summary>Parses a JsonElement into the loose object graph Seatbelt expects.</summary>
    internal static class WfWmiJson
    {
        public static object ToObject(JsonElement el)
        {
            switch (el.ValueKind)
            {
                case JsonValueKind.String: return el.GetString();
                case JsonValueKind.Number:
                    // WMI returns most counters/flags as CIM_UINT32 / CIM_UINT64.
                    // The .NET WMI BCL preserves those types when boxing, so
                    // consumer casts like `(uint)result["X"]` only succeed when
                    // the boxed value is genuinely uint. Prefer uint > ulong >
                    // int > long > double to maximize cast compatibility.
                    if (el.TryGetUInt32(out uint u32)) return u32;
                    if (el.TryGetUInt64(out ulong u64)) return u64;
                    if (el.TryGetInt32(out int i32)) return i32;
                    if (el.TryGetInt64(out long i64)) return i64;
                    if (el.TryGetDouble(out double d)) return d;
                    return el.GetRawText();
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                case JsonValueKind.Null: return null;
                case JsonValueKind.Array:
                    // Detect homogeneous element types and return a typed
                    // array so consumer-side casts like (int[]) / (string[])
                    // succeed. CredGuard's SecurityServicesConfigured comes
                    // back as a JSON int array and must cast to int[].
                    var rawItems = new List<object>();
                    bool allUInt = true, allInt = true, allULong = true, allLong = true, allString = true, allBool = true;
                    foreach (var item in el.EnumerateArray())
                    {
                        var v = ToObject(item);
                        rawItems.Add(v);
                        if (!(v is uint))   allUInt   = false;
                        if (!(v is int))    allInt    = false;
                        if (!(v is ulong))  allULong  = false;
                        if (!(v is long))   allLong   = false;
                        if (!(v is string)) allString = false;
                        if (!(v is bool))   allBool   = false;
                    }
                    if (rawItems.Count == 0) return new object[0];
                    // Prefer int[] for integer arrays — Seatbelt's WMI consumers
                    // cast directly to int[] (CredGuard's SecurityServicesConfigured
                    // etc.). uint[] would be more type-accurate but fails the cast
                    // on NativeAOT. Values fit since they're status flags / counts.
                    if (allUInt || allInt)
                    {
                        var arr = new int[rawItems.Count];
                        for (int i = 0; i < rawItems.Count; i++)
                        {
                            var v = rawItems[i];
                            arr[i] = v is uint u ? unchecked((int)u) : (int)v;
                        }
                        return arr;
                    }
                    if (allULong)
                    {
                        var arr = new ulong[rawItems.Count];
                        for (int i = 0; i < rawItems.Count; i++) arr[i] = (ulong)rawItems[i];
                        return arr;
                    }
                    if (allLong)
                    {
                        var arr = new long[rawItems.Count];
                        for (int i = 0; i < rawItems.Count; i++) arr[i] = (long)rawItems[i];
                        return arr;
                    }
                    if (allString)
                    {
                        var arr = new string[rawItems.Count];
                        for (int i = 0; i < rawItems.Count; i++) arr[i] = (string)rawItems[i];
                        return arr;
                    }
                    if (allBool)
                    {
                        var arr = new bool[rawItems.Count];
                        for (int i = 0; i < rawItems.Count; i++) arr[i] = (bool)rawItems[i];
                        return arr;
                    }
                    return rawItems.ToArray();
                case JsonValueKind.Object:
                    var dict = new Dictionary<string, object>();
                    foreach (var prop in el.EnumerateObject()) dict[prop.Name] = ToObject(prop.Value);
                    return dict;
                default: return null;
            }
        }

        public static List<Dictionary<string, object>> ParseRows(string json)
        {
            var rows = new List<Dictionary<string, object>>();
            if (string.IsNullOrEmpty(json) || json == "[]") return rows;
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) return rows;
                foreach (var rowEl in doc.RootElement.EnumerateArray())
                {
                    if (rowEl.ValueKind != JsonValueKind.Object) continue;
                    var row = new Dictionary<string, object>();
                    foreach (var prop in rowEl.EnumerateObject())
                    {
                        row[prop.Name] = ToObject(prop.Value);
                    }
                    rows.Add(row);
                }
            }
            catch { /* malformed JSON → empty rows */ }
            return rows;
        }
    }

    /// <summary>A single WMI result row. Indexed by property name.</summary>
    public class ManagementBaseObject : IDisposable
    {
        internal Dictionary<string, object> _props;
        // WMI property indexing is case-insensitive (e.g., Seatbelt's
        // NetworkSharesCommand reads `result["type"]` against WMI's
        // canonical "Type" property). Match real-WMI semantics here so
        // consumer code that mixes cases keeps working.
        public ManagementBaseObject() { _props = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase); }
        internal ManagementBaseObject(Dictionary<string, object> props)
        {
            if (props == null) { _props = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase); return; }
            if (props.Comparer == StringComparer.OrdinalIgnoreCase) { _props = props; return; }
            _props = new Dictionary<string, object>(props, StringComparer.OrdinalIgnoreCase);
        }

        public object this[string propertyName]
        {
            get => _props.TryGetValue(propertyName, out var v) ? v : null;
            set => _props[propertyName] = value;
        }

        public PropertyDataCollection Properties => new PropertyDataCollection(_props);
        public PropertyDataCollection SystemProperties => new PropertyDataCollection(_props);
        public string ClassPath => "";

        public object GetPropertyValue(string propertyName) => this[propertyName];
        public void SetPropertyValue(string propertyName, object value) => _props[propertyName] = value;

        public ManagementBaseObject Clone() => new ManagementBaseObject(new Dictionary<string, object>(_props));

        public void Dispose() { _props = null; }
    }

    /// <summary>Object collection enumerable.</summary>
    public class ManagementObjectCollection : IEnumerable<ManagementBaseObject>, IDisposable
    {
        private readonly List<ManagementBaseObject> _rows;
        internal ManagementObjectCollection(List<ManagementBaseObject> rows) { _rows = rows ?? new List<ManagementBaseObject>(); }
        public int Count => _rows.Count;
        public IEnumerator<ManagementBaseObject> GetEnumerator() => _rows.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        public void Dispose() { foreach (var r in _rows) r.Dispose(); _rows.Clear(); }
    }

    /// <summary>Property data wrapper.</summary>
    public class PropertyData
    {
        public string Name { get; }
        public object Value { get; set; }
        public bool IsArray => Value is Array;
        public CimType Type
        {
            get
            {
                if (Value is null) return CimType.None;
                if (Value is string) return CimType.String;
                if (Value is bool) return CimType.Boolean;
                if (Value is byte) return CimType.UInt8;
                if (Value is sbyte) return CimType.SInt8;
                if (Value is short) return CimType.SInt16;
                if (Value is ushort) return CimType.UInt16;
                if (Value is int) return CimType.SInt32;
                if (Value is uint) return CimType.UInt32;
                if (Value is long) return CimType.SInt64;
                if (Value is ulong) return CimType.UInt64;
                if (Value is float) return CimType.Real32;
                if (Value is double) return CimType.Real64;
                if (Value is DateTime) return CimType.DateTime;
                if (Value is Array) return CimType.Object;
                return CimType.Object;
            }
        }
        public QualifierDataCollection Qualifiers => new QualifierDataCollection();
        public PropertyData(string name, object value) { Name = name; Value = value; }
    }

    public enum CimType
    {
        None        = 0,
        SInt16      = 2,
        SInt32      = 3,
        Real32      = 4,
        Real64      = 5,
        String      = 8,
        Boolean     = 11,
        Object      = 13,
        SInt8       = 16,
        UInt8       = 17,
        UInt16      = 18,
        UInt32      = 19,
        SInt64      = 20,
        UInt64      = 21,
        DateTime    = 101,
        Reference   = 102,
        Char16      = 103,
    }

    /// <summary>Stub for qualifier metadata. SharpDPAPI iterates these for some
    /// classes but treats missing entries as defaults — empty collection is fine.</summary>
    public class QualifierData
    {
        public string Name { get; }
        public object Value { get; set; }
        public bool IsAmended { get; set; }
        public bool IsLocal { get; set; } = true;
        public bool IsOverridable { get; set; } = true;
        public bool PropagatesToInstance { get; set; }
        public bool PropagatesToSubclass { get; set; }
        public QualifierData(string name, object value) { Name = name; Value = value; }
    }

    public class QualifierDataCollection : List<QualifierData>
    {
        public QualifierData this[string name]
        {
            get
            {
                foreach (var q in this)
                    if (q.Name == name) return q;
                throw new ManagementException("Qualifier not found: " + name);
            }
        }
        public void Add(string name, object value) { base.Add(new QualifierData(name, value)); }
    }

    public class PropertyDataCollection : IEnumerable<PropertyData>
    {
        private readonly Dictionary<string, object> _props;
        internal PropertyDataCollection(Dictionary<string, object> props) { _props = props ?? new Dictionary<string, object>(); }
        public PropertyData this[string name] => new PropertyData(name, _props.TryGetValue(name, out var v) ? v : null);
        public void Add(string name, object value) { _props[name] = value; }
        public void Add(string name, CimType type) { _props[name] = null; }
        public void Add(string name, object value, CimType type) { _props[name] = value; }
        public void Add(string name, CimType type, bool isArray) { _props[name] = isArray ? (object)Array.Empty<object>() : null; }
        public void Add(string name, object value, bool isArray) { _props[name] = value; }
        public void Remove(string name) { _props.Remove(name); }
        public int Count => _props.Count;
        public IEnumerator<PropertyData> GetEnumerator()
        {
            foreach (var kv in _props) yield return new PropertyData(kv.Key, kv.Value);
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class ManagementScope
    {
        public string Path { get; set; }
        public ConnectionOptions Options { get; set; }
        public ManagementScope() { }
        public ManagementScope(string path) { Path = path; }
        public ManagementScope(string path, ConnectionOptions options) { Path = path; Options = options; }
        public ManagementScope(ManagementPath path) { Path = path?.Path; }
        public ManagementScope(ManagementPath path, ConnectionOptions options) { Path = path?.Path; Options = options; }
        public bool IsConnected => true;
        public void Connect() { /* no-op */ }
    }

    public class ObjectQuery
    {
        public string QueryString { get; set; }
        public ObjectQuery() { }
        public ObjectQuery(string queryString) { QueryString = queryString; }
    }

    /// <summary>Primary entry point used by Seatbelt and other GhostPack tools.</summary>
    public class ManagementObjectSearcher : IDisposable
    {
        public ManagementScope Scope { get; set; }
        public ObjectQuery Query { get; set; }

        public ManagementObjectSearcher() { }
        public ManagementObjectSearcher(string queryString) { Query = new ObjectQuery(queryString); Scope = new ManagementScope("root\\cimv2"); }
        public ManagementObjectSearcher(string scope, string queryString) { Scope = new ManagementScope(scope); Query = new ObjectQuery(queryString); }
        public ManagementObjectSearcher(ManagementScope scope, ObjectQuery query) { Scope = scope; Query = query; }

        public ManagementObjectCollection Get()
        {
            string nspace = Scope?.Path ?? "root\\cimv2";
            string queryStr = Query?.QueryString ?? "";
            // Direct COM path: WfWmiCom runs the full CoCreateInstance →
            // ConnectServer → ExecQuery chain inside WASM via wf_call_ptr.
            // No host-side wmi_query stub — pure ole32 + IWbemServices
            // vtable dispatch. Replaces the legacy JSON bridge.
            List<Dictionary<string, object>> raw;
            try
            {
                raw = WfWmiCom.Query(nspace, queryStr);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] WfWmiCom.Query threw: " + ex.Message);
                raw = new List<Dictionary<string, object>>();
            }
            var objs = new List<ManagementBaseObject>(raw.Count);
            // Return ManagementObject (subclass of ManagementBaseObject) so
            // consumer code that casts `(ManagementObject)o` succeeds.
            foreach (var row in raw)
            {
                var mo = new ManagementObject();
                // Use case-insensitive dictionary so consumer code that
                // reads `result["type"]` against WMI's "Type" works.
                mo._props = new Dictionary<string, object>(row, StringComparer.OrdinalIgnoreCase);
                objs.Add(mo);
            }
            return new ManagementObjectCollection(objs);
        }

        public void Dispose() { }
    }

    /// <summary>ManagementObject — subclass of ManagementBaseObject with path info.
    /// Seatbelt's ServicesCommand and a few others reference this type.</summary>
    public class ManagementObject : ManagementBaseObject
    {
        public ManagementPath Path { get; set; }
        public ManagementScope Scope { get; set; }
        public ManagementObject() { }
        public ManagementObject(string path) { Path = new ManagementPath(path); }
        public ManagementObject(ManagementPath path) { Path = path; }
        public ManagementObject(ManagementScope scope, ManagementPath path, object options)
        {
            Scope = scope;
            Path = path;
        }

        public void Get() { /* no-op; data is loaded on demand */ }

        public object InvokeMethod(string methodName, object[] args)
        {
            // Positional-argument form. WMI methods all take named parameters,
            // so for the most common cases (Terminate, GetOwner) we drop args
            // and call with empty input — these methods read state from the
            // implicit "this" object path, not from inputs.
            string path = Path?.RelativePath ?? Path?.Path ?? "";
            var (ns, cls) = WfWmiBridge.SplitPath(path);
            string json = WfWmiBridge.InvokeMethod(ns, cls, methodName, "{}");
            return ParseReturnValue(json);
        }

        public ManagementBaseObject InvokeMethod(string methodName, ManagementBaseObject inParams, object options)
        {
            string path = Path?.RelativePath ?? Path?.Path ?? "";
            var (ns, cls) = WfWmiBridge.SplitPath(path);
            string inJson = inParams != null ? WfWmiBridge.PropsToJson(inParams._props) : "{}";
            string outJson = WfWmiBridge.InvokeMethod(ns, cls, methodName, inJson);
            return ParseOutParams(outJson);
        }

        /// <summary>Parse a WMI method output JSON into a ManagementBaseObject.</summary>
        internal static ManagementBaseObject ParseOutParams(string json)
        {
            var result = new ManagementBaseObject();
            if (string.IsNullOrEmpty(json) || json == "{}") return result;
            try
            {
                using var doc = JsonDocument.Parse(json);
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    result._props[prop.Name] = WfWmiJson.ToObject(prop.Value);
                }
            }
            catch { /* return empty on parse error */ }
            return result;
        }

        /// <summary>Extract the WMI ReturnValue from method output JSON (defaults to 0).</summary>
        internal static object ParseReturnValue(string json)
        {
            var outp = ParseOutParams(json);
            return outp._props.TryGetValue("ReturnValue", out var v) ? v : (object)(uint)0;
        }

        public ManagementPath Put() { return Path ?? new ManagementPath(); }
        public ManagementPath Put(PutOptions options) { return Path ?? new ManagementPath(); }
        public void Delete() { /* no-op */ }
        public void Delete(DeleteOptions options) { /* no-op */ }
    }

    public class DeleteOptions
    {
        public TimeSpan Timeout { get; set; } = TimeSpan.MaxValue;
    }

    /// <summary>Minimal ManagementClass stub. WMI method invocation isn't supported.
    /// Derives from ManagementObject (not ManagementBaseObject directly) so SharpWMI's
    /// `ManagementObject classInstance = mgmtClass` assignments compile.</summary>
    public class ManagementClass : ManagementObject
    {
        public string Path { get; set; }
        public ManagementScope Scope { get; set; }
        public ManagementClass() { }
        public ManagementClass(string path) { Path = path; }
        public ManagementClass(string nspace, string className, object options) { Path = $"{nspace}:{className}"; }
        public ManagementClass(ManagementScope scope, ManagementPath path, object options) { Scope = scope; Path = path?.Path; }
        public ManagementClass(ManagementPath path) { Path = path?.Path; }

        public ManagementBaseObject GetMethodParameters(string methodName)
        {
            return new ManagementBaseObject();
        }

        public ManagementObjectCollection GetInstances() => GetInstances(null);
        public ManagementObjectCollection GetInstances(EnumerationOptions options)
        {
            // Path is "namespace:ClassName" — split and issue "SELECT * FROM ClassName".
            string nspace = "root\\cimv2";
            string className = Path ?? "";
            int colon = className.IndexOf(':');
            if (colon >= 0)
            {
                nspace = className.Substring(0, colon);
                className = className.Substring(colon + 1);
            }
            using var searcher = new ManagementObjectSearcher(nspace, "SELECT * FROM " + className);
            return searcher.Get();
        }

        public new ManagementBaseObject InvokeMethod(string methodName, ManagementBaseObject inParams, object options)
        {
            var (ns, cls) = WfWmiBridge.SplitPath(Path ?? "");
            string inJson = inParams != null ? WfWmiBridge.PropsToJson(inParams._props) : "{}";
            string outJson = WfWmiBridge.InvokeMethod(ns, cls, methodName, inJson);
            return ManagementObject.ParseOutParams(outJson);
        }

        public new object InvokeMethod(string methodName, object[] args)
        {
            var (ns, cls) = WfWmiBridge.SplitPath(Path ?? "");
            string outJson = WfWmiBridge.InvokeMethod(ns, cls, methodName, "{}");
            return ManagementObject.ParseReturnValue(outJson);
        }

        public ManagementObject CreateInstance()
        {
            return new ManagementObject { Path = new ManagementPath(Path), Scope = Scope };
        }
    }

    /// <summary>Connection options stub.</summary>
    public class ConnectionOptions
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Authority { get; set; }
        public AuthenticationLevel Authentication { get; set; }
        public ImpersonationLevel Impersonation { get; set; }
        public bool EnablePrivileges { get; set; }
    }

    public enum AuthenticationLevel { Default, None, Connect, Call, Packet, PacketIntegrity, PacketPrivacy, Unchanged }
    public enum ImpersonationLevel { Default, Anonymous, Identify, Impersonate, Delegate }

    public class ManagementPath
    {
        public string Path { get; set; }
        public string RelativePath { get; set; }
        public string NamespacePath { get; set; }
        public string ClassName { get; set; }
        public string Server { get; set; }
        public ManagementPath() { }
        public ManagementPath(string path)
        {
            Path = path;
            RelativePath = path;
            // Parse "namespace:Class[.Key=value]" minimally
            if (!string.IsNullOrEmpty(path))
            {
                int colon = path.LastIndexOf(':');
                if (colon >= 0)
                {
                    NamespacePath = path.Substring(0, colon);
                    var rest = path.Substring(colon + 1);
                    int dot = rest.IndexOf('.');
                    ClassName = dot >= 0 ? rest.Substring(0, dot) : rest;
                    RelativePath = rest;
                }
            }
        }
    }

    /// <summary>WqlEventQuery stub — represents a WMI event subscription
    /// (e.g., "SELECT * FROM __InstanceCreationEvent WITHIN 5"). SharpWMI
    /// constructs these but we don't deliver events, so the type exists
    /// for compile-time only.</summary>
    public class WqlEventQuery
    {
        public string QueryString { get; set; }
        public string QueryLanguage { get; set; } = "WQL";
        public string EventClassName { get; set; }
        public TimeSpan WithinInterval { get; set; }
        public string Condition { get; set; }
        public WqlEventQuery() { }
        public WqlEventQuery(string queryString) { QueryString = queryString; }
        public WqlEventQuery(string eventClassName, TimeSpan withinInterval)
        { EventClassName = eventClassName; WithinInterval = withinInterval; }
        public WqlEventQuery(string eventClassName, TimeSpan withinInterval, string condition)
        { EventClassName = eventClassName; WithinInterval = withinInterval; Condition = condition; }
    }

    public class WqlObjectQuery : ObjectQuery
    {
        public WqlObjectQuery() { }
        public WqlObjectQuery(string queryString) : base(queryString) { }
    }

    /// <summary>Event watcher — also throws on Start because we don't deliver
    /// events in this stub. Tools that need this would need a host-side event
    /// pump (not implemented).</summary>
    public class ManagementEventWatcher : IDisposable
    {
        public ManagementScope Scope { get; set; }
        public EventArrivedEventHandler EventArrived;
        public ManagementEventWatcher() { }
        public ManagementEventWatcher(WqlEventQuery query) { Query = query; }
        public ManagementEventWatcher(ManagementScope scope, WqlEventQuery query) { Scope = scope; Query = query; }
        public WqlEventQuery Query { get; set; }
        public void Start() { throw new NotSupportedException("WMI event delivery is not implemented in NativeAOT-WASI"); }
        public void Stop() { }
        public void Dispose() { }
        public ManagementBaseObject WaitForNextEvent()
        {
            throw new NotSupportedException("WMI event delivery is not implemented in NativeAOT-WASI");
        }
    }

    public delegate void EventArrivedEventHandler(object sender, EventArrivedEventArgs e);
    public class EventArrivedEventArgs : EventArgs
    {
        public ManagementBaseObject NewEvent { get; set; }
    }

    /// <summary>WMI date format converter — used by Seatbelt's LogonSessionsCommand etc.
    /// WMI returns dates as YYYYMMDDHHMMSS.ffffff+TZM; convert to DateTime.</summary>
    public static class ManagementDateTimeConverter
    {
        public static DateTime ToDateTime(string dmtfDate)
        {
            // dmtf format: YYYYMMDDHHMMSS.ffffff[+|-]ooo
            if (string.IsNullOrEmpty(dmtfDate) || dmtfDate.Length < 14) return DateTime.MinValue;
            try
            {
                int year   = int.Parse(dmtfDate.Substring(0, 4));
                int month  = int.Parse(dmtfDate.Substring(4, 2));
                int day    = int.Parse(dmtfDate.Substring(6, 2));
                int hour   = int.Parse(dmtfDate.Substring(8, 2));
                int minute = int.Parse(dmtfDate.Substring(10, 2));
                int second = int.Parse(dmtfDate.Substring(12, 2));
                int ms = 0;
                if (dmtfDate.Length >= 21 && dmtfDate[14] == '.')
                {
                    string frac = dmtfDate.Substring(15, 3);
                    int.TryParse(frac, out ms);
                }
                return new DateTime(year, month, day, hour, minute, second, ms, DateTimeKind.Local);
            }
            catch { return DateTime.MinValue; }
        }

        public static string ToDmtfDateTime(DateTime date)
        {
            return date.ToString("yyyyMMddHHmmss.ffffff") + "+000";
        }

        public static TimeSpan ToTimeSpan(string dmtfInterval) => TimeSpan.Zero;
        public static string ToDmtfTimeInterval(TimeSpan interval) => "00000000000000.000000:000";
    }

    public enum ManagementStatus
    {
        NoError = 0,
        Failed = -2147217407,
        NotFound = -2147217406,
        InvalidParameter = -2147217400,
        NotSupported = -2147217396,
        AccessDenied = -2147217405,
        InvalidClass = -2147217392,
        InvalidNamespace = -2147217394,
        InvalidQuery = -2147217385,
        TimedOut = -2147209215,
    }

    public class ManagementException : Exception
    {
        public ManagementStatus ErrorCode { get; set; } = ManagementStatus.Failed;
        public ManagementException() : base() { }
        public ManagementException(string message) : base(message) { }
        public ManagementException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>Options class for ManagementClass / ManagementObject ctors.
    /// SharpDPAPI and SharpWMI reference this type explicitly.</summary>
    public class ObjectGetOptions
    {
        public TimeSpan Timeout { get; set; } = TimeSpan.MaxValue;
        public bool UseAmendedQualifiers { get; set; }
        public ObjectGetOptions() { }
        public ObjectGetOptions(object context) { }
        public ObjectGetOptions(object context, TimeSpan timeout, bool useAmendedQualifiers)
        { Timeout = timeout; UseAmendedQualifiers = useAmendedQualifiers; }
    }

    /// <summary>Options class for method invocation on ManagementObject.</summary>
    public class InvokeMethodOptions
    {
        public TimeSpan Timeout { get; set; } = TimeSpan.MaxValue;
        public InvokeMethodOptions() { }
        public InvokeMethodOptions(object context, TimeSpan timeout) { Timeout = timeout; }
    }

    /// <summary>Options class for put/update operations.</summary>
    public class PutOptions
    {
        public PutType Type { get; set; } = PutType.UpdateOrCreate;
        public TimeSpan Timeout { get; set; } = TimeSpan.MaxValue;
        public bool UseAmendedQualifiers { get; set; }
        public PutOptions() { }
    }
    public enum PutType { None, UpdateOnly, CreateOnly, UpdateOrCreate }

    public class EnumerationOptions
    {
        public bool ReturnImmediately { get; set; } = true;
        public bool Rewindable { get; set; }
        public bool EnumerateDeep { get; set; }
        public bool DirectRead { get; set; }
        public int BlockSize { get; set; } = 1;
        public TimeSpan Timeout { get; set; } = TimeSpan.MaxValue;
        public bool EnsureLocatable { get; set; }
        public bool PrototypeOnly { get; set; }
        public bool UseAmendedQualifiers { get; set; }
    }
}
