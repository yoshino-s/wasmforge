// WfWmi.cs — WMI WQL driver via direct COM vtable dispatch.
//
// Generalizable WMI client modeled after Go's go-ole / hcsshim approach:
// read vtable pointer from interface, index by slot number, call host
// function pointer via wf_call_ptr. No host-side wmi_query stub —
// pure CoCreateInstance + IWbemServices chain runs inside WASM.
//
// Chain:
//   CoInitializeEx → CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator)
//     → pLoc->ConnectServer(...) → pSvc
//     → pSvc->ExecQuery("WQL", wql, flags, NULL, &pEnum)
//     → loop pEnum->Next → pObj
//        pObj->BeginEnumeration → loop Next(name,var) → EndEnumeration
//     → Release pObj, pEnum, pSvc, pLoc
//
// NOTE: A duplicate of this class (`WfWmiCom`) lives inside
// dotnet/stubs/System.Management/Stubs.cs because the stub assembly
// can't reference the parent project's WasmForge.Helpers namespace.
// Both must stay in sync; bugfix here means bugfix in Stubs.cs too.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfWmi
    {
        public static readonly Guid CLSID_WbemLocator = new Guid("4590f811-1d3a-11d0-891f-00aa004b2e24");
        public static readonly Guid IID_IWbemLocator  = new Guid("dc12a687-737f-11cf-884d-00aa004b2e24");

        const int IWbemLocator_ConnectServer = 3;
        const int IWbemServices_ExecQuery    = 20;
        const int IEnumWbemClassObject_Next  = 4;
        const int IWbemClassObject_BeginEnumeration = 8;
        const int IWbemClassObject_Next             = 9;
        const int IWbemClassObject_EndEnumeration   = 10;

        const uint WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
        const uint WBEM_FLAG_FORWARD_ONLY       = 0x20;
        const uint WBEM_FLAG_NONSYSTEM_ONLY     = 0x40;
        const uint WBEM_INFINITE                = 0xFFFFFFFF;
        const uint WBEM_S_NO_MORE_DATA          = 0x40005;

        [DllImport("env", EntryPoint = "wf_call_ptr_fixed12")]
        private static extern ulong NativeCallPtr12(ulong funcptr, int nargs,
            uint ptrMask, uint out8Mask,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11);

        static bool _initialized = false;
        static void EnsureInitialized()
        {
            if (_initialized) return;
            WfCom.Initialize();
            _initialized = true;
        }

        /// <summary>
        /// Execute a WQL query and return matching rows as
        /// List&lt;Dict&lt;string,object&gt;&gt;. Empty list on any failure.
        /// </summary>
        public static List<Dictionary<string, object>> Query(string nspace, string wql)
        {
            var results = new List<Dictionary<string, object>>();
            if (string.IsNullOrEmpty(wql)) return results;
            EnsureInitialized();

            IntPtr pLoc = WfCom.CreateInstance(CLSID_WbemLocator, IID_IWbemLocator);
            if (pLoc == IntPtr.Zero) return results;

            // Hoist all heap-allocated COM resources up so a single
            // finally block can release everything unconditionally —
            // avoids the goto-cleanup leak path the reviewer flagged.
            ulong  bstrRes   = 0;
            ulong  bstrLang  = 0;
            ulong  bstrQuery = 0;
            IntPtr pSvc      = IntPtr.Zero;
            IntPtr pEnum     = IntPtr.Zero;

            try
            {
                bstrRes  = WfCom.StringToBstr(nspace ?? "root\\cimv2");
                bstrLang = WfCom.StringToBstr("WQL");

                // ── ConnectServer (9 args incl this — uses fixed12) ──
                ulong fnConnect = WfCom.ReadVtableSlot(pLoc, IWbemLocator_ConnectServer);
                if (fnConnect == 0) return results;

                IntPtr ppSvc = Marshal.AllocHGlobal(8);
                *((ulong*)ppSvc) = 0;
                // ptrMask: this(0) + ppSvc(8) = 0x101
                // out8Mask: ppSvc(8) = 0x100
                ulong hrC = NativeCallPtr12(fnConnect, 9, 0x101, 0x100,
                    (ulong)(uint)pLoc,
                    bstrRes, 0, 0, 0,
                    0, 0, 0,
                    (ulong)(uint)ppSvc,
                    0, 0, 0);
                if ((uint)hrC != 0)
                {
                    Marshal.FreeHGlobal(ppSvc);
                    // Mirror native System.Management semantics: ManagementScope.Connect()
                    // (and the implicit connect inside ManagementObjectSearcher.Get()) raises
                    // ManagementException for well-known WBEM error HRESULTs. Without this,
                    // wasmforge silently returns an empty result set on a bad namespace and
                    // callers that expect to catch the exception (e.g. SharpDPAPI SCCM.cs's
                    // `catch (Exception e)` around NewSccmConnection) never see it.
                    // 0x8004100E = WBEM_E_INVALID_NAMESPACE — surface as ManagementException
                    // so the patched call sites get the same semantics as native.
                    if ((uint)hrC == 0x8004100E)
                        throw new System.Management.ManagementException("Invalid namespace ");
                    return results;
                }
                pSvc = (IntPtr)(*((uint*)ppSvc));
                Marshal.FreeHGlobal(ppSvc);
                if (pSvc == IntPtr.Zero) return results;

                // Set proxy authn/imp posture before ExecQuery via CoSetProxyBlanket.
                // Mandatory for restricted namespaces (root\SecurityCenter2,
                // ROOT\Subscription) to prevent IUnknown auth callbacks from
                // re-entering WASM and corrupting the Go runtime syscall frame.
                WfCom.SetProxyBlanket(pSvc);

                // ── ExecQuery (6 args incl this — uses fixed8) ──
                ulong fnExec = WfCom.ReadVtableSlot(pSvc, IWbemServices_ExecQuery);
                if (fnExec == 0) return results;
                bstrQuery = WfCom.StringToBstr(wql);

                IntPtr ppEnum = Marshal.AllocHGlobal(8);
                *((ulong*)ppEnum) = 0;
                // ptrMask: this(0) + ppEnum(5) = 0x21; out8Mask: ppEnum(5) = 0x20
                ulong hrE = WfCom.InvokeMethod(fnExec, pSvc, /*ptrMask*/ 0x21,
                    arg1: bstrLang,
                    arg2: bstrQuery,
                    arg3: WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                    arg4: 0,
                    arg5: (ulong)(uint)ppEnum,
                    nargs: 6,
                    out8Mask: 0x20);
                if ((uint)hrE != 0)
                {
                    Marshal.FreeHGlobal(ppEnum);
                    return results;
                }
                pEnum = (IntPtr)(*((uint*)ppEnum));
                Marshal.FreeHGlobal(ppEnum);
                if (pEnum == IntPtr.Zero) return results;

                // ── Enumerate ──
                ulong fnNext = WfCom.ReadVtableSlot(pEnum, IEnumWbemClassObject_Next);
                if (fnNext == 0) return results;

                int safetyMax = 4096;
                while (safetyMax-- > 0)
                {
                    IntPtr ppObj = Marshal.AllocHGlobal(8);
                    *((ulong*)ppObj) = 0;
                    IntPtr pUret = Marshal.AllocHGlobal(4);
                    *((uint*)pUret) = 0;
                    // ptrMask: this(0)+apObjects(3)+puReturned(4) = 0x19
                    // out8Mask: apObjects(3) = 0x08
                    ulong hrN = WfCom.InvokeMethod(fnNext, pEnum, /*ptrMask*/ 0x19,
                        arg1: WBEM_INFINITE,
                        arg2: 1,
                        arg3: (ulong)(uint)ppObj,
                        arg4: (ulong)(uint)pUret,
                        nargs: 5,
                        out8Mask: 0x08);
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
                WfCom.FreeBstr(bstrRes);
                WfCom.FreeBstr(bstrLang);
                WfCom.FreeBstr(bstrQuery);
                ReleaseCom(pEnum);
                ReleaseCom(pSvc);
                ReleaseCom(pLoc);
            }
            return results;
        }

        private static Dictionary<string, object> ExtractProperties(IntPtr pObj)
        {
            var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            ulong fnBegin = WfCom.ReadVtableSlot(pObj, IWbemClassObject_BeginEnumeration);
            ulong fnNext  = WfCom.ReadVtableSlot(pObj, IWbemClassObject_Next);
            ulong fnEnd   = WfCom.ReadVtableSlot(pObj, IWbemClassObject_EndEnumeration);
            if (fnBegin == 0 || fnNext == 0 || fnEnd == 0) return row;

            ulong hr0 = WfCom.InvokeMethod(fnBegin, pObj, 0x01,
                arg1: WBEM_FLAG_NONSYSTEM_ONLY, nargs: 2);
            if ((uint)hr0 != 0) return row;

            int safetyMax = 1024;
            while (safetyMax-- > 0)
            {
                IntPtr ppName = Marshal.AllocHGlobal(8);
                *((ulong*)ppName) = 0;
                IntPtr pVar = WfCom.AllocVariant();
                // ptrMask: this(0)+ppName(2)+pVar(3) = 0x0D
                // out8Mask: ppName(2)+pVar(3) = 0x0C
                ulong hrN = WfCom.InvokeMethod(fnNext, pObj, 0x0D,
                    arg1: 0,
                    arg2: (ulong)(uint)ppName,
                    arg3: (ulong)(uint)pVar,
                    arg4: 0,
                    arg5: 0,
                    nargs: 6,
                    out8Mask: 0x0C);
                if ((uint)hrN != 0)
                {
                    Marshal.FreeHGlobal(ppName);
                    WfCom.ClearVariant(pVar); WfCom.FreeVariant(pVar);
                    break;
                }
                ulong bstrHost = *((ulong*)ppName);
                string propName = WfCom.BstrToString(bstrHost);
                object value = WfCom.VariantToObject(pVar);
                if (!string.IsNullOrEmpty(propName))
                    row[propName] = value;
                if (bstrHost != 0) WfCom.FreeBstr(bstrHost);
                Marshal.FreeHGlobal(ppName);
                WfCom.ClearVariant(pVar); WfCom.FreeVariant(pVar);
            }

            WfCom.InvokeMethod(fnEnd, pObj, 0x01, nargs: 1);
            return row;
        }

        public static void ReleaseCom(IntPtr ifc)
        {
            if (ifc == IntPtr.Zero) return;
            ulong fnRelease = WfCom.ReadVtableSlot(ifc, /*IUnknown_Release*/ 2);
            if (fnRelease == 0) return;
            WfCom.InvokeMethod(fnRelease, ifc, 0x01, nargs: 1);
        }

        // QueryRestricted: host-side WMI query for restricted namespaces
        // (root\SecurityCenter2, ROOT\Subscription) that fire IUnknown callbacks
        // during ConnectServer. The host handles the full COM sequence —
        // CoSetProxyBlanket on the IWbemServices proxy, synchronous ExecQuery,
        // and result serialisation — entirely on the COM STA thread. No FFI
        // crossing during the WMI handshake means no chanrecv2 panic in wazero.
        //
        // The host function returns JSON (same format as the cimv2 wf_call_ptr
        // path) which we deserialise here into the same Dictionary type.
        [DllImport("env", EntryPoint = "wmi_query_r")]
        private static extern uint WfWmiQueryRestrictedNative(
            uint queryPtr, uint queryLen,
            uint nsPtr, uint nsLen,
            uint outBufPtr, uint outBufLen);

        public static List<Dictionary<string, object>> QueryRestricted(string nspace, string wql)
        {
            var results = new List<Dictionary<string, object>>();
            if (string.IsNullOrEmpty(wql)) return results;
            EnsureInitialized();

            // Marshal the two strings into fixed pinned memory and call the host.
            byte[] queryBytes = System.Text.Encoding.UTF8.GetBytes(wql);
            byte[] nsBytes    = System.Text.Encoding.UTF8.GetBytes(nspace ?? "root\\cimv2");
            const int outCap  = 131072; // 128 KB — generous for AV / event consumer lists
            byte[] outBuf     = new byte[outCap];

            uint written;
            unsafe
            {
                fixed (byte* qp = queryBytes, np = nsBytes, op = outBuf)
                {
                    written = WfWmiQueryRestrictedNative(
                        (uint)(ulong)qp, (uint)queryBytes.Length,
                        (uint)(ulong)np, (uint)nsBytes.Length,
                        (uint)(ulong)op, (uint)outBuf.Length);
                }
            }
            if (written == 0) return results;

            string json = System.Text.Encoding.UTF8.GetString(outBuf, 0, (int)written);
            try
            {
                // Deserialise JSON array produced by wmiQueryJSON on the host.
                // Format: [{"key":"value",...}, ...]
                // Use JsonDocument.Parse + manual property walk — reflection-based
                // JsonSerializer.Deserialize<T> is stripped by NativeAOT trimming.
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array)
                    return results;
                foreach (var row in doc.RootElement.EnumerateArray())
                {
                    if (row.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                    var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    foreach (var prop in row.EnumerateObject())
                    {
                        object val;
                        switch (prop.Value.ValueKind)
                        {
                            case System.Text.Json.JsonValueKind.String:
                                val = prop.Value.GetString() ?? ""; break;
                            case System.Text.Json.JsonValueKind.Number:
                                val = prop.Value.TryGetInt64(out long lv) ? (object)lv : prop.Value.GetDouble(); break;
                            case System.Text.Json.JsonValueKind.True:
                                val = true; break;
                            case System.Text.Json.JsonValueKind.False:
                                val = false; break;
                            default:
                                val = ""; break;
                        }
                        dict[prop.Name] = val;
                    }
                    results.Add(dict);
                }
            }
            catch { /* malformed JSON — return empty */ }
            return results;
        }
    }
}
