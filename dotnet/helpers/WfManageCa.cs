// WfManageCa.cs — Minimal manageca via ICertConfig::GetConfig.
//
// Verifies the WfCom + wf_call_ptr COM-vtable-dispatch pipeline by
// calling the simplest possible COM method: ICertConfig::GetConfig,
// which returns the default CA's config string ("\\<dc>\<ca-name>").
//
// If this works, the same pattern extends to ICertAdmin2 / ICertRequest3
// for the rest of Certify's COM-dependent verbs.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfManageCa
    {
        // ICertConfig vtable layout (after IUnknown/IDispatch headers):
        //   slot 7  Reset(dwFlags, [out] pdwCount)
        //   slot 8  Next([out] pwszConfig)
        //   slot 9  GetField(strFieldName, [out] pwszValue)
        //   slot 10 GetConfig(dwFlags, [out] pwszConfig)
        private const int ICertConfig_GetConfig_VtableSlot = 10;
        private const uint CC_DEFAULTCONFIG = 0;
        private const uint CC_UIPICKCONFIG  = 1;

        public static int Execute()
        {
            Console.WriteLine("[*] Action: Manage a certificate authority");
            // Don't bail on CoInitializeEx return value — the wasmforge host
            // already initializes COM on its worker thread, and the message we
            // get here may be benign (S_FALSE, RPC_E_CHANGED_MODE, etc).
            // Just call it and proceed; CoCreateInstance will fail clearly if
            // COM isn't actually usable on this thread.
            int hr = WfCom.Initialize();
            Console.WriteLine("[trace] CoInitializeEx hr=0x{0:X} (continuing regardless)", hr);

            Console.WriteLine("[*] WfCom: creating ICertConfig instance...");
            IntPtr ifc = WfCom.CreateInstance(WfCom.CLSID_CCertConfig, WfCom.IID_ICertConfig);
            if (ifc == IntPtr.Zero)
            {
                Console.WriteLine("[X] Failed to create CCertConfig instance.");
                return 1;
            }
            Console.WriteLine("[*] WfCom: ifc (WASM mirror) = 0x{0:X}", ifc);

            // Dump the first 80 bytes of the mirror to see the vtable.
            unsafe {
                ulong* p = (ulong*)ifc;
                Console.WriteLine("[trace] ifc[0..3] = 0x{0:X} 0x{1:X} 0x{2:X} 0x{3:X}", p[0], p[1], p[2], p[3]);
                if (p[0] != 0) {
                    ulong* vt = (ulong*)(IntPtr)(uint)p[0];
                    Console.WriteLine("[trace] vtable[0..10] = 0x{0:X} 0x{1:X} 0x{2:X} 0x{3:X} 0x{4:X} 0x{5:X} 0x{6:X} 0x{7:X} 0x{8:X} 0x{9:X} 0x{10:X}",
                        vt[0], vt[1], vt[2], vt[3], vt[4], vt[5], vt[6], vt[7], vt[8], vt[9], vt[10]);
                }
            }

            ulong getConfigFn = WfCom.ReadVtableSlot(ifc, ICertConfig_GetConfig_VtableSlot);
            if (getConfigFn == 0)
            {
                Console.WriteLine("[X] Failed to read vtable[GetConfig].");
                return 1;
            }
            Console.WriteLine("[*] WfCom: GetConfig funcptr = 0x{0:X}", getConfigFn);

            // ICertConfig::GetConfig(dwFlags, out BSTR pwszConfig).
            // Args: this, dwFlags, pBSTROutput.
            // BSTR output: API allocates a string and writes the pointer.
            // We need a WASM slot for the BSTR pointer.
            ulong bstrOut = 0;
            // ptrMask: bit 0 (this) = WASM mirror that translates,
            //          bit 1 (dwFlags) = scalar,
            //          bit 2 (pBSTRout) = WASM ptr to output slot.
            //          mask = bits 0 and 2 set = 0x05.
            ulong* pBstr = &bstrOut;
            ulong result = WfCom.InvokeMethod(
                getConfigFn, ifc, /*ptrMask=*/ 0x05,
                arg1: CC_DEFAULTCONFIG,
                arg2: (ulong)(IntPtr)pBstr,
                nargs: 3);

            Console.WriteLine("[*] WfCom: GetConfig returned hr=0x{0:X} bstr=0x{1:X}", result, bstrOut);

            if ((uint)result != 0)
            {
                Console.WriteLine("[X] GetConfig HRESULT=0x{0:X}", result);
                return 1;
            }
            if (bstrOut == 0)
            {
                Console.WriteLine("[X] GetConfig returned NULL BSTR.");
                return 1;
            }

            // BSTR is a wide string preceded by a 4-byte length. The pointer
            // points to the first wide character. Read up to 256 chars.
            try
            {
                char* p = (char*)(IntPtr)(uint)bstrOut;
                int len = 0;
                while (len < 256 && p[len] != 0) len++;
                string config = new string(p, 0, len);
                Console.WriteLine("[+] Default CA config: {0}", config);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to read BSTR: {0}", ex.Message);
            }

            return 0;
        }
    }
}
