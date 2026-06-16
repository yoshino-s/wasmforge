// WfCom.cs — COM vtable dispatch via wf_call_ptr.
//
// Bridges C# code into the existing wasmforge COM infrastructure:
//
//   1. CoCreateInstance is invoked via a normal wf_call wrapper. The
//      output ppv slot is a WASM pointer; the host mirrors the COM
//      object (and recursively its vtable) into WASM memory and writes
//      the WASM mirror address into ppv.
//
//   2. C# reads ifc[0] from the mirror to get the WASM mirror address
//      of the vtable. Each vtable[N] entry, in turn, is a HOST funcptr
//      (numeric, copied verbatim during recursive mirroring — not a
//      mirror address, since funcptrs aren't heap objects).
//
//   3. To invoke a method, C# calls WfCom.Invoke(funcptr, ptrMask,
//      ifc_mirror_wasm_addr, ...args). wf_call_ptr registers the funcptr
//      with the host (mod_regptr → synthetic proc handle), then calls
//      mod_invoke. The host's Step 0 mirror reverse translation
//      converts ifc_mirror_wasm_addr → host ifc_addr before calling.
//
// This file is scaffolding — not yet driving any verb. The next-session
// work is wiring manageca / request / renew / download / requestonbehalf
// to the appropriate COM CLSID + method indices using this helper.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfCom
    {
        // Standard COM CLSIDs / IIDs used by Certify. GUIDs are 16-byte
        // structs that lay out identically on wasm32 and x64 (no
        // embedded pointers), so passing &guid directly to ole32 works.

        // CLSIDs (CoClasses) — verified from HKLM\SOFTWARE\Classes\<ProgID>\CLSID
        // on a Server 2022 AD CS host. Note the CLSID for CCertConfig
        // differs from MSDN docs that reference EA4DD5F4-... (older).
        public static readonly Guid CLSID_CCertConfig  = new Guid("372fce38-4324-11d0-8810-00a0c903b83c");
        public static readonly Guid CLSID_CCertRequest = new Guid("98aff3f0-5524-11d0-8812-00a0c903b83c");
        public static readonly Guid CLSID_CCertAdmin   = new Guid("37eabaf0-7fb6-11d0-8817-00a0c903b83c");

        // IIDs (Interface IDs) — verified from HKEY_CLASSES_ROOT\Interface
        // by interface name. Earlier guesses had ICertAdminD2 (server-only)
        // instead of ICertAdmin2 (client), etc.
        public static readonly Guid IID_ICertConfig   = new Guid("372fce34-4324-11d0-8810-00a0c903b83c"); // ...FCE34, not ...FCE38
        public static readonly Guid IID_ICertConfig2  = new Guid("7a18edde-7e78-4163-8ded-78e2c9cee924");
        public static readonly Guid IID_ICertRequest3 = new Guid("afc8f92b-33a2-4861-bf36-2933b7cd67b3");
        public static readonly Guid IID_ICertAdmin2   = new Guid("f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39");

        // CLSCTX_INPROC_SERVER for in-process COM activation.
        public const uint CLSCTX_INPROC_SERVER = 0x1;
        public const uint CLSCTX_LOCAL_SERVER  = 0x4;

        // CoInitializeEx flags.
        public const uint COINIT_APARTMENTTHREADED = 0x2;
        public const uint COINIT_MULTITHREADED     = 0x0;

        // ole32 P/Invokes — these go through the standard wf_call path,
        // so pointer masks for them need to be in semanticOverrides on
        // the host side (next-session task).
        [DllImport("ole32.dll")]
        private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

        [DllImport("ole32.dll")]
        private static extern void CoUninitialize();

        // CoInitializeSecurity — required by non-cimv2 WMI namespaces
        // (root\SecurityCenter2, root\subscription) which gate access on
        // the caller's impersonation level. Without this, ConnectServer
        // for those namespaces fails in ways that cross the Go FFI boundary
        // unrecoverably (chanrecv2 panic).
        [DllImport("ole32.dll")]
        private static extern int CoInitializeSecurity(
            IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc,
            IntPtr pReserved1, uint dwAuthnLevel, uint dwImpLevel,
            IntPtr pAuthList, uint dwCapabilities, IntPtr pReserved3);

        // RPC authentication / impersonation constants.
        private const uint RPC_C_AUTHN_LEVEL_DEFAULT = 0;
        private const uint RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        private const uint RPC_C_IMP_LEVEL_IDENTIFY = 2;
        private const uint EOAC_DYNAMIC_CLOAKING = 0x40;
        private const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
        private const uint EOAC_NONE = 0;
        private static bool _securityInitialized;

        // CoSetProxyBlanket sets the authentication/impersonation posture
        // on an existing COM proxy. Critical after IWbemLocator.ConnectServer
        // against restricted namespaces (root\SecurityCenter2, ROOT\Subscription)
        // — without it the proxy fires IUnknown auth callbacks during ExecQuery
        // that re-enter WASM via host function pointers and corrupt the Go
        // runtime's syscall frame.
        [DllImport("ole32.dll")]
        private static extern int CoSetProxyBlanket(
            IntPtr pProxy,
            uint dwAuthnSvc,        // RPC_C_AUTHN_*
            uint dwAuthzSvc,        // RPC_C_AUTHZ_*
            IntPtr pServerPrincName,
            uint dwAuthnLevel,      // RPC_C_AUTHN_LEVEL_*
            uint dwImpLevel,        // RPC_C_IMP_LEVEL_*
            IntPtr pAuthInfo,
            uint dwCapabilities);   // EOAC_*

        // CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv).
        // Take rclsid and riid as IntPtr (explicit pointer) instead of
        // `ref Guid` — the wasm32/x64 calling convention for `ref struct`
        // marshalling differs and produced REGDB_E_CLASSNOTREG. Callers
        // must pin the Guid and pass its address.
        [DllImport("ole32.dll")]
        private static extern int CoCreateInstance(
            IntPtr rclsid, IntPtr pUnkOuter, uint dwClsContext,
            IntPtr riid, out IntPtr ppv);

        // Initialize the COM apartment (idempotent — safe to call
        // multiple times; subsequent calls return S_FALSE).
        public static int Initialize()
        {
            int rc = CoInitializeEx(IntPtr.Zero, COINIT_APARTMENTTHREADED);
            // CoInitializeSecurity must be called exactly once per process,
            // BEFORE the first WMI ConnectServer call against a non-cimv2
            // namespace. Multiple calls return RPC_E_TOO_LATE — guard with
            // _securityInitialized so idempotent. Pass DEFAULT auth and
            // IMPERSONATE imp level (sufficient for SecurityCenter2 +
            // subscription namespaces; same posture as native Seatbelt).
            if (!_securityInitialized)
            {
                _securityInitialized = true;
                try
                {
                    CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero,
                        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                        IntPtr.Zero, EOAC_DYNAMIC_CLOAKING, IntPtr.Zero);
                }
                catch { /* RPC_E_TOO_LATE or other — ignore */ }
            }
            return rc;
        }

        // SetProxyBlanket configures an IWbemServices proxy for the
        // "restricted namespace" posture: RPC_C_AUTHN_LEVEL_CALL +
        // RPC_C_IMP_LEVEL_IMPERSONATE, no callbacks. Required after
        // IWbemLocator.ConnectServer on root\SecurityCenter2,
        // ROOT\Subscription, and other namespaces that fire IUnknown
        // auth callbacks under default authn. Returns the HRESULT;
        // callers may ignore failure (E_NOTIMPL, RPC_E_TOO_LATE, etc.).
        public static int SetProxyBlanket(IntPtr pProxy)
        {
            if (pProxy == IntPtr.Zero) return -1;
            const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;
            const uint RPC_C_AUTHZ_DEFAULT = 0xFFFFFFFF;
            const uint RPC_C_AUTHN_LEVEL_CALL = 3;
            const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
            const uint EOAC_NONE = 0;
            return CoSetProxyBlanket(pProxy,
                RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, IntPtr.Zero,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                IntPtr.Zero, EOAC_NONE);
        }

        // Create a COM instance. Returns the WASM mirror address of the
        // interface, or 0 on failure. Pins the Guids and passes raw
        // IntPtrs to avoid the wasm32/x64 `ref struct` marshalling issue.
        public static IntPtr CreateInstance(Guid clsid, Guid iid)
        {
            IntPtr ppv = IntPtr.Zero;
            // Allocate 32 bytes (2 × 16-byte Guids) and copy in.
            IntPtr buf = Marshal.AllocHGlobal(32);
            try
            {
                byte[] cBytes = clsid.ToByteArray();
                byte[] iBytes = iid.ToByteArray();
                Marshal.Copy(cBytes, 0, buf, 16);
                Marshal.Copy(iBytes, 0, buf + 16, 16);
                int hr = CoCreateInstance(buf, IntPtr.Zero,
                    CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
                    buf + 16, out ppv);
                if (hr != 0)
                {
                    Console.WriteLine("[X] CoCreateInstance failed: hr=0x{0:X}", hr);
                    return IntPtr.Zero;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return ppv;
        }

        // ReadVtableSlot: read the host funcptr at vtable[index] of the
        // COM object pointed to by ifc (a WASM mirror address).
        //
        // ifc points to the mirrored COM object. *ifc is the WASM mirror
        // address of the vtable. *(vtable + index*8) is the host funcptr
        // for the method (recursively mirrored as raw bytes; funcptrs
        // aren't translated by the mirror chain).
        public static ulong ReadVtableSlot(IntPtr ifc, int index)
        {
            if (ifc == IntPtr.Zero) return 0;
            ulong* vtablePtr = (ulong*)ifc;
            ulong vtableMirror = *vtablePtr; // WASM mirror addr of the vtable
            if (vtableMirror == 0) return 0;
            ulong* vtable = (ulong*)(IntPtr)(uint)vtableMirror;
            return vtable[index];
        }

        // Invoke a COM method via wf_call_ptr. funcptr is the host
        // address read from the mirrored vtable. ifc is the WASM mirror
        // address of the interface (host translates Step 0 → host ifc).
        //
        // For methods with multiple args, the caller must pass them in
        // order after `ifc`. The ptr_mask describes which of those args
        // (counting ifc as arg 0) are WASM pointers requiring translation.
        //
        // This is a thin wrapper around the wf_call_ptr C bridge; it's
        // declared in dotnet/bridge/wf_bridge.h.
        [DllImport("env", EntryPoint = "wf_call_ptr_fixed8")]
        private static extern ulong NativeCallPtr(ulong funcptr, int nargs,
            uint ptrMask, uint out8Mask,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7);

        public static ulong InvokeMethod(ulong funcptr, IntPtr ifc, uint ptrMask,
            ulong arg1 = 0, ulong arg2 = 0, ulong arg3 = 0,
            ulong arg4 = 0, ulong arg5 = 0, ulong arg6 = 0, ulong arg7 = 0,
            int nargs = 1, uint out8Mask = 0)
        {
            // arg 0 is always `this` (the interface pointer). The caller
            // specifies nargs as the TOTAL number of args including this.
            return NativeCallPtr(funcptr, nargs, ptrMask, out8Mask,
                (ulong)(uint)ifc, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
        }

        // ─────────────────────────────────────────────────────────────
        // Generic host-memory read (mod_hread wrapper).
        // ─────────────────────────────────────────────────────────────
        [DllImport("env", EntryPoint = "mod_hread")]
        private static extern uint mod_hread(ulong hostAddr, uint len, void* outBuf);

        /// <summary>Read `nbytes` host bytes (max 4096 per call) at hostAddr.</summary>
        public static byte[] ReadHostBytes(ulong hostAddr, uint nbytes)
        {
            if (hostAddr == 0 || nbytes == 0) return Array.Empty<byte>();
            if (nbytes > 4096) nbytes = 4096;
            byte[] buf = new byte[nbytes];
            fixed (byte* p = buf)
            {
                uint rc = mod_hread(hostAddr, nbytes, p);
                if (rc != 0) return Array.Empty<byte>();
            }
            return buf;
        }

        public static uint ReadHostUInt32(ulong hostAddr)
        {
            byte[] b = ReadHostBytes(hostAddr, 4);
            return b.Length == 4 ? BitConverter.ToUInt32(b, 0) : 0;
        }

        public static ulong ReadHostUInt64(ulong hostAddr)
        {
            byte[] b = ReadHostBytes(hostAddr, 8);
            return b.Length == 8 ? BitConverter.ToUInt64(b, 0) : 0;
        }

        // ─────────────────────────────────────────────────────────────
        // BSTR support.
        //
        // BSTR layout in host memory:
        //   [hostBstr - 4 .. hostBstr)   uint32 byte-length prefix
        //   [hostBstr .. hostBstr+len)   UTF-16LE chars (NO BOM)
        //   [hostBstr+len .. +2)         trailing NUL (not in length)
        // ─────────────────────────────────────────────────────────────
        public static string BstrToString(ulong hostBstr)
        {
            if (hostBstr == 0) return null;
            uint byteLen = ReadHostUInt32(hostBstr - 4);
            if (byteLen == 0 || byteLen > 4096) return string.Empty;
            byte[] data = ReadHostBytes(hostBstr, byteLen);
            if (data.Length == 0) return string.Empty;
            int charCount = (int)(byteLen / 2);
            char[] chars = new char[charCount];
            for (int i = 0; i < charCount; i++)
                chars[i] = (char)(data[2*i] | (data[2*i + 1] << 8));
            return new string(chars);
        }

        [DllImport("oleaut32.dll")]
        private static extern void SysFreeString(ulong bstr);
        public static void FreeBstr(ulong hostBstr)
        {
            if (hostBstr != 0) SysFreeString(hostBstr);
        }

        // SysAllocString takes IntPtr (not [MarshalAs(LPWStr)] string) because
        // NativeAOT-LLVM/wasm-ld generates a 2-arg (i32,i32)→i64 wrapper for
        // the marshalled signature, mismatching the C bridge's 1-arg (i32)→i64
        // function, which causes wasm-ld to emit `undefined_stub` at the call
        // site (per lld WebAssembly behavior for unresolvable signatures).
        // Passing a pinned char* avoids the runtime marshaller entirely.
        [DllImport("oleaut32.dll")]
        private static extern ulong SysAllocString(IntPtr wstrPtr);
        public static unsafe ulong StringToBstr(string s)
        {
            if (s == null) return 0;
            fixed (char* p = s)
            {
                return SysAllocString((IntPtr)p);
            }
        }

        // ─────────────────────────────────────────────────────────────
        // VARIANT support (24 bytes — 64-bit Windows COM layout).
        //
        //   [0..2)   VARTYPE vt
        //   [2..8)   wReserved1/2/3
        //   [8..24)  union (DECIMAL = 16; primitives in low 8 bytes)
        //
        // Host COM writes into WASM-allocated 24-byte buffer via the
        // wf_call pointer translation. WASM reads back via direct mem.
        // ─────────────────────────────────────────────────────────────
        public const ushort VT_EMPTY    = 0;
        public const ushort VT_NULL     = 1;
        public const ushort VT_I2       = 2;
        public const ushort VT_I4       = 3;
        public const ushort VT_R4       = 4;
        public const ushort VT_R8       = 5;
        public const ushort VT_CY       = 6;
        public const ushort VT_DATE     = 7;
        public const ushort VT_BSTR     = 8;
        public const ushort VT_DISPATCH = 9;
        public const ushort VT_ERROR    = 10;
        public const ushort VT_BOOL     = 11;
        public const ushort VT_VARIANT  = 12;
        public const ushort VT_UNKNOWN  = 13;
        public const ushort VT_DECIMAL  = 14;
        public const ushort VT_I1       = 16;
        public const ushort VT_UI1      = 17;
        public const ushort VT_UI2      = 18;
        public const ushort VT_UI4      = 19;
        public const ushort VT_I8       = 20;
        public const ushort VT_UI8      = 21;
        public const ushort VT_INT      = 22;
        public const ushort VT_UINT     = 23;
        public const ushort VT_ARRAY    = 0x2000;
        public const ushort VT_BYREF    = 0x4000;

        public const int VARIANT_SIZE = 24;

        public static IntPtr AllocVariant()
        {
            IntPtr p = Marshal.AllocHGlobal(VARIANT_SIZE);
            byte* bp = (byte*)p;
            for (int i = 0; i < VARIANT_SIZE; i++) bp[i] = 0;
            return p;
        }

        public static void FreeVariant(IntPtr pVar)
        {
            if (pVar != IntPtr.Zero) Marshal.FreeHGlobal(pVar);
        }

        [DllImport("oleaut32.dll")]
        private static extern int VariantClear(IntPtr pVar);
        public static void ClearVariant(IntPtr pVar)
        {
            if (pVar != IntPtr.Zero) VariantClear(pVar);
        }

        /// <summary>
        /// Unpack a VARIANT into a managed object. BSTRs are dereferenced
        /// via mod_hread. Returns null for VT_NULL/VT_EMPTY, "VT(0xHHHH)"
        /// for unsupported types (so consumer sees diagnostic info).
        /// </summary>
        public static object VariantToObject(IntPtr pVar)
        {
            if (pVar == IntPtr.Zero) return null;
            byte* bp = (byte*)pVar;
            ushort vt = (ushort)(bp[0] | (bp[1] << 8));
            byte* val = bp + 8;
            switch (vt)
            {
                case VT_EMPTY:
                case VT_NULL:    return null;
                case VT_I2:      return (short)(val[0] | (val[1] << 8));
                case VT_I4:
                case VT_INT:     return val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24);
                case VT_UI2:     return (ushort)(val[0] | (val[1] << 8));
                case VT_UI4:
                case VT_UINT:    return (uint)(val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24));
                case VT_I8:
                {
                    long l = 0;
                    for (int i = 0; i < 8; i++) l |= ((long)val[i]) << (i * 8);
                    return l;
                }
                case VT_UI8:
                {
                    ulong u = 0;
                    for (int i = 0; i < 8; i++) u |= ((ulong)val[i]) << (i * 8);
                    return u;
                }
                case VT_R4:
                {
                    byte[] b = new byte[4];
                    for (int i = 0; i < 4; i++) b[i] = val[i];
                    return BitConverter.ToSingle(b, 0);
                }
                case VT_R8:
                case VT_DATE:
                {
                    byte[] b = new byte[8];
                    for (int i = 0; i < 8; i++) b[i] = val[i];
                    return BitConverter.ToDouble(b, 0);
                }
                case VT_BOOL:
                {
                    short b = (short)(val[0] | (val[1] << 8));
                    return b != 0;
                }
                case VT_BSTR:
                {
                    ulong bstrHost = 0;
                    for (int i = 0; i < 8; i++) bstrHost |= ((ulong)val[i]) << (i * 8);
                    return BstrToString(bstrHost);
                }
                case VT_I1:      return (sbyte)val[0];
                case VT_UI1:     return val[0];
                default:         return $"VT(0x{vt:X4})";
            }
        }
    }
}
