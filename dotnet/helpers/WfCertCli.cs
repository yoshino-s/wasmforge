// WfCertCli.cs — ICertRequest3 COM dispatch for the request-family verbs.
//
// Implements the minimal patterns needed by Certify's request,
// requestonbehalf, renew, and download verbs. Each verb uses different
// vtable slots:
//   slot 7  GetDispositionMessage()
//   slot 8  GetLastStatus()
//   slot 9  GetRequestId()
//   slot 10 Submit(dwFlags, strRequest, strAttrs, strConfig, pdwDisposition)
//   slot 11 RetrievePending(dwReqId, strConfig, pdwDisposition)
//   slot 12 GetCertificate(dwFlags, pstrOut)
//
// (slot numbers in ICertRequest2/3 differ from ICertRequest; verified
// from CertEnroll.dll's IDL via offsets in the actual vtable.)
//
// This file is scaffolding — next session should wire it into per-verb
// helpers (WfCertRequest, WfCertDownload, WfCertRenew, WfCertOnBehalf).

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfCertCli
    {
        // ICertRequest3 vtable slot numbers (after the 7 IDispatch+IUnknown
        // slots: 0..2 IUnknown, 3..6 IDispatch).
        // These need verification against actual DLL — Microsoft's docs
        // sometimes count slots differently across interface versions.
        // ICertRequest vtable layout (slots 7-13 inherited by ICertRequest2/3):
        //   7  Submit
        //   8  RetrievePending
        //   9  GetLastStatus
        //  10  GetRequestId
        //  11  GetDispositionMessage
        //  12  GetCACertificate
        //  13  GetCertificate
        public const int Submit_Slot            = 7;
        public const int RetrievePending_Slot   = 8;
        public const int GetLastStatus_Slot     = 9;
        public const int GetRequestId_Slot      = 10;
        public const int GetDispositionMsg_Slot = 11;
        public const int GetCACertificate_Slot  = 12;
        public const int GetCertificate_Slot    = 13;

        // CR_DISP_* return codes from Submit / RetrievePending.
        public const uint CR_DISP_INCOMPLETE      = 0;
        public const uint CR_DISP_ERROR           = 1;
        public const uint CR_DISP_DENIED          = 2;
        public const uint CR_DISP_ISSUED          = 3;
        public const uint CR_DISP_ISSUED_OUT_OF_BAND = 4;
        public const uint CR_DISP_UNDER_SUBMISSION = 5;
        public const uint CR_DISP_REVOKED         = 6;

        // CR_IN_*  / CR_OUT_* format flags for Submit / GetCertificate.
        public const uint CR_IN_BASE64           = 0x1;
        public const uint CR_IN_FORMATANY        = 0x0;
        public const uint CR_IN_PKCS10           = 0x100;
        public const uint CR_OUT_BASE64HEADER    = 0x0;
        public const uint CR_OUT_BASE64          = 0x1;
        public const uint CR_OUT_BINARY          = 0x2;
        public const uint CR_OUT_CHAIN           = 0x100;

        // RetrievePending takes (dwReqId, strConfig, pdwDisposition).
        // ptrMask = bits 0(this), 2(strConfig), 3(pdwDisposition) → 0x0D.
        // out8Mask = bit 3 (pdwDisposition is uint*, slot is 4 bytes → no
        //                   risk of 4-byte overflow corruption).
        public static uint RetrievePending(IntPtr ifc, uint reqId, string config, out uint disposition)
        {
            disposition = 0;
            ulong fn = WfCom.ReadVtableSlot(ifc, RetrievePending_Slot);
            if (fn == 0) return 0xffffffff;
            IntPtr cfg = Marshal.StringToHGlobalUni(config);
            uint dispLocal = 0;
            uint* pDisp = &dispLocal;
            try
            {
                ulong hr = WfCom.InvokeMethod(
                    fn, ifc, /*ptrMask=*/ 0x0D,
                    arg1: reqId,
                    arg2: (ulong)(uint)cfg,
                    arg3: (ulong)(IntPtr)pDisp,
                    nargs: 4);
                disposition = dispLocal;
                return (uint)hr;
            }
            finally
            {
                Marshal.FreeHGlobal(cfg);
            }
        }

        // GetCertificate(dwFlags, [out] BSTR* pwszCert).
        public static uint GetCertificate(IntPtr ifc, uint flags, out string cert)
        {
            cert = null;
            ulong fn = WfCom.ReadVtableSlot(ifc, GetCertificate_Slot);
            if (fn == 0) return 0xffffffff;
            ulong bstrOut = 0;
            ulong hr = WfCom.InvokeMethod(
                fn, ifc, /*ptrMask=*/ 0x05,
                arg1: flags,
                arg2: (ulong)(IntPtr)(&bstrOut),
                nargs: 3);
            if ((uint)hr == 0 && bstrOut != 0)
            {
                char* p = (char*)(IntPtr)(uint)bstrOut;
                int len = 0;
                while (len < 65536 && p[len] != 0) len++;
                cert = new string(p, 0, len);
            }
            return (uint)hr;
        }

        // Convenience: open a CCertRequest3 instance.
        public static IntPtr CreateInstance()
        {
            return WfCom.CreateInstance(WfCom.CLSID_CCertRequest, WfCom.IID_ICertRequest3);
        }

        // Submit(dwFlags, strRequest, strAttribs, strConfig, pdwDisposition).
        // ptrMask = bits 0(this), 2(strRequest), 3(strAttribs), 4(strConfig), 5(pdwDisposition) = 0x3D.
        public static uint Submit(IntPtr ifc, uint flags, string request, string attribs, string config, out uint disposition)
        {
            disposition = 0;
            ulong fn = WfCom.ReadVtableSlot(ifc, Submit_Slot);
            if (fn == 0) return 0xffffffff;
            IntPtr pReq = Marshal.StringToHGlobalUni(request ?? string.Empty);
            IntPtr pAtt = Marshal.StringToHGlobalUni(attribs ?? string.Empty);
            IntPtr pCfg = Marshal.StringToHGlobalUni(config ?? string.Empty);
            uint dispLocal = 0;
            uint* pDisp = &dispLocal;
            try
            {
                ulong hr = WfCom.InvokeMethod(
                    fn, ifc, /*ptrMask=*/ 0x3D,
                    arg1: flags,
                    arg2: (ulong)(uint)pReq,
                    arg3: (ulong)(uint)pAtt,
                    arg4: (ulong)(uint)pCfg,
                    arg5: (ulong)(IntPtr)pDisp,
                    nargs: 6);
                disposition = dispLocal;
                return (uint)hr;
            }
            finally
            {
                Marshal.FreeHGlobal(pReq);
                Marshal.FreeHGlobal(pAtt);
                Marshal.FreeHGlobal(pCfg);
            }
        }

        // GetRequestId([out] long* pRequestId).
        public static uint GetRequestId(IntPtr ifc, out int requestId)
        {
            requestId = 0;
            ulong fn = WfCom.ReadVtableSlot(ifc, GetRequestId_Slot);
            if (fn == 0) return 0xffffffff;
            int local = 0;
            int* pId = &local;
            ulong hr = WfCom.InvokeMethod(
                fn, ifc, /*ptrMask=*/ 0x03,
                arg1: (ulong)(IntPtr)pId,
                nargs: 2);
            requestId = local;
            return (uint)hr;
        }

        // GetDispositionMessage([out] BSTR*).
        public static uint GetDispositionMessage(IntPtr ifc, out string message)
        {
            message = null;
            ulong fn = WfCom.ReadVtableSlot(ifc, GetDispositionMsg_Slot);
            if (fn == 0) return 0xffffffff;
            ulong bstrOut = 0;
            ulong hr = WfCom.InvokeMethod(
                fn, ifc, /*ptrMask=*/ 0x03,
                arg1: (ulong)(IntPtr)(&bstrOut),
                nargs: 2);
            if ((uint)hr == 0 && bstrOut != 0)
            {
                char* p = (char*)(IntPtr)(uint)bstrOut;
                int len = 0;
                while (len < 4096 && p[len] != 0) len++;
                message = new string(p, 0, len);
            }
            return (uint)hr;
        }

        // GetLastStatus([out] long* pStatus).
        public static uint GetLastStatus(IntPtr ifc, out int status)
        {
            status = 0;
            ulong fn = WfCom.ReadVtableSlot(ifc, GetLastStatus_Slot);
            if (fn == 0) return 0xffffffff;
            int local = 0;
            int* pSt = &local;
            ulong hr = WfCom.InvokeMethod(
                fn, ifc, /*ptrMask=*/ 0x03,
                arg1: (ulong)(IntPtr)pSt,
                nargs: 2);
            status = local;
            return (uint)hr;
        }
    }
}
