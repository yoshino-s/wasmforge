// CERTCLILib stub for NativeAOT-WASI compilation.
// Provides type surface for Certify (GhostPack) to compile to WASM.
// All COM-backed methods throw PlatformNotSupportedException at runtime —
// certificate request submission operations are non-functional until real
// COM host functions are implemented.

using System;

namespace CERTCLILib
{
    public class CCertRequest
    {
        public const int CR_IN_FORMATANY = 0;
        public const int CR_OUT_CHAIN = 0x100;
        public const int CR_DISP_ISSUED = 3;
        public const int CR_DISP_UNDER_SUBMISSION = 5;
        public const int CR_DISP_DENIED = 2;
        public const int CR_DISP_INCOMPLETE = 0;
        public const int CR_DISP_ERROR = 6;
        public const int CR_PROP_TEMPLATES = 0x1d;
        public const int CR_PROP_CATYPE = 0xa;

        public int Submit(
            int dwFlags,
            string strRequest,
            string strAttributes,
            string strConfig)
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public string GetDispositionMessage()
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public object GetFullResponseProperty(int propId, int propIndex, int propType)
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public string GetCertificate(int dwFlags)
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public int GetLastStatus()
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public int GetRequestId()
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }

        public int RetrievePending(int requestId, string strConfig)
        {
            throw new PlatformNotSupportedException("COM certificate request submission not available in NativeAOT-WASI");
        }
    }
}
