// WfHost.cs — Safe host-memory dereference helpers for NativeAOT-WASI.
//
// Wraps the WasmForge host-memory primitives exposed by
// internal/hostmod/win32_windows_memory.go and registered under the
// anonymized names "mod_hread" (read arbitrary host memory),
// "mem_alloc"/"mem_free" (VirtualAlloc/VirtualFree), "mem_write"/"mem_read"
// (copy bytes), "mem_write32"/"mem_write64" (scalar writes), and
// "mem_addr" (resolve handle → real host address).
//
// Two use cases:
//   1. ReadHostBytes / ReadHostUInt32 — read arbitrary host-process
//      memory via mod_hread (used by mirrored COM pointer chains).
//   2. HostAlloc / HostWrite / HostRead / GetHostAddress / HostFree —
//      allocate a contiguous host-side buffer that the caller can
//      pass as a real host pointer to wf_call (so the host's
//      ptr-translation skips it — see internal/hostmod/
//      win32_windows_dll.go's `wasmVal >= wasmMemSize` short-circuit).
//      Used by WfSspi to build SecBufferDesc + SecBuffer[] arrays in
//      host memory so that secur32!InitializeSecurityContextW
//      receives a valid nested struct chain.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfHost
    {
        // ── Read arbitrary host memory (pre-existing) ──

        [DllImport("env", EntryPoint = "mod_hread")]
        internal static extern uint NativeReadBytes(ulong hostAddr, uint len, void* outBuf);

        public static uint ReadHostUInt32(ulong hostAddr, uint offsetBytes)
        {
            uint value = 0;
            uint rc = NativeReadBytes(hostAddr + offsetBytes, 4, &value);
            if (rc != 0) throw new AccessViolationException(
                $"wf_host_read_bytes failed: errno {rc}");
            return value;
        }

        public static byte[] ReadHostBytes(ulong hostAddr, uint len)
        {
            if (len == 0) return Array.Empty<byte>();
            byte[] buf = new byte[len];
            fixed (byte* p = buf)
            {
                uint rc = NativeReadBytes(hostAddr, len, p);
                if (rc != 0) throw new AccessViolationException(
                    $"wf_host_read_bytes failed: errno {rc}");
            }
            return buf;
        }

        // ── Host-side allocation (for nested-pointer Win32 chains) ──

        // win32_virtual_alloc: size, alloc_type, protect, handle_ptr → errno
        [DllImport("env", EntryPoint = "mem_alloc")]
        private static extern uint NativeMemAlloc(uint size, uint allocType, uint protect, uint handlePtr);

        // win32_virtual_free: handle → errno
        [DllImport("env", EntryPoint = "mem_free")]
        private static extern uint NativeMemFree(int handle);

        // win32_hmem_write: handle, offset, data_ptr, data_len → errno
        [DllImport("env", EntryPoint = "mem_write")]
        private static extern uint NativeMemWrite(int handle, uint offset, void* dataPtr, uint dataLen);

        // win32_hmem_read: handle, offset, buf_ptr, buf_len → errno
        [DllImport("env", EntryPoint = "mem_read")]
        private static extern uint NativeMemRead(int handle, uint offset, void* bufPtr, uint bufLen);

        // win32_hmem_write32: handle, offset, value → errno
        [DllImport("env", EntryPoint = "mem_write32")]
        private static extern uint NativeMemWrite32(int handle, uint offset, uint value);

        // win32_hmem_write64: handle, offset, value_ptr → errno
        // (value is passed by pointer because i64 args under wasm32 are awkward)
        [DllImport("env", EntryPoint = "mem_write64")]
        private static extern uint NativeMemWrite64(int handle, uint offset, uint valuePtr);

        // win32_hmem_addr: handle, addr_ptr → errno (host addr written to addr_ptr as i64)
        [DllImport("env", EntryPoint = "mem_addr")]
        private static extern uint NativeMemAddr(int handle, uint addrPtr);

        private const uint MEM_COMMIT_RESERVE = 0x3000;
        private const uint PAGE_READWRITE     = 0x4;

        /// <summary>
        /// HostAlloc — allocate a host-side buffer of `size` bytes and
        /// return an opaque handle (NOT a host address). Use
        /// GetHostAddress to retrieve the actual host pointer for
        /// passing to wf_call.
        /// </summary>
        public static int HostAlloc(int size)
        {
            int handle = 0;
            // Local variables are stable on the stack — no `fixed` block
            // needed, just &handle directly.
            int* hp = &handle;
            uint rc = NativeMemAlloc((uint)size, MEM_COMMIT_RESERVE, PAGE_READWRITE,
                (uint)(IntPtr)hp);
            if (rc != 0 || handle == 0)
                throw new InvalidOperationException(
                    $"WfHost.HostAlloc({size}) failed: errno {rc}");
            return handle;
        }

        /// <summary>HostFree — release a previously-allocated host buffer.</summary>
        public static void HostFree(int handle)
        {
            if (handle == 0) return;
            NativeMemFree(handle);
        }

        /// <summary>HostWrite — copy `data` bytes into a host buffer at `offset`.</summary>
        public static void HostWrite(int handle, uint offset, byte[] data)
        {
            if (data == null || data.Length == 0) return;
            fixed (byte* p = data)
            {
                uint rc = NativeMemWrite(handle, offset, p, (uint)data.Length);
                if (rc != 0)
                    throw new InvalidOperationException(
                        $"WfHost.HostWrite(handle={handle}, off={offset}, len={data.Length}) failed: errno {rc}");
            }
        }

        /// <summary>HostWriteUInt32 — write a 4-byte uint at `offset`.</summary>
        public static void HostWriteUInt32(int handle, uint offset, uint value)
        {
            uint rc = NativeMemWrite32(handle, offset, value);
            if (rc != 0)
                throw new InvalidOperationException(
                    $"WfHost.HostWriteUInt32 failed: errno {rc}");
        }

        /// <summary>
        /// HostWriteUInt64 — write an 8-byte ulong at `offset`.
        /// Used to write host pointers (e.g. SecBufferDesc.pBuffers).
        /// </summary>
        public static void HostWriteUInt64(int handle, uint offset, ulong value)
        {
            ulong v = value;
            uint rc = NativeMemWrite64(handle, offset, (uint)(IntPtr)(&v));
            if (rc != 0)
                throw new InvalidOperationException(
                    $"WfHost.HostWriteUInt64 failed: errno {rc}");
        }

        /// <summary>HostRead — copy `length` bytes from a host buffer at `offset` into a managed byte[].</summary>
        public static byte[] HostRead(int handle, uint offset, int length)
        {
            if (length <= 0) return Array.Empty<byte>();
            byte[] buf = new byte[length];
            fixed (byte* p = buf)
            {
                uint rc = NativeMemRead(handle, offset, p, (uint)length);
                if (rc != 0)
                    throw new InvalidOperationException(
                        $"WfHost.HostRead(handle={handle}, off={offset}, len={length}) failed: errno {rc}");
            }
            return buf;
        }

        /// <summary>
        /// GetHostAddress — return the real host-process address of a buffer
        /// previously allocated via HostAlloc. Pass this value directly to
        /// wf_call as an argument; the host-side pointer-translation skips
        /// values >= wasmMemSize so a real host pointer passes through
        /// unmodified.
        /// </summary>
        public static ulong GetHostAddress(int handle)
        {
            ulong addr = 0;
            ulong* ap = &addr;
            uint rc = NativeMemAddr(handle, (uint)(IntPtr)ap);
            if (rc != 0)
                throw new InvalidOperationException(
                    $"WfHost.GetHostAddress(handle={handle}) failed: errno {rc}");
            return addr;
        }
    }
}
