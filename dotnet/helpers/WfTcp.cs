// WfTcp.cs — Pure WASM-side TCP via WasmForge's WASI socket primitives.
//
// Rationale:
//   WASI P2 sockets are stubbed (no-ops) on NativeAOT-WASI, so System.Net.Sockets
//   doesn't reach the wire. The Go bridge env import `net_tcpsendrecv` (called
//   via WfHostBridge.TcpSendRecv → NetworkHostHelper.TcpSendRecv) is the prior
//   workaround, but the round-trip through a host-side dialer makes it brittle
//   and ties Rubeus to a function the wasm-side has no other use for.
//
//   This helper instead drives WasmForge's existing WASI-style socket exports
//   (sock_open / sock_connect / sock_write / sock_read / sock_close, plus
//   sock_getaddrinfo for DNS) directly from C# via DllImport("env"). The host
//   side already implements these using Go's syscall.Socket() across all
//   platforms (internal/hostmod/tcp.go, dns.go).
//
//   Anonymized export names (internal/names/names.go):
//     sock_open        -> fd_open
//     sock_connect     -> fd_connect
//     sock_read        -> fd_read2
//     sock_write       -> fd_write2
//     sock_close       -> fd_close2
//     sock_getaddrinfo -> addr_resolve
//
// Usage (replaces Rubeus's Networking.SendBytes):
//
//   byte[] resp = WfTcp.SendRecv("kingslanding.sevenkingdoms.local", 88, asReqBytes);
//
//   The KRB framing (4-byte big-endian length prefix on send and response) is
//   built in so the call site stays a drop-in for the existing Rubeus call.

using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WasmForge.Helpers
{
    public static unsafe class WfTcp
    {
        // ── WASI errno constants (internal/hostmod/module.go) ───────────────────
        private const uint ESUCCESS    = 0;
        private const uint EAGAIN      = 6;
        private const uint EINPROGRESS = 26;
        private const uint EBADF       = 8;

        // ── Berkeley socket constants ───────────────────────────────────────────
        private const int AF_INET     = 2;
        private const int SOCK_STREAM = 1;
        private const int IPPROTO_TCP = 6;

        // ── WASI socket primitive imports ───────────────────────────────────────
        [DllImport("env", EntryPoint = "fd_open")]
        private static extern uint sock_open(int domain, int socktype, int protocol, int* fdPtr);

        [DllImport("env", EntryPoint = "fd_connect")]
        private static extern uint sock_connect(int fd, byte* addrPtr, uint addrLen);

        [DllImport("env", EntryPoint = "fd_read2")]
        private static extern uint sock_read(int fd, byte* bufPtr, uint bufLen, uint* nreadPtr);

        [DllImport("env", EntryPoint = "fd_write2")]
        private static extern uint sock_write(int fd, byte* bufPtr, uint bufLen, uint* nwrittenPtr);

        [DllImport("env", EntryPoint = "fd_close2")]
        private static extern uint sock_close(int fd);

        [DllImport("env", EntryPoint = "addr_resolve")]
        private static extern uint sock_getaddrinfo(
            byte* namePtr, uint nameLen,
            byte* svcPtr, uint svcLen,
            uint hints,
            byte* resultPtr, uint maxResults,
            uint* nPtr);

        // ── DNS resolution ──────────────────────────────────────────────────────
        // Returns IPv4 bytes (4) on success; null on failure.
        // First tries IP-literal parse to skip the DNS round-trip when not needed.
        public static byte[] ResolveIPv4(string host)
        {
            if (string.IsNullOrEmpty(host)) return null;

            if (IPAddress.TryParse(host, out var literal) &&
                literal.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return literal.GetAddressBytes();
            }

            byte[] nameBytes = Encoding.UTF8.GetBytes(host);
            // sock_getaddrinfo wire format (per internal/hostmod/dns.go):
            //   per-entry: [family:u16 LE][socktype:u16 LE][protocol:u16 LE][addrlen:u16 LE][addr:N]
            //   IPv4 entry total = 8 (header) + 8 (addr+padding to addrSizeIPv4) = 16 bytes
            byte[] resultBuf = new byte[4 * 32];
            uint nResults = 0;
            uint err;
            fixed (byte* np = nameBytes, rp = resultBuf)
            {
                err = sock_getaddrinfo(
                    np, (uint)nameBytes.Length,
                    null, 0,
                    0u,
                    rp, 4u,
                    &nResults);
            }
            if (err != ESUCCESS || nResults == 0) return null;

            // Walk entries to find the first IPv4. Per dns.go:
            //   header[0:8]: [family LE u16][socktype LE u16][protocol LE u16][addrlen LE u16]
            //   body[8:8+addrlen]: inner sockaddr_in = [family LE u16][port BE u16][addr 4]
            // For IPv4 addrlen=8; the actual addr bytes are at off+8+4 = off+12.
            int off = 0;
            for (uint i = 0; i < nResults && off + 8 <= resultBuf.Length; i++)
            {
                ushort family = (ushort)(resultBuf[off + 0] | (resultBuf[off + 1] << 8));
                ushort alen   = (ushort)(resultBuf[off + 6] | (resultBuf[off + 7] << 8));
                int entryEnd = off + 8 + (alen == 0 ? 8 : alen);
                if (family == AF_INET && alen >= 8 && entryEnd <= resultBuf.Length)
                {
                    var ip = new byte[4];
                    Array.Copy(resultBuf, off + 12, ip, 0, 4);
                    return ip;
                }
                off = entryEnd;
            }
            return null;
        }

        // ── Single TCP send+recv round-trip with KRB-style 4-byte framing ───────
        // Equivalent to Rubeus's Networking.SendBytes(host, port, data).
        // Returns the response PDU (without the 4-byte length prefix), or null on
        // any failure.
        public static byte[] SendRecv(string host, int port, byte[] data)
        {
            if (string.IsNullOrEmpty(host) || data == null) return null;

            byte[] ip = ResolveIPv4(host);
            if (ip == null) return null;

            int fd = -1;
            uint err;

            err = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, &fd);
            if (err != ESUCCESS || fd < 0) return null;

            try
            {
                // sockaddr_in wire format (internal/hostmod/addr.go):
                //   [family:u16 LE][port:u16 BE][addr:4 bytes] = 8 bytes total
                byte[] addr = new byte[8];
                addr[0] = (byte)(AF_INET & 0xff);
                addr[1] = (byte)((AF_INET >> 8) & 0xff);
                addr[2] = (byte)((port >> 8) & 0xff);
                addr[3] = (byte)(port & 0xff);
                addr[4] = ip[0]; addr[5] = ip[1]; addr[6] = ip[2]; addr[7] = ip[3];

                fixed (byte* ap = addr)
                {
                    err = sock_connect(fd, ap, (uint)addr.Length);
                }
                // EINPROGRESS on Unix indicates non-blocking connect in flight; the
                // host's sock_connect already blocks on Windows via select(), so any
                // non-fatal status here is fine. EAGAIN returns from the same path.
                if (err != ESUCCESS && err != EINPROGRESS && err != EAGAIN) return null;

                // Build framed payload: 4-byte big-endian length prefix.
                byte[] framed = new byte[4 + data.Length];
                framed[0] = (byte)((data.Length >> 24) & 0xff);
                framed[1] = (byte)((data.Length >> 16) & 0xff);
                framed[2] = (byte)((data.Length >> 8) & 0xff);
                framed[3] = (byte)(data.Length & 0xff);
                Buffer.BlockCopy(data, 0, framed, 4, data.Length);

                // Write the framed payload, retrying on EAGAIN.
                int totalWritten = 0;
                int writeTries = 0;
                while (totalWritten < framed.Length && writeTries < 200)
                {
                    uint nw = 0;
                    fixed (byte* fp = framed)
                    {
                        err = sock_write(fd, fp + totalWritten, (uint)(framed.Length - totalWritten), &nw);
                    }
                    if (err == ESUCCESS)
                    {
                        totalWritten += (int)nw;
                        if (nw == 0) { Thread.Sleep(10); writeTries++; }
                    }
                    else if (err == EAGAIN)
                    {
                        Thread.Sleep(10);
                        writeTries++;
                    }
                    else
                    {
                        return null;
                    }
                }
                if (totalWritten < framed.Length) return null;

                // Read 4-byte response length prefix.
                byte[] lenBuf = new byte[4];
                if (!ReadExact(fd, lenBuf, lenBuf.Length)) return null;

                int respLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                if (respLen <= 0 || respLen > 65536 * 16) return null;

                byte[] resp = new byte[respLen];
                if (!ReadExact(fd, resp, respLen)) return null;
                return resp;
            }
            finally
            {
                sock_close(fd);
            }
        }

        // ReadExact retries sock_read until `count` bytes are filled or repeated
        // EAGAIN / zero-read indicates EOF or stall.
        private static bool ReadExact(int fd, byte[] dst, int count)
        {
            int got = 0;
            int idleTries = 0;
            while (got < count)
            {
                uint nr = 0;
                uint err;
                fixed (byte* dp = dst)
                {
                    err = sock_read(fd, dp + got, (uint)(count - got), &nr);
                }
                if (err == ESUCCESS)
                {
                    if (nr == 0)
                    {
                        // Zero-byte successful read = EOF or no data yet under non-blocking.
                        idleTries++;
                        if (idleTries > 200) return false;
                        Thread.Sleep(10);
                        continue;
                    }
                    got += (int)nr;
                    idleTries = 0;
                }
                else if (err == EAGAIN)
                {
                    idleTries++;
                    if (idleTries > 200) return false;
                    Thread.Sleep(10);
                }
                else
                {
                    return false;
                }
            }
            return true;
        }
    }
}
