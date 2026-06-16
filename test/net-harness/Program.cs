using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NetTest
{
    internal static unsafe class Bridge
    {
        [DllImport("*", EntryPoint = "WfGetDCName")]
        internal static extern uint WfGetDCName(
            byte* domainPtr, uint domainLen,
            uint flags,
            byte* outBufPtr, uint outBufLen);

        [DllImport("*", EntryPoint = "WfTcpSendRecv")]
        internal static extern uint WfTcpSendRecv(
            byte* hostPtr, uint hostLen,
            uint port,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);
    }

    // L3: WASI socket primitives exposed by hostmod under anonymized names.
    // Module "env" anonymized export names from internal/names/names.go:
    //   sock_open        -> fd_open
    //   sock_connect     -> fd_connect
    //   sock_read        -> fd_read2
    //   sock_write       -> fd_write2
    //   sock_close       -> fd_close2
    //   sock_getaddrinfo -> addr_resolve
    internal static unsafe class Sock
    {
        // sock_open(domain, socktype, protocol, fd_ptr) -> errno
        [DllImport("env", EntryPoint = "fd_open")]
        internal static extern uint Open(int domain, int socktype, int protocol, int* fdPtr);

        // sock_connect(fd, addr_ptr, addr_len) -> errno (0 = ok, 6 = EINPROGRESS)
        [DllImport("env", EntryPoint = "fd_connect")]
        internal static extern uint Connect(int fd, byte* addrPtr, uint addrLen);

        // sock_read(fd, buf_ptr, buf_len, nread_ptr) -> errno
        [DllImport("env", EntryPoint = "fd_read2")]
        internal static extern uint Read(int fd, byte* bufPtr, uint bufLen, uint* nreadPtr);

        // sock_write(fd, buf_ptr, buf_len, nwritten_ptr) -> errno
        [DllImport("env", EntryPoint = "fd_write2")]
        internal static extern uint Write(int fd, byte* bufPtr, uint bufLen, uint* nwrittenPtr);

        // sock_close(fd) -> errno
        [DllImport("env", EntryPoint = "fd_close2")]
        internal static extern uint Close(int fd);

        // sock_getaddrinfo(name_ptr, name_len, svc_ptr, svc_len, hints, result_ptr, max_results, n_ptr) -> errno
        // Each result: [family u16 LE][socktype u16 LE][protocol u16 LE][addrlen u16 LE][addr N bytes]
        [DllImport("env", EntryPoint = "addr_resolve")]
        internal static extern uint GetAddrInfo(
            byte* namePtr, uint nameLen,
            byte* svcPtr, uint svcLen,
            uint hints,
            byte* resultPtr, uint maxResults,
            uint* nPtr);

        public const int AF_INET     = 2;
        public const int SOCK_STREAM = 1;
        public const int IPPROTO_TCP = 6;

        // EINPROGRESS in WASI errno space (per hostmod/module.go: errnoEINPROGRESS = 26)
        public const uint EINPROGRESS = 26;
        public const uint EAGAIN      = 6;
    }

    internal static class Program
    {
        static int L1_WfGetDCName(string domain)
        {
            Console.WriteLine();
            Console.WriteLine("[L1 WfGetDCName] domain=" + domain);
            byte[] domainBytes = Encoding.UTF8.GetBytes(domain);
            byte[] outBuf = new byte[1024];
            uint written;
            unsafe
            {
                fixed (byte* dp = domainBytes, op = outBuf)
                {
                    written = Bridge.WfGetDCName(
                        dp, (uint)domainBytes.Length,
                        0u,
                        op, (uint)outBuf.Length);
                }
            }
            Console.WriteLine("  written: " + written);
            if (written == 0) { Console.WriteLine("  -> EMPTY"); return 1; }
            string result = Encoding.UTF8.GetString(outBuf, 0, (int)written);
            Console.WriteLine("  result: " + result.Trim());
            return 0;
        }

        static int L2_WfTcpSendRecv(string host, int port)
        {
            Console.WriteLine();
            Console.WriteLine("[L2 WfTcpSendRecv] host=" + host + " port=" + port);
            byte[] payload = Encoding.ASCII.GetBytes("PING");
            byte[] hostBytes = Encoding.UTF8.GetBytes(host);
            byte[] outBuf = new byte[8192];
            uint written;
            unsafe
            {
                fixed (byte* hp = hostBytes, dp = payload, op = outBuf)
                {
                    written = Bridge.WfTcpSendRecv(
                        hp, (uint)hostBytes.Length,
                        (uint)port,
                        dp, (uint)payload.Length,
                        op, (uint)outBuf.Length);
                }
            }
            Console.WriteLine("  written: " + written + " bytes");
            if (written == 0) { Console.WriteLine("  -> EMPTY"); return 1; }
            int n = Math.Min((int)written, 32);
            var sb = new StringBuilder();
            for (int i = 0; i < n; i++) sb.Append(outBuf[i].ToString("x2") + " ");
            Console.WriteLine("  first " + n + " bytes: " + sb.ToString().Trim());
            return 0;
        }

        // L3a: addr_resolve a hostname, write parsed IPv4 to ipOut[0..4], port (BE u16) to portBuf[0..2].
        static unsafe bool L3a_Resolve(string host, int port, byte[] ipOut, byte[] portBuf)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(host);
            byte[] svcBytes = Encoding.UTF8.GetBytes(port.ToString());
            // Each result entry = 8 (header) + 8 (IPv4 family pad) bytes. Reserve room for 4 entries.
            byte[] resultBuf = new byte[4 * 32];
            uint nResults;
            uint err;
            fixed (byte* np = nameBytes, sp = svcBytes, rp = resultBuf)
            {
                err = Sock.GetAddrInfo(
                    np, (uint)nameBytes.Length,
                    sp, (uint)svcBytes.Length,
                    0u,
                    rp, 4u,
                    &nResults);
            }
            Console.WriteLine("  addr_resolve err=" + err + " nResults=" + nResults);
            if (err != 0 || nResults == 0) return false;
            // First entry layout per internal/hostmod/dns.go:
            //   [0:8]  header = [family LE u16][socktype LE u16][protocol LE u16][addrlen LE u16]
            //   [8:16] inner sockaddr_in (addrlen=8) = [family LE u16][port BE u16][addr 4]
            ushort family = (ushort)(resultBuf[0] | (resultBuf[1] << 8));
            ushort alen   = (ushort)(resultBuf[6] | (resultBuf[7] << 8));
            Console.WriteLine("  first entry: family=" + family + " addrlen=" + alen);
            if (family != Sock.AF_INET || alen < 8) return false;
            // IPv4 addr bytes start at offset 12 (skip 8-byte header + 4-byte inner family+port).
            Array.Copy(resultBuf, 12, ipOut, 0, 4);
            // Port (BE u16)
            portBuf[0] = (byte)((port >> 8) & 0xff);
            portBuf[1] = (byte)(port & 0xff);
            Console.WriteLine("  resolved IPv4: " + ipOut[0] + "." + ipOut[1] + "." + ipOut[2] + "." + ipOut[3]);
            return true;
        }

        // L3b: full sock_* pipeline against the DC's Kerberos port (88).
        static unsafe int L3_SockPrimitives(string host, int port)
        {
            Console.WriteLine();
            Console.WriteLine("[L3 sock_* primitives] host=" + host + " port=" + port);

            byte[] ip = new byte[4];
            byte[] portBE = new byte[2];

            // If host is an IPv4 literal, parse directly. Otherwise resolve via addr_resolve.
            if (System.Net.IPAddress.TryParse(host, out var parsed) &&
                parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                Array.Copy(parsed.GetAddressBytes(), 0, ip, 0, 4);
                portBE[0] = (byte)((port >> 8) & 0xff);
                portBE[1] = (byte)(port & 0xff);
                Console.WriteLine("  literal IPv4: " + ip[0] + "." + ip[1] + "." + ip[2] + "." + ip[3]);
            }
            else if (!L3a_Resolve(host, port, ip, portBE))
            {
                Console.WriteLine("  -> RESOLVE FAILED");
                return 1;
            }

            // sock_open
            int fd;
            uint err;
            err = Sock.Open(Sock.AF_INET, Sock.SOCK_STREAM, Sock.IPPROTO_TCP, &fd);
            Console.WriteLine("  sock_open err=" + err + " fd=" + fd);
            if (err != 0) { Console.WriteLine("  -> OPEN FAILED"); return 1; }

            try
            {
                // Build sockaddr_in: [family u16 LE][port u16 BE][addr 4 bytes] = 8 bytes
                byte[] addr = new byte[8];
                addr[0] = (byte)(Sock.AF_INET & 0xff);
                addr[1] = (byte)((Sock.AF_INET >> 8) & 0xff);
                addr[2] = portBE[0];
                addr[3] = portBE[1];
                addr[4] = ip[0]; addr[5] = ip[1]; addr[6] = ip[2]; addr[7] = ip[3];

                fixed (byte* ap = addr)
                {
                    err = Sock.Connect(fd, ap, (uint)addr.Length);
                }
                Console.WriteLine("  sock_connect err=" + err);
                // EINPROGRESS (26) is success-with-poll. EAGAIN (6) can also indicate non-blocking connect.
                if (err != 0 && err != Sock.EINPROGRESS && err != Sock.EAGAIN)
                {
                    Console.WriteLine("  -> CONNECT FAILED");
                    return 1;
                }

                // For non-blocking sockets, poll write-readiness via short busy-wait.
                // The host's sock_connect already calls waitConnectComplete on Windows so this is
                // belt-and-suspenders.
                System.Threading.Thread.Sleep(50);

                // Build a minimal KRB AS-REQ-ish probe: 4-byte length prefix + dummy payload.
                // We only care whether the host writes bytes back (RST/response/anything > 0).
                byte[] probe = new byte[] { 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef };
                uint nWritten;
                fixed (byte* pp = probe)
                {
                    err = Sock.Write(fd, pp, (uint)probe.Length, &nWritten);
                }
                Console.WriteLine("  sock_write err=" + err + " nWritten=" + nWritten);
                if (err != 0) { Console.WriteLine("  -> WRITE FAILED"); return 1; }

                // Read response (best-effort; KDC will probably send a KRB-ERROR back). Retry on EAGAIN.
                byte[] resp = new byte[8192];
                uint nRead = 0;
                int tries = 0;
                while (tries < 20)
                {
                    fixed (byte* rp = resp)
                    {
                        err = Sock.Read(fd, rp, (uint)resp.Length, &nRead);
                    }
                    if (err == 0 && nRead > 0) break;
                    if (err == Sock.EAGAIN || err == 0) { System.Threading.Thread.Sleep(50); tries++; continue; }
                    Console.WriteLine("  sock_read err=" + err);
                    break;
                }
                Console.WriteLine("  sock_read final err=" + err + " nRead=" + nRead);
                if (nRead == 0)
                {
                    Console.WriteLine("  -> NO RESPONSE BYTES");
                    return 1;
                }

                int n = (int)Math.Min(nRead, 32u);
                var sb = new StringBuilder();
                for (int i = 0; i < n; i++) sb.Append(resp[i].ToString("x2") + " ");
                Console.WriteLine("  first " + n + " bytes: " + sb.ToString().Trim());
                return 0;
            }
            finally
            {
                Sock.Close(fd);
            }
        }

        static int Main()
        {
            Console.WriteLine("=== Net Bridge Triage (WfHostBridge + sock_* chains) ===");
            int failures = 0;

            var _parityDomain = Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DOMAIN") ?? "example.local";
            var _parityDC     = Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DC") ?? "dc01.example.local";
            var _parityDCIP   = Environment.GetEnvironmentVariable("WASMFORGE_PARITY_DC_IP") ?? "192.0.2.10";
            failures += L1_WfGetDCName(_parityDomain);
            failures += L2_WfTcpSendRecv(_parityDomain, 88);
            failures += L2_WfTcpSendRecv(_parityDCIP, 88);

            // L3 sock_* primitive layer
            failures += L3_SockPrimitives(_parityDCIP, 88);
            failures += L3_SockPrimitives(_parityDC, 88);

            Console.WriteLine();
            Console.WriteLine(failures == 0 ? "=== ALL PASS ===" : "=== " + failures + " FAILED ===");
            return failures;
        }
    }
}
