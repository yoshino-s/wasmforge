// WfSocket.cs — Raw TCP socket via ws2_32.dll through mod_invoke.
//
// Provides a minimal WfSocket class with Connect/Send/Recv/Close that
// calls Winsock2 APIs directly via the mod_load / mod_resolve / mod_invoke
// bridge, matching the canonical pattern in WfNetapi.cs.
//
// Usage:
//   using (var sock = new WfSocket())
//   {
//       if (sock.Connect("kingslanding.sevenkingdoms.local", 88))
//       {
//           sock.Send(krbAsReqBytes);
//           byte[] response = new byte[65536];
//           int n = sock.Recv(response);
//       }
//   }
//
// Note: WSAStartup is called lazily once (static initializer guard).
// Each WfSocket instance creates one SOCKET handle via socket(AF_INET, SOCK_STREAM, IPPROTO_TCP).
//
// For Rubeus kerberos verbs (asktgt / kerberoast / asreproast):
//   Replace Networking.SendBytes(host, port, data) with WfSocket-backed wrapper.
//   Patcher rule rewrites "Networking.SendBytes(" → "WfSocket.SendRecv(" in Ask.cs.

using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public unsafe class WfSocket : IDisposable
    {
        // ── SOCKET constants ─────────────────────────────────────────────────────
        private const int AF_INET        = 2;
        private const int SOCK_STREAM    = 1;
        private const int IPPROTO_TCP    = 6;
        private const ulong INVALID_SOCKET = unchecked((ulong)(long)-1); // 0xFFFFFFFFFFFFFFFF

        // ── mod_load / mod_resolve / mod_invoke DllImports ──────────────────────
        [DllImport("env", EntryPoint = "mod_load")]
        private static extern uint mod_load(uint namePtr);

        [DllImport("env", EntryPoint = "mod_resolve")]
        private static extern uint mod_resolve(uint libHandle, uint namePtr);

        [DllImport("env", EntryPoint = "mod_invoke")]
        private static extern ulong mod_invoke(
            ulong procHandle, uint nargs,
            ulong a0, ulong a1, ulong a2, ulong a3,
            ulong a4, ulong a5, ulong a6, ulong a7,
            ulong a8, ulong a9, ulong a10, ulong a11,
            ulong a12, ulong a13, ulong a14,
            ulong ret1Ptr, ulong errPtr);

        // ── Per-proc handle cache ────────────────────────────────────────────────
        private static uint _ws2_32;
        private static uint _ntdll;
        private static uint _hRtlMoveMemory;
        private static uint _hWSAStartup;
        private static uint _hSocket;
        private static uint _hGethostbyname;
        private static uint _hHtons;
        private static uint _hConnect;
        private static uint _hSend;
        private static uint _hRecv;
        private static uint _hClosesocket;
        private static uint _hWSAGetLastError;

        // ── WSAStartup guard ─────────────────────────────────────────────────────
        private static bool _wsaInitialized;

        // ── This instance's SOCKET handle ────────────────────────────────────────
        private ulong _socket = INVALID_SOCKET;

        // ── Resolve helper ───────────────────────────────────────────────────────
        private static uint Resolve(string dll, ref uint cachedLib, string fn, ref uint cachedProc)
        {
            if (cachedProc != 0) return cachedProc;
            if (cachedLib == 0)
            {
                byte[] db = Encoding.ASCII.GetBytes(dll + "\0");
                fixed (byte* dp = db) cachedLib = mod_load((uint)(IntPtr)dp);
                if (cachedLib == 0) return 0;
            }
            byte[] fb = Encoding.ASCII.GetBytes(fn + "\0");
            fixed (byte* fp = fb) cachedProc = mod_resolve(cachedLib, (uint)(IntPtr)fp);
            return cachedProc;
        }

        // ── Low-level invoke ─────────────────────────────────────────────────────
        private static ulong Invoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0)
        {
            ulong ret1 = 0, err = 0;
            return mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // ── Copy bytes from host memory into a managed buffer ────────────────────
        private static bool CopyHostToWasm(ulong hostAddr, byte* wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == null || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            Invoke(pCopy, 3, (ulong)(uint)(IntPtr)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        // ── Constructor: WSAStartup (once) + socket() ────────────────────────────
        public WfSocket()
        {
            EnsureWsaInit();

            uint pSocket = Resolve("ws2_32.dll", ref _ws2_32, "socket", ref _hSocket);
            if (pSocket == 0) return;

            // socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6)
            ulong sock = Invoke(pSocket, 3, AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock != INVALID_SOCKET) _socket = sock;
        }

        private static void EnsureWsaInit()
        {
            if (_wsaInitialized) return;
            uint pStartup = Resolve("ws2_32.dll", ref _ws2_32, "WSAStartup", ref _hWSAStartup);
            if (pStartup == 0) { _wsaInitialized = true; return; }

            // WSAStartup(WORD wVersionRequested=0x0202, LPWSADATA lpWSAData)
            // WSADATA is ~400 bytes; allocate on stack and pass WASM address.
            byte[] wsaData = new byte[408];
            fixed (byte* wdp = wsaData)
            {
                Invoke(pStartup, 2, 0x0202u, (ulong)(uint)(IntPtr)wdp);
            }
            _wsaInitialized = true;
        }

        // ── Connect(host, port) ───────────────────────────────────────────────────
        // Resolves host via gethostbyname, then calls connect() with sockaddr_in.
        public bool Connect(string host, int port)
        {
            if (_socket == INVALID_SOCKET) return false;

            uint pGethostbyname = Resolve("ws2_32.dll", ref _ws2_32, "gethostbyname", ref _hGethostbyname);
            uint pHtons         = Resolve("ws2_32.dll", ref _ws2_32, "htons", ref _hHtons);
            uint pConnect       = Resolve("ws2_32.dll", ref _ws2_32, "connect", ref _hConnect);
            if (pGethostbyname == 0 || pHtons == 0 || pConnect == 0) return false;

            // gethostbyname expects an ANSI string
            byte[] hostBytes = Encoding.ASCII.GetBytes(host + "\0");
            ulong hostentPtr;
            fixed (byte* hp = hostBytes)
            {
                hostentPtr = Invoke(pGethostbyname, 1, (ulong)(uint)(IntPtr)hp);
            }
            if (hostentPtr == 0) return false;

            // HOSTENT layout (x64):
            //   offset  0: char*  h_name      (8 bytes)
            //   offset  8: char** h_aliases   (8 bytes)
            //   offset 16: short  h_addrtype  (2 bytes)
            //   offset 18: short  h_length    (2 bytes)
            //   offset 20: pad    (4 bytes)
            //   offset 24: char** h_addr_list (8 bytes)  — ptr to array of (char*) → uint32 IP
            ulong addrListPtr = ReadHostU64(hostentPtr + 24);
            if (addrListPtr == 0) return false;

            // h_addr_list[0] is a char* that points to 4 bytes of IPv4 address
            ulong firstAddrPtr = ReadHostU64(addrListPtr);
            if (firstAddrPtr == 0) return false;

            // Read the 4-byte IPv4 address
            byte[] ipBytes = new byte[4];
            fixed (byte* ip = ipBytes)
            {
                if (!CopyHostToWasm(firstAddrPtr, ip, 4)) return false;
            }
            uint ipAddr = (uint)(ipBytes[0] | (ipBytes[1] << 8) | (ipBytes[2] << 16) | (ipBytes[3] << 24));

            // htons(port)
            ulong netPort = Invoke(pHtons, 1, (ulong)(ushort)port);

            // Build sockaddr_in (16 bytes) on WASM stack:
            //   short  sin_family   = AF_INET (2)   [offset 0]
            //   ushort sin_port     = htons(port)    [offset 2]
            //   uint   sin_addr     = ipAddr (NBO)   [offset 4]
            //   byte[8] sin_zero    = 0              [offset 8]
            byte[] saddr = new byte[16];
            saddr[0] = AF_INET & 0xff;
            saddr[1] = (AF_INET >> 8) & 0xff;
            saddr[2] = (byte)(netPort & 0xff);
            saddr[3] = (byte)((netPort >> 8) & 0xff);
            saddr[4] = ipBytes[0];
            saddr[5] = ipBytes[1];
            saddr[6] = ipBytes[2];
            saddr[7] = ipBytes[3];
            // sin_zero already zero

            fixed (byte* sp = saddr)
            {
                // connect(SOCKET s, const sockaddr* name, int namelen)
                ulong rc = Invoke(pConnect, 3,
                    _socket,
                    (ulong)(uint)(IntPtr)sp,
                    16u);
                return rc == 0;
            }
        }

        // ── Send(data) ────────────────────────────────────────────────────────────
        // Returns bytes sent, or -1 on error.
        public int Send(byte[] data)
        {
            if (_socket == INVALID_SOCKET || data == null || data.Length == 0) return -1;
            uint pSend = Resolve("ws2_32.dll", ref _ws2_32, "send", ref _hSend);
            if (pSend == 0) return -1;

            fixed (byte* dp = data)
            {
                // send(SOCKET, const char* buf, int len, int flags=0)
                ulong result = Invoke(pSend, 4,
                    _socket,
                    (ulong)(uint)(IntPtr)dp,
                    (ulong)(uint)data.Length,
                    0u);
                return (int)(uint)result;
            }
        }

        // ── Recv(buffer) ──────────────────────────────────────────────────────────
        // Returns bytes received, 0 on closed connection, -1 on error.
        public int Recv(byte[] buffer)
        {
            if (_socket == INVALID_SOCKET || buffer == null || buffer.Length == 0) return -1;
            uint pRecv = Resolve("ws2_32.dll", ref _ws2_32, "recv", ref _hRecv);
            if (pRecv == 0) return -1;

            fixed (byte* bp = buffer)
            {
                // recv(SOCKET, char* buf, int len, int flags=0)
                ulong result = Invoke(pRecv, 4,
                    _socket,
                    (ulong)(uint)(IntPtr)bp,
                    (ulong)(uint)buffer.Length,
                    0u);
                int n = (int)(uint)result;
                return n;
            }
        }

        // ── Receive exactly n bytes (Kerberos framing) ────────────────────────────
        // Kerberos over TCP uses a 4-byte big-endian length prefix followed by the PDU.
        // This method reads until exactly `length` bytes are accumulated.
        public byte[] RecvAll(int length)
        {
            if (length <= 0 || length > 65536 * 16) return null;
            byte[] buf = new byte[length];
            int received = 0;
            while (received < length)
            {
                byte[] tmp = new byte[length - received];
                int n = Recv(tmp);
                if (n <= 0) return received > 0 ? buf : null;
                Buffer.BlockCopy(tmp, 0, buf, received, n);
                received += n;
            }
            return buf;
        }

        // ── Close ─────────────────────────────────────────────────────────────────
        public void Close()
        {
            if (_socket == INVALID_SOCKET) return;
            uint pClose = Resolve("ws2_32.dll", ref _ws2_32, "closesocket", ref _hClosesocket);
            if (pClose != 0) Invoke(pClose, 1, _socket);
            _socket = INVALID_SOCKET;
        }

        // ── IDisposable ───────────────────────────────────────────────────────────
        public void Dispose() => Close();

        // ── Helper: read 8 bytes at host address (reuses same pattern as WfNetapi) ─
        private static ulong ReadHostU64(ulong hostAddr)
        {
            if (hostAddr == 0) return 0;
            byte[] buf = new byte[8];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, bp, 8)) return 0;
            }
            return ((ulong)buf[0])
                 | ((ulong)buf[1] << 8)
                 | ((ulong)buf[2] << 16)
                 | ((ulong)buf[3] << 24)
                 | ((ulong)buf[4] << 32)
                 | ((ulong)buf[5] << 40)
                 | ((ulong)buf[6] << 48)
                 | ((ulong)buf[7] << 56);
        }

        // ── Static convenience: KRB-style TCP send+receive (4-byte length prefix) ──
        // Equivalent to Networking.SendBytes(host, port, data) in Rubeus.
        // Returns the response PDU (without the 4-byte length prefix), or null on failure.
        public static byte[] SendRecv(string host, int port, byte[] data)
        {
            if (string.IsNullOrEmpty(host) || data == null) return null;
            using (var sock = new WfSocket())
            {
                if (!sock.Connect(host, port)) return null;

                // KRB TCP framing: prepend 4-byte big-endian length
                byte[] framed = new byte[4 + data.Length];
                framed[0] = (byte)((data.Length >> 24) & 0xff);
                framed[1] = (byte)((data.Length >> 16) & 0xff);
                framed[2] = (byte)((data.Length >>  8) & 0xff);
                framed[3] = (byte)( data.Length        & 0xff);
                Buffer.BlockCopy(data, 0, framed, 4, data.Length);

                if (sock.Send(framed) < framed.Length) return null;

                // Read 4-byte response length prefix
                byte[] lenBuf = new byte[4];
                int n = sock.Recv(lenBuf);
                if (n != 4) return null;

                int respLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                if (respLen <= 0 || respLen > 65536 * 16) return null;

                return sock.RecvAll(respLen);
            }
        }
    }
}
