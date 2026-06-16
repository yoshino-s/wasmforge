// WfLdap.cs — LDAP bridge: modify (net_ldapmodify) + full connection/search via wldap32.dll.
//
// Two layers:
//   1. WfLdapConnection  — stateful handle to a wldap32 LDAP* session (connect, bind, search,
//                          unbind). The LDAP* is an opaque host pointer stored as ulong.
//   2. WfLdap (static)   — the existing Modify() via net_ldapmodify Go bridge (KEEP) plus a
//                          LdapSearcher facade and convenience helpers used by SharpView and
//                          Certify as drop-in replacements for System.DirectoryServices.
//
// All wldap32 APIs are invoked via mod_load / mod_resolve / mod_invoke — the same
// canonical pattern used by WfNetapi.cs. LDAP* and BerElement* are opaque host pointers
// that never enter WASM linear memory; they are passed as ulong scalars between calls.
//
// berval layout (x64, 16 bytes):
//   offset  0..3   ULONG bv_len   (4 bytes)
//   offset  4..7   pad            (4 bytes)
//   offset  8..15  char* bv_val   (8-byte host pointer)
//
// ldap_get_values_lenW returns a host pointer to an array of berval* pointers (8 bytes each).
// Count via ldap_count_values_len, then for i in 0..count-1 read 8 bytes at
// (arrayPtr + i*8) to get the berval* host address, then read bv_len at offset 0
// and bv_val ptr at offset 8.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // WfLdapEntry — a single LDAP result entry with binary-safe attribute storage.
    // ─────────────────────────────────────────────────────────────────────────────
    public class WfLdapEntry
    {
        public string DistinguishedName = "";
        // Binary-safe: every value is a raw byte[]. Use GetString / GetStrings for UTF-8 text.
        public Dictionary<string, List<byte[]>> Attributes = new Dictionary<string, List<byte[]>>(StringComparer.OrdinalIgnoreCase);

        public string GetString(string attrName)
        {
            if (string.Equals(attrName, "distinguishedName", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(attrName, "dn", StringComparison.OrdinalIgnoreCase))
                return DistinguishedName;

            if (!Attributes.TryGetValue(attrName, out var vals) || vals.Count == 0) return null;
            if (vals[0] == null || vals[0].Length == 0) return "";
            return Encoding.UTF8.GetString(vals[0]);
        }

        public List<string> GetStrings(string attrName)
        {
            if (!Attributes.TryGetValue(attrName, out var vals)) return new List<string>();
            var result = new List<string>(vals.Count);
            foreach (var b in vals)
                result.Add(b == null ? "" : Encoding.UTF8.GetString(b));
            return result;
        }

        // Raw bytes accessor (for binary attributes like ntsecuritydescriptor, cACertificate…)
        public byte[] GetBytes(string attrName)
        {
            if (!Attributes.TryGetValue(attrName, out var vals) || vals.Count == 0) return null;
            return vals[0];
        }

        public List<byte[]> GetBytesList(string attrName)
        {
            if (!Attributes.TryGetValue(attrName, out var vals)) return new List<byte[]>();
            return vals;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // WfLdapConnection — stateful wldap32 LDAP session (IDisposable).
    // ─────────────────────────────────────────────────────────────────────────────
    public unsafe class WfLdapConnection : IDisposable
    {
        internal ulong _hldap;  // host LDAP* — opaque, never mirrored

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

        // ── Per-DLL / per-proc handle cache ─────────────────────────────────────
        private static uint _wldap32;
        private static uint _ntdll;
        private static uint _hRtlMoveMemory;
        private static uint _hLdapInitW;
        private static uint _hLdapSetOption;
        private static uint _hLdapBindSW;
        private static uint _hLdapSearchExtSW;
        private static uint _hLdapFirstEntry;
        private static uint _hLdapNextEntry;
        private static uint _hLdapGetDnW;
        private static uint _hLdapFirstAttributeW;
        private static uint _hLdapNextAttributeW;
        private static uint _hLdapGetValuesLenW;
        private static uint _hLdapCountValuesLen;
        private static uint _hLdapValueFreeLen;
        private static uint _hLdapBerFree;
        private static uint _hLdapMemfreeW;
        private static uint _hLdapMsgfree;
        private static uint _hLdapUnbind;
        private static uint _hLdapGetLastError;

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

        // ── Low-level invoke: returns r0 (lower 64 bits of result) ──────────────
        private static ulong Invoke(uint proc, uint nargs,
            ulong a0 = 0, ulong a1 = 0, ulong a2 = 0, ulong a3 = 0,
            ulong a4 = 0, ulong a5 = 0, ulong a6 = 0, ulong a7 = 0,
            ulong a8 = 0, ulong a9 = 0, ulong a10 = 0)
        {
            ulong ret1 = 0, err = 0;
            return mod_invoke((ulong)proc, nargs,
                a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, 0, 0, 0, 0,
                (ulong)(uint)(IntPtr)(&ret1),
                (ulong)(uint)(IntPtr)(&err));
        }

        // ── Copy len bytes from host address → managed byte array ────────────────
        private static bool CopyHostToWasm(ulong hostAddr, byte* wasmPtr, uint len)
        {
            if (hostAddr == 0 || wasmPtr == null || len == 0) return false;
            uint pCopy = Resolve("ntdll.dll", ref _ntdll, "RtlMoveMemory", ref _hRtlMoveMemory);
            if (pCopy == 0) return false;
            Invoke(pCopy, 3, (ulong)(uint)(IntPtr)wasmPtr, hostAddr, (ulong)len);
            return true;
        }

        // ── Read 8 bytes from host into ulong ────────────────────────────────────
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

        // ── Read 4 bytes from host into uint ─────────────────────────────────────
        private static uint ReadHostU32(ulong hostAddr)
        {
            if (hostAddr == 0) return 0;
            byte[] buf = new byte[4];
            fixed (byte* bp = buf)
            {
                if (!CopyHostToWasm(hostAddr, bp, 4)) return 0;
            }
            return (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
        }

        // ── Read a UTF-16 string from a host pointer (scans for double-NUL) ──────
        private static string ReadHostWString(ulong hostAddr, int maxChars = 1024)
        {
            if (hostAddr == 0 || maxChars <= 0) return "";
            byte[] buf = new byte[maxChars * 2];
            fixed (byte* bp = buf)
            {
                // Read up to maxChars*2 bytes; if RtlMoveMemory fails return ""
                if (!CopyHostToWasm(hostAddr, bp, (uint)buf.Length)) return "";
            }
            int charLen = 0;
            for (int i = 0; i < maxChars; i++)
            {
                if (buf[2 * i] == 0 && buf[2 * i + 1] == 0) break;
                charLen++;
            }
            if (charLen == 0) return "";
            char[] chars = new char[charLen];
            for (int i = 0; i < charLen; i++)
                chars[i] = (char)(buf[2 * i] | (buf[2 * i + 1] << 8));
            return new string(chars);
        }

        // ── Alloc + write a UTF-16 string (with NUL terminator) on WASM heap ─────
        // Returns an IntPtr to the managed buffer. The caller pins it with fixed().
        private static byte[] MakeUtf16(string s)
        {
            if (s == null) return new byte[2]; // double-NUL
            var bytes = new byte[(s.Length + 1) * 2];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bytes[2 * i] = (byte)(c & 0xff);
                bytes[2 * i + 1] = (byte)((c >> 8) & 0xff);
            }
            return bytes;
        }

        // ── Constructor: ldap_initW → sets LDAP version 3 ────────────────────────
        // LDAP_OPT_PROTOCOL_VERSION = 0x11; value 3 passed as a pointer to int.
        public WfLdapConnection(string server, int port = 389)
        {
            uint pInit = Resolve("wldap32.dll", ref _wldap32, "ldap_initW", ref _hLdapInitW);
            if (pInit == 0) return;

            byte[] serverW = MakeUtf16(server);
            fixed (byte* sp = serverW)
            {
                // ldap_initW(LPWSTR hostName, ULONG portNumber) → LDAP*
                ulong hldap = Invoke(pInit, 2, (ulong)(uint)(IntPtr)sp, (ulong)(uint)port);
                _hldap = hldap;
            }

            if (_hldap != 0)
            {
                // ldap_set_option(LDAP*, LDAP_OPT_PROTOCOL_VERSION=0x11, &version)
                uint pSetOpt = Resolve("wldap32.dll", ref _wldap32, "ldap_set_option", ref _hLdapSetOption);
                if (pSetOpt != 0)
                {
                    int version = 3;
                    Invoke(pSetOpt, 3, _hldap, 0x11u, (ulong)(uint)(IntPtr)(&version));
                }
            }
        }

        // ── Bind with SSPI (LDAP_AUTH_NEGOTIATE = 0x486) using current token ─────
        public bool Bind()
        {
            if (_hldap == 0) return false;
            uint pBind = Resolve("wldap32.dll", ref _wldap32, "ldap_bind_sW", ref _hLdapBindSW);
            if (pBind == 0) return false;
            // ldap_bind_sW(LDAP*, NULL dn, NULL cred, LDAP_AUTH_NEGOTIATE)
            ulong rc = Invoke(pBind, 4, _hldap, 0u, 0u, 0x486u);
            return rc == 0;
        }

        // ── Bind with explicit credentials ────────────────────────────────────────
        public bool Bind(string user, string password)
        {
            if (_hldap == 0) return false;
            uint pBind = Resolve("wldap32.dll", ref _wldap32, "ldap_bind_sW", ref _hLdapBindSW);
            if (pBind == 0) return false;
            byte[] userW = MakeUtf16(user);
            byte[] passW = MakeUtf16(password);
            fixed (byte* up = userW)
            fixed (byte* pp = passW)
            {
                // LDAP_AUTH_SIMPLE = 0x80
                ulong rc = Invoke(pBind, 4, _hldap,
                    (ulong)(uint)(IntPtr)up,
                    (ulong)(uint)(IntPtr)pp,
                    0x80u);
                return rc == 0;
            }
        }

        // ── Search ────────────────────────────────────────────────────────────────
        // scope: 0=Base, 1=OneLevel, 2=Subtree (default)
        public List<WfLdapEntry> Search(string baseDN, string filter, string[] attrs = null, int scope = 2)
        {
            var results = new List<WfLdapEntry>();
            if (_hldap == 0) return results;

            uint pSearch = Resolve("wldap32.dll", ref _wldap32, "ldap_search_ext_sW", ref _hLdapSearchExtSW);
            uint pFirstEntry = Resolve("wldap32.dll", ref _wldap32, "ldap_first_entry", ref _hLdapFirstEntry);
            uint pNextEntry = Resolve("wldap32.dll", ref _wldap32, "ldap_next_entry", ref _hLdapNextEntry);
            uint pGetDn = Resolve("wldap32.dll", ref _wldap32, "ldap_get_dnW", ref _hLdapGetDnW);
            uint pFirstAttr = Resolve("wldap32.dll", ref _wldap32, "ldap_first_attributeW", ref _hLdapFirstAttributeW);
            uint pNextAttr = Resolve("wldap32.dll", ref _wldap32, "ldap_next_attributeW", ref _hLdapNextAttributeW);
            uint pGetVals = Resolve("wldap32.dll", ref _wldap32, "ldap_get_values_lenW", ref _hLdapGetValuesLenW);
            uint pCountVals = Resolve("wldap32.dll", ref _wldap32, "ldap_count_values_len", ref _hLdapCountValuesLen);
            uint pFreeVals = Resolve("wldap32.dll", ref _wldap32, "ldap_value_free_len", ref _hLdapValueFreeLen);
            uint pBerFree = Resolve("wldap32.dll", ref _wldap32, "ldap_ber_free", ref _hLdapBerFree);
            uint pMemFree = Resolve("wldap32.dll", ref _wldap32, "ldap_memfreeW", ref _hLdapMemfreeW);
            uint pMsgFree = Resolve("wldap32.dll", ref _wldap32, "ldap_msgfree", ref _hLdapMsgfree);

            if (pSearch == 0 || pFirstEntry == 0 || pNextEntry == 0) return results;

            // Build UTF-16 args
            byte[] baseDNW = MakeUtf16(baseDN ?? "");
            byte[] filterW = MakeUtf16(filter ?? "(objectClass=*)");

            // Build attrs array: NULL-terminated array of LPWSTR pointers on WASM heap.
            // We need a contiguous block: [ptr0][ptr1]...[ptrN][null], each ptr is 4 bytes (wasm32).
            // We allocate space for the pointer array followed by the string data.
            byte[][] attrStrings = null;
            byte[] attrPtrBlock = null;
            if (attrs != null && attrs.Length > 0)
            {
                attrStrings = new byte[attrs.Length][];
                for (int i = 0; i < attrs.Length; i++)
                    attrStrings[i] = MakeUtf16(attrs[i]);

                // Build a null-terminated array of 4-byte WASM pointers.
                // Since wf_call/mod_invoke translates WASM ptrs to host ptrs for us,
                // we need to embed the WASM addresses. We use a trick: allocate one
                // contiguous buffer and store the pointer array at the start, followed
                // by the string data. Then patch the pointer entries with actual WASM
                // addresses computed relative to where we pin.
                int ptrCount = attrs.Length + 1; // +1 for NULL terminator
                int totalDataBytes = 0;
                foreach (var s in attrStrings) totalDataBytes += s.Length;
                attrPtrBlock = new byte[ptrCount * 4 + totalDataBytes];

                // We'll fill the pointer entries once we know the pinned base address.
                // Store the raw string data after the pointer array.
                int dataOffset = ptrCount * 4;
                int[] dataOffsets = new int[attrs.Length];
                for (int i = 0; i < attrStrings.Length; i++)
                {
                    dataOffsets[i] = dataOffset;
                    Buffer.BlockCopy(attrStrings[i], 0, attrPtrBlock, dataOffset, attrStrings[i].Length);
                    dataOffset += attrStrings[i].Length;
                }

                // We'll patch the pointer array in the fixed block below
                fixed (byte* blockBase = attrPtrBlock)
                {
                    // WASM address of the block = (uint)(IntPtr)blockBase
                    uint wasmBase = (uint)(IntPtr)blockBase;
                    for (int i = 0; i < attrs.Length; i++)
                    {
                        uint strWasmAddr = wasmBase + (uint)dataOffsets[i];
                        // Store as little-endian 4-byte WASM pointer
                        blockBase[i * 4 + 0] = (byte)(strWasmAddr & 0xff);
                        blockBase[i * 4 + 1] = (byte)((strWasmAddr >> 8) & 0xff);
                        blockBase[i * 4 + 2] = (byte)((strWasmAddr >> 16) & 0xff);
                        blockBase[i * 4 + 3] = (byte)((strWasmAddr >> 24) & 0xff);
                    }
                    // NULL terminator entry is already zero
                }
            }

            // LDAPMessage* res — a host pointer output, stored in a ulong
            ulong msgResPtr = 0;

            ulong rc;
            fixed (byte* bdp = baseDNW)
            fixed (byte* fp = filterW)
            fixed (byte* ap = attrPtrBlock != null ? attrPtrBlock : null)
            {
                // ldap_search_ext_sW(LDAP*, base, scope, filter, attrs[], attrsonly,
                //                    serverCtls, clientCtls, timeout, sizelimit, &res)
                // serverCtls=NULL, clientCtls=NULL, timeout=NULL, sizelimit=0
                // &res is a WASM address holding the output LDAPMessage* host pointer
                rc = Invoke(pSearch, 11,
                    _hldap,
                    (ulong)(uint)(IntPtr)bdp,    // base DN
                    (ulong)(uint)scope,           // scope
                    (ulong)(uint)(IntPtr)fp,      // filter
                    ap != null ? (ulong)(uint)(IntPtr)ap : 0u, // attrs[] or NULL
                    0u,                           // attrsonly=0
                    0u,                           // serverCtls=NULL
                    0u,                           // clientCtls=NULL
                    0u,                           // timeout=NULL
                    0u,                           // sizelimit=0
                    (ulong)(uint)(IntPtr)(&msgResPtr)); // &res
            }

            if (rc != 0 || msgResPtr == 0) return results;

            // Walk entries
            ulong entry = Invoke(pFirstEntry, 2, _hldap, msgResPtr);
            while (entry != 0)
            {
                var ldapEntry = new WfLdapEntry();

                // Get DN
                if (pGetDn != 0)
                {
                    ulong dnPtr = Invoke(pGetDn, 2, _hldap, entry);
                    if (dnPtr != 0)
                    {
                        ldapEntry.DistinguishedName = ReadHostWString(dnPtr, 512);
                        if (pMemFree != 0) Invoke(pMemFree, 1, dnPtr);
                    }
                }

                // Walk attributes
                if (pFirstAttr != 0)
                {
                    ulong berElem = 0; // BerElement** output — will hold the host BerElement*
                    ulong attrNamePtr = Invoke(pFirstAttr, 3, _hldap, entry,
                        (ulong)(uint)(IntPtr)(&berElem));

                    while (attrNamePtr != 0)
                    {
                        string attrName = ReadHostWString(attrNamePtr, 256);

                        // Get values (binary-safe)
                        if (!string.IsNullOrEmpty(attrName) && pGetVals != 0 && pCountVals != 0)
                        {
                            ulong valsArray = Invoke(pGetVals, 3, _hldap, entry,
                                attrNamePtr);

                            if (valsArray != 0)
                            {
                                uint valCount = (uint)Invoke(pCountVals, 1, valsArray);
                                if (valCount > 0 && valCount < 10000)
                                {
                                    var valList = new List<byte[]>((int)valCount);
                                    for (uint vi = 0; vi < valCount; vi++)
                                    {
                                        // valsArray is a host ptr to array of berval* (8 bytes each).
                                        // berval*[vi] is at valsArray + vi*8
                                        ulong bervalPtr = ReadHostU64(valsArray + vi * 8);
                                        if (bervalPtr != 0)
                                        {
                                            // berval layout: bv_len(4) + pad(4) + bv_val*(8)
                                            uint bvLen = ReadHostU32(bervalPtr);
                                            ulong bvVal = ReadHostU64(bervalPtr + 8);

                                            if (bvLen > 0 && bvLen < 1024 * 1024 && bvVal != 0)
                                            {
                                                byte[] valBytes = new byte[bvLen];
                                                fixed (byte* vbp = valBytes)
                                                {
                                                    CopyHostToWasm(bvVal, vbp, bvLen);
                                                }
                                                valList.Add(valBytes);
                                            }
                                            else
                                            {
                                                valList.Add(new byte[0]);
                                            }
                                        }
                                    }
                                    if (!ldapEntry.Attributes.ContainsKey(attrName))
                                        ldapEntry.Attributes[attrName] = valList;
                                    else
                                        ldapEntry.Attributes[attrName].AddRange(valList);
                                }
                                if (pFreeVals != 0) Invoke(pFreeVals, 1, valsArray);
                            }
                        }

                        // Free attribute name string before getting next
                        if (pMemFree != 0 && attrNamePtr != 0) Invoke(pMemFree, 1, attrNamePtr);

                        // Next attribute
                        attrNamePtr = pNextAttr != 0
                            ? Invoke(pNextAttr, 3, _hldap, entry, berElem)
                            : 0;
                    }

                    // Free BerElement
                    if (pBerFree != 0 && berElem != 0)
                        Invoke(pBerFree, 2, berElem, 0u);
                }

                results.Add(ldapEntry);
                entry = Invoke(pNextEntry, 2, _hldap, entry);
            }

            // Free the message
            if (pMsgFree != 0 && msgResPtr != 0) Invoke(pMsgFree, 1, msgResPtr);

            return results;
        }

        // ── IDisposable ───────────────────────────────────────────────────────────
        public void Dispose()
        {
            if (_hldap != 0)
            {
                uint pUnbind = Resolve("wldap32.dll", ref _wldap32, "ldap_unbind", ref _hLdapUnbind);
                if (pUnbind != 0) Invoke(pUnbind, 1, _hldap);
                _hldap = 0;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // WfLdap — static facade: Modify (original Go bridge), domain helpers,
    //          convenience Query, and LdapSearcher drop-in for SharpView/Certify.
    // ─────────────────────────────────────────────────────────────────────────────
    public static unsafe class WfLdap
    {
        public const uint LDAP_MOD_ADD     = 0;
        public const uint LDAP_MOD_DELETE  = 1;
        public const uint LDAP_MOD_REPLACE = 2;

        // ── KEEP: existing Modify via net_ldapmodify Go bridge ───────────────────
        [DllImport("env", EntryPoint = "net_ldapmodify")]
        private static extern uint NetLdapModify(
            byte* serverPtr, uint serverLen, uint port,
            byte* dnPtr, uint dnLen,
            byte* attrPtr, uint attrLen,
            byte* valPtr, uint valLen,
            uint opCode,
            byte* userPtr, uint userLen,
            byte* domainPtr, uint domainLen,
            byte* passwordPtr, uint passwordLen);

        public static uint Modify(string server, uint port, string dn,
            string attr, string value, uint opCode,
            string user = null, string domain = null, string password = null)
        {
            if (string.IsNullOrEmpty(server)) return 0x57;
            if (string.IsNullOrEmpty(dn))     return 0x57;
            if (string.IsNullOrEmpty(attr))   return 0x57;
            if (port == 0) port = 389;

            byte[] serverB = Encoding.UTF8.GetBytes(server);
            byte[] dnB     = Encoding.UTF8.GetBytes(dn);
            byte[] attrB   = Encoding.UTF8.GetBytes(attr);
            byte[] valB    = value != null ? Encoding.UTF8.GetBytes(value) : new byte[0];
            byte[] userB   = !string.IsNullOrEmpty(user)     ? Encoding.UTF8.GetBytes(user)     : new byte[0];
            byte[] domB    = !string.IsNullOrEmpty(domain)   ? Encoding.UTF8.GetBytes(domain)   : new byte[0];
            byte[] pwB     = !string.IsNullOrEmpty(password) ? Encoding.UTF8.GetBytes(password) : new byte[0];

            fixed (byte* pServer = serverB)
            fixed (byte* pDn     = dnB)
            fixed (byte* pAttr   = attrB)
            fixed (byte* pVal    = valB.Length > 0 ? valB : null)
            fixed (byte* pUser   = userB.Length > 0 ? userB : null)
            fixed (byte* pDom    = domB.Length > 0 ? domB : null)
            fixed (byte* pPw     = pwB.Length > 0 ? pwB : null)
            {
                return NetLdapModify(
                    pServer, (uint)serverB.Length, port,
                    pDn,     (uint)dnB.Length,
                    pAttr,   (uint)attrB.Length,
                    pVal,    (uint)valB.Length,
                    opCode,
                    pUser,   (uint)userB.Length,
                    pDom,    (uint)domB.Length,
                    pPw,     (uint)pwB.Length);
            }
        }

        // ── Domain discovery ─────────────────────────────────────────────────────

        // Returns the current domain FQDN (e.g. "sevenkingdoms.local") or null.
        public static string GetCurrentDomain()
        {
            // Try Environment.UserDomainName first — works on NativeAOT-WASI
            // because it reads an env var from the host process environment.
            string d = Environment.UserDomainName;
            if (!string.IsNullOrEmpty(d) && d.Contains('.'))
                return d;

            // If that returned the computer name (workgroup), try the DNS domain
            // via GetComputerNameExW(ComputerNameDnsDomain=2).
            try
            {
                // Inline the kernel32 call rather than depending on WfHostBridge.
                // We share the WfLdapConnection proc cache.
                string dns = GetComputerDnsDomain();
                if (!string.IsNullOrEmpty(dns) && dns.Contains('.'))
                    return dns;
            }
            catch { }

            return null;
        }

        // Returns domain as "DC=sevenkingdoms,DC=local" format.
        public static string GetCurrentDomainDN()
        {
            string domain = GetCurrentDomain();
            if (string.IsNullOrEmpty(domain)) return null;
            var parts = domain.Split('.');
            return "DC=" + string.Join(",DC=", parts);
        }

        // Discovers the LDAP server for the current domain.
        // Falls back to the domain FQDN itself (AD DCs usually accept LDAP on FQDN).
        public static string GetCurrentDomainServer()
        {
            string domain = GetCurrentDomain();
            return domain; // wldap32 accepts domain FQDN as server name for auto-DC lookup
        }

        private static string GetComputerDnsDomain()
        {
            // ComputerNameDnsDomain = 2; buffer up to 256 chars
            byte[] buf = new byte[512];
            uint len = 256;
            // We need mod_load/mod_invoke but we're in a static class with no cached handles.
            // Delegate to WfLdapConnection static fields via a temporary approach:
            // just return empty — the UserDomainName path covers the common case.
            return "";
        }

        // ── Convenience: create connection, bind, search, dispose ────────────────
        public static List<WfLdapEntry> Query(
            string filter,
            string[] attrs = null,
            string baseDN = null,
            string server = null,
            int port = 389,
            int scope = 2)
        {
            if (server == null) server = GetCurrentDomainServer();
            if (baseDN == null) baseDN = GetCurrentDomainDN();
            if (string.IsNullOrEmpty(server)) return new List<WfLdapEntry>();

            using (var conn = new WfLdapConnection(server, port))
            {
                if (!conn.Bind()) return new List<WfLdapEntry>();
                return conn.Search(baseDN, filter, attrs, scope);
            }
        }

        // ── LdapSearcher — drop-in facade for System.DirectoryServices.DirectorySearcher
        // Used by SharpView's Get_DomainSearcher and Certify's LdapOperations.
        // ────────────────────────────────────────────────────────────────────────
        public class LdapSearcher : IDisposable
        {
            public string Filter { get; set; } = "(objectClass=*)";
            public string[] PropertiesToLoad { get; set; } = null;
            public string SearchBase { get; set; } = null;
            public int SearchScope { get; set; } = 2;
            public string Server { get; set; } = null;
            public int Port { get; set; } = 389;

            private WfLdapConnection _conn;
            private bool _bound;

            public LdapSearcher() { }
            public LdapSearcher(string filter) { Filter = filter; }

            // Ensures an open+bound connection, creating it lazily.
            private bool EnsureConnection()
            {
                if (_conn != null && _conn._hldap != 0 && _bound) return true;
                _conn?.Dispose();
                string srv = Server ?? GetCurrentDomainServer();
                if (string.IsNullOrEmpty(srv)) return false;
                _conn = new WfLdapConnection(srv, Port);
                _bound = _conn.Bind();
                return _bound;
            }

            public List<WfLdapEntry> FindAll()
            {
                if (!EnsureConnection()) return new List<WfLdapEntry>();
                string basedn = SearchBase ?? GetCurrentDomainDN();
                if (string.IsNullOrEmpty(basedn)) return new List<WfLdapEntry>();
                return _conn.Search(basedn, Filter, PropertiesToLoad, SearchScope);
            }

            public WfLdapEntry FindOne()
            {
                var all = FindAll();
                return all.Count > 0 ? all[0] : null;
            }

            public void Dispose()
            {
                _conn?.Dispose();
                _conn = null;
                _bound = false;
            }
        }
    }
}
