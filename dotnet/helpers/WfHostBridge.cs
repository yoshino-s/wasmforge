// WfHostBridge.cs — Core P/Invoke declarations for WasmForge NativeAOT-WASI host functions.
//
// These declarations map to the host functions registered in
// internal/hostmod/nativeaot.go (Go side). They are imported from the
// "env" WASM module via NativeAOT's static P/Invoke linking.
//
// Usage: Add this file to your .NET project before NativeAOT-WASI compilation.
// The [DllImport("*")] attribute tells NativeAOT to link against native C
// implementations (in wf_bridge.c / pinvoke_nativeaot.c) which call the
// WASM host imports.
//
// For direct host functions (SDDL, WMI, LSA), [DllImport("env")] is used
// to import directly from the WASM host module without going through the
// C bridge. These are the anonymized export names from internal/names/names.go.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Bridge
{
    /// <summary>
    /// Direct imports of WasmForge NativeAOT host functions.
    /// These bypass the SyscallN path — complex operations run atomically on the host.
    /// </summary>
    public static unsafe class WfHostBridge
    {
        // ── Constants ────────────────────────────────────────────────

        /// <summary>Maximum output buffer size for host function calls.</summary>
        public const int DefaultBufSize = 256 * 1024; // 256 KB

        /// <summary>Small buffer for single-value returns.</summary>
        public const int SmallBufSize = 8192; // 8 KB

        // ── SDDL ────────────────────────────────────────────────────

        /// <summary>
        /// Parse an SDDL string into ACE entries with translated account names.
        /// Returns null-separated "account\tSID\taccess_type" lines.
        /// </summary>
        [DllImport("env", EntryPoint = "sec_parsesddl")]
        public static extern uint ParseSddlAcl(
            byte* sddlPtr, uint sddlLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Get the SDDL string for a file/directory path.
        /// Returns UTF-16 chars written.
        /// </summary>
        [DllImport("env", EntryPoint = "sec_sddl")]
        public static extern uint GetSddl(
            byte* pathPtr,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Get the SDDL string for a file or service by SE_OBJECT_TYPE.
        /// objectType: 1 = SE_FILE_OBJECT, 5 = SE_SERVICE_OBJECT.
        /// Returns UTF-8 chars written.
        /// </summary>
        [DllImport("env", EntryPoint = "sec_sddl_typed")]
        public static extern uint GetPathSddlTyped(byte* pathPtr, uint objectType, byte* outBufPtr, uint outBufLen);

        // ── Security Enumeration ────────────────────────────────────

        /// <summary>
        /// Enumerate accounts with each user right assignment.
        /// Returns null-separated "Right\tSID" lines.
        /// </summary>
        [DllImport("env", EntryPoint = "sec_enumrights")]
        public static extern uint EnumUserRights(byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Enumerate all logon sessions.
        /// Returns tab-separated "field\tvalue\n" records.
        /// </summary>
        [DllImport("*", EntryPoint = "WfEnumLogonSessions")]
        public static extern uint EnumLogonSessions(byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Enumerate RPC mapped endpoints.
        /// Returns null-separated "Protocol\tEndpoint\tAnnotation\tUUID" lines.
        /// </summary>
        [DllImport("env", EntryPoint = "rpc_enumeps")]
        public static extern uint EnumRpcEndpoints(byte* outBufPtr, uint outBufLen);

        // ── WMI ─────────────────────────────────────────────────────

        /// <summary>
        /// Execute a WQL query via native COM WMI.
        /// Returns JSON results.
        /// </summary>
        [DllImport("env", EntryPoint = "wmi_query")]
        public static extern uint WmiQuery(
            byte* queryPtr, uint queryLen,
            byte* nsPtr, uint nsLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Invoke a WMI method (IWbemServices::ExecMethod) on a class with
        /// JSON-serialized input parameters. Returns JSON of the output
        /// parameters (e.g., {"ReturnValue":0,"ProcessId":1234}).
        /// </summary>
        [DllImport("env", EntryPoint = "wmi_method")]
        public static extern uint WmiMethod(
            byte* nsPtr, uint nsLen,
            byte* classPtr, uint classLen,
            byte* methodPtr, uint methodLen,
            byte* inJsonPtr, uint inJsonLen,
            byte* outBufPtr, uint outBufLen);

        // ── Filesystem ──────────────────────────────────────────────

        /// <summary>
        /// List directory contents on the host (bypasses WASI path mapping).
        /// </summary>
        [DllImport("env", EntryPoint = "sys_listdir")]
        public static extern uint ListDir(
            byte* pathPtr, uint pathLen,
            byte* bufPtr, uint bufCap, uint* countPtr);

        /// <summary>
        /// Check if a file exists on the host (bypasses WASI path mapping).
        /// </summary>
        [DllImport("env", EntryPoint = "sys_fileexists")]
        public static extern uint FileExists(byte* pathPtr, uint pathLen);

        // ── Network ─────────────────────────────────────────────────

        /// <summary>
        /// Enumerate network adapters.
        /// Returns "index\tname\tdescription\tip_list\n" lines.
        /// </summary>
        [DllImport("env", EntryPoint = "net_adapters")]
        public static extern uint EnumNetworkAdapters(byte* outBufPtr, uint outBufLen);

        // ── PE / Registry ───────────────────────────────────────────

        /// <summary>
        /// Get the CompanyName from a PE file's VERSIONINFO resource.
        /// </summary>
        [DllImport("env", EntryPoint = "ver_info")]
        public static extern uint GetFileVersionInfo(
            byte* pathPtr, uint pathLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Enumerate all values under a registry key.
        /// Returns null-separated "name\ttype\tdata" lines.
        /// </summary>
        [DllImport("env", EntryPoint = "reg_enumvals")]
        public static extern uint EnumRegValues(
            uint* hivePtr,
            byte* keyPathPtr, uint keyPathLen,
            byte* outBufPtr, uint outBufLen);

        // ── LSA Kerberos ────────────────────────────────────────────

        /// <summary>
        /// Execute an LSA Kerberos operation atomically on the host.
        /// Operations: "enumerate_tickets", "retrieve_ticket\tSERVER",
        ///             "purge_tickets[\tSERVER\tREALM]",
        ///             "submit_ticket\tBASE64_KIRBI"
        /// Returns tab-separated "field\tvalue\n" records.
        /// </summary>
        [DllImport("*", EntryPoint = "WfLsaKerberosOp")]
        public static extern uint LsaKerberosOp(
            byte* opPtr, uint opLen,
            uint luidLow, uint luidHigh,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Generic crypto dispatcher: one host import handles all looped-crypto
        /// operations (MS-PBKDF2, RFC PBKDF2, HMAC, plain hash, AES-CBC).
        /// Opcode is short ASCII (e.g., "mspbkdf2_512", "sha256", "aescbcdec");
        /// args is a packed buffer of length-prefixed byte fields. See
        /// CryptoHostHelper.CryptoOp for the high-level C# entry point.
        /// </summary>
        [DllImport("*", EntryPoint = "WfCryptoOp")]
        public static extern uint CryptoOp(
            byte* opPtr, uint opLen,
            byte* argsPtr, uint argsLen,
            byte* outPtr, uint outCap);

        /// <summary>
        /// Generic IO dispatcher: one host import for file/dir operations.
        /// Single wf_call replaces the 6-8 wf_call CreateFile+ReadFile chain
        /// in fs_read_all. Opcode is "read", "stat", or "list"; args is a
        /// single length-prefixed UTF-8 path field. See nativeaot_os.go
        /// nativeaotIoOp for the dispatcher.
        /// </summary>
        [DllImport("*", EntryPoint = "WfIoOp")]
        public static extern uint IoOp(
            byte* opPtr, uint opLen,
            byte* argsPtr, uint argsLen,
            byte* outPtr, uint outCap);

        // ── Kerberos Crypto ─────────────────────────────────────────

        /// <summary>
        /// Compute a Kerberos password hash via CDLocateCSystem on the host.
        /// Returns hex-encoded hash bytes written to output buffer.
        /// </summary>
        [DllImport("*", EntryPoint = "WfKerberosHash")]
        public static extern uint KerberosHash(
            uint etype,
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations,
            byte* outBufPtr, uint outBufLen);

        // ── Kerberos Encrypt/Decrypt/Checksum ────────────────────────

        /// <summary>
        /// Encrypt data using CDLocateCSystem on the host.
        /// Returns raw encrypted bytes written to output buffer.
        /// </summary>
        [DllImport("*", EntryPoint = "WfKerberosEncrypt")]
        public static extern uint KerberosEncrypt(
            uint etype, uint keyUsage,
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Decrypt data using CDLocateCSystem on the host.
        /// Returns raw decrypted bytes written to output buffer.
        /// </summary>
        [DllImport("*", EntryPoint = "WfKerberosDecrypt")]
        public static extern uint KerberosDecrypt(
            uint etype, uint keyUsage,
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Compute a Kerberos checksum using CDLocateCheckSum on the host.
        /// Returns raw checksum bytes written to output buffer.
        /// </summary>
        [DllImport("*", EntryPoint = "WfKerberosChecksum")]
        public static extern uint KerberosChecksum(
            uint cksumType, uint keyUsage,
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>PBKDF2-HMAC-SHA1 for DPAPI master key derivation.</summary>
        [DllImport("*", EntryPoint = "WfPbkdf2Sha1")]
        public static extern uint Pbkdf2Sha1(
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations, uint keyLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>PBKDF2-HMAC-SHA256 for newer DPAPI master keys.</summary>
        [DllImport("*", EntryPoint = "WfPbkdf2Sha256")]
        public static extern uint Pbkdf2Sha256(
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations, uint keyLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>PBKDF2-HMAC-SHA512 for AES-256 DPAPI master keys.</summary>
        [DllImport("*", EntryPoint = "WfPbkdf2Sha512")]
        public static extern uint Pbkdf2Sha512(
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations, uint keyLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA512 variant (the "MS PBKDF2 bug" — feeds the
        /// accumulated XOR result back into HMAC each iteration). Required for Windows DPAPI master
        /// key derivation parity (Mimikatz / SharpDPAPI / impacket all replicate this bug).</summary>
        [DllImport("*", EntryPoint = "WfMsPbkdf2Sha512")]
        public static extern uint MsPbkdf2Sha512(
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations,
            byte* outBufPtr, uint outBufLen);

        /// <summary>Microsoft-CryptoAPI PBKDF2-HMAC-SHA1 variant. See MsPbkdf2Sha512 for rationale.</summary>
        [DllImport("*", EntryPoint = "WfMsPbkdf2Sha1")]
        public static extern uint MsPbkdf2Sha1(
            byte* passwordPtr, uint passwordLen,
            byte* saltPtr, uint saltLen,
            uint iterations,
            byte* outBufPtr, uint outBufLen);

        /// <summary>HMAC-SHA1(key, data).</summary>
        [DllImport("*", EntryPoint = "WfHmacSha1")]
        public static extern uint HmacSha1(
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>HMAC-SHA256(key, data).</summary>
        [DllImport("*", EntryPoint = "WfHmacSha256")]
        public static extern uint HmacSha256(
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>HMAC-SHA512(key, data). Used by SharpDPAPI credentials parser.</summary>
        [DllImport("*", EntryPoint = "WfHmacSha512")]
        public static extern uint HmacSha512(
            byte* keyPtr, uint keyLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>Enumerate loaded modules across all accessible processes.
        /// Wire format: "pid\tprocessName\tmodulePath\n" per module. Used by
        /// SharpUp ProcessDLLHijack.</summary>
        [DllImport("*", EntryPoint = "WfProcModulesAll")]
        public static extern uint ProcModulesAll(byte* outBufPtr, uint outBufLen);

        /// <summary>AES-CBC decrypt (no padding). 16/24/32-byte key, 16-byte IV.</summary>
        [DllImport("*", EntryPoint = "WfAesCbcDecrypt")]
        public static extern uint AesCbcDecrypt(
            byte* keyPtr, uint keyLen,
            byte* ivPtr, uint ivLen,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>SHA1(data) → 20 bytes.</summary>
        [DllImport("*", EntryPoint = "WfSha1")]
        public static extern uint Sha1(
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>SHA256(data) → 32 bytes.</summary>
        [DllImport("*", EntryPoint = "WfSha256")]
        public static extern uint Sha256(
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        // ── Network Operations ──────────────────────────────────────

        /// <summary>
        /// Send data over TCP and receive the response (Kerberos framing).
        /// </summary>
        [DllImport("*", EntryPoint = "WfTcpSendRecv")]
        public static extern uint TcpSendRecv(
            byte* hostPtr, uint hostLen,
            uint port,
            byte* dataPtr, uint dataLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Execute an LDAP search query via wldap32.dll on the host.
        /// Returns "attr\tvalue\n" per attribute, '\0' between entries.
        /// </summary>
        [DllImport("*", EntryPoint = "WfLdapSearchExt")]
        public static extern uint LdapSearchExt(
            byte* serverPtr, uint serverLen, uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* userPtr, uint userLen,
            byte* domainPtr, uint domainLen,
            byte* passwordPtr, uint passwordLen,
            byte* outBufPtr, uint outBufLen);

        [DllImport("*", EntryPoint = "WfLdapSearch")]
        public static extern uint LdapSearch(
            byte* serverPtr, uint serverLen,
            uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>
        /// Resolve domain controller IP/hostname via DsGetDcNameW.
        /// </summary>
        [DllImport("*", EntryPoint = "WfGetDCName")]
        public static extern uint GetDCName(
            byte* domainPtr, uint domainLen,
            uint flags,
            byte* outBufPtr, uint outBufLen);

        // ── Managed helpers ─────────────────────────────────────────

        /// <summary>
        /// Call LsaKerberosOp with a managed operation string and return
        /// the result as a managed string.
        /// </summary>
        public static string CallLsaKerberosOp(string operation, uint luidLow, uint luidHigh)
        {
            byte[] opBytes = Encoding.UTF8.GetBytes(operation);
            byte[] outBuf = new byte[DefaultBufSize];

            uint written;
            fixed (byte* opPtr = opBytes)
            fixed (byte* outPtr = outBuf)
            {
                written = LsaKerberosOp(opPtr, (uint)opBytes.Length,
                    luidLow, luidHigh, outPtr, (uint)outBuf.Length);
            }

            if (written == 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>
        /// Call WmiQuery with managed strings and return JSON result.
        /// </summary>
        public static string CallWmiQuery(string query, string ns = "root\\cimv2")
        {
            byte[] queryBytes = Encoding.UTF8.GetBytes(query);
            byte[] nsBytes = Encoding.UTF8.GetBytes(ns);
            byte[] outBuf = new byte[DefaultBufSize];

            uint written;
            fixed (byte* qPtr = queryBytes)
            fixed (byte* nPtr = nsBytes)
            fixed (byte* oPtr = outBuf)
            {
                written = WmiQuery(qPtr, (uint)queryBytes.Length,
                    nPtr, (uint)nsBytes.Length,
                    oPtr, (uint)outBuf.Length);
            }

            if (written == 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>
        /// Call WmiMethod with managed strings. The inputJson is a flat JSON
        /// object whose keys map to WMI in-parameter names. Returns JSON of
        /// output parameters, or null on failure.
        ///
        /// Example: CallWmiMethod("Win32_Process", "Create",
        ///     "{\"CommandLine\":\"cmd.exe /c whoami > C:\\\\out.txt\"}")
        /// → {"ReturnValue":0,"ProcessId":1234}
        /// </summary>
        public static string CallWmiMethod(string className, string methodName,
            string inputJson = null, string ns = "root\\cimv2")
        {
            byte[] nsBytes = Encoding.UTF8.GetBytes(ns);
            byte[] classBytes = Encoding.UTF8.GetBytes(className);
            byte[] methodBytes = Encoding.UTF8.GetBytes(methodName);
            byte[] inBytes = Encoding.UTF8.GetBytes(inputJson ?? "");
            byte[] outBuf = new byte[DefaultBufSize];

            uint written;
            fixed (byte* nPtr = nsBytes)
            fixed (byte* cPtr = classBytes)
            fixed (byte* mPtr = methodBytes)
            fixed (byte* iPtr = inBytes)
            fixed (byte* oPtr = outBuf)
            {
                written = WmiMethod(
                    nPtr, (uint)nsBytes.Length,
                    cPtr, (uint)classBytes.Length,
                    mPtr, (uint)methodBytes.Length,
                    iPtr, (uint)inBytes.Length,
                    oPtr, (uint)outBuf.Length);
            }

            if (written == 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>
        /// Call EnumLogonSessions and return raw result string.
        /// </summary>
        public static string CallEnumLogonSessions()
        {
            byte[] outBuf = new byte[DefaultBufSize];
            uint written;
            fixed (byte* oPtr = outBuf)
            {
                written = EnumLogonSessions(oPtr, (uint)outBuf.Length);
            }
            if (written == 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }
    }
}

// ── FileSecurity / GetAccessControl compat helpers ───────────────────────
// .NET 5+ removed the static File.GetAccessControl(string) method and made
// it an extension method on FileInfo via System.Security.AccessControl.
// FileSystemAclExtensions. To keep csharp_patcher's string-replacement
// simple, we wrap the new API in helpers that take the original signatures.
namespace WasmForge.Bridge
{
    public static class FileSecurityCompat
    {
        // In .NET 5+ the static File/Directory.GetAccessControl are gone and
        // GetAccessControl is provided as extension methods via
        // System.Security.AccessControl.FileSystemAclExtensions. We call
        // those statics explicitly here so callers don't need to import
        // the namespace.
        public static global::System.Security.AccessControl.FileSecurity GetFileAccessControl(string path) =>
            global::System.IO.FileSystemAclExtensions.GetAccessControl(
                new global::System.IO.FileInfo(path));

        public static global::System.Security.AccessControl.FileSecurity GetFileAccessControl(
            string path,
            global::System.Security.AccessControl.AccessControlSections sections) =>
            global::System.IO.FileSystemAclExtensions.GetAccessControl(
                new global::System.IO.FileInfo(path), sections);

        public static global::System.Security.AccessControl.DirectorySecurity GetDirectoryAccessControl(string path) =>
            global::System.IO.FileSystemAclExtensions.GetAccessControl(
                new global::System.IO.DirectoryInfo(path));

        public static global::System.Security.AccessControl.DirectorySecurity GetDirectoryAccessControl(
            string path,
            global::System.Security.AccessControl.AccessControlSections sections) =>
            global::System.IO.FileSystemAclExtensions.GetAccessControl(
                new global::System.IO.DirectoryInfo(path), sections);
    }
}

// ── System.Web.Script.Serialization compat stub ──────────────────────────
// NativeAOT-WASI doesn't ship System.Web.Extensions.dll.  We provide a thin
// shim over System.Text.Json so that existing JavaScriptSerializer call-sites
// (Chromium bookmarks, Slack, JSON output sinks) compile and work unchanged.
//
// Reflection-based JsonSerializer.Deserialize<T> is disabled in NativeAOT-WASI
// trimmed builds. We hand-walk JsonDocument and build Dictionary<string,object>/
// ArrayList trees — the exact shape legacy JavaScriptSerializer produced.
namespace System.Web.Script.Serialization
{
    public class JavaScriptSerializer
    {
        // Maximum input length (ignored — present for source compat)
        public int MaxJsonLength { get; set; } = 2097152;

        public T Deserialize<T>(string input)
        {
            using var doc = global::System.Text.Json.JsonDocument.Parse(input);
            object result = ConvertElement(doc.RootElement);
            return (T)result!;
        }

        public string Serialize(object obj) =>
            global::System.Text.Json.JsonSerializer.Serialize(obj);

        // Recursive converter: JsonElement → Dictionary<string,object>/ArrayList/
        // string/double/bool/null. Matches legacy JavaScriptSerializer semantics.
        private static object ConvertElement(global::System.Text.Json.JsonElement el)
        {
            switch (el.ValueKind)
            {
                case global::System.Text.Json.JsonValueKind.Object:
                    var dict = new global::System.Collections.Generic.Dictionary<string, object>();
                    foreach (var prop in el.EnumerateObject())
                        dict[prop.Name] = ConvertElement(prop.Value);
                    return dict;
                case global::System.Text.Json.JsonValueKind.Array:
                    var arr = new global::System.Collections.ArrayList();
                    foreach (var item in el.EnumerateArray())
                        arr.Add(ConvertElement(item));
                    return arr;
                case global::System.Text.Json.JsonValueKind.String:
                    return el.GetString() ?? "";
                case global::System.Text.Json.JsonValueKind.Number:
                    if (el.TryGetInt64(out long lv)) return lv;
                    return el.GetDouble();
                case global::System.Text.Json.JsonValueKind.True:
                    return true;
                case global::System.Text.Json.JsonValueKind.False:
                    return false;
                case global::System.Text.Json.JsonValueKind.Null:
                case global::System.Text.Json.JsonValueKind.Undefined:
                default:
                    return null!;
            }
        }
    }
}
