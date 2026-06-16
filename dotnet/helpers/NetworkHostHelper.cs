// NetworkHostHelper.cs — C# wrappers for network host functions.
//
// Bridges Rubeus's network operations to WasmForge host functions:
// - TcpSendRecv: Kerberos AS-REQ/TGS-REQ over TCP (fixes asktgt)
// - GetDCIP: Domain controller discovery via DsGetDcNameW (fixes GetDCIP)
// - LdapSearch: LDAP queries via wldap32.dll (fixes kerberoast)
//
// These bypass WASI P2 sockets (which are no-op stubs) by running
// network operations entirely on the host.

using System;
using System.Collections.Generic;
using System.Text;

namespace WasmForge.Bridge
{
    /// <summary>
    /// Bridges Rubeus network operations to WasmForge host functions.
    /// </summary>
    public static class NetworkHostHelper
    {
        /// <summary>
        /// Send data to a TCP server and receive the response.
        /// Uses Kerberos TCP framing (4-byte big-endian length prefix).
        /// Drop-in replacement for Networking.SendBytes().
        /// </summary>
        public static byte[] TcpSendRecv(string host, int port, byte[] data)
        {
            if (string.IsNullOrEmpty(host) || data == null || data.Length == 0)
                return null;

            byte[] hostBytes = Encoding.UTF8.GetBytes(host);
            byte[] outBuf = new byte[WfHostBridge.DefaultBufSize];

            uint written;
            unsafe
            {
                fixed (byte* hPtr = hostBytes)
                fixed (byte* dPtr = data)
                fixed (byte* oPtr = outBuf)
                {
                    written = WfHostBridge.TcpSendRecv(
                        hPtr, (uint)hostBytes.Length,
                        (uint)port,
                        dPtr, (uint)data.Length,
                        oPtr, (uint)outBuf.Length);
                }
            }

            if (written == 0) return null;
            byte[] result = new byte[written];
            Array.Copy(outBuf, result, (int)written);
            return result;
        }

        /// <summary>
        /// Resolve the IP address of a domain controller.
        /// Drop-in replacement for Networking.GetDCIP().
        /// </summary>
        public static string GetDCIP(string domainName, uint flags = 0)
        {
            if (string.IsNullOrEmpty(domainName)) return null;

            byte[] domainBytes = Encoding.UTF8.GetBytes(domainName);
            byte[] outBuf = new byte[WfHostBridge.SmallBufSize];

            uint written;
            unsafe
            {
                fixed (byte* dPtr = domainBytes)
                fixed (byte* oPtr = outBuf)
                {
                    written = WfHostBridge.GetDCName(
                        dPtr, (uint)domainBytes.Length,
                        flags,
                        oPtr, (uint)outBuf.Length);
                }
            }

            if (written == 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, (int)written);
        }

        /// <summary>
        /// Execute an LDAP search query and return structured results.
        /// Each entry is a dictionary of attribute name to list of values.
        /// </summary>
        public static List<Dictionary<string, List<string>>> LdapSearch(
            string server, int port, string baseDN, string filter, string[] attributes,
            string username = null, string password = null, string domain = null)
        {
            if (string.IsNullOrEmpty(server))
                return new List<Dictionary<string, List<string>>>();

            byte[] serverBytes = Encoding.UTF8.GetBytes(server);
            byte[] baseDNBytes = Encoding.UTF8.GetBytes(baseDN ?? "");
            byte[] filterBytes = Encoding.UTF8.GetBytes(filter ?? "(objectClass=*)");
            string attrsJoined = attributes != null ? string.Join("\t", attributes) : "";
            byte[] attrsBytes = Encoding.UTF8.GetBytes(attrsJoined);
            byte[] outBuf = new byte[WfHostBridge.DefaultBufSize];

            bool useCreds = !string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password);
            byte[] userBytes = Encoding.UTF8.GetBytes(username ?? "");
            byte[] domainBytes = Encoding.UTF8.GetBytes(domain ?? "");
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password ?? "");

            uint written;
            unsafe
            {
                fixed (byte* sPtr = serverBytes)
                fixed (byte* bPtr = baseDNBytes)
                fixed (byte* fPtr = filterBytes)
                fixed (byte* aPtr = attrsBytes)
                fixed (byte* uPtr = userBytes)
                fixed (byte* dPtr = domainBytes)
                fixed (byte* pwPtr = passwordBytes)
                fixed (byte* oPtr = outBuf)
                {
                    if (useCreds)
                    {
                        written = WfHostBridge.LdapSearchExt(
                            sPtr, (uint)serverBytes.Length, (uint)port,
                            bPtr, (uint)baseDNBytes.Length,
                            fPtr, (uint)filterBytes.Length,
                            aPtr, (uint)attrsBytes.Length,
                            uPtr, (uint)userBytes.Length,
                            dPtr, (uint)domainBytes.Length,
                            pwPtr, (uint)passwordBytes.Length,
                            oPtr, (uint)outBuf.Length);
                    }
                    else
                    {
                        written = WfHostBridge.LdapSearch(
                            sPtr, (uint)serverBytes.Length, (uint)port,
                            bPtr, (uint)baseDNBytes.Length,
                            fPtr, (uint)filterBytes.Length,
                            aPtr, (uint)attrsBytes.Length,
                            oPtr, (uint)outBuf.Length);
                    }
                }
            }

            if (written == 0) return new List<Dictionary<string, List<string>>>();
            return ParseLdapResults(Encoding.UTF8.GetString(outBuf, 0, (int)written));
        }

        private static List<Dictionary<string, List<string>>> ParseLdapResults(string raw)
        {
            var results = new List<Dictionary<string, List<string>>>();
            string[] entries = raw.Split('\0');

            foreach (string entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;

                var dict = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in entry.Split('\n'))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    int tab = line.IndexOf('\t');
                    if (tab < 0) continue;

                    string attr = line.Substring(0, tab);
                    string value = line.Substring(tab + 1);

                    if (!dict.ContainsKey(attr))
                        dict[attr] = new List<string>();
                    dict[attr].Add(value);
                }

                if (dict.Count > 0) results.Add(dict);
            }

            return results;
        }
    }
}
