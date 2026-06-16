// WfPrivRights.cs — wraps the env-side priv_rights helper for Seatbelt's
// UserRightAssignmentsCommand. The env helper does the full LSA pipeline
// in host memory (LsaOpenPolicy + LsaEnumerateAccountsWithUserRight +
// ConvertSidToStringSidW) and returns "RightName|sid1,sid2,...\n" entries
// in a flat byte buffer.
//
// See bridge/pinvoke_env_ext.c::priv_rights for the host implementation
// and the LSA bridge test harness at test/lsa-harness/ for the diagnostic
// that proved the host-memory deep-marshal pattern is required.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WasmForge.Helpers
{
    public static unsafe class WfPrivRights
    {
        [DllImport("env", EntryPoint = "priv_rights")]
        private static extern uint priv_rights(byte* outBuf, uint outCap, uint* countPtr);

        // Enumerate well-known user rights via the env helper. Returns a
        // map of right-name → list of SDDL SID strings. Empty if the env
        // helper isn't registered or LSA enumeration fails.
        public static Dictionary<string, List<string>> Enumerate()
        {
            var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var buf = new byte[65536];
                uint count = 0;
                uint bytes;
                fixed (byte* bp = buf)
                    bytes = priv_rights(bp, (uint)buf.Length, &count);
                if (bytes == 0) return result;
                string text = Encoding.UTF8.GetString(buf, 0, (int)bytes);
                foreach (var line in text.Split('\n'))
                {
                    if (string.IsNullOrEmpty(line)) continue;
                    int pipe = line.IndexOf('|');
                    if (pipe <= 0) continue;
                    string rightName = line.Substring(0, pipe);
                    string sidsCsv = line.Substring(pipe + 1);
                    var sids = new List<string>();
                    if (!string.IsNullOrEmpty(sidsCsv))
                    {
                        foreach (var sid in sidsCsv.Split(','))
                        {
                            if (!string.IsNullOrEmpty(sid)) sids.Add(sid);
                        }
                    }
                    result[rightName] = sids;
                }
            }
            catch { /* return whatever we parsed */ }
            return result;
        }

        // Return a list of Principal objects for the given privilege. The
        // map is what Enumerate() returned; principal resolution piggy-
        // backs on WfToken.ResolveWellKnownSid for canonical names and
        // falls back to the SDDL form for everything else.
        // Type is `dynamic List<Principal>` — we use reflection-free
        // construction via the Seatbelt.Interop.Netapi32.Principal type.
        // Returns tuples (sid, user, domain) because the Seatbelt Principal
        // class is internal. The caller in UserRightAssignmentsCommand
        // turns these into Principal instances locally.
        public static List<(string Sid, string User, string Domain)> ReadSids(
            Dictionary<string, List<string>> map, string rightName)
        {
            var result = new List<(string, string, string)>();
            if (map == null) return result;
            if (!map.TryGetValue(rightName, out var sids) || sids == null) return result;

            foreach (var sddl in sids)
            {
                // First try the well-known SID table (covers ~70 canonical
                // accounts: BUILTIN\Administrators, NT AUTHORITY\NETWORK
                // SERVICE, Everyone, etc). For everything else — domain
                // SIDs like S-1-5-21-...-1003 — fall back to WfSec.SidToAccountName
                // which calls LookupAccountSidW via the advapi32 bridge.
                // Without this fallback, domain SIDs print as raw SDDL in the
                // UserRightAssignmentsTextFormatter output.
                string accountName = WfToken.ResolveWellKnownSid(sddl);
                if (string.IsNullOrEmpty(accountName))
                    accountName = WfSec.SidToAccountName(sddl);
                string user = "", domain = "";
                if (!string.IsNullOrEmpty(accountName))
                {
                    int slash = accountName.IndexOf('\\');
                    if (slash > 0) { domain = accountName.Substring(0, slash); user = accountName.Substring(slash + 1); }
                    else { user = accountName; }
                }
                result.Add((sddl, user, domain));
            }
            return result;
        }
    }
}
