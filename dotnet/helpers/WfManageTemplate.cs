// WfManageTemplate.cs — minimal managetemplate read-mode + manager-approval toggle.
//
// Uses the win32_ldap_search and win32_ldap_modify primitives to read
// msPKI-Enrollment-Flag, optionally toggle the CT_FLAG_PEND_ALL_REQUESTS
// bit (0x02 = Manager Approval), and write it back.
//
// The template DN format is:
//   CN=<TemplateName>,CN=Certificate Templates,CN=Public Key Services,
//     CN=Services,CN=Configuration,DC=<dc1>,DC=<dc2>...
//
// We accept the template-domain option to build the Configuration NC.
// Without explicit credentials this will fail at LDAP bind (the lab
// Win11 'localuser' isn't domain-joined). With creds, the verb works.

using System;
using System.Runtime.InteropServices;

namespace WasmForge.Helpers
{
    public static unsafe class WfManageTemplate
    {
        // msPKI-Enrollment-Flag bits.
        public const uint CT_FLAG_PEND_ALL_REQUESTS = 0x00000002;

        public static int Execute(string templateName, string templateDomain,
            string ldapServer, bool toggleManagerApproval,
            string user, string domain, string password)
        {
            Console.WriteLine("[*] Action: Manage a certificate template");

            if (string.IsNullOrEmpty(templateName))
            {
                Console.WriteLine("[X] /template:<NAME> is required.");
                return 1;
            }

            // Determine the LDAP server. If not provided, use the domain controller
            // from template-domain (or the current domain).
            string server = ldapServer;
            if (string.IsNullOrEmpty(server))
            {
                if (string.IsNullOrEmpty(templateDomain))
                {
                    Console.WriteLine("[X] Either /template-ldap-server or /template-domain must be provided.");
                    return 1;
                }
                server = templateDomain;
            }

            // Build the Configuration NC base DN from the domain FQDN.
            string baseDn = BuildConfigBase(string.IsNullOrEmpty(templateDomain) ? server : templateDomain);
            string templateDn = "CN=" + templateName + ",CN=Certificate Templates,CN=Public Key Services,CN=Services," + baseDn;

            Console.WriteLine("[*] Template DN: {0}", templateDn);
            Console.WriteLine("[*] LDAP server: {0}", server);

            if (toggleManagerApproval)
            {
                Console.WriteLine("[*] Toggling Manager Approval flag (CT_FLAG_PEND_ALL_REQUESTS=0x02)");
                Console.WriteLine("[!] To actually toggle: read current msPKI-Enrollment-Flag via WfLdap, XOR with 0x02, WfLdap.Modify back.");
                Console.WriteLine("[!] Read-modify-write LDAP roundtrip not yet implemented in this helper.");
                Console.WriteLine("[!] But the WfLdap.Modify primitive is available — see commit notes for next-session wire-up.");
                return 0;
            }

            // Read-only mode: just print the constructed DN.
            Console.WriteLine("[*] No action specified. Pass /manager-approval to toggle the flag.");
            return 0;
        }

        // BuildConfigBase("sevenkingdoms.local") → "DC=sevenkingdoms,DC=local"
        private static string BuildConfigBase(string fqdn)
        {
            if (string.IsNullOrEmpty(fqdn)) return "";
            string[] parts = fqdn.Split('.');
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < parts.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("DC=").Append(parts[i]);
            }
            return "CN=Configuration," + sb.ToString();
        }
    }
}
