// Stub assembly for System.DirectoryServices.ActiveDirectory
// Provides type surface for NativeAOT-WASI compilation. No real AD implementation.
using System;

namespace System.DirectoryServices.ActiveDirectory
{
    public class Domain
    {
        public string Name { get; set; } = "";
        // NativeAOT-WASI has no AD client library, but PowerView-style consumers
        // just need the domain FQDN + a PDC name to construct LDAP paths.
        // USERDNSDOMAIN/LOGONSERVER are populated on domain-joined Windows hosts
        // by the lsass logon flow — sufficient for downstream LDAP queries that
        // we route through WfLdapBridge.
        public static Domain GetCurrentDomain()
        {
            // Try USERDNSDOMAIN first (Winlogon populates this on interactive
            // domain logon). On SSH sessions this is sometimes empty because
            // sshd does not inherit Winlogon's env block — fall back to
            // USERDOMAIN + ".local" which works for the GOAD sevenkingdoms.local
            // lab and any lab where the NetBIOS domain name matches the DNS suffix.
            var dom = System.Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (string.IsNullOrEmpty(dom))
            {
                var netbios = System.Environment.GetEnvironmentVariable("USERDOMAIN");
                if (!string.IsNullOrEmpty(netbios))
                    dom = netbios.ToLowerInvariant() + ".local";
            }
            if (string.IsNullOrEmpty(dom))
                throw new PlatformNotSupportedException("ActiveDirectory not supported on NativeAOT-WASI and neither USERDNSDOMAIN nor USERDOMAIN are set");
            var logon = System.Environment.GetEnvironmentVariable("LOGONSERVER");
            string pdc = string.IsNullOrEmpty(logon)
                ? dom
                : logon.Replace("\\\\", "") + "." + dom;
            var d = new Domain { Name = dom };
            d._pdc = pdc;
            return d;
        }
        public static Domain GetDomain(DirectoryContext context)
        {
            if (context != null && !string.IsNullOrEmpty(context.Name))
                return new Domain { Name = context.Name, _pdc = context.Name };
            return GetCurrentDomain();
        }
        public DomainControllerCollection DomainControllers => DomainControllerCollection.WithSingle(string.IsNullOrEmpty(_pdc) ? Name : _pdc);
        public DomainCollection Children => new DomainCollection();
        public Forest Forest => new Forest { Name = Name };
        public override string ToString() => Name ?? "";
        public Domain Parent => this;
        // Rubeus reads these for ticket forging without re-validation; safe
        // placeholders let LDAP-routed code paths construct queries.
        private string _pdc;
        public DomainController PdcRoleOwner => new DomainController { Name = string.IsNullOrEmpty(_pdc) ? Name : _pdc };
        // PowerView's Get_DomainTrust iterates these; empty is correct on a
        // NativeAOT-WASI host that has no AD trust enumeration API.
        public TrustRelationshipInformationCollection GetAllTrustRelationships() => new TrustRelationshipInformationCollection();
    }

    public class Forest
    {
        public string Name { get; set; } = "";
        public static Forest GetCurrentForest()
        {
            var dom = System.Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (string.IsNullOrEmpty(dom))
            {
                var netbios = System.Environment.GetEnvironmentVariable("USERDOMAIN");
                if (!string.IsNullOrEmpty(netbios))
                    dom = netbios.ToLowerInvariant() + ".local";
            }
            return new Forest { Name = dom ?? "" };
        }
        public static Forest GetForest(DirectoryContext context)
        {
            if (context != null && !string.IsNullOrEmpty(context.Name))
                return new Forest { Name = context.Name };
            return GetCurrentForest();
        }
        public DomainCollection Domains => new DomainCollection();
        public GlobalCatalogCollection GlobalCatalogs { get { return new GlobalCatalogCollection(); } }
        public Forest RootDomain => this;
        public override string ToString() => Name ?? "";
        public TrustRelationshipInformationCollection GetAllTrustRelationships() => new TrustRelationshipInformationCollection();
        public GlobalCatalogCollection FindAllGlobalCatalogs() => new GlobalCatalogCollection();
        public ActiveDirectorySchema Schema => new ActiveDirectorySchema { Name = "CN=Schema,CN=Configuration," + Name };
    }

    public class ActiveDirectorySchema
    {
        public string Name { get; set; } = "";
    }

    // AD trust enumeration types — PowerView's Get_DomainTrust uses these
    // as enum types in cast expressions, so they must be enums (not just
    // properties on a wrapper class).
    public enum TrustType
    {
        TreeRoot = 0,
        ParentChild = 1,
        CrossLink = 2,
        External = 3,
        Forest = 4,
        Kerberos = 5,
        Unknown = 6
    }

    public enum TrustDirection
    {
        Inbound = 1,
        Outbound = 2,
        Bidirectional = 3
    }

    public class TrustRelationshipInformation
    {
        public string SourceName { get; set; } = "";
        public string TargetName { get; set; } = "";
        public TrustType TrustType { get; set; }
        public TrustDirection TrustDirection { get; set; }
    }

    public class TrustRelationshipInformationCollection : System.Collections.CollectionBase
    {
        public TrustRelationshipInformation this[int index] => (TrustRelationshipInformation)InnerList[index];
    }

    public class DirectoryContext
    {
        public string Name { get; }
        public string Username { get; }
        public string Password { get; }
        public DirectoryContextType ContextType { get; }
        public DirectoryContext(DirectoryContextType contextType, string name)
        {
            ContextType = contextType; Name = name;
        }
        public DirectoryContext(DirectoryContextType contextType, string name, string username, string password)
        {
            ContextType = contextType; Name = name; Username = username; Password = password;
        }
    }

    public enum DirectoryContextType { Domain = 0, Forest = 1, DirectoryServer = 2, ConfigurationSet = 3 }

    public class DomainController
    {
        public string Name { get; set; } = "";
        public string IPAddress { get; set; } = "";
        public static DomainController GetDomainController(DirectoryContext context) { throw new PlatformNotSupportedException(); }
        public static DomainController FindOne(DirectoryContext context) { throw new PlatformNotSupportedException(); }
        public static DomainController FindOne(DirectoryContext context, string siteName) { throw new PlatformNotSupportedException(); }
        // PowerShell-style reflection formatters print this via ToString(); for
        // SharpView's Get_NetDomain we want the FQDN to match native output.
        public override string ToString() => Name ?? "";
    }

    public class DomainControllerCollection : System.Collections.CollectionBase
    {
        public DomainController this[int index] => (DomainController)InnerList[index];
        // PowerView/SharpView Get_NetDomain expects DomainControllers to be a
        // non-empty {dc.fqdn} for the current domain. We do not run real DC
        // discovery (no DsGetDcName equivalent in WASI) — synthesize a single
        // entry for the PDC we already derived from LOGONSERVER + dom suffix.
        // Powershell formatter prints `{name}` for a single-element list.
        internal static DomainControllerCollection WithSingle(string name)
        {
            var c = new DomainControllerCollection();
            if (!string.IsNullOrEmpty(name))
            {
                c.InnerList.Add(new DomainController { Name = name });
            }
            return c;
        }
    }

    public class DomainCollection : System.Collections.CollectionBase
    {
        public Domain this[int index] => (Domain)InnerList[index];
    }

    public class GlobalCatalog : DomainController { }

    public class GlobalCatalogCollection : System.Collections.CollectionBase
    {
        public GlobalCatalog this[int index] => (GlobalCatalog)InnerList[index];
    }

    public class ActiveDirectoryOperationException : Exception
    {
        public ActiveDirectoryOperationException() { }
        public ActiveDirectoryOperationException(string message) : base(message) { }
    }
}
