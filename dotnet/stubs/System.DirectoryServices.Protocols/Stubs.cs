// System.DirectoryServices.Protocols stub for NativeAOT-WASI.
// Provides LDAP protocol types used by Rubeus for direct LDAP queries.

using System;
using System.Collections;

namespace System.DirectoryServices.Protocols
{
    public class LdapConnection : IDisposable
    {
        public LdapConnection(string server) { }
        public LdapConnection(LdapDirectoryIdentifier identifier) { }
        public LdapConnection(LdapDirectoryIdentifier identifier, System.Net.NetworkCredential credential) { }

        public System.Net.NetworkCredential Credential { get; set; }
        public AuthType AuthType { get; set; }
        public LdapSessionOptions SessionOptions => new LdapSessionOptions();
        public TimeSpan Timeout { get; set; }

        public void Bind() => throw new PlatformNotSupportedException("LDAP not available in NativeAOT-WASI");
        public void Bind(System.Net.NetworkCredential credential) => throw new PlatformNotSupportedException("LDAP not available in NativeAOT-WASI");
        public DirectoryResponse SendRequest(DirectoryRequest request) => throw new PlatformNotSupportedException("LDAP not available in NativeAOT-WASI");
        public void Dispose() { }
    }

    public class LdapDirectoryIdentifier
    {
        public LdapDirectoryIdentifier(string server) { }
        public LdapDirectoryIdentifier(string server, int portNumber) { }
        public LdapDirectoryIdentifier(string[] servers, bool fullyQualifiedDnsHostName, bool connectionless) { }
        public string[] Servers => Array.Empty<string>();
    }

    public delegate bool VerifyServerCertificateCallback(LdapConnection connection,
        System.Security.Cryptography.X509Certificates.X509Certificate certificate);

    public class LdapSessionOptions
    {
        public bool Signing { get; set; }
        public bool Sealing { get; set; }
        public int ProtocolVersion { get; set; }
        public ReferralChasingOptions ReferralChasing { get; set; }
        public bool SecureSocketLayer { get; set; }
        public VerifyServerCertificateCallback VerifyServerCertificate { get; set; }
    }

    public abstract class DirectoryControl
    {
        public string Type { get; set; }
        public byte[] Value { get; set; }
        public bool IsCritical { get; set; }
    }

    public class DirectoryControlCollection : System.Collections.Generic.List<DirectoryControl> { }

    public class PageResultRequestControl : DirectoryControl
    {
        public int PageSize { get; set; }
        public byte[] Cookie { get; set; } = Array.Empty<byte>();
        public PageResultRequestControl() { Type = "1.2.840.113556.1.4.319"; }
        public PageResultRequestControl(int pageSize) { Type = "1.2.840.113556.1.4.319"; PageSize = pageSize; }
    }

    public class PageResultResponseControl : DirectoryControl
    {
        public byte[] Cookie { get; set; } = Array.Empty<byte>();
        public int TotalCount { get; set; }
        public PageResultResponseControl() { Type = "1.2.840.113556.1.4.319"; }
    }

    public abstract class DirectoryRequest
    {
        public DirectoryControlCollection Controls { get; } = new DirectoryControlCollection();
    }
    public abstract class DirectoryResponse
    {
        public DirectoryControl[] Controls { get; set; } = Array.Empty<DirectoryControl>();
        public ResultCode ResultCode { get; set; } = ResultCode.Success;
    }

    public class SearchRequest : DirectoryRequest
    {
        public string DistinguishedName { get; set; }
        public string Filter { get; set; }
        public SearchScope Scope { get; set; }
        public StringCollection Attributes { get; } = new StringCollection();

        public SearchRequest() { }
        public SearchRequest(string distinguishedName, string ldapFilter, SearchScope searchScope, params string[] attributeList)
        {
            DistinguishedName = distinguishedName;
            Filter = ldapFilter;
            Scope = searchScope;
            if (attributeList != null)
                foreach (var a in attributeList) Attributes.Add(a);
        }
    }

    public class SearchResponse : DirectoryResponse
    {
        public SearchResultEntryCollection Entries { get; } = new SearchResultEntryCollection();
    }

    public enum ResultCode
    {
        Success = 0, OperationsError = 1, ProtocolError = 2, TimeLimitExceeded = 3,
        SizeLimitExceeded = 4, CompareFalse = 5, CompareTrue = 6,
        AuthMethodNotSupported = 7, StrongAuthRequired = 8, Referral = 10,
        AdminLimitExceeded = 11, UnavailableCriticalExtension = 12,
        ConfidentialityRequired = 13, SaslBindInProgress = 14,
        NoSuchAttribute = 16, UndefinedAttributeType = 17,
        InappropriateMatching = 18, ConstraintViolation = 19,
        AttributeOrValueExists = 20, InvalidAttributeSyntax = 21,
        NoSuchObject = 32, AliasProblem = 33, InvalidDNSyntax = 34,
        AliasDereferencingProblem = 36, InappropriateAuthentication = 48,
        InsufficientAccessRights = 50, Busy = 51, Unavailable = 52,
        UnwillingToPerform = 53, LoopDetect = 54,
        NamingViolation = 64, ObjectClassViolation = 65,
        NotAllowedOnNonLeaf = 66, NotAllowedOnRdn = 67,
        EntryAlreadyExists = 68, ObjectClassModificationsProhibited = 69,
        AffectsMultipleDsas = 71, Other = 80,
    }

    public class SearchResultEntry
    {
        public string DistinguishedName => "";
        public SearchResultAttributeCollection Attributes { get; } = new SearchResultAttributeCollection();
    }

    public class SearchResultEntryCollection : IEnumerable
    {
        public int Count => 0;
        public SearchResultEntry this[int index] => throw new IndexOutOfRangeException();
        public IEnumerator GetEnumerator() { yield break; }
    }

    public class SearchResultAttributeCollection : IEnumerable
    {
        public DirectoryAttribute this[string attributeName] => null;
        public bool Contains(string attributeName) => false;
        public ICollection AttributeNames => Array.Empty<string>();
        public IEnumerator GetEnumerator() { yield break; }
    }

    public class DirectoryAttribute : IEnumerable
    {
        public string Name => "";
        public int Count => 0;
        public object this[int index] => throw new IndexOutOfRangeException();
        public object[] GetValues(Type valType) => Array.Empty<object>();
        public IEnumerator GetEnumerator() { yield break; }
    }

    public class StringCollection : IList
    {
        private readonly ArrayList _list = new ArrayList();
        public int Add(string value) => _list.Add(value);
        public int Count => _list.Count;
        public string this[int index] { get => (string)_list[index]; set => _list[index] = value; }
        bool IList.IsReadOnly => false;
        bool IList.IsFixedSize => false;
        object IList.this[int index] { get => _list[index]; set => _list[index] = value; }
        int IList.Add(object v) => _list.Add(v);
        bool IList.Contains(object v) => _list.Contains(v);
        int IList.IndexOf(object v) => _list.IndexOf(v);
        void IList.Insert(int i, object v) => _list.Insert(i, v);
        void IList.Remove(object v) => _list.Remove(v);
        void IList.RemoveAt(int i) => _list.RemoveAt(i);
        void IList.Clear() => _list.Clear();
        void ICollection.CopyTo(Array a, int i) => _list.CopyTo(a, i);
        bool ICollection.IsSynchronized => false;
        object ICollection.SyncRoot => _list.SyncRoot;
        public IEnumerator GetEnumerator() => _list.GetEnumerator();
    }

    public enum AuthType { Anonymous = 0, Basic = 1, Negotiate = 2, Ntlm = 3, Digest = 4, Sicily = 5, Dpa = 6, Msn = 7, External = 8, Kerberos = 9 }
    public enum SearchScope { Base = 0, OneLevel = 1, Subtree = 2 }
    public enum ReferralChasingOptions { None = 0, Subordinate = 0x20, External = 0x40, All = 0x60 }
}
