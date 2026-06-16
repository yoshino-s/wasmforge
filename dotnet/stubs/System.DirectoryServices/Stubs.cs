// System.DirectoryServices stub for NativeAOT-WASI compilation.
// Provides enough type surface for Rubeus to compile. LDAP operations
// throw PlatformNotSupportedException at runtime — LDAP-dependent
// Rubeus commands (kerberoast auto-SPN, s4u DC lookup) are non-functional
// until real LDAP host functions are implemented.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace System.DirectoryServices
{
    /// <summary>Bridge to WasmForge's host LDAP search function.
    /// Replicated here (rather than calling WfHostBridge) to keep the stub
    /// project free of cross-references to the consumer's helpers folder.</summary>
    internal static unsafe class WfLdapBridge
    {
        [DllImport("*", EntryPoint = "WfLdapSearch")]
        internal static extern uint WfLdapSearch(
            byte* serverPtr, uint serverLen, uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* outBufPtr, uint outBufLen);

        [DllImport("*", EntryPoint = "WfLdapSearchExt")]
        internal static extern uint WfLdapSearchExt(
            byte* serverPtr, uint serverLen, uint port,
            byte* baseDNPtr, uint baseDNLen,
            byte* filterPtr, uint filterLen,
            byte* attrsPtr, uint attrsLen,
            byte* userPtr, uint userLen,
            byte* domainPtr, uint domainLen,
            byte* passwordPtr, uint passwordLen,
            byte* outBufPtr, uint outBufLen);

        /// <summary>Returns the joined-domain DNS suffix (e.g.
        /// "sevenkingdoms.local") via USERDNSDOMAIN, with USERDOMAIN +
        /// ".local" as a fallback for SSH sessions that didn't inherit
        /// Winlogon's env block. Empty string if neither is available.</summary>
        internal static string ResolveDomainDns()
        {
            string dom = System.Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (!string.IsNullOrEmpty(dom)) return dom.ToLowerInvariant();
            string netbios = System.Environment.GetEnvironmentVariable("USERDOMAIN");
            if (!string.IsNullOrEmpty(netbios)) return netbios.ToLowerInvariant() + ".local";
            return "";
        }

        /// <summary>Parses "LDAP://server/dn" / "LDAP://dn" / "LDAP://RootDSE".
        /// Returns (server="" if absent, dn="" for RootDSE).</summary>
        internal static (string server, string dn) ParsePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return ("", "");
            string s = path;
            if (s.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(7);
            if (s.Equals("RootDSE", StringComparison.OrdinalIgnoreCase))
                return ("", "");
            // If first segment contains no '=', it's a server name (DN segments have '=').
            int slash = s.IndexOf('/');
            if (slash > 0)
            {
                string head = s.Substring(0, slash);
                string tail = s.Substring(slash + 1);
                if (!head.Contains("="))
                {
                    if (tail.Equals("RootDSE", StringComparison.OrdinalIgnoreCase))
                        return (head, "");
                    return (head, tail);
                }
            }
            return ("", s);
        }

        internal static List<Dictionary<string, List<string>>> Search(
            string server, string baseDN, string filter, string[] attributes,
            string username = null, string password = null, string domain = null)
        {
            byte[] serverBytes = Encoding.UTF8.GetBytes(server ?? "");
            byte[] baseDNBytes = Encoding.UTF8.GetBytes(baseDN ?? "");
            byte[] filterBytes = Encoding.UTF8.GetBytes(filter ?? "(objectClass=*)");
            string attrsJoined = attributes != null ? string.Join("\t", attributes) : "";
            byte[] attrsBytes = Encoding.UTF8.GetBytes(attrsJoined);
            byte[] outBuf = new byte[512 * 1024];

            bool useCreds = !string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password);
            byte[] userBytes = Encoding.UTF8.GetBytes(username ?? "");
            byte[] domainBytes = Encoding.UTF8.GetBytes(domain ?? "");
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password ?? "");

            uint written;
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
                    written = WfLdapSearchExt(
                        sPtr, (uint)serverBytes.Length, 389,
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
                    written = WfLdapSearch(
                        sPtr, (uint)serverBytes.Length, 389,
                        bPtr, (uint)baseDNBytes.Length,
                        fPtr, (uint)filterBytes.Length,
                        aPtr, (uint)attrsBytes.Length,
                        oPtr, (uint)outBuf.Length);
                }
            }

            var results = new List<Dictionary<string, List<string>>>();
            if (written == 0 || written > outBuf.Length) return results;
            string raw = Encoding.UTF8.GetString(outBuf, 0, (int)written);
            // Wire format: entries separated by \0, each entry has lines "attr: value"
            // separated by \n. Multi-valued attributes repeat the attr name.
            foreach (var entry in raw.Split('\0'))
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;
                var dict = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in entry.Split('\n'))
                {
                    int colon = line.IndexOf(':');
                    if (colon <= 0) continue;
                    string k = line.Substring(0, colon).Trim();
                    string v = colon + 1 < line.Length ? line.Substring(colon + 1).Trim() : "";
                    if (!dict.TryGetValue(k, out var list))
                    {
                        list = new List<string>();
                        dict[k] = list;
                    }
                    list.Add(v);
                }
                if (dict.Count > 0) results.Add(dict);
            }
            return results;
        }
    }

    public class DirectoryEntry : IDisposable
    {
        public string Path { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public AuthenticationTypes AuthenticationType { get; set; }
        public DirectoryEntries Children => new DirectoryEntries(this);
        public string SchemaClassName => "";
        public string Name => Path ?? "";

        private PropertyCollection _props;
        public PropertyCollection Properties
        {
            get
            {
                if (_props == null) LoadProperties();
                return _props;
            }
        }

        public ActiveDirectorySecurity ObjectSecurity { get; set; } = new ActiveDirectorySecurity();
        // PowerView uses DirectoryEntry.Options to twiddle SecurityMasks
        // before commit; ADS provider exposed this on real Windows.
        public DirectoryEntryConfiguration Options { get; } = new DirectoryEntryConfiguration();
        // InvokeGet/InvokeSet route to legacy IADs property bag on real
        // Windows; we route to Properties for parity with our LDAP path.
        public object InvokeGet(string propertyName)
        {
            if (string.IsNullOrEmpty(propertyName)) return null;
            var pvc = Properties[propertyName];
            return pvc != null && pvc.Count > 0 ? pvc.Value : null;
        }
        public void InvokeSet(string propertyName, params object[] args)
        {
            // No-op for stub: real implementation would update IADs; LDAP
            // modify must go through win32_ldap_modify bridge.
        }
        public object Invoke(string methodName, params object[] args) => null;

        public DirectoryEntry() { _props = new PropertyCollection(); }
        public DirectoryEntry(string path) { Path = path; }
        public DirectoryEntry(string path, string username, string password) { Path = path; Username = username; Password = password; }
        public DirectoryEntry(string path, string username, string password, AuthenticationTypes authenticationType)
        { Path = path; Username = username; Password = password; AuthenticationType = authenticationType; }

        internal void LoadProperties()
        {
            _props = new PropertyCollection();
            if (string.IsNullOrEmpty(Path)) return;

            // Special-case RootDSE: the standard LDAP RootDSE query is a
            // base-scope search on an empty DN, which our wldap32-backed
            // host helper can't represent directly. Synthesize the handful
            // of operational attributes Certify LdapOperations and PowerView
            // GetADObject read from RootDSE — they're computable from the
            // joined domain's DNS suffix (which our env var path already
            // exposes).
            if (Path.IndexOf("RootDSE", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                string dom = WfLdapBridge.ResolveDomainDns();
                if (!string.IsNullOrEmpty(dom))
                {
                    string dn = "DC=" + dom.Replace(".", ",DC=");
                    var entry = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>>(System.StringComparer.OrdinalIgnoreCase)
                    {
                        ["defaultNamingContext"]        = new System.Collections.Generic.List<string> { dn },
                        ["rootDomainNamingContext"]     = new System.Collections.Generic.List<string> { dn },
                        ["configurationNamingContext"]  = new System.Collections.Generic.List<string> { "CN=Configuration," + dn },
                        ["schemaNamingContext"]         = new System.Collections.Generic.List<string> { "CN=Schema,CN=Configuration," + dn },
                        ["dnsHostName"]                 = new System.Collections.Generic.List<string> { dom },
                        ["currentTime"]                 = new System.Collections.Generic.List<string> { System.DateTime.UtcNow.ToString("yyyyMMddHHmmss.0Z") },
                    };
                    _props.LoadFromDictionary(entry);
                    return;
                }
            }

            try
            {
                var (server, dn) = WfLdapBridge.ParsePath(Path);
                // Username/Password — defer to creds form if set so the host
                // can build a SEC_WINNT_AUTH_IDENTITY_W instead of falling
                // back to anonymous.
                var results = WfLdapBridge.Search(server, dn, "(objectClass=*)", null,
                    Username, Password, null);
                if (results.Count > 0)
                {
                    _props.LoadFromDictionary(results[0]);
                }
            }
            catch { /* return empty Properties */ }
        }

        public void CommitChanges() { }
        public void RefreshCache() { _props = null; }
        public void RefreshCache(string[] propertyNames) { _props = null; }
        public void Close() { }
        public void Dispose() { }
    }

    public class DirectoryEntries : IEnumerable
    {
        private readonly DirectoryEntry _parent;
        public DirectoryEntries() { }
        internal DirectoryEntries(DirectoryEntry parent) { _parent = parent; }
        public IEnumerator GetEnumerator()
        {
            // Children are obtained via a one-level search at the parent's path.
            if (_parent == null || string.IsNullOrEmpty(_parent.Path)) yield break;
            var (server, baseDN) = WfLdapBridge.ParsePath(_parent.Path);
            List<Dictionary<string, List<string>>> results;
            try { results = WfLdapBridge.Search(server, baseDN, "(objectClass=*)", null); }
            catch { yield break; }
            foreach (var entry in results)
            {
                if (entry.TryGetValue("distinguishedName", out var dnList) && dnList.Count > 0)
                {
                    var child = new DirectoryEntry("LDAP://" + dnList[0]);
                    yield return child;
                }
            }
        }
        public DirectoryEntry Add(string name, string schemaClassName) => new DirectoryEntry();
        public DirectoryEntry Find(string name) => null;
        public DirectoryEntry Find(string name, string schemaClassName) => null;
    }

    public class DirectorySearcher : IDisposable
    {
        public DirectoryEntry SearchRoot { get; set; }
        public string Filter { get; set; }
        public int SizeLimit { get; set; }
        public int PageSize { get; set; }
        public StringCollection PropertiesToLoad { get; } = new StringCollection();
        public SearchScope SearchScope { get; set; }
        public ReferralChasingOption ReferralChasing { get; set; }
        public bool CacheResults { get; set; }
        public SecurityMasks SecurityMasks { get; set; }
        // PowerView sets these for search tuning; they're no-ops in our
        // host-LDAP path but the type surface must exist.
        public TimeSpan ServerTimeLimit { get; set; }
        public TimeSpan ClientTimeout { get; set; }
        public bool Tombstone { get; set; }
        public bool Asynchronous { get; set; }
        public bool ExtendedDN { get; set; }

        public DirectorySearcher() { }
        public DirectorySearcher(DirectoryEntry entry) { SearchRoot = entry; }
        public DirectorySearcher(DirectoryEntry entry, string filter) { SearchRoot = entry; Filter = filter; }
        public DirectorySearcher(string filter) { Filter = filter; }

        public SearchResult FindOne()
        {
            var all = FindAll();
            foreach (SearchResult r in all) return r;
            // PowerView (and similar consumers) frequently dereferences
            // result.Properties[...] without null-checking the FindOne return
            // value. On a wasmforge build where LDAP can return empty (no DC
            // reachable, no creds, etc.) returning null causes NRE deep inside
            // SharpView. Return a benign empty SearchResult so consumers see
            // "no fields" instead of crashing — semantically equivalent to
            // "no matching entry" for downstream iteration.
            return new SearchResult();
        }

        public SearchResultCollection FindAll()
        {
            string server = "";
            string baseDN = "";
            string user = null, pass = null;
            if (SearchRoot != null && !string.IsNullOrEmpty(SearchRoot.Path))
            {
                var (s, d) = WfLdapBridge.ParsePath(SearchRoot.Path);
                server = s; baseDN = d;
                user = SearchRoot.Username;
                pass = SearchRoot.Password;
            }
            string[] attrs = null;
            if (PropertiesToLoad != null && PropertiesToLoad.Count > 0)
            {
                attrs = new string[PropertiesToLoad.Count];
                for (int i = 0; i < PropertiesToLoad.Count; i++) attrs[i] = PropertiesToLoad[i];
            }
            try
            {
                var entries = WfLdapBridge.Search(server, baseDN, Filter, attrs, user, pass, null);
                var col = new SearchResultCollection();
                foreach (var e in entries)
                {
                    var sr = new SearchResult();
                    sr.LoadFromDictionary(e);
                    col.Add(sr);
                }
                return col;
            }
            catch
            {
                return new SearchResultCollection();
            }
        }
        public void Dispose() { }
    }

    public class SearchResult
    {
        private string _path = "";
        public string Path => _path;
        private readonly ResultPropertyCollection _properties = new ResultPropertyCollection();
        public ResultPropertyCollection Properties => _properties;
        public DirectoryEntry GetDirectoryEntry()
        {
            var de = new DirectoryEntry(_path);
            return de;
        }

        internal void LoadFromDictionary(System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>> entry)
        {
            if (entry == null) return;
            foreach (var kv in entry)
            {
                var rpvc = new ResultPropertyValueCollection();
                foreach (var v in kv.Value) rpvc.AddValue(v);
                _properties.Add(kv.Key, rpvc);
                if (string.Equals(kv.Key, "distinguishedName", System.StringComparison.OrdinalIgnoreCase) && kv.Value.Count > 0)
                {
                    _path = "LDAP://" + kv.Value[0];
                }
            }
        }
    }

    public class SearchResultCollection : IEnumerable, IDisposable
    {
        private readonly System.Collections.Generic.List<SearchResult> _results = new System.Collections.Generic.List<SearchResult>();
        internal void Add(SearchResult r) { if (r != null) _results.Add(r); }
        public int Count => _results.Count;
        public SearchResult this[int index] => _results[index];
        public IEnumerator GetEnumerator() { foreach (var r in _results) yield return r; }
        public void Dispose() { }
        // PowerView calls items.CopyTo(arr, index) — typed overload required
        // because the iteration assigns into a `SearchResult[]`.
        public void CopyTo(SearchResult[] array, int index)
        {
            if (array == null) return;
            for (int i = 0; i < _results.Count && index + i < array.Length; i++)
                array[index + i] = _results[i];
        }
    }

    public class ResultPropertyCollection : IEnumerable
    {
        private readonly System.Collections.Generic.Dictionary<string, ResultPropertyValueCollection> _backing
            = new System.Collections.Generic.Dictionary<string, ResultPropertyValueCollection>(System.StringComparer.OrdinalIgnoreCase);
        internal void Add(string name, ResultPropertyValueCollection values)
        {
            if (!string.IsNullOrEmpty(name) && values != null) _backing[name] = values;
        }
        public ResultPropertyValueCollection this[string propertyName]
        {
            get
            {
                if (propertyName != null && _backing.TryGetValue(propertyName, out var v)) return v;
                return new ResultPropertyValueCollection();
            }
        }
        public ICollection PropertyNames
        {
            get
            {
                var keys = new string[_backing.Count];
                int i = 0;
                foreach (var k in _backing.Keys) keys[i++] = k;
                return keys;
            }
        }
        public bool Contains(string propertyName) =>
            propertyName != null && _backing.ContainsKey(propertyName);
        public IEnumerator GetEnumerator() { foreach (var kv in _backing) yield return new System.Collections.DictionaryEntry(kv.Key, kv.Value); }
    }

    public class ResultPropertyValueCollection : IEnumerable
    {
        private readonly System.Collections.Generic.List<object> _values = new System.Collections.Generic.List<object>();
        internal void AddValue(object v) { if (v != null) _values.Add(v); }
        public int Count => _values.Count;
        public object this[int index] => index >= 0 && index < _values.Count ? _values[index] : (object)"";
        public IEnumerator GetEnumerator() { foreach (var v in _values) yield return v; }
        // PowerView's range-retrieve loop uses CopyTo(string[], int) to flatten
        // multi-valued attributes into a string array.
        public void CopyTo(Array array, int index)
        {
            if (array == null) return;
            for (int i = 0; i < _values.Count && index + i < array.Length; i++)
                array.SetValue(_values[i], index + i);
        }
        public void CopyTo(string[] array, int index)
        {
            if (array == null) return;
            for (int i = 0; i < _values.Count && index + i < array.Length; i++)
                array[index + i] = _values[i]?.ToString() ?? "";
        }
    }

    public class PropertyCollection : IEnumerable
    {
        private readonly System.Collections.Generic.Dictionary<string, PropertyValueCollection> _backing
            = new System.Collections.Generic.Dictionary<string, PropertyValueCollection>(System.StringComparer.OrdinalIgnoreCase);

        /// <summary>Populate from a parsed LDAP entry (attribute → list of values).</summary>
        internal void LoadFromDictionary(System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string>> entry)
        {
            if (entry == null) return;
            foreach (var kv in entry)
            {
                var pvc = new PropertyValueCollection();
                foreach (var v in kv.Value) pvc.AddValue(v);
                _backing[kv.Key] = pvc;
            }
        }

        public PropertyValueCollection this[string propertyName]
        {
            get
            {
                if (propertyName != null && _backing.TryGetValue(propertyName, out var v))
                    return v;
                return new PropertyValueCollection();
            }
        }
        public ICollection PropertyNames
        {
            get
            {
                var keys = new string[_backing.Count];
                int i = 0;
                foreach (var k in _backing.Keys) keys[i++] = k;
                return keys;
            }
        }
        public bool Contains(string propertyName) =>
            propertyName != null && _backing.ContainsKey(propertyName);
        public IEnumerator GetEnumerator() { foreach (var v in _backing.Values) yield return v; }
    }

    public class PropertyValueCollection : IEnumerable
    {
        private readonly System.Collections.Generic.List<object> _values = new System.Collections.Generic.List<object>();
        internal void AddValue(object v) { if (v != null) _values.Add(v); }
        public int Count => _values.Count;
        // Return empty-string instead of throwing — Certify and similar consumers
        // index Properties["foo"][0] without checking Count, so an empty stub
        // would otherwise IndexOutOfRangeException before any code can report
        // "LDAP unavailable". With "" they get a benign falsy value and proceed
        // to issue the next query (which still fails gracefully via DirectoryEntry).
        public object this[int index]
        {
            get => index >= 0 && index < _values.Count ? _values[index] : (object)"";
            // PowerView's Set-DomainObject path writes back via indexer.
            set
            {
                while (_values.Count <= index) _values.Add("");
                if (index >= 0) _values[index] = value;
            }
        }
        public object Value
        {
            get => _values.Count > 0 ? _values[0] : null;
            set { _values.Clear(); if (value != null) _values.Add(value); }
        }
        public void Add(object value) { if (value != null) _values.Add(value); }
        public bool Contains(object value) => false;
        public void Remove(object value) { }
        public void Clear() { _values.Clear(); }
        public void AddRange(object[] values) { if (values != null) foreach (var v in values) if (v != null) _values.Add(v); }
        public void AddRange(PropertyValueCollection values) { }
        public IEnumerator GetEnumerator() { foreach (var v in _values) yield return v; }
    }

    /// <summary>Mirrors System.DirectoryServices.DirectoryEntryConfiguration —
    /// a property bag used by PowerView to set SecurityMasks before commit.</summary>
    public class DirectoryEntryConfiguration
    {
        public SecurityMasks SecurityMasks { get; set; }
        public ReferralChasingOption Referral { get; set; }
        public PasswordEncodingMethod PasswordEncoding { get; set; }
        public int PageSize { get; set; }
    }

    public enum PasswordEncodingMethod { PasswordEncodingSsl = 0, PasswordEncodingClear = 1 }

    public class StringCollection : IList
    {
        private readonly ArrayList _list = new ArrayList();
        public int Count => _list.Count;
        public string this[int index] { get => (string)_list[index]; set => _list[index] = value; }
        public int Add(string value) => _list.Add(value);
        public void AddRange(string[] value) { foreach (var v in value) _list.Add(v); }
        public bool Contains(string value) => _list.Contains(value);
        public void Clear() => _list.Clear();

        // IList implementation
        bool IList.IsReadOnly => false;
        bool IList.IsFixedSize => false;
        object IList.this[int index] { get => _list[index]; set => _list[index] = value; }
        int IList.Add(object value) => _list.Add(value);
        bool IList.Contains(object value) => _list.Contains(value);
        int IList.IndexOf(object value) => _list.IndexOf(value);
        void IList.Insert(int index, object value) => _list.Insert(index, value);
        void IList.Remove(object value) => _list.Remove(value);
        void IList.RemoveAt(int index) => _list.RemoveAt(index);

        // ICollection
        bool ICollection.IsSynchronized => false;
        object ICollection.SyncRoot => _list.SyncRoot;
        void ICollection.CopyTo(Array array, int index) => _list.CopyTo(array, index);

        public IEnumerator GetEnumerator() => _list.GetEnumerator();
    }

    public enum AuthenticationTypes
    {
        None = 0,
        Secure = 1,
        Encryption = 2,
        SecureSocketsLayer = 2,
        ReadonlyServer = 4,
        Anonymous = 16,
        FastBind = 32,
        Signing = 64,
        Sealing = 128,
        Delegation = 256,
        ServerBind = 512,
    }

    public enum SearchScope
    {
        Base = 0,
        OneLevel = 1,
        Subtree = 2,
    }

    public enum ReferralChasingOption
    {
        None = 0,
        Subordinate = 0x20,
        External = 0x40,
        All = 0x60,
    }

    [Flags]
    public enum SecurityMasks
    {
        None = 0,
        Owner = 1,
        Group = 2,
        Dacl = 4,
        Sacl = 8,
    }

    /// <summary>WasmForge stub: ActiveDirectorySecurity.
    ///
    /// The BCL ActiveDirectorySecurity derives from System.Security.AccessControl.
    /// NativeObjectSecurity, whose ctor wires up Windows ACL P/Invokes that throw
    /// PlatformNotSupportedException on NativeAOT-WASI ("Access Control List (ACL)
    /// APIs are part of resource management on Windows and are not supported on
    /// this platform.") That crash blocked Certify enumcas at the very first
    /// `new ActiveDirectorySecurity()` call.
    ///
    /// This rewrite makes ActiveDirectorySecurity a standalone class — no
    /// NativeObjectSecurity inheritance, no native ACL calls. It maintains an
    /// in-memory list of access rules. Callers like Certify still get their
    /// expected surface and can populate the rules via SetSecurityDescriptorBinaryForm
    /// or AddAccessRule.</summary>
    public class ActiveDirectorySecurity
    {
        private readonly System.Collections.Generic.List<ActiveDirectoryAccessRule> _rules
            = new System.Collections.Generic.List<ActiveDirectoryAccessRule>();
        private byte[] _binaryForm = System.Array.Empty<byte>();

        public ActiveDirectorySecurity() { }

        public byte[] GetSecurityDescriptorBinaryForm() => _binaryForm;

        public void SetSecurityDescriptorBinaryForm(byte[] binaryForm,
            System.Security.AccessControl.AccessControlSections sections)
        {
            _binaryForm = binaryForm ?? System.Array.Empty<byte>();
        }

        public void SetSecurityDescriptorBinaryForm(byte[] binaryForm)
        {
            _binaryForm = binaryForm ?? System.Array.Empty<byte>();
        }

        /// <summary>Returns the rules. BCL returns AuthorizationRuleCollection
        /// (sealed, internal AddRule). We return a plain List which still
        /// satisfies the LINQ patterns Certify uses (`rules.Where(r => ...)`).
        /// Callers that do `var rules = ...` adapt automatically.</summary>
        public System.Collections.Generic.List<ActiveDirectoryAccessRule> GetAccessRules(
            bool includeExplicit, bool includeInherited, System.Type targetType)
        {
            return new System.Collections.Generic.List<ActiveDirectoryAccessRule>(_rules);
        }

        public void AddAccessRule(ActiveDirectoryAccessRule rule)
        {
            if (rule != null) _rules.Add(rule);
        }

        public void SetAccessRule(System.Security.AccessControl.AccessRule rule)
        {
            if (rule is ActiveDirectoryAccessRule ad) _rules.Add(ad);
        }

        public void RemoveAccess(System.Security.Principal.IdentityReference identity,
            System.Security.AccessControl.AccessControlType type)
        {
            _rules.RemoveAll(r =>
                r.IdentityReference != null
                && identity != null
                && r.IdentityReference.Value == identity.Value
                && r.AccessControlType == type);
        }

        public System.Type AccessRightType => typeof(ActiveDirectoryRights);
        public System.Type AccessRuleType => typeof(ActiveDirectoryAccessRule);
        public System.Type AuditRuleType => typeof(System.Security.AccessControl.AuditRule);

        // Owner — Certify reads/sets this via GetOwner(typeof(SecurityIdentifier))
        // / SetOwner(...). We track it in-memory.
        private System.Security.Principal.IdentityReference _owner;

        public System.Security.Principal.IdentityReference GetOwner(System.Type targetType)
        {
            if (_owner == null) return null;
            if (targetType == null) return _owner;
            // If caller asked for a specific representation, translate via the
            // BCL IdentityReference.Translate (works on SecurityIdentifier ↔
            // NTAccount without P/Invoke; relies on local SID lookup tables).
            try { return _owner.Translate(targetType); }
            catch { return _owner; }
        }

        public void SetOwner(System.Security.Principal.IdentityReference identity)
        {
            _owner = identity;
        }
    }


    [System.Flags]
    public enum ActiveDirectoryRights
    {
        CreateChild = 1,
        DeleteChild = 2,
        ListChildren = 4,
        Self = 8,
        ReadProperty = 16,
        WriteProperty = 32,
        DeleteTree = 64,
        ListObject = 128,
        ExtendedRight = 256,
        Delete = 65536,
        ReadControl = 131072,
        GenericExecute = 131076,
        GenericWrite = 131112,
        GenericRead = 131220,
        WriteDacl = 262144,
        WriteOwner = 524288,
        GenericAll = 983551,
        Synchronize = 1048576,
        AccessSystemSecurity = 16777216,
    }

    public class ActiveDirectoryAccessRule : System.Security.AccessControl.ObjectAccessRule
    {
        public ActiveDirectoryAccessRule(
            System.Security.Principal.IdentityReference identity,
            ActiveDirectoryRights adRights,
            System.Security.AccessControl.AccessControlType type)
            : base(identity, (int)adRights, false, System.Security.AccessControl.InheritanceFlags.None,
                   System.Security.AccessControl.PropagationFlags.None, System.Guid.Empty, System.Guid.Empty, type) { }

        public ActiveDirectoryAccessRule(
            System.Security.Principal.IdentityReference identity,
            ActiveDirectoryRights adRights,
            System.Security.AccessControl.AccessControlType type,
            System.Guid objectType)
            : base(identity, (int)adRights, false, System.Security.AccessControl.InheritanceFlags.None,
                   System.Security.AccessControl.PropagationFlags.None, objectType, System.Guid.Empty, type) { }

        // PowerView's Add-DomainObjectAcl emits this 4-arg shape (no objectType).
        public ActiveDirectoryAccessRule(
            System.Security.Principal.IdentityReference identity,
            ActiveDirectoryRights adRights,
            System.Security.AccessControl.AccessControlType type,
            ActiveDirectorySecurityInheritance inheritanceType)
            : base(identity, (int)adRights, false,
                   inheritanceType == ActiveDirectorySecurityInheritance.None
                       ? System.Security.AccessControl.InheritanceFlags.None
                       : System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                   System.Security.AccessControl.PropagationFlags.None, System.Guid.Empty, System.Guid.Empty, type) { }

        // 5-arg shape: identity, rights, type, objectType, inheritanceType (no inheritedObjectType).
        public ActiveDirectoryAccessRule(
            System.Security.Principal.IdentityReference identity,
            ActiveDirectoryRights adRights,
            System.Security.AccessControl.AccessControlType type,
            System.Guid objectType,
            ActiveDirectorySecurityInheritance inheritanceType)
            : base(identity, (int)adRights, false,
                   inheritanceType == ActiveDirectorySecurityInheritance.None
                       ? System.Security.AccessControl.InheritanceFlags.None
                       : System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                   System.Security.AccessControl.PropagationFlags.None, objectType, System.Guid.Empty, type) { }

        public ActiveDirectoryAccessRule(
            System.Security.Principal.IdentityReference identity,
            ActiveDirectoryRights adRights,
            System.Security.AccessControl.AccessControlType type,
            System.Guid objectType,
            ActiveDirectorySecurityInheritance inheritanceType,
            System.Guid inheritedObjectType)
            : base(identity, (int)adRights, false,
                   inheritanceType == ActiveDirectorySecurityInheritance.None
                       ? System.Security.AccessControl.InheritanceFlags.None
                       : System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                   System.Security.AccessControl.PropagationFlags.None, objectType, inheritedObjectType, type) { }

        public ActiveDirectoryRights ActiveDirectoryRights => (ActiveDirectoryRights)AccessMask;
        public ActiveDirectorySecurityInheritance InheritanceType => ActiveDirectorySecurityInheritance.None;
    }

    public enum ActiveDirectorySecurityInheritance { None = 0, All = 1, Descendents = 2, SelfAndChildren = 3, Children = 4 }

    // Rubeus catches this around DirectoryEntry/DirectorySearcher ops to handle
    // server-side errors (referral failures, etc.). On NativeAOT-WASI we don't
    // emit the underlying COM type, but the class needs to exist so catch
    // blocks compile.
    public class DirectoryServicesCOMException : System.Runtime.InteropServices.COMException
    {
        public DirectoryServicesCOMException() : base() { }
        public DirectoryServicesCOMException(string message) : base(message) { }
        public DirectoryServicesCOMException(string message, System.Exception inner) : base(message, inner) { }
        public int ExtendedError => 0;
        public string ExtendedErrorMessage => "";
    }
}
