using System;
using System.Collections;
using System.Collections.Generic;

namespace WasmForge.Helpers
{
    // Drop-in API facade for System.Management.ManagementObjectSearcher used by
    // SharpUp and Seatbelt. Routes through WfWmi.Query / WfWmi.QueryRestricted
    // which dispatch WQL over the host COM/WMI bridge.
    //
    // WfWmi.Query signature (confirmed from WfWmi.cs line 64):
    //   public static List<Dictionary<string,object>> Query(string nspace, string wql)
    //
    // Both constructors normalise the namespace then call Get() which delegates
    // to WfWmi.Query.  QueryRestricted is used when the patcher rule emits
    // WfWmiSearcherShim with namespace root\\SecurityCenter2 or root\\subscription.
    public class WfWmiSearcherShim : IDisposable
    {
        private readonly string _ns;
        private readonly string _query;

        public WfWmiSearcherShim(string query) : this("root\\cimv2", query) { }

        public WfWmiSearcherShim(string ns, string query)
        {
            _ns    = ns    ?? "root\\cimv2";
            _query = query ?? "";
        }

        public WfWmiSearcherResultCollection Get() =>
            new WfWmiSearcherResultCollection(_ns, _query);

        public void Dispose() { }
    }

    public class WfWmiSearcherResultCollection : IEnumerable<WfWmiObject>, IDisposable
    {
        private readonly List<WfWmiObject> _items = new List<WfWmiObject>();

        public WfWmiSearcherResultCollection(string ns, string query)
        {
            try
            {
                // WfWmi.Query returns List<Dictionary<string,object>>.
                // WfWmi.QueryRestricted has the identical signature and return type;
                // we use it for namespaces that need CoSetProxyBlanket on the host.
                List<Dictionary<string, object>> rows =
                    IsRestrictedNamespace(ns)
                        ? WfWmi.QueryRestricted(ns, query)
                        : WfWmi.Query(ns, query);

                if (rows != null)
                    foreach (var row in rows)
                        _items.Add(new WfWmiObject(row));
            }
            catch { /* return empty collection on any failure */ }
        }

        public int Count => _items.Count;

        public IEnumerator<WfWmiObject> GetEnumerator()       => _items.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator()               => GetEnumerator();

        public void Dispose() { }

        // Namespaces that require CoSetProxyBlanket (restricted WMI paths).
        private static bool IsRestrictedNamespace(string ns)
        {
            if (ns == null) return false;
            string lower = ns.ToLowerInvariant();
            return lower.Contains("securitycenter") || lower.Contains("subscription");
        }
    }

    public class WfWmiObject : IDisposable
    {
        private readonly Dictionary<string, object> _data;

        public WfWmiObject(Dictionary<string, object> data)
        {
            _data = data ?? new Dictionary<string, object>();
        }

        public WfWmiPropertyData this[string key]
        {
            get
            {
                _data.TryGetValue(key, out var v);
                return new WfWmiPropertyData(v);
            }
        }

        public WfWmiPropertyCollection Properties => new WfWmiPropertyCollection(_data);

        public void Dispose() { }
    }

    public class WfWmiPropertyData
    {
        public object Value { get; }

        public WfWmiPropertyData(object v) { Value = v; }

        public override string ToString()           => Value?.ToString() ?? "";
        public static implicit operator string(WfWmiPropertyData p) => p?.Value?.ToString() ?? "";
    }

    public class WfWmiPropertyCollection : IEnumerable<KeyValuePair<string, object>>
    {
        private readonly Dictionary<string, object> _data;

        public WfWmiPropertyCollection(Dictionary<string, object> data)
        {
            _data = data ?? new Dictionary<string, object>();
        }

        public IEnumerator<KeyValuePair<string, object>> GetEnumerator() => _data.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator()                          => GetEnumerator();
    }
}
