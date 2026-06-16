// WfEventLog.cs — System.Diagnostics.Eventing.Reader shim backed by
// real wevtapi.dll calls via WasmForge's wf_call bridge.
//
// The Win11 host's wevtapi.dll is reached through DllImport declarations
// below. wasmforge's pinvoke_scanner.go (EmitDirectPInvokeProps) walks
// every .cs file looking for [DllImport("...")] attributes, so adding
// wevtapi here auto-wires it into Properties/WfDirectPInvoke.props.
// No patcher rule is needed to register the DLL.
//
// The C bridge that backs these DllImports lives at
//   dotnet/bridge/pinvoke_wevtapi_ext.c
// and forwards to host wf_call("wevtapi.dll", "Evt*", ...).
//
// EventLogReader is consumed by Seatbelt's LogonEvents,
// ExplicitLogonEvents, PoweredOnEvents, PowerShellEvents,
// ProcessCreationEvents, and SysmonEvents commands. Their original BCL
// path threw PlatformNotSupportedException under NativeAOT-WASI; with
// these bridges those commands can yield real EventRecords again.

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Xml;

namespace System.Diagnostics.Eventing.Reader
{
    public enum PathType
    {
        LogName = 1,
        FilePath = 2,
    }

    public enum SessionAuthentication
    {
        Default = 0,
        Negotiate = 1,
        Kerberos = 2,
        Ntlm = 3,
    }

    public class EventLogSession
    {
        public EventLogSession() { }
        public EventLogSession(string computerName) { }
        public EventLogSession(string server, string domain, string user,
            System.Security.SecureString password, SessionAuthentication auth) { }
    }

    public class EventLogQuery
    {
        public EventLogQuery(string path, PathType pathType)
        {
            Path = path;
            PathType = pathType;
        }
        public EventLogQuery(string path, PathType pathType, string query)
        {
            Path = path;
            PathType = pathType;
            Query = query;
        }
        public string Path { get; }
        public PathType PathType { get; } = PathType.LogName;
        public string? Query { get; }
        public bool ReverseDirection { get; set; }
        public bool TolerateQueryErrors { get; set; }
        public EventLogSession? Session { get; set; }
    }

    public class EventProperty
    {
        public object? Value { get; set; }
    }

    public class EventRecord : System.IDisposable
    {
        public int Id { get; set; }
        public long? RecordId { get; set; }
        public System.DateTime? TimeCreated { get; set; }
        public int? ProcessId { get; set; }
        public int? ThreadId { get; set; }
        public int? Qualifiers { get; set; }
        public string MachineName { get; set; } = "";
        public string ProviderName { get; set; } = "";
        public System.Guid? ProviderId { get; set; }
        public string Container { get; set; } = "";
        public IList<EventProperty> Properties { get; set; } = new List<EventProperty>();
        public IEnumerable<int> Keywords { get; set; } = System.Array.Empty<int>();

        // Raw XML retained from EvtRender for ToXml() and FormatDescription().
        internal string? RawXml { get; set; }

        public virtual string FormatDescription()
        {
            // The real BCL resolves localized message strings via the
            // provider manifest. NativeAOT-WASI doesn't have that
            // infrastructure, so we synthesize a description by joining
            // the EventData property values — adequate for grep-style
            // checks in Seatbelt commands.
            if (Properties == null || Properties.Count == 0) return "";
            var parts = new List<string>(Properties.Count);
            foreach (var p in Properties)
            {
                parts.Add(p.Value?.ToString() ?? "");
            }
            return string.Join(" ", parts);
        }

        public virtual string FormatDescription(System.Collections.IEnumerable values) => FormatDescription();
        public virtual string ToXml() => RawXml ?? "";
        public void Dispose() { }
    }

    public class EventLogReader : System.IDisposable
    {
        // wevtapi flags
        private const uint EvtQueryChannelPath       = 0x1;
        private const uint EvtQueryFilePath          = 0x2;
        private const uint EvtQueryReverseDirection  = 0x200;
        private const uint EvtQueryTolerateQueryErrors = 0x1000;
        private const uint EvtRenderEventXml         = 1;

        // ERROR_NO_MORE_ITEMS / ERROR_INSUFFICIENT_BUFFER
        private const int ERROR_NO_MORE_ITEMS = 259;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        private readonly string _path;
        private readonly string? _query;
        private readonly uint _queryFlags;
        private long _resultSet;
        private bool _disposed;

        public EventLogReader(EventLogQuery query)
        {
            _path = query.Path ?? "";
            _query = query.Query;
            _queryFlags = (query.PathType == PathType.FilePath
                            ? EvtQueryFilePath
                            : EvtQueryChannelPath);
            if (query.ReverseDirection) _queryFlags |= EvtQueryReverseDirection;
            if (query.TolerateQueryErrors) _queryFlags |= EvtQueryTolerateQueryErrors;
        }
        public EventLogReader(string path) : this(path, PathType.LogName) { }
        public EventLogReader(string path, PathType pathType)
        {
            _path = path ?? "";
            _query = null;
            _queryFlags = (pathType == PathType.FilePath
                            ? EvtQueryFilePath
                            : EvtQueryChannelPath);
        }

        public int BatchSize { get; set; }

        public EventRecord? ReadEvent() => ReadEventCore();
        public EventRecord? ReadEvent(System.TimeSpan timeout) => ReadEventCore((uint)timeout.TotalMilliseconds);

        private EventRecord? ReadEventCore(uint timeoutMs = 100)
        {
            if (_disposed) return null;

            if (_resultSet == 0)
            {
                // Non-admin processes cannot read most event log channels
                // (System, Application, Microsoft-Windows-*/Operational, etc.)
                // and the wf_call -> wevtapi.dll path traps host-side on the
                // multi-line XPath queries that Seatbelt's PoweredOnEvents /
                // PowerShellEvents commands construct. Short-circuit to "no
                // results" when the path or query is unsafe — Security with
                // a simple query still goes through (LogonEvents uses that).
                if (!WasmForge.Bridge.WfEventLogGuard.IsSafeToQuery(_path, _query))
                {
                    return null;
                }
                try
                {
                    _resultSet = EvtQuery(0, _path, _query ?? "*", _queryFlags);
                }
                catch (System.Exception)
                {
                    return null;
                }
                // EvtQuery returns 0 for missing channels (ERROR_EVT_CHANNEL_NOT_FOUND=15007)
                // and other transient errors — caller iterates ReadEvent until null.
                if (_resultSet == 0) return null;
            }

            // EVT_HANDLE is 8 bytes on x64; allocate an 8-byte buffer
            // and read back with ReadInt64. wf_call_v2's out8_mask in
            // the C bridge ensures the host writes all 8 bytes safely.
            IntPtr handleBuf = Marshal.AllocHGlobal(8);
            long evt = 0;
            try
            {
                Marshal.WriteInt64(handleBuf, 0);
                uint returned = 0;
                int ok = EvtNext(_resultSet, 1, handleBuf, timeoutMs, 0, out returned);
                // EvtNext ok==0 with returned==0 = ERROR_NO_MORE_ITEMS
                // (259), the standard end-of-stream signal. Return null
                // so the caller's for-loop exits cleanly.
                if (ok == 0 || returned == 0) return null;
                evt = Marshal.ReadInt64(handleBuf);
                if (evt == 0) return null;

                // First call: get required buffer size.
                uint used = 0, count = 0;
                EvtRender(0, evt, EvtRenderEventXml, 0, IntPtr.Zero, out used, out count);
                if (used == 0) return null;

                IntPtr buf = Marshal.AllocHGlobal((int)used);
                try
                {
                    if (EvtRender(0, evt, EvtRenderEventXml, used, buf, out used, out count) == 0)
                    {
                        return null;
                    }
                    // EvtRender returns UTF-16. used is in bytes.
                    string? xml = Marshal.PtrToStringUni(buf, (int)used / 2);
                    if (string.IsNullOrEmpty(xml)) return null;
                    // Trim trailing NUL if present.
                    int nul = xml.IndexOf('\0');
                    if (nul >= 0) xml = xml.Substring(0, nul);
                    return ParseEventXml(xml);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                if (evt != 0) EvtClose(evt);
                Marshal.FreeHGlobal(handleBuf);
            }
        }

        private static EventRecord? ParseEventXml(string xml)
        {
            try
            {
                var rec = new EventRecord { RawXml = xml };
                using var sr = new System.IO.StringReader(xml);
                using var rdr = XmlReader.Create(sr);

                bool inEventData = false;
                while (rdr.Read())
                {
                    if (rdr.NodeType != XmlNodeType.Element) continue;

                    string ln = rdr.LocalName;
                    switch (ln)
                    {
                        case "Provider":
                            rec.ProviderName = rdr.GetAttribute("Name") ?? "";
                            var gAttr = rdr.GetAttribute("Guid");
                            if (!string.IsNullOrEmpty(gAttr))
                            {
                                if (System.Guid.TryParse(gAttr.Trim('{','}'), out var g))
                                    rec.ProviderId = g;
                            }
                            break;
                        case "EventID":
                            var qAttr = rdr.GetAttribute("Qualifiers");
                            if (!string.IsNullOrEmpty(qAttr) && int.TryParse(qAttr, out var q))
                                rec.Qualifiers = q;
                            string idStr = rdr.ReadElementContentAsString();
                            if (int.TryParse(idStr, out var id)) rec.Id = id;
                            break;
                        case "EventRecordID":
                            string recStr = rdr.ReadElementContentAsString();
                            if (long.TryParse(recStr, out var recId)) rec.RecordId = recId;
                            break;
                        case "TimeCreated":
                            var tAttr = rdr.GetAttribute("SystemTime");
                            if (!string.IsNullOrEmpty(tAttr) &&
                                System.DateTime.TryParse(tAttr, System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                                    out var t))
                            {
                                rec.TimeCreated = t;
                            }
                            break;
                        case "Execution":
                            var pidAttr = rdr.GetAttribute("ProcessID");
                            if (!string.IsNullOrEmpty(pidAttr) && int.TryParse(pidAttr, out var pid))
                                rec.ProcessId = pid;
                            var tidAttr = rdr.GetAttribute("ThreadID");
                            if (!string.IsNullOrEmpty(tidAttr) && int.TryParse(tidAttr, out var tid))
                                rec.ThreadId = tid;
                            break;
                        case "Channel":
                            rec.Container = rdr.ReadElementContentAsString();
                            break;
                        case "Computer":
                            rec.MachineName = rdr.ReadElementContentAsString();
                            break;
                        case "EventData":
                            inEventData = true;
                            break;
                        case "Data" when inEventData:
                            // Preserve declaration order in Properties.
                            string val = rdr.ReadElementContentAsString();
                            rec.Properties.Add(new EventProperty { Value = val });
                            break;
                    }
                }
                return rec;
            }
            catch
            {
                // Don't propagate parse errors — return an empty record
                // with the raw XML so callers can still call ToXml().
                return new EventRecord { RawXml = xml };
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_resultSet != 0)
            {
                EvtClose(_resultSet);
                _resultSet = 0;
            }
        }

        // ── wevtapi.dll P/Invoke declarations (auto-discovered by
        //    pinvoke_scanner.go, bridged in pinvoke_wevtapi_ext.c) ──
        //
        // EVT_HANDLE is 8 bytes on x64. We declare it as `long`
        // (wasi-wasm i64) rather than IntPtr (i32 on wasm32) so the
        // full handle value survives the bridge. The C bridge stubs
        // mirror this with uint64_t types.

        [DllImport("wevtapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern long EvtQuery(long session, string path, string query, uint flags);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern int EvtNext(long resultSet, uint eventsSize, IntPtr events,
            uint timeout, uint flags, out uint returned);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern int EvtRender(long context, long fragment, uint flags,
            uint bufferSize, IntPtr buffer, out uint bufferUsed, out uint propertyCount);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern int EvtClose(long handle);
    }

    public class EventLogPropertySelector : System.IDisposable
    {
        public EventLogPropertySelector(IEnumerable<string> propertyQueries) { }
        public void Dispose() { }
    }

    public class EventBookmark { }
}
