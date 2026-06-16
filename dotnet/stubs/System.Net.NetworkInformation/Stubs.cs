// WasmForge stub for System.Net.NetworkInformation.
//
// BCL throws PlatformNotSupportedException for every call on wasm32. Most
// GhostPack tools just want IPGlobalProperties.DomainName (the AD/DNS
// domain). We back it with a WMI query for Win32_ComputerSystem.Domain.
// All other API surface returns sensible defaults so consumer code can
// take Get-then-format paths without throwing.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Management;

namespace System.Net.NetworkInformation
{
    public abstract class IPGlobalProperties
    {
        public abstract string HostName { get; }
        public abstract string DomainName { get; }
        public abstract string DhcpScopeName { get; }
        public abstract bool IsWinsProxy { get; }
        public abstract NetBiosNodeType NodeType { get; }

        public static IPGlobalProperties GetIPGlobalProperties() => new WfIPGlobalProperties();

        public virtual TcpConnectionInformation[] GetActiveTcpConnections() => Array.Empty<TcpConnectionInformation>();
        public virtual IPEndPoint[] GetActiveTcpListeners() => Array.Empty<IPEndPoint>();
        public virtual IPEndPoint[] GetActiveUdpListeners() => Array.Empty<IPEndPoint>();
        public virtual IcmpV4Statistics GetIcmpV4Statistics() => null;
        public virtual IcmpV6Statistics GetIcmpV6Statistics() => null;
        public virtual IPGlobalStatistics GetIPv4GlobalStatistics() => null;
        public virtual IPGlobalStatistics GetIPv6GlobalStatistics() => null;
        public virtual TcpStatistics GetTcpIPv4Statistics() => null;
        public virtual TcpStatistics GetTcpIPv6Statistics() => null;
        public virtual UdpStatistics GetUdpIPv4Statistics() => null;
        public virtual UdpStatistics GetUdpIPv6Statistics() => null;
    }

    internal sealed class WfIPGlobalProperties : IPGlobalProperties
    {
        private static string _cachedDomain;
        private static string _cachedHost;

        public override string HostName
        {
            get
            {
                if (_cachedHost != null) return _cachedHost;
                // COMPUTERNAME env var instead of Environment.MachineName so
                // the AST rule that rewrites Environment.MachineName →
                // WfOsInfo.MachineName() in the main project doesn't fire
                // here (stub project has no reference to WasmForge.Helpers).
                try { _cachedHost = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? ""; }
                catch { _cachedHost = ""; }
                return _cachedHost;
            }
        }

        public override string DomainName
        {
            get
            {
                if (_cachedDomain != null) return _cachedDomain;
                try
                {
                    // Win32_ComputerSystem.Domain holds the AD or workgroup name.
                    using var s = new ManagementObjectSearcher(@"root\cimv2",
                        "SELECT Domain FROM Win32_ComputerSystem");
                    foreach (var obj in s.Get())
                    {
                        var d = obj["Domain"] as string;
                        if (!string.IsNullOrEmpty(d)) { _cachedDomain = d; return d; }
                    }
                }
                catch { }
                _cachedDomain = "";
                return _cachedDomain;
            }
        }

        public override string DhcpScopeName => "";
        public override bool IsWinsProxy => false;
        public override NetBiosNodeType NodeType => NetBiosNodeType.Unknown;
    }

    public enum NetBiosNodeType { Unknown = 0, Broadcast = 1, Peer2Peer = 2, Mixed = 4, Hybrid = 8 }

    // Minimal placeholders for downstream types so consumer code that just
    // references them (e.g., in unused branches) compiles cleanly.
    public abstract class TcpConnectionInformation
    {
        public abstract IPEndPoint LocalEndPoint { get; }
        public abstract IPEndPoint RemoteEndPoint { get; }
        public abstract TcpState State { get; }
    }

    public enum TcpState { Unknown, Closed, Listen, SynSent, SynReceived, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, DeleteTcb }

    public abstract class IcmpV4Statistics { }
    public abstract class IcmpV6Statistics { }
    public abstract class IPGlobalStatistics { }
    public abstract class TcpStatistics { }
    public abstract class UdpStatistics { }

    public class NetworkInterface
    {
        public static NetworkInterface[] GetAllNetworkInterfaces() => Array.Empty<NetworkInterface>();
        public static bool GetIsNetworkAvailable() => true;
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public OperationalStatus OperationalStatus { get; set; } = OperationalStatus.Up;
        public long Speed { get; set; }
        public NetworkInterfaceType NetworkInterfaceType { get; set; } = NetworkInterfaceType.Ethernet;
        public bool IsReceiveOnly { get; set; }
        public bool SupportsMulticast { get; set; }
        public IPInterfaceProperties GetIPProperties() => new IPInterfaceProperties();
        public IPInterfaceStatistics GetIPStatistics() => null;
        public PhysicalAddress GetPhysicalAddress() => new PhysicalAddress(Array.Empty<byte>());
    }

    public enum OperationalStatus { Up, Down, Testing, Unknown, Dormant, NotPresent, LowerLayerDown }
    public enum NetworkInterfaceType { Unknown, Ethernet = 6, Loopback = 24, Wireless80211 = 71, Tunnel = 131, Wwanpp = 243 }

    public class IPInterfaceProperties
    {
        public IPAddressInformationCollection AnycastAddresses => new IPAddressInformationCollection();
        public IPAddressCollection DnsAddresses => new IPAddressCollection();
        public string DnsSuffix => "";
        public GatewayIPAddressInformationCollection GatewayAddresses => new GatewayIPAddressInformationCollection();
        public bool IsDnsEnabled => false;
        public bool IsDynamicDnsEnabled => false;
        public MulticastIPAddressInformationCollection MulticastAddresses => new MulticastIPAddressInformationCollection();
        public UnicastIPAddressInformationCollection UnicastAddresses => new UnicastIPAddressInformationCollection();
        public IPAddressCollection WinsServersAddresses => new IPAddressCollection();
    }

    public abstract class IPInterfaceStatistics { }
    public class IPAddressInformationCollection : List<IPAddressInformation> { }
    public class IPAddressCollection : List<IPAddress> { }
    public class GatewayIPAddressInformationCollection : List<GatewayIPAddressInformation> { }
    public class MulticastIPAddressInformationCollection : List<MulticastIPAddressInformation> { }
    public class UnicastIPAddressInformationCollection : List<UnicastIPAddressInformation> { }
    public abstract class IPAddressInformation
    {
        public abstract IPAddress Address { get; }
        public abstract bool IsDnsEligible { get; }
        public abstract bool IsTransient { get; }
    }
    public abstract class GatewayIPAddressInformation
    {
        public abstract IPAddress Address { get; }
    }
    public abstract class MulticastIPAddressInformation : IPAddressInformation { }
    public abstract class UnicastIPAddressInformation : IPAddressInformation { }

    public class PhysicalAddress
    {
        private readonly byte[] _bytes;
        public PhysicalAddress(byte[] address) { _bytes = address ?? Array.Empty<byte>(); }
        public byte[] GetAddressBytes() => (byte[])_bytes.Clone();
        public override string ToString() => BitConverter.ToString(_bytes).Replace("-", "");
        public static PhysicalAddress Parse(string address) => new PhysicalAddress(Array.Empty<byte>());
    }
}
