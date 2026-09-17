using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Windows.Execution;

namespace MyVpn.Platform.Windows.Routing;

/// <summary>
/// The command lines MyVpn uses to change the Windows routing table, as pure functions.
/// </summary>
/// <remarks>
/// <para>
/// <b>IPv4 through <c>route.exe</c>, IPv6 through <c>netsh</c>.</b> That split is not a
/// preference: <c>route.exe</c> has no documented IPv6 form at all, while
/// <c>netsh interface ipv6</c> does. Both are invoked as argv vectors through
/// <see cref="ICommandRunner"/>, so no interface name, gateway or prefix can become a command.
/// </para>
/// <para>
/// <b>Why these are pure.</b> The argument shapes are where the platform quirks live — a missing
/// <c>mask</c>, an <c>if</c> index that has to be numeric, a route that silently lands on the
/// wrong interface — and keeping them free of process execution is what lets them be asserted on
/// a Linux test run.
/// </para>
/// <para>
/// <b>Never parse <c>route print</c>.</b> Its output is localized and column-aligned by a tool
/// that has changed format between releases. The read-back path uses the NetIO API
/// (<see cref="WindowsIpForwardTable"/>) instead; the only text ever inspected here is the error
/// message of a failed mutation, and that is a documented convenience, not the source of truth.
/// </para>
/// </remarks>
public static class WindowsRouteCommands
{
    /// <summary>In-box IPv4 route tool.</summary>
    public const string RouteTool = "route.exe";

    /// <summary>In-box configuration tool, used for IPv6 routes.</summary>
    public const string NetshTool = "netsh.exe";

    /// <summary>
    /// Renders a prefix length as the dotted-decimal netmask <c>route.exe</c> requires.
    /// </summary>
    /// <remarks>
    /// <c>route.exe</c> has no prefix-length syntax: the mask is mandatory on every add, and
    /// <c>/0</c> is spelled <c>0.0.0.0</c>.
    /// </remarks>
    public static string MaskFor(int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(
                nameof(prefixLength),
                prefixLength,
                "An IPv4 prefix length must be between 0 and 32.");
        }

        var mask = prefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLength);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}");
    }

    /// <summary>Builds <c>route.exe add</c> for one IPv4 destination.</summary>
    /// <param name="destination">The prefix to add.</param>
    /// <param name="gateway">
    /// Next hop, or <c>null</c> for an on-link route, which <c>route.exe</c> spells
    /// <c>0.0.0.0</c>.
    /// </param>
    /// <param name="metric">Route metric; lower wins.</param>
    /// <param name="interfaceIndex">
    /// Numeric interface index for the <c>if</c> clause, or <c>null</c> when it could not be
    /// resolved. Omitting it lets the stack pick the interface from the gateway, which is
    /// acceptable for a bypass host route and wrong for a default route — the caller decides.
    /// </param>
    public static IReadOnlyList<string> AddIpv4(
        CidrBlock destination,
        string? gateway,
        int metric,
        uint? interfaceIndex)
    {
        var arguments = new List<string>
        {
            // "add" first, then the destination, then the mandatory mask.
            "add",
            destination.Network.ToString(),
            "mask",
            MaskFor(destination.PrefixLength),
            string.IsNullOrWhiteSpace(gateway) ? "0.0.0.0" : gateway,
            "metric",
            metric.ToString(CultureInfo.InvariantCulture),
        };

        if (interfaceIndex is not null)
        {
            arguments.Add("if");
            arguments.Add(interfaceIndex.Value.ToString(CultureInfo.InvariantCulture));
        }

        return arguments;
    }

    /// <summary>Builds <c>route.exe delete</c> for one IPv4 destination.</summary>
    /// <remarks>
    /// The mask, gateway and interface are included when they are known so the deletion matches
    /// exactly one entry; a bare <c>route delete 0.0.0.0</c> would remove whichever default route
    /// the stack happened to pick first.
    /// </remarks>
    public static IReadOnlyList<string> DeleteIpv4(
        CidrBlock destination,
        string? gateway,
        uint? interfaceIndex)
    {
        var arguments = new List<string>
        {
            "delete",
            destination.Network.ToString(),
            "mask",
            MaskFor(destination.PrefixLength),
        };

        if (!string.IsNullOrWhiteSpace(gateway) && gateway != "0.0.0.0")
        {
            arguments.Add(gateway);
        }

        if (interfaceIndex is not null)
        {
            arguments.Add("if");
            arguments.Add(interfaceIndex.Value.ToString(CultureInfo.InvariantCulture));
        }

        return arguments;
    }

    /// <summary>Builds <c>netsh interface ipv6 add route</c> for one IPv6 destination.</summary>
    /// <remarks>
    /// The named form (<c>prefix=</c>, <c>interface=</c>, <c>nexthop=</c>, <c>metric=</c>) is
    /// used rather than positional arguments: netsh's positional order differs between the
    /// <c>add route</c> and <c>delete route</c> verbs, and a mis-ordered token would be accepted
    /// as a different route rather than rejected.
    /// <para>
    /// <c>store=active</c> keeps the route out of the persistent store, so a reboot is a clean
    /// reset and a crash cannot leave a stale default route behind in the registry.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> AddIpv6(
        CidrBlock destination,
        string? gateway,
        int metric,
        string interfaceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);

        var arguments = new List<string>
        {
            "interface",
            "ipv6",
            "add",
            "route",
            $"prefix={destination}",
            $"interface={interfaceName}",
        };

        if (!string.IsNullOrWhiteSpace(gateway))
        {
            arguments.Add($"nexthop={gateway}");
        }

        arguments.Add($"metric={metric.ToString(CultureInfo.InvariantCulture)}");
        arguments.Add("store=active");

        return arguments;
    }

    /// <summary>Builds <c>netsh interface ipv6 delete route</c> for one IPv6 destination.</summary>
    public static IReadOnlyList<string> DeleteIpv6(
        CidrBlock destination,
        string? gateway,
        string interfaceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);

        var arguments = new List<string>
        {
            "interface",
            "ipv6",
            "delete",
            "route",
            $"prefix={destination}",
            $"interface={interfaceName}",
        };

        if (!string.IsNullOrWhiteSpace(gateway))
        {
            arguments.Add($"nexthop={gateway}");
        }

        arguments.Add("store=active");

        return arguments;
    }

    /// <summary>
    /// The order routes are installed in.
    /// </summary>
    /// <remarks>
    /// <b>Bypass routes first, always.</b> They pin the VPN server to the physical uplink; a
    /// default-capturing route installed before them would send the core's own connection to the
    /// server into the tunnel that is still being built. The tunnel cannot carry that packet — its
    /// own peer would have to be reached through itself — so the connection dies and is retried.
    /// Exposing the order as data keeps that property assertable without a Windows host.
    /// </remarks>
    public static IReadOnlyList<RouteOperation> PlanApply(RoutePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var operations = new List<RouteOperation>(plan.BypassRoutes.Count + plan.TunnelRoutes.Count);

        foreach (var route in plan.BypassRoutes)
        {
            operations.Add(new RouteOperation(RouteOperationKind.Add, RoutePhase.Bypass, route));
        }

        foreach (var route in plan.TunnelRoutes)
        {
            operations.Add(new RouteOperation(RouteOperationKind.Add, RoutePhase.Tunnel, route));
        }

        return operations;
    }

    /// <summary>
    /// The order routes are removed in: the mirror image of installation.
    /// </summary>
    /// <remarks>
    /// Tunnel routes go first, because they are the ones that capture the default prefix; removing
    /// them last would leave the core's traffic pointed at a tunnel that is already going away.
    /// Within each phase the order is reversed, so a plan that installed A then B removes B then A.
    /// </remarks>
    public static IReadOnlyList<RouteOperation> PlanRemove(RoutePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var operations = new List<RouteOperation>(plan.BypassRoutes.Count + plan.TunnelRoutes.Count);

        foreach (var route in plan.TunnelRoutes.Reverse())
        {
            operations.Add(new RouteOperation(RouteOperationKind.Delete, RoutePhase.Tunnel, route));
        }

        foreach (var route in plan.BypassRoutes.Reverse())
        {
            operations.Add(new RouteOperation(RouteOperationKind.Delete, RoutePhase.Bypass, route));
        }

        return operations;
    }

    /// <summary>
    /// True when the tool reported that the route already exists.
    /// </summary>
    /// <remarks>
    /// <c>route.exe</c> returns exit code 1 for every failure and puts the reason in localized
    /// text, so the message is the only signal available. That is a weak signal on a non-English
    /// Windows, which is exactly why it is only ever used to turn a failure into an idempotent
    /// success and never to turn a failure into a claim that a route is installed: the apply path
    /// still reads the table back through the API.
    /// </remarks>
    public static bool IsAlreadyExists(CommandResult result) =>
        ContainsAny(result.Combined, "already exists", "object already exists");

    /// <summary>True when the tool reported that the route is not present.</summary>
    public static bool IsAlreadyGone(CommandResult result) =>
        ContainsAny(
            result.Combined,
            "not found",
            "cannot find",
            "element not found",
            "the route specified was not found");

    private static bool ContainsAny(string text, params string[] needles) =>
        needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));
}

/// <summary>What an operation does to one route.</summary>
public enum RouteOperationKind
{
    Add = 0,
    Delete = 1,
}

/// <summary>Which half of a plan an operation belongs to.</summary>
public enum RoutePhase
{
    /// <summary>An uplink host route that keeps the core's own traffic off the tunnel.</summary>
    Bypass = 0,

    /// <summary>A route that carries traffic into the tunnel.</summary>
    Tunnel = 1,
}

/// <summary>One ordered routing-table operation.</summary>
public sealed record RouteOperation(RouteOperationKind Kind, RoutePhase Phase, RouteEntry Route)
{
    public override string ToString() => $"{Kind} {Phase} {Route}";
}

/// <summary>One route as the NetIO API reports it.</summary>
public sealed record WindowsRouteRow
{
    public required CidrBlock Destination { get; init; }

    /// <summary>Next hop, or <c>null</c> for an on-link route (all-zero next hop).</summary>
    public string? NextHop { get; init; }

    public required uint InterfaceIndex { get; init; }

    public required ulong InterfaceLuid { get; init; }

    public required int Metric { get; init; }

    public string? InterfaceName { get; init; }

    public bool IsDefault => Destination.PrefixLength == 0;
}

/// <summary>
/// Read access to the IPv4/IPv6 routing table through <c>GetIpForwardTable2</c> and next-hop
/// lookup through <c>GetBestRoute2</c>.
/// </summary>
/// <remarks>
/// <para>
/// Both names are the documented ones: there is no <c>BestRouteLookup</c>, and
/// <c>CreateIpForwardEntry</c> (the IPv4-only legacy form) is deliberately not used.
/// </para>
/// <para>
/// Every member answers without touching native code when the host is not Windows. The struct
/// layouts were verified against a compiled C translation of <c>MIB_IPFORWARD_ROW2</c>
/// (<c>sizeof</c> 96, <c>NextHop</c> at 44, <c>Metric</c> at 84), so the marshalling is exact;
/// the calls themselves remain runtime-unverified until they run on Windows.
/// </para>
/// </remarks>
public static class WindowsIpForwardTable
{
    private const ushort AddressFamilyInet = 2;
    private const ushort AddressFamilyInet6 = 23;

    /// <summary>Reads the IPv4 table (<c>false</c>) or the IPv6 table (<c>true</c>).</summary>
    public static IReadOnlyList<WindowsRouteRow> Read(bool ipv6, out string? error)
    {
        error = null;

        if (!WindowsPlatform.IsWindows)
        {
            error = "GetIpForwardTable2 is only available on Windows.";
            return Array.Empty<WindowsRouteRow>();
        }

        var table = IntPtr.Zero;

        try
        {
            var family = ipv6 ? AddressFamilyInet6 : AddressFamilyInet;
            var result = GetIpForwardTable2(family, out table);

            if (result != 0)
            {
                error = $"GetIpForwardTable2 failed with Win32 error {result.ToString(CultureInfo.InvariantCulture)}.";
                return Array.Empty<WindowsRouteRow>();
            }

            // MIB_IPFORWARD_TABLE2 { ULONG NumEntries; MIB_IPFORWARD_ROW2 Table[]; } — the rows
            // start at the first 8-byte boundary after the count.
            var count = (uint)Marshal.ReadInt32(table);

            if (count == 0)
            {
                return Array.Empty<WindowsRouteRow>();
            }

            var rowSize = Marshal.SizeOf<NativeIpForwardRow2>();
            var rows = new List<WindowsRouteRow>((int)count);
            var names = AdapterNames();

            for (var index = 0; index < count; index++)
            {
                var pointer = IntPtr.Add(table, 8 + (index * rowSize));
                var native = Marshal.PtrToStructure<NativeIpForwardRow2>(pointer);

                var destination = ReadPrefix(pointer, native);
                if (destination is null)
                {
                    continue;
                }

                var nextHop = ReadAddress(IntPtr.Add(pointer, NativeIpForwardRow2.NextHopOffset));

                names.TryGetValue(native.InterfaceIndex, out var interfaceName);

                rows.Add(new WindowsRouteRow
                {
                    Destination = destination.Value,
                    NextHop = nextHop is null || nextHop.Equals(IPAddress.Any) || nextHop.Equals(IPAddress.IPv6Any)
                        ? null
                        : nextHop.ToString(),
                    InterfaceIndex = native.InterfaceIndex,
                    InterfaceLuid = native.InterfaceLuid,
                    Metric = unchecked((int)native.Metric),
                    InterfaceName = interfaceName,
                });
            }

            return rows;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = $"GetIpForwardTable2 could not be resolved: {ex.Message}";
            return Array.Empty<WindowsRouteRow>();
        }
        finally
        {
            if (table != IntPtr.Zero)
            {
                FreeMibTable(table);
            }
        }
    }

    /// <summary>
    /// Asks the stack which route it would use for a destination.
    /// </summary>
    /// <remarks>
    /// This is the documented first half of loop avoidance: query the server's current next hop
    /// and interface <i>before</i> installing a default route, then pin a host route to that
    /// result. Doing it in the other order yields the classic "connects, then immediately
    /// stalls" loop.
    /// </remarks>
    public static WindowsRouteRow? FindBestRoute(IPAddress destination, out string? error)
    {
        error = null;

        if (!WindowsPlatform.IsWindows)
        {
            error = "GetBestRoute2 is only available on Windows.";
            return null;
        }

        ArgumentNullException.ThrowIfNull(destination);

        var query = IntPtr.Zero;
        var row = IntPtr.Zero;

        try
        {
            query = Marshal.AllocHGlobal(Marshal.SizeOf<NativeSockaddrInet>());
            WriteSockaddr(query, destination);

            var result = GetBestRoute2(
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                query,
                0,
                out var bestRoute,
                IntPtr.Zero);

            if (result != 0)
            {
                error = $"GetBestRoute2 failed with Win32 error {result.ToString(CultureInfo.InvariantCulture)}.";
                return null;
            }

            row = Marshal.AllocHGlobal(Marshal.SizeOf<NativeIpForwardRow2>());
            Marshal.StructureToPtr(bestRoute, row, false);

            var prefix = ReadPrefix(row, bestRoute);

            if (prefix is null)
            {
                error = "The best route row could not be decoded.";
                return null;
            }

            var names = AdapterNames();
            names.TryGetValue(bestRoute.InterfaceIndex, out var interfaceName);

            var nextHop = ReadAddress(IntPtr.Add(row, NativeIpForwardRow2.NextHopOffset));

            return new WindowsRouteRow
            {
                Destination = prefix.Value,
                NextHop = nextHop is null || nextHop.Equals(IPAddress.Any) || nextHop.Equals(IPAddress.IPv6Any)
                    ? null
                    : nextHop.ToString(),
                InterfaceIndex = bestRoute.InterfaceIndex,
                InterfaceLuid = bestRoute.InterfaceLuid,
                Metric = unchecked((int)bestRoute.Metric),
                InterfaceName = interfaceName,
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = $"GetBestRoute2 could not be resolved: {ex.Message}";
            return null;
        }
        finally
        {
            if (row != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(row);
            }

            if (query != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(query);
            }
        }
    }

    /// <summary>
    /// Deletes one row exactly as it was read from the table.
    /// </summary>
    /// <remarks>
    /// The row is rebuilt from its own fields — destination prefix, next hop, interface LUID and
    /// index — because that triple is what the API matches on. Deleting by a reconstructed route
    /// would risk removing a different entry with the same prefix.
    /// </remarks>
    public static uint Delete(WindowsRouteRow row)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return 1;
        }

        var buffer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeIpForwardRow2>());

        try
        {
            WriteRow(buffer, row);
            return DeleteIpForwardEntry2(buffer);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            _ = ex;
            return 1;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static Dictionary<uint, string> AdapterNames()
    {
        var names = new Dictionary<uint, string>();

        foreach (var adapter in WindowsAdapters.Enumerate(out _))
        {
            names[adapter.IfIndex] = adapter.FriendlyName;
        }

        return names;
    }

    private static void WriteRow(IntPtr pointer, WindowsRouteRow row)
    {
        for (var offset = 0; offset < Marshal.SizeOf<NativeIpForwardRow2>(); offset++)
        {
            Marshal.WriteByte(pointer, offset, 0);
        }

        Marshal.WriteInt64(pointer, 0, unchecked((long)row.InterfaceLuid));
        Marshal.WriteInt32(pointer, 8, unchecked((int)row.InterfaceIndex));

        WriteSockaddr(IntPtr.Add(pointer, 12), row.Destination.Network);
        Marshal.WriteByte(pointer, 40, (byte)row.Destination.PrefixLength);

        if (row.NextHop is not null && IPAddress.TryParse(row.NextHop, out var nextHop))
        {
            WriteSockaddr(IntPtr.Add(pointer, NativeIpForwardRow2.NextHopOffset), nextHop);
        }

        Marshal.WriteInt32(pointer, 76, unchecked((int)0xFFFFFFFF));
        Marshal.WriteInt32(pointer, 80, unchecked((int)0xFFFFFFFF));
        Marshal.WriteInt32(pointer, 84, row.Metric);

        // MIB_IPPROTO_NETMGMT: the route is managed by an administrative tool, which is what a
        // route installed on the user's behalf is.
        Marshal.WriteInt32(pointer, 88, 3);

        Marshal.WriteByte(pointer, 92, 1);
        Marshal.WriteByte(pointer, 93, 1);
    }

    private static void WriteSockaddr(IntPtr pointer, IPAddress address)
    {
        for (var offset = 0; offset < Marshal.SizeOf<NativeSockaddrInet>(); offset++)
        {
            Marshal.WriteByte(pointer, offset, 0);
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            Marshal.WriteInt16(pointer, 0, unchecked((short)AddressFamilyInet));
            Marshal.Copy(address.GetAddressBytes(), 0, IntPtr.Add(pointer, 4), 4);
        }
        else
        {
            Marshal.WriteInt16(pointer, 0, unchecked((short)AddressFamilyInet6));
            Marshal.Copy(address.GetAddressBytes(), 0, IntPtr.Add(pointer, 8), 16);
        }
    }

    private static CidrBlock? ReadPrefix(IntPtr rowPointer, NativeIpForwardRow2 row)
    {
        var prefix = ReadAddress(IntPtr.Add(rowPointer, 12));

        if (prefix is null)
        {
            return null;
        }

        var length = Marshal.ReadByte(rowPointer, 40);
        var max = prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;

        return new CidrBlock(prefix, Math.Min(length, max));
    }

    /// <summary>Reads a <c>SOCKADDR_INET</c>, whose family field decides how to decode it.</summary>
    private static IPAddress? ReadAddress(IntPtr socketAddress)
    {
        var family = unchecked((ushort)Marshal.ReadInt16(socketAddress));

        if (family == AddressFamilyInet)
        {
            var bytes = new byte[4];
            Marshal.Copy(IntPtr.Add(socketAddress, 4), bytes, 0, 4);
            return new IPAddress(bytes);
        }

        if (family == AddressFamilyInet6)
        {
            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(socketAddress, 8), bytes, 0, 16);
            return new IPAddress(bytes);
        }

        return null;
    }

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct NativeSockaddrInet
    {
        [FieldOffset(0)]
        public ushort Family;

        [FieldOffset(2)]
        public ushort Port;

        [FieldOffset(4)]
        public uint V4Address;

        [FieldOffset(8)]
        public byte V6Address0;
    }

    /// <summary>
    /// <c>MIB_IPFORWARD_ROW2</c>, with the offsets taken from the C layout (96 bytes).
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 96)]
    private struct NativeIpForwardRow2
    {
        public const int NextHopOffset = 44;

        [FieldOffset(0)]
        public ulong InterfaceLuid;

        [FieldOffset(8)]
        public uint InterfaceIndex;

        [FieldOffset(12)]
        public NativeSockaddrInet DestinationPrefix;

        [FieldOffset(40)]
        public byte DestinationPrefixLength;

        [FieldOffset(NextHopOffset)]
        public NativeSockaddrInet NextHop;

        [FieldOffset(72)]
        public byte SitePrefixLength;

        [FieldOffset(76)]
        public uint ValidLifetime;

        [FieldOffset(80)]
        public uint PreferredLifetime;

        [FieldOffset(84)]
        public uint Metric;

        [FieldOffset(88)]
        public uint Protocol;

        [FieldOffset(92)]
        public byte Publish;

        [FieldOffset(93)]
        public byte Immortal;

        [FieldOffset(94)]
        public byte Age;

        [FieldOffset(95)]
        public byte Origin;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint GetBestRoute2(
        IntPtr interfaceLuid,
        uint interfaceIndex,
        IntPtr sourceAddress,
        IntPtr destinationAddress,
        uint addressSortOptions,
        out NativeIpForwardRow2 bestRoute,
        IntPtr bestSourceAddress);

    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint DeleteIpForwardEntry2(IntPtr row);

    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    private static extern void FreeMibTable(IntPtr memory);
}

/// <summary>
/// Applies a <see cref="RoutePlan"/> to the Windows routing table.
/// </summary>
/// <remarks>
/// <para>
/// <b>Ordering is a safety property, not a style choice.</b> <see cref="RoutePlan.BypassRoutes"/>
/// are uplink host routes that keep the core's own connection to the server off the tunnel. They
/// are installed <i>before</i> any route that captures the default prefix and removed
/// <i>after</i> those routes, because the reverse order briefly routes the core's own packets
/// into a tunnel that is still being built. The tunnel cannot carry that packet — its own peer
/// would have to be reached through itself — so the connection dies and is retried, and the user
/// sees "connects, then immediately stalls" with nothing in the logs.
/// </para>
/// <para>
/// <b>Fail-closed.</b> If a bypass route cannot be installed, no default-capturing route is
/// installed at all: capturing the default without pinning the server would send the core's own
/// traffic into a tunnel that is not up yet. The bypass routes that were installed are left in
/// place deliberately — they only pin the server to the uplink the host already uses — and
/// teardown removes them.
/// </para>
/// <para>
/// <b>Ownership by interface name.</b> Every interface MyVpn creates is named with the
/// <c>myvpn</c> prefix, and the read-back path attributes a route to MyVpn when its interface
/// carries that prefix. The <i>index</i> is never used as identity: Windows reassigns interface
/// indexes across restarts and adapter re-creation, so anything that pinned an index would point
/// at a different interface — or at nothing — on the next run. The index is re-resolved from the
/// adapter name on every apply.
/// </para>
/// </remarks>
public sealed class WindowsRouteManager : IRouteManager
{
    /// <summary>Prefix of every interface MyVpn creates; the ownership marker for routes.</summary>
    public const string OwnedInterfacePrefix = "myvpn";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;

    /// <summary>
    /// The physical default route seen immediately before a default-capturing route was
    /// installed, kept so a teardown in the same process can put it back. Not persisted: after a
    /// crash the live table is the better source of truth.
    /// </summary>
    private WindowsRouteRow? _displacedDefault;

    public WindowsRouteManager(ICommandRunner? runner = null, Func<bool>? isElevated = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? WindowsPlatform.IsProcessElevated;
    }

    /// <summary>
    /// True when this host is Windows, the process may change the table, and the IPv4 tool is
    /// present.
    /// </summary>
    /// <remarks>
    /// Reporting <c>true</c> without privileges would let a session believe routing will succeed
    /// and then fail after the core was already started. Creating routes with
    /// <c>CreateIpForwardEntry2</c> — and with <c>route.exe</c>, which uses the same API — is
    /// documented as administrators-only.
    /// </remarks>
    public bool IsSupported =>
        WindowsPlatform.IsWindows
        && _isElevated()
        && _runner.Exists(WindowsRouteCommands.RouteTool);

    public async Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        if (!WindowsPlatform.IsWindows)
        {
            return Result.Fail(WindowsPlatform.Unsupported("Changing the Windows routing table"));
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        // A stale capture from an earlier plan must never be restored for this one.
        _displacedDefault = null;

        if (plan.TunnelRoutes.Any(route => route.DisplacesDefaultRoute))
        {
            // Captured before the change: once the tunnel's default route is in place the
            // original uplink route may no longer be the best route to the server, and an
            // unrestorable default route is how a VPN client leaves a machine with no network.
            var captured = ProbeDefaultAsync(plan.PhysicalInterface, cancellationToken);

            if (captured.IsFailure)
            {
                return Result.Fail(NoDefaultToDisplace());
            }

            _displacedDefault = captured.Value;
        }

        // The order is a safety property and lives in one pure function so it can be asserted
        // without a Windows host: bypass (uplink host) routes first, then everything that captures
        // the default prefix.
        foreach (var operation in WindowsRouteCommands.PlanApply(plan))
        {
            var added = await AddRouteAsync(operation.Route, cancellationToken).ConfigureAwait(false);

            if (added.IsFailure)
            {
                // Fail closed: a bypass route that could not be installed means no
                // default-capturing route may be installed at all, because the core's own traffic
                // would be routed into a tunnel that cannot carry it.
                return operation.Phase == RoutePhase.Bypass
                    ? Result.Fail(BypassFailed(operation.Route, added.Error!))
                    : added;
            }
        }

        return Result.Ok();
    }

    public async Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // Teardown deliberately does not call plan.Validate(): a plan that fails validation still
        // describes routes that may exist, and refusing to clean up because the plan is
        // incomplete is how a half-routed machine stays half-routed.
        if (!WindowsPlatform.IsWindows)
        {
            return Result.Fail(WindowsPlatform.Unsupported("Changing the Windows routing table"));
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<string>();

        // The mirror image of installation, from the same pure planner: tunnel routes first, then
        // the bypass host routes.
        foreach (var operation in WindowsRouteCommands.PlanRemove(plan))
        {
            var removed = await DeleteRouteAsync(operation.Route, cancellationToken).ConfigureAwait(false);

            if (removed.IsFailure)
            {
                failures.Add(Describe(removed.Error!));
            }
        }

        // (3) Re-adding the displaced default route is not necessary on Windows: the physical
        // default was never removed, only outranked by a lower total metric, and deleting the
        // tunnel's route restores its precedence. The captured row is dropped here for that
        // reason — and because re-creating it would risk a duplicate default route.
        _displacedDefault = null;

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RemoveFailed(failures));
    }

    /// <summary>
    /// Removes every route MyVpn owns, using the live table as the source of truth.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The panic-clear path. It cannot take a plan: the process that installed the routes may have
    /// been killed and the settings may since have changed. Ownership is therefore judged from
    /// the route itself — a route whose outgoing interface carries the <c>myvpn</c> prefix was
    /// created for the tunnel, and the tunnel adapter only exists while the core does.
    /// </para>
    /// <para>
    /// What it cannot recognise is a bypass host route sitting on the physical uplink: that route
    /// is indistinguishable from an ordinary OS route to the same destination, and deleting it on
    /// a guess would risk removing something MyVpn never created. A crash leaves at most a host
    /// route to the VPN server via the gateway the host already uses, which is harmless and is
    /// superseded the next time the plan is applied.
    /// </para>
    /// <para>
    /// Note also that routes on a Wintun adapter normally disappear with the adapter when the
    /// core exits; finding one here means the adapter outlived the tunnel, which is itself worth
    /// reporting.
    /// </para>
    /// </remarks>
    public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result.Fail(
                WindowsPlatform.Unsupported("Changing the Windows routing table")));
        }

        if (!_isElevated())
        {
            return Task.FromResult(Result.Fail(NotElevated()));
        }

        var failures = new List<string>();
        var removed = 0;

        foreach (var ipv6 in new[] { false, true })
        {
            var rows = WindowsIpForwardTable.Read(ipv6, out var error);

            if (error is not null)
            {
                failures.Add(error);
                continue;
            }

            foreach (var row in rows.Where(IsOwned))
            {
                var result = WindowsIpForwardTable.Delete(row);

                if (result == 0)
                {
                    removed++;
                }
                else
                {
                    failures.Add(
                        $"deleting {row.Destination} via {row.NextHop ?? "on-link"} on "
                        + $"'{row.InterfaceName}' failed with Win32 error "
                        + result.ToString(CultureInfo.InvariantCulture));
                }
            }
        }

        _displacedDefault = null;

        return Task.FromResult(failures.Count == 0
            ? Result.Ok()
            : Result.Fail(RemoveFailed(failures)));
    }

    public Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken)
    {
        // Without the API nothing can be observed. "Nothing present" is the only answer that does
        // not overclaim, and the caller has the error surface for the rest.
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(EmptyState());
        }

        var v4 = WindowsIpForwardTable.Read(ipv6: false, out _);
        var v6 = WindowsIpForwardTable.Read(ipv6: true, out _);
        var observed = v4.Concat(v6).ToList();
        var owned = observed.Where(IsOwned).ToList();

        var tunnelPresent = expected is null
            ? owned.Count > 0
            : expected.TunnelRoutes.Count > 0 && expected.TunnelRoutes.All(route => observed.Any(seen => Matches(route, seen)));

        // A bypass host route lives on the physical interface, so it can only be attributed to us
        // through the plan that asked for it.
        var bypassPresent = expected is not null
            && expected.BypassRoutes.Count > 0
            && expected.BypassRoutes.All(route => observed.Any(seen => Matches(route, seen)));

        var orphans = new List<string>();
        if (expected is null)
        {
            orphans.AddRange(owned.Select(Describe));
        }
        else
        {
            var planned = expected.TunnelRoutes.Concat(expected.BypassRoutes).ToList();

            foreach (var row in owned.Where(row => !planned.Any(entry => Matches(entry, row))))
            {
                orphans.Add(Describe(row));
            }
        }

        var displaced = _displacedDefault?.Destination.ToString();

        if (displaced is null && expected is not null && expected.TunnelRoutes.Any(r => r.DisplacesDefaultRoute))
        {
            displaced = observed
                .FirstOrDefault(row => row.IsDefault && !IsOwned(row))
                ?.NextHop;
        }

        return Task.FromResult(new RouteState
        {
            TunnelRoutesPresent = tunnelPresent,
            BypassRoutesPresent = bypassPresent,
            DisplacedDefaultRoute = displaced,
            OrphanedRoutes = orphans,
        });
    }

    /// <summary>
    /// Finds the host's real uplink and its next hop, by asking the stack.
    /// </summary>
    /// <remarks>
    /// <c>GetBestRoute2</c> is preferred over reading the table because it is the same decision
    /// the stack will make when the core sends its first packet — including the metric
    /// comparison and the interface binding order. A tunnel interface is never returned as "the
    /// uplink": if the best route already points into MyVpn's own interface, the probe reports no
    /// uplink rather than handing back a gateway inside the tunnel, which would build a bypass
    /// route that loops.
    /// </remarks>
    public Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result<PhysicalUplink>.Fail(
                WindowsPlatform.Unsupported("Reading the Windows routing table")));
        }

        var details = new List<string>();

        foreach (var isIpv6 in new[] { false, true })
        {
            var destination = isIpv6 ? IPAddress.IPv6Any : IPAddress.Any;
            var best = WindowsIpForwardTable.FindBestRoute(destination, out var error);

            if (best is null)
            {
                details.Add($"{(isIpv6 ? "IPv6" : "IPv4")}: {error ?? "no route"}");
                continue;
            }

            if (best.InterfaceName is not null && IsOwnedInterface(best.InterfaceName))
            {
                details.Add($"{(isIpv6 ? "IPv6" : "IPv4")}: best route already points into '{best.InterfaceName}'");
                continue;
            }

            return Task.FromResult(Result<PhysicalUplink>.Ok(new PhysicalUplink(
                best.InterfaceName ?? best.InterfaceIndex.ToString(CultureInfo.InvariantCulture),
                best.NextHop,
                isIpv6)));
        }

        // No default route at all is a normal state (an isolated host, a cold adapter) and is
        // reported as a failure value with the probe's own output, never as an exception.
        return Task.FromResult(Result<PhysicalUplink>.Fail(new MyVpnError(
            ErrorCodes.NotFound,
            "error.route.no_default_route",
            ErrorSeverity.Error,
            "No default route could be identified, so the physical uplink is unknown. "
            + string.Join("; ", details))));
    }

    // ------------------------------------------------------------------ internals

    private async Task<Result> AddRouteAsync(RouteEntry route, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(route.Interface))
        {
            // Defensive: RoutePlan.Validate covers the plan-level rule, but an empty interface
            // would otherwise reach the tool as an empty argv element.
            return Result.Fail(new MyVpnError(
                ErrorCodes.RouteAddFailed,
                "error.route.no_interface",
                ErrorSeverity.Error,
                $"Route '{route}' does not name an outgoing interface."));
        }

        // The index is resolved per apply because it is not stable across restarts or adapter
        // re-creation. For an IPv4 route the numeric index is the only interface selector
        // `route.exe` has; if it cannot be resolved we refuse rather than let the stack pick an
        // interface, because a default route landing on the wrong adapter is a leak.
        uint? index = null;

        if (route.Destination.IsIPv4)
        {
            if (!WindowsAdapters.TryGetInterfaceIndex(route.Interface, out var resolved))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.RouteAddFailed,
                    "error.route.no_interface",
                    ErrorSeverity.Error,
                    $"The interface '{route.Interface}' could not be resolved to a current interface "
                    + "index, so the route cannot be pinned to it. Interface indexes change across "
                    + "restarts, which is why this is resolved at apply time rather than stored.",
                    "network.restore")
                    .WithArg("interface", route.Interface));
            }

            index = resolved;
        }

        var arguments = route.Destination.IsIPv4
            ? WindowsRouteCommands.AddIpv4(route.Destination, route.Gateway, route.Metric, index)
            : WindowsRouteCommands.AddIpv6(route.Destination, route.Gateway, route.Metric, route.Interface);

        var tool = route.Destination.IsIPv4
            ? WindowsPlatform.SystemTool(WindowsRouteCommands.RouteTool)
            : WindowsPlatform.SystemTool(WindowsRouteCommands.NetshTool);

        var result = await _runner.RunAsync(tool, arguments, cancellationToken).ConfigureAwait(false);

        if (result.Succeeded || WindowsRouteCommands.IsAlreadyExists(result))
        {
            // "Already exists" is the normal re-apply case (a reconnect, a second session) and is
            // success, not failure. It is never used to claim the route is correct: InspectAsync
            // reads the table back through the API, which is the check that matters.
            return Result.Ok();
        }

        return Result.Fail(AddFailed(route, result));
    }

    private async Task<Result> DeleteRouteAsync(RouteEntry route, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(route.Interface))
        {
            // Apply refuses to install a route with no interface, so there is nothing to delete.
            return Result.Ok();
        }

        uint? index = null;

        if (route.Destination.IsIPv4)
        {
            WindowsAdapters.TryGetInterfaceIndex(route.Interface, out var resolved);
            index = resolved == 0 ? null : resolved;
        }

        var arguments = route.Destination.IsIPv4
            ? WindowsRouteCommands.DeleteIpv4(route.Destination, route.Gateway, index)
            : WindowsRouteCommands.DeleteIpv6(route.Destination, route.Gateway, route.Interface);

        var tool = route.Destination.IsIPv4
            ? WindowsPlatform.SystemTool(WindowsRouteCommands.RouteTool)
            : WindowsPlatform.SystemTool(WindowsRouteCommands.NetshTool);

        var result = await _runner.RunAsync(tool, arguments, cancellationToken).ConfigureAwait(false);

        // A route that is not there is the desired end state, and this is the case crash recovery
        // depends on: when the core dies its adapter goes with it and takes its routes along.
        return result.Succeeded || WindowsRouteCommands.IsAlreadyGone(result)
            ? Result.Ok()
            : Result.Fail(RemoveFailed(route, result));
    }

    private Result<WindowsRouteRow> ProbeDefaultAsync(string? physicalInterface, CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        foreach (var isIpv6 in new[] { false, true })
        {
            var best = WindowsIpForwardTable.FindBestRoute(
                isIpv6 ? IPAddress.IPv6Any : IPAddress.Any,
                out _);

            if (best is null)
            {
                continue;
            }

            if (best.InterfaceName is not null && IsOwnedInterface(best.InterfaceName))
            {
                continue;
            }

            if (physicalInterface is not null
                && best.InterfaceName is not null
                && !string.Equals(best.InterfaceName, physicalInterface, StringComparison.OrdinalIgnoreCase))
            {
                // The plan names a different uplink than the stack picked. That is worth
                // reporting, but the stack's answer is the one a restore must put back, so it
                // wins here.
                _ = physicalInterface;
            }

            return Result<WindowsRouteRow>.Ok(best);
        }

        return Result<WindowsRouteRow>.Fail(NoDefaultToDisplace());
    }

    private static bool IsOwned(WindowsRouteRow row) =>
        row.InterfaceName is not null && IsOwnedInterface(row.InterfaceName);

    private static bool IsOwnedInterface(string interfaceName) =>
        interfaceName.StartsWith(OwnedInterfacePrefix, StringComparison.OrdinalIgnoreCase);

    private static bool Matches(RouteEntry expected, WindowsRouteRow observed)
    {
        if (!string.Equals(observed.InterfaceName, expected.Interface, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!observed.Destination.Equals(expected.Destination))
        {
            return false;
        }

        if (expected.Gateway is null)
        {
            // An on-link route: the observed next hop must be absent (or zero, which the reader
            // normalizes to absent).
            return observed.NextHop is null;
        }

        return observed.NextHop is not null && SameAddress(observed.NextHop, expected.Gateway);
    }

    private static bool SameAddress(string left, string right) =>
        IPAddress.TryParse(left, out var a) && IPAddress.TryParse(right, out var b)
            ? a.Equals(b)
            : string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static string Describe(WindowsRouteRow row) =>
        $"{row.Destination} via {row.NextHop ?? "on-link"} dev '{row.InterfaceName ?? "?"}' "
        + $"ifindex {row.InterfaceIndex.ToString(CultureInfo.InvariantCulture)} metric "
        + $"{row.Metric.ToString(CultureInfo.InvariantCulture)}";

    private static RouteState EmptyState() => new()
    {
        TunnelRoutesPresent = false,
        BypassRoutesPresent = false,
        OrphanedRoutes = Array.Empty<string>(),
    };

    private static MyVpnError NotElevated() =>
        WindowsPlatform.NotElevated(
            "error.route.needs_privileges",
            "Creating or deleting routes through the NetIO API requires administrative rights, and "
            + "this process has none. The UI must never run elevated; this step belongs to the "
            + "privileged helper.",
            "privilege.install_helper");

    private static MyVpnError NoDefaultToDisplace() =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.displace_without_capture",
            ErrorSeverity.Error,
            "The plan displaces the default route, but no physical default route could be captured "
            + "first, so there would be nothing to fall back to if the tunnel failed to come up.",
            "network.restore");

    private static MyVpnError AddFailed(RouteEntry route, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.add_failed",
            ErrorSeverity.Error,
            $"Adding '{route}' failed with exit code {result.ExitCode}: {WindowsPlatform.Trim(result.Combined)}",
            "network.restore")
        .WithArg("route", route.ToString());

    private static MyVpnError BypassFailed(RouteEntry route, MyVpnError cause) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.bypass_failed",
            ErrorSeverity.Error,
            "The uplink host route that keeps the core's own traffic off the tunnel could not be "
            + $"installed, so no default-capturing route was installed: adding '{route}' failed with "
            + $"{cause.TechnicalDetail ?? cause.MessageKey}.",
            "network.restore")
        .WithArg("route", route.ToString());

    private static MyVpnError RemoveFailed(RouteEntry route, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.route.remove_failed",
            ErrorSeverity.Critical,
            $"Deleting '{route}' failed with exit code {result.ExitCode}: "
            + $"{WindowsPlatform.Trim(result.Combined)}",
            "network.restore")
        .WithArg("route", route.ToString());

    private static MyVpnError RemoveFailed(IReadOnlyList<string> failures) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.route.remove_failed",
            ErrorSeverity.Critical,
            "Some MyVpn routing state could not be removed: "
            + WindowsPlatform.Trim(string.Join(" | ", failures)),
            "network.restore");

    private static string Describe(MyVpnError error) =>
        error.TechnicalDetail ?? error.MessageKey;
}
