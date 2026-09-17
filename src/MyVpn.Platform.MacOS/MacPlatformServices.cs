using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.MacOS.Dns;
using MyVpn.Platform.MacOS.KillSwitch;
using MyVpn.Platform.MacOS.Network;
using MyVpn.Platform.MacOS.Proxy;
using MyVpn.Platform.MacOS.Routing;
using MyVpn.Platform.MacOS.Tun;

namespace MyVpn.Platform.MacOS;

/// <summary>
/// Everything platform-specific for macOS.
/// </summary>
public sealed class MacPlatformServices : IPlatformServices
{
    public MacPlatformServices(
        ICommandRunner? runner = null,
        string tunnelInterfaceName = "utun0",
        string killSwitchIdentifier = "myvpn_ks")
    {
        var shared = runner ?? new ProcessCommandRunner();

        KillSwitch = new MacPfKillSwitch(shared);
        Routes = new MacRouteManager(shared);
        Dns = new MacDnsConfigurator(shared);
        SystemProxy = new MacSystemProxy(shared);
        Tun = new MacTunDeviceManager(shared);
        ProcessRouter = new MacProcessRouter();
        PrivilegedHost = new UnavailablePrivilegedHost();

        NetworkState = new MacNetworkStateManager(
            shared,
            KillSwitch,
            Routes,
            Dns,
            SystemProxy,
            Tun,
            tunnelInterfaceName,
            killSwitchIdentifier);
    }

    public PlatformCapabilities Capabilities { get; } = new()
    {
        Kind = PlatformKind.MacOS,
        SupportsTun = true,
        RequiresElevationForTun = true,

        KillSwitchMechanism = KillSwitchMechanism.PfAnchors,
        SupportsFailClosedKillSwitch = true,

        // Needs a privileged launchd daemon to re-install rules, which this build does not have.
        SupportsBootPersistentKillSwitch = false,

        SupportsIpv6KillSwitch = true,

        // The honest verdict, recorded at length in MacPfKillSwitch: true per-process tunnelling
        // is not achievable for a self-distributed client, so only UID block-lists are offered.
        ProcessRouting = ProcessRoutingCapability.UidBlockList,

        SupportsSystemProxy = true,
        SupportsSplitDns = true,
        SupportsDnsChangeNotifications = true,

        // Apple technote TN3165 states verbatim that Packet Filter "is not considered API" and
        // directs developers to Network Extension instead. The mechanism works today but carries
        // no compatibility guarantee, and the UI must say so rather than presenting it as
        // equivalent to the other platforms.
        KillSwitchIsBestEffort = true,

        Limitations = new[]
        {
            "platform.limitation.pf_not_api",
            "platform.limitation.process_routing_uid_only",
            "platform.limitation.utun_name_dynamic",
        },
    };

    public IPrivilegedHost PrivilegedHost { get; }

    public MyVpn.Platform.Abstractions.KillSwitch.IKillSwitch KillSwitch { get; }

    public MyVpn.Platform.Abstractions.Routing.IRouteManager Routes { get; }

    public MyVpn.Platform.Abstractions.Dns.IDnsConfigurator Dns { get; }

    public MyVpn.Platform.Abstractions.Proxy.ISystemProxy SystemProxy { get; }

    public IProcessRouter ProcessRouter { get; }

    public MyVpn.Platform.Abstractions.Platform.ITunDeviceManager Tun { get; }

    public MyVpn.Platform.Abstractions.Platform.INetworkStateManager NetworkState { get; }

    public string PathSeparator => "/";

    public IReadOnlyList<string> DefaultCoreSearchPaths { get; } = new[]
    {
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/local/lib/myvpn",
    };
}

/// <summary>
/// macOS process routing.
/// </summary>
/// <remarks>
/// <see cref="ProcessRoutingCapability.UidBlockList"/> is the honest ceiling: PF's
/// <c>user</c>/<c>group</c> are match criteria only and cannot appear on <c>nat</c>/<c>rdr</c>,
/// <c>NEAppRule</c> is read-only to the provider, and <c>NEFilterDataProvider</c> cannot relay.
/// Enumeration works; enforcement does not exist.
/// </remarks>
public sealed class MacProcessRouter : ProcessRouterBase
{
    public MacProcessRouter() : base(ProcessRoutingCapability.UidBlockList)
    {
    }
}
