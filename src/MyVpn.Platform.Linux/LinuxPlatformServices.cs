using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Linux.Dns;
using MyVpn.Platform.Linux.KillSwitch;
using MyVpn.Platform.Linux.Network;
using MyVpn.Platform.Linux.Proxy;
using MyVpn.Platform.Linux.Routing;
using MyVpn.Platform.Linux.Tun;

namespace MyVpn.Platform.Linux;

/// <summary>
/// Everything platform-specific for Linux, resolved once and injected as one value.
/// </summary>
/// <remarks>
/// All executors share a single <see cref="ICommandRunner"/> so that a test or a diagnostic run
/// can observe or replace every external invocation in one place.
/// </remarks>
public sealed class LinuxPlatformServices : IPlatformServices
{
    public LinuxPlatformServices(
        ICommandRunner? runner = null,
        string tunnelInterfaceName = "myvpn0",
        string killSwitchIdentifier = "myvpn_ks")
    {
        var shared = runner ?? new ProcessCommandRunner();

        KillSwitch = new NftablesKillSwitch(shared);
        Routes = new LinuxRouteManager(shared);
        Dns = new LinuxDnsConfigurator(shared);
        SystemProxy = new LinuxSystemProxy(shared);
        Tun = new LinuxTunDeviceManager(shared);
        ProcessRouter = new LinuxProcessRouter();
        PrivilegedHost = new UnavailablePrivilegedHost();

        NetworkState = new LinuxNetworkStateManager(
            shared,
            KillSwitch,
            Routes,
            Dns,
            SystemProxy,
            tunnelInterfaceName,
            killSwitchIdentifier);
    }

    public PlatformCapabilities Capabilities { get; } = new()
    {
        Kind = PlatformKind.Linux,
        SupportsTun = true,
        RequiresElevationForTun = true,

        // nftables is preferred because a failed `nft -f` batch aborts entirely, leaving the
        // previous rules in force -- a stronger guarantee than iptables' rule-by-rule commits.
        KillSwitchMechanism = KillSwitchMechanism.Nftables,
        SupportsFailClosedKillSwitch = true,

        // Surviving a reboot needs the privileged helper: the rules must be re-installed by a
        // service, and this build has none.
        SupportsBootPersistentKillSwitch = false,

        SupportsIpv6KillSwitch = true,

        // cgroups v2 plus nftables and policy routing make true redirection possible, unlike the
        // other two platforms. See ADR-0007.
        ProcessRouting = ProcessRoutingCapability.FullRedirect,

        SupportsSystemProxy = true,
        SupportsSplitDns = true,

        // Linux has no notification API for resolver changes; the state must be read.
        SupportsDnsChangeNotifications = false,

        KillSwitchIsBestEffort = false,

        Limitations = new[]
        {
            "platform.limitation.system_proxy_is_advisory",
            "platform.limitation.dns_backend_varies_by_distro",
        },
    };

    public IPrivilegedHost PrivilegedHost { get; }

    public IKillSwitch KillSwitch { get; }

    public IRouteManager Routes { get; }

    public IDnsConfigurator Dns { get; }

    public ISystemProxy SystemProxy { get; }

    public IProcessRouter ProcessRouter { get; }

    public ITunDeviceManager Tun { get; }

    public INetworkStateManager NetworkState { get; }

    public string PathSeparator => "/";

    public IReadOnlyList<string> DefaultCoreSearchPaths { get; } = new[]
    {
        "/usr/lib/myvpn",
        "/usr/lib/xray",
        "/usr/local/bin",
        "/usr/bin",
        "/opt/xray",
    };
}

/// <summary>
/// Linux process routing.
/// </summary>
/// <remarks>
/// Enumeration is real. Enforcement is not implemented, and the capability value states what the
/// platform permits rather than what this build does — cgroups v2 with an nftables
/// <c>socket cgroupv2</c> match and policy routing is the documented path (ADR-0007).
/// </remarks>
public sealed class LinuxProcessRouter : ProcessRouterBase
{
    public LinuxProcessRouter() : base(ProcessRoutingCapability.FullRedirect)
    {
    }
}
