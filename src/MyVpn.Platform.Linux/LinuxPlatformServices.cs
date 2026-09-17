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
using MyVpn.Platform.Linux.ProcessRouting;
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
    /// <param name="vpnServerEndpoints">
    /// Resolved server addresses, when the caller already knows them.
    /// </param>
    /// <remarks>
    /// The endpoints are the outermost loop-prevention layer for process routing: an
    /// <c>ip rule to &lt;server&gt; lookup main</c> that keeps the core's own connection off any
    /// policy-routed table. They are only known after the profile's server has been resolved, so
    /// a composition that enables process routing should construct the router once resolution has
    /// happened rather than expecting the factory to conjure them. Passing <c>null</c> is
    /// supported and leaves the remaining two layers in force — the core is never moved into a
    /// routed slice, and the rendered rules <c>return</c> for traffic leaving via the tunnel.
    /// </remarks>
    public LinuxPlatformServices(
        ICommandRunner? runner = null,
        string tunnelInterfaceName = "myvpn0",
        string killSwitchIdentifier = "myvpn_ks",
        IReadOnlyList<string>? vpnServerEndpoints = null)
    {
        var shared = runner ?? new ProcessCommandRunner();

        KillSwitch = new NftablesKillSwitch(shared);
        Routes = new LinuxRouteManager(shared);
        Dns = new LinuxDnsConfigurator(shared);
        SystemProxy = new LinuxSystemProxy(shared);
        Tun = new LinuxTunDeviceManager(shared);
        // CgroupV2ProcessRouter, not the stub: the stub refuses every plan, which would look
        // like a working feature that silently never applies. The stub was removed rather than
        // left beside this one, because two similarly named routers is a footgun.
        ProcessRouter = new CgroupV2ProcessRouter(
            shared,
            tunnelInterface: tunnelInterfaceName,
            vpnServerEndpoints: vpnServerEndpoints);
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
