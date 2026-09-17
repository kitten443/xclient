using System.Runtime.InteropServices;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.Windows.Dns;
using MyVpn.Platform.Windows.KillSwitch;
using MyVpn.Platform.Windows.Network;
using MyVpn.Platform.Windows.Proxy;
using MyVpn.Platform.Windows.Routing;
using MyVpn.Platform.Windows.Tun;

namespace MyVpn.Platform.Windows;

/// <summary>
/// Everything platform-specific for Windows.
/// </summary>
public sealed class WindowsPlatformServices : IPlatformServices
{
    public WindowsPlatformServices(
        ICommandRunner? runner = null,
        string tunnelInterfaceName = "myvpn0",
        string killSwitchIdentifier = "myvpn_ks")
    {
        var shared = runner ?? new ProcessCommandRunner();

        KillSwitch = new WindowsWfpKillSwitch();
        Routes = new WindowsRouteManager(shared);
        Dns = new WindowsDnsConfigurator(shared);
        // These two deliberately take no command runner: the proxy writes the WinINet registry
        // keys directly and the TUN manager queries adapters through iphlpapi. Reaching for an
        // external tool would be strictly worse -- more failure modes, localised output to parse,
        // and a process launch per query.
        SystemProxy = new WindowsSystemProxy();
        Tun = new WindowsTunDeviceManager();
        ProcessRouter = new WindowsProcessRouter();
        PrivilegedHost = new UnavailablePrivilegedHost();

        NetworkState = new WindowsNetworkStateManager(
            KillSwitch,
            Routes,
            Dns,
            SystemProxy,
            tunnelInterfaceName,
            killSwitchIdentifier);
    }

    public PlatformCapabilities Capabilities { get; } = new()
    {
        Kind = PlatformKind.Windows,
        SupportsTun = true,
        RequiresElevationForTun = true,

        KillSwitchMechanism = KillSwitchMechanism.WindowsFilteringPlatform,
        SupportsFailClosedKillSwitch = true,

        // Achievable in principle: persistent filters plus boot-time twins. It is false here
        // because persistent filters are silently disabled unless the provider sets a service
        // name AND that service is auto-start -- and there is no service in this build yet.
        SupportsBootPersistentKillSwitch = false,

        SupportsIpv6KillSwitch = true,

        // Without a kernel-mode callout driver, WFP can permit or block an application but cannot
        // redirect it into the tunnel. ALE_APP_ID is also path-based, not hash-based, and does not
        // inherit to child processes.
        ProcessRouting = ProcessRoutingCapability.BlockOnly,

        SupportsSystemProxy = true,
        SupportsSplitDns = true,
        SupportsDnsChangeNotifications = true,

        KillSwitchIsBestEffort = false,

        Limitations = new[]
        {
            "platform.limitation.process_routing_block_only",
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

    /// <summary>
    /// Windows accepts both separators; the canonical one is a backslash.
    /// </summary>
    public string PathSeparator => "\\";

    public IReadOnlyList<string> DefaultCoreSearchPaths
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return Array.Empty<string>();
            }

            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            return new[]
            {
                Path.Combine(programFiles, "Xray"),
                Path.Combine(programFiles, "MyVpn"),
            };
        }
    }

    /// <summary>
    /// True when the process can create the tunnel device.
    /// </summary>
    /// <remarks>
    /// Xray needs the Wintun driver and elevation. This is only a hint for the UI; the
    /// authoritative check happens when the core is started.
    /// </remarks>
    public static bool IsElevatedHint => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
}

/// <summary>
/// Windows process routing.
/// </summary>
/// <remarks>
/// The capability is <see cref="ProcessRoutingCapability.BlockOnly"/> because that is what the
/// operating system permits without a kernel-mode WFP callout driver: WFP's <c>ALE_APP_ID</c> can
/// drop an application's traffic, but steering it into the tunnel needs <c>ALE_CONNECT_REDIRECT</c>,
/// which is kernel-mode only. Stating this here is what stops the UI promising per-app tunnelling.
/// </remarks>
public sealed class WindowsProcessRouter : ProcessRouterBase
{
    public WindowsProcessRouter() : base(ProcessRoutingCapability.BlockOnly)
    {
    }
}
