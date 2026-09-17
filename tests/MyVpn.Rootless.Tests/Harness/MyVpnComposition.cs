using Microsoft.Extensions.Logging;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.App;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Net;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Linux.Dns;
using MyVpn.Platform.Linux.KillSwitch;
using MyVpn.Platform.Linux.Routing;

namespace MyVpn.Rootless.Harness;

/// <summary>Inputs the scenario fixes for one run.</summary>
internal sealed record ScenarioOptions
{
    /// <summary>Throwaway directory for everything this run writes.</summary>
    public required string WorkDirectory { get; init; }

    /// <summary>Root of the per-user state MyVpn writes (inside <see cref="WorkDirectory"/>).</summary>
    public required string AppRoot { get; init; }

    /// <summary>The real core binary.</summary>
    public required string CoreBinaryPath { get; init; }

    /// <summary>Throwaway <c>resolv.conf</c> the DNS executor is pointed at.</summary>
    public required string ResolvConfPath { get; init; }

    /// <summary>Throwaway state directory for the DNS executor's backup.</summary>
    public required string DnsStateDirectory { get; init; }

    /// <summary>Read-only geo data shipped next to the core.</summary>
    public required string SeedGeoDataDirectory { get; init; }

    /// <summary>Kill-switch mode to exercise.</summary>
    public required KillSwitchMode KillSwitch { get; init; }

    /// <summary>Address of the core on the far side, as an IP literal so no lookup is involved.</summary>
    public required string ServerAddress { get; init; }

    /// <summary>Port of the core's VLESS inbound.</summary>
    public required int ServerPort { get; init; }

    /// <summary>Credential shared with the far-side inbound.</summary>
    public required string UserId { get; init; }
}

/// <summary>The session and the executors it was wired to.</summary>
internal sealed record VpnComposition(
    VpnSession Session,
    XrayEngineManager Engine,
    LinuxRouteManager Routes,
    LinuxDnsConfigurator Dns,
    RecordingLoggerFactory Loggers);

/// <summary>
/// Builds the same object graph <c>myvpn connect --mode tun</c> builds.
/// </summary>
/// <remarks>
/// <para>
/// This is a deliberate copy of <c>src/MyVpn.Cli/ConnectCommand.cs</c> rather than a new
/// abstraction: the value of the end-to-end test is that it exercises the <i>real</i> composition
/// — the real session, the real route manager, the real DNS executor, the real nftables kill
/// switch — so any drift between this and the CLI is a drift the test would stop catching. The two
/// differences are inputs, not wiring:
/// </para>
/// <list type="number">
/// <item><description>
/// every writable path is redirected under the run's throwaway directory, so the run cannot touch
/// the user's own state;
/// </description></item>
/// <item><description>
/// <c>SkipVerification</c> is set, because the built-in verification measures the exit address by
/// reaching a public endpoint and this namespace has no route to the internet by construction.
/// The tunnel is verified instead by the traffic probe in <see cref="ClientScenario"/>, which is a
/// stronger check than the built-in one for this environment: it proves the destination was
/// reached <i>through</i> the far side rather than merely that some address answered.
/// </description></item>
/// </list>
/// </remarks>
internal static class MyVpnComposition
{
    public static VpnComposition Create(ScenarioOptions options, RecordingLoggerFactory loggers)
    {
        var paths = new AppPaths(options.AppRoot, options.SeedGeoDataDirectory);
        paths.EnsureCreated();

        var stateMachine = new VpnStateMachine();

        var geoManager = new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = paths.GeoDataDirectory,
                SeedDirectory = paths.SeedGeoDataDirectory,
                BackupDirectory = paths.GeoBackupDirectory,
                ManifestPath = paths.GeoManifestPath,
            },
            loggers.CreateLogger<GeoDataManager>());

        var engine = new XrayEngineManager(
            loggers.CreateLogger<XrayEngineManager>(),
            new XrayEngineOptions { AutoRestart = false });

        var routes = new LinuxRouteManager();

        // The file paths are the documented test seam of the executor: without them it would write
        // the host's /etc/resolv.conf and its own state under /var/lib, which a test must never do.
        var dns = new LinuxDnsConfigurator(
            runner: null,
            isElevated: null,
            resolvConfPath: options.ResolvConfPath,
            resolvConfStateDirectory: Path.Combine(options.WorkDirectory, "resolvconf"),
            stateDirectory: options.DnsStateDirectory);

        var session = new VpnSession(
            stateMachine,
            paths,
            new AtomicConfigFileStore(),
            new CoreLocatorAdapter(engine),
            new CoreSupervisorAdapter(engine),
            new GeoDataProviderAdapter(geoManager),
            new DnsServerEndpointResolver(),
            new HttpProxyConnectionVerifier(),

            killSwitch: new NftablesKillSwitch(),
            systemProxy: null,
            routes: routes,
            dns: dns,
            loggers.CreateLogger<VpnSession>());

        return new VpnComposition(session, engine, routes, dns, loggers);
    }

    /// <summary>The settings <c>myvpn connect --mode tun</c> uses, with the same defaults.</summary>
    public static AppSettings BuildSettings(KillSwitchMode killSwitch) => new()
    {
        TunnelMode = TunnelMode.Tun,
        KillSwitch = killSwitch,
        Subscriptions = new SubscriptionSettings(),
        Dns = new DnsSettings { Mode = DnsMode.ThroughTunnel },
        Routing = new RoutingSettings { BypassLan = true },
        Proxy = new ProxySettings { ListenPort = 10808, EnableSocks = true, EnableHttp = true },
        Logging = new LoggingSettings { Verbosity = LogVerbosity.Warning },
    };

    /// <summary>A plain VLESS-over-TCP profile; the far side accepts exactly this credential.</summary>
    public static ServerProfile BuildProfile(ScenarioOptions options) => new()
    {
        DisplayName = "rootless-harness",
        Address = options.ServerAddress,
        Port = options.ServerPort,
        Protocol = ProxyProtocol.Vless,
        UserId = options.UserId,
        Transport = TransportKind.Tcp,
        Security = SecurityKind.None,
    };
}
