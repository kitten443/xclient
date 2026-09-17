using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Subscriptions;
using MyVpn.Infrastructure.App;
using MyVpn.Infrastructure.Diagnostics;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Net;
using MyVpn.Infrastructure.Subscriptions;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.UI.Localization;
using MyVpn.UI.ViewModels;

namespace MyVpn.UI.Composition;

/// <summary>
/// Knobs the composition root needs that are not part of the application graph.
/// </summary>
/// <remarks>
/// <paramref name="StateDirectory"/> exists so tests (and a future portable mode) can point the
/// whole graph at a temporary root instead of the real per-user profile. The connect path writes
/// a config file, seeds geo data and spawns a process, so a test that used the default root would
/// be modifying the machine running it.
/// </remarks>
public sealed record VpnCompositionOptions
{
    /// <summary>Overrides the per-user state root. <c>null</c> uses the platform default.</summary>
    public string? StateDirectory { get; init; }

    /// <summary>Overrides the read-only geo seed directory. <c>null</c> uses the default search.</summary>
    public string? SeedGeoDataDirectory { get; init; }

    /// <summary>
    /// Restart the core automatically after an unexpected exit.
    /// </summary>
    /// <remarks>
    /// Off by default here, matching the CLI: a GUI that silently restarts the core is a GUI
    /// whose displayed state can diverge from what the user asked for. Reconnection is a decision
    /// for the session/user, not a background thread.
    /// </remarks>
    public bool AutoRestartCore { get; init; }

    /// <summary>
    /// Overrides the platform factory.
    /// </summary>
    /// <remarks>
    /// A seam for tests, and the only way to exercise the "this platform has no Kill Switch"
    /// path without a machine that actually lacks one. It does not weaken the security property
    /// it appears to: the override still has to be supplied by the process that builds the graph,
    /// and the graph it builds is exactly the production one.
    /// </remarks>
    public Func<IPlatformServices>? PlatformServicesFactory { get; init; }
}

/// <summary>
/// The composition root: one object graph, built once.
/// </summary>
/// <remarks>
/// <para>
/// <b>The UI never calls a privileged API.</b> Everything that mutates the network — the firewall,
/// routes, the resolver, the desktop proxy, the Xray process — is reached through
/// <see cref="IVpnSession"/>, which reaches it through the ports in
/// <c>MyVpn.Application.Abstractions</c>. The one privileged-adjacent act the UI performs is
/// constructing the platform services factory for the current operating system
/// (<see cref="CreatePlatformServices"/>); after that it only ever holds the port interfaces that
/// factory exposes, and the view models hold nothing but <see cref="IVpnSession"/>.
/// </para>
/// <para>
/// The graph deliberately mirrors <c>MyVpn.Cli/ConnectCommand.cs</c>. Two entry points that
/// compose the same application differently is how the GUI and the CLI start disagreeing about
/// what "connected" means, so this is a copy of that wiring rather than a second design.
/// </para>
/// <para>
/// Two registration details are load-bearing:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="XrayEngineManager"/> is registered as a <i>singleton</i> and both
/// <see cref="CoreLocatorAdapter"/> and <see cref="CoreSupervisorAdapter"/> wrap that same
/// instance. Registering the engine twice would give the locator a different process supervisor
/// from the one the session starts, so the version probe and the running core would be unrelated.
/// </description></item>
/// <item><description>
/// The platform executors are resolved from the <i>same</i> factory instance, so they share one
/// <c>ICommandRunner</c> and one view of the machine.
/// </description></item>
/// </list>
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>Registers the complete graph. Call once, at startup.</summary>
    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "Every IDisposable created here is owned by the container, which disposes it.")]
    public static IServiceCollection AddMyVpn(
        this IServiceCollection services,
        VpnCompositionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var effective = options ?? new VpnCompositionOptions();

        services.AddSingleton(effective);
        services.AddSingleton<LocalizationService>();

        // ---- paths -----------------------------------------------------------
        // EnsureCreated() runs here rather than lazily on first write: the core's working
        // directory, the log directory and the geo working copy must all exist before anything
        // tries to use them, and a failure to create them is a startup problem worth surfacing
        // immediately rather than a mid-connect surprise.
        services.AddSingleton<IAppPaths>(_ =>
        {
            var paths = new AppPaths(effective.StateDirectory, effective.SeedGeoDataDirectory);
            paths.EnsureCreated();
            return paths;
        });

        services.AddSingleton<IConfigFileStore, AtomicConfigFileStore>();

        // The UI's own persisted state (profile list, chosen core binary, subscription URL).
        // Registered here rather than beside the view models because the import view model is
        // constructed with it and reads the live settings out of it.
        services.AddSingleton<IUserSettingsStore, JsonUserSettingsStore>();

        // ---- core supervision ------------------------------------------------
        services.AddSingleton(_ => new XrayEngineManager(
            _.GetRequiredService<ILogger<XrayEngineManager>>(),
            new XrayEngineOptions { AutoRestart = effective.AutoRestartCore }));

        // The engine is also exposed as IXrayEngine, so the diagnostics context can inspect the
        // very supervisor the session starts the core with.
        services.AddSingleton<IXrayEngine>(sp => sp.GetRequiredService<XrayEngineManager>());

        // Both adapters wrap the singleton engine registered above.
        services.AddSingleton<ICoreLocator>(sp => new CoreLocatorAdapter(
            sp.GetRequiredService<XrayEngineManager>()));
        services.AddSingleton<ICoreSupervisor>(sp => new CoreSupervisorAdapter(
            sp.GetRequiredService<XrayEngineManager>()));

        // ---- geo data --------------------------------------------------------
        services.AddSingleton(sp => new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = sp.GetRequiredService<IAppPaths>().GeoDataDirectory,
                SeedDirectory = sp.GetRequiredService<IAppPaths>().SeedGeoDataDirectory,
                BackupDirectory = sp.GetRequiredService<IAppPaths>().GeoBackupDirectory,
                ManifestPath = sp.GetRequiredService<IAppPaths>().GeoManifestPath,
            },
            sp.GetRequiredService<ILogger<GeoDataManager>>()));

        services.AddSingleton<IGeoDataProvider>(sp => new GeoDataProviderAdapter(
            sp.GetRequiredService<GeoDataManager>()));

        // ---- network services ------------------------------------------------
        services.AddSingleton<IServerEndpointResolver, DnsServerEndpointResolver>();
        services.AddSingleton<IConnectionVerifier, HttpProxyConnectionVerifier>();

        // ---- platform executors ----------------------------------------------
        // The factory is built once behind a Lazy: resolving it twice would construct two
        // command runners and two kill switches, and the kill switch the session armed would
        // not be the one anything else inspected. Lazy (rather than an eagerly built instance)
        // keeps the selection at startup instead of at graph-registration time, so a failure to
        // construct a platform service is attributed to the resolution that needed it.
        var platformFactory = effective.PlatformServicesFactory ?? CreatePlatformServices;

        services.AddSingleton(_ => new Lazy<IPlatformServices>(
            platformFactory,
            LazyThreadSafetyMode.ExecutionAndPublication));

        services.AddSingleton(sp =>
        {
            var platform = sp.GetRequiredService<Lazy<IPlatformServices>>().Value;

            return new PlatformPorts(
                platform.KillSwitch,
                platform.SystemProxy,
                platform.Routes,
                platform.Dns);
        });

        // ---- the session -----------------------------------------------------
        services.AddSingleton<VpnStateMachine>();
        services.AddSingleton<IVpnSession>(sp => new VpnSession(
            sp.GetRequiredService<VpnStateMachine>(),
            sp.GetRequiredService<IAppPaths>(),
            sp.GetRequiredService<IConfigFileStore>(),
            sp.GetRequiredService<ICoreLocator>(),
            sp.GetRequiredService<ICoreSupervisor>(),
            sp.GetRequiredService<IGeoDataProvider>(),
            sp.GetRequiredService<IServerEndpointResolver>(),
            sp.GetRequiredService<IConnectionVerifier>(),

            // These four are legitimately absent on a platform or a build that cannot provide
            // them, and the session handles null by warning instead of pretending. Resolving
            // them from the factory (rather than constructing them here) is what keeps the UI
            // free of any reference to a concrete executor.
            sp.GetRequiredService<PlatformPorts>().KillSwitch,
            sp.GetRequiredService<PlatformPorts>().SystemProxy,
            sp.GetRequiredService<PlatformPorts>().Routes,
            sp.GetRequiredService<PlatformPorts>().Dns,
            sp.GetRequiredService<ILogger<VpnSession>>()));

        // ---- subscriptions ---------------------------------------------------
        // A singleton, so its connection pool and certificate-revocation policy are reused across
        // refreshes. It is never handed a URL by anything but the user's own input, and the URL
        // is never logged (it carries a token).
        services.AddSingleton(_ => new SubscriptionFetcher());
        services.AddSingleton(_ => SubscriptionHeaderRegistry.CreateDefault());
        services.AddSingleton<ISubscriptionImporter, SubscriptionImporter>();

        // ---- diagnostics -----------------------------------------------------
        services.AddSingleton(sp => new DiagnosticRunner(
            DiagnosticRunner.CreateDefaultChecks(),
            sp.GetRequiredService<ILogger<DiagnosticRunner>>()));

        services.AddSingleton(sp => new DiagnosticContextProvider(
            sp.GetRequiredService<IUserSettingsStore>(),
            sp.GetRequiredService<ServerListViewModel>(),
            sp.GetRequiredService<GeoDataManager>(),
            sp.GetRequiredService<IXrayEngine>(),
            sp.GetRequiredService<Lazy<IPlatformServices>>().Value));

        // ---- view models -----------------------------------------------------
        services.AddSingleton<MainWindowViewModel>();
        services.AddSingleton<ServerListViewModel>();
        services.AddSingleton<SubscriptionImportViewModel>();
        services.AddSingleton<DiagnosticsViewModel>();
        services.AddSingleton<SettingsViewModel>();

        return services;
    }

    /// <summary>
    /// The platform executors this graph resolved, or <c>null</c> for one the platform lacks.
    /// </summary>
    /// <remarks>
    /// Registered by the composition root so the session factory and any test or diagnostic can
    /// observe the same decision. "Absent" and "broken" have to be distinguishable: a platform
    /// with no Kill Switch is a documented limitation the session warns about, while a port that
    /// failed to register is a bug in the graph.
    /// </remarks>
    public sealed record PlatformPorts(
        IKillSwitch? KillSwitch,
        ISystemProxy? SystemProxy,
        IRouteManager? Routes,
        IDnsConfigurator? Dns);


    /// <summary>
    /// Builds the platform services factory for the operating system this process runs on.
    /// </summary>
    /// <remarks>
    /// This is the only place in the UI that names a concrete platform type. It is a factory
    /// choice, not an operation: nothing here touches the firewall, the routing table or the
    /// resolver, and every executor it produces is used exclusively through the abstractions.
    /// </remarks>
    public static IPlatformServices CreatePlatformServices()
    {
        if (OperatingSystem.IsWindows())
        {
            return new MyVpn.Platform.Windows.WindowsPlatformServices();
        }

        if (OperatingSystem.IsMacOS())
        {
            return new MyVpn.Platform.MacOS.MacPlatformServices();
        }

        return new MyVpn.Platform.Linux.LinuxPlatformServices();
    }
}
