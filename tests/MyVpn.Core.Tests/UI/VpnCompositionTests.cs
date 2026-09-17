using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.Infrastructure.App;
using MyVpn.Infrastructure.Diagnostics;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Subscriptions;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.UI.Composition;
using MyVpn.UI.Localization;
using MyVpn.UI.ViewModels;
using Shouldly;

namespace MyVpn.Core.Tests.UI;

/// <summary>
/// The composition root, exercised as a graph rather than as a list of registrations.
/// </summary>
/// <remarks>
/// <para>
/// These tests exist because the whole point of the work is that the UI is driven by the real
/// <see cref="IVpnSession"/> rather than by a private state machine. A test that only checked
/// "the view model has a Connect command" would pass just as happily against the fake that
/// preceded it; resolving the session out of the container and asserting its collaborators is
/// what pins the wiring down.
/// </para>
/// <para>
/// Every test builds the graph against a throwaway state directory. The connect path writes a
/// config file, seeds geo data and spawns a process, so a test using the default root would be
/// modifying the machine it runs on.
/// </para>
/// </remarks>
public sealed class VpnCompositionTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "myvpn-ui-composition",
        Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover temporary directory is not a test failure.
        }
    }

    [Fact]
    public void TheGraphBuildsAndResolvesEveryRegisteredService()
    {
        using var provider = Build();

        // Resolving the session is the assertion that matters: it forces the container to
        // construct the state machine, the paths, the config store, the locator and supervisor
        // over one engine, the geo provider, the resolver, the verifier and the platform ports.
        var session = provider.GetRequiredService<IVpnSession>();
        session.ShouldBeOfType<VpnSession>();

        provider.GetRequiredService<VpnStateMachine>().ShouldNotBeNull();
        provider.GetRequiredService<IAppPaths>().ShouldNotBeNull();
        provider.GetRequiredService<IConfigFileStore>().ShouldBeOfType<AtomicConfigFileStore>();
        provider.GetRequiredService<IGeoDataProvider>().ShouldNotBeNull();
        provider.GetRequiredService<IServerEndpointResolver>().ShouldNotBeNull();
        provider.GetRequiredService<IConnectionVerifier>().ShouldNotBeNull();
        provider.GetRequiredService<SubscriptionFetcher>().ShouldNotBeNull();
        provider.GetRequiredService<SubscriptionHeaderRegistry>().ShouldNotBeNull();
        provider.GetRequiredService<ISubscriptionImporter>().ShouldBeOfType<SubscriptionImporter>();
        provider.GetRequiredService<DiagnosticRunner>().ShouldNotBeNull();
    }

    [Fact]
    public void TheSessionAndItsEngineAreSingletons()
    {
        using var provider = Build();

        provider.GetRequiredService<IVpnSession>().ShouldBeSameAs(provider.GetRequiredService<IVpnSession>());

        // Both adapters must wrap the same engine: a locator built over a second engine would
        // version-probe one supervisor's binary and start it under another.
        var locator = provider.GetRequiredService<ICoreLocator>();
        var supervisor = provider.GetRequiredService<ICoreSupervisor>();
        var engine = provider.GetRequiredService<XrayEngineManager>();

        locator.ShouldBeOfType<CoreLocatorAdapter>();
        supervisor.ShouldBeOfType<CoreSupervisorAdapter>();
        engine.ShouldBeSameAs(provider.GetRequiredService<XrayEngineManager>());

        // The adapters are constructed over that exact instance, which is only observable through
        // the state they report: a fresh engine reports Stopped, and so must both adapters.
        supervisor.State.ShouldBe(CoreState.Stopped);
        locator.Locate(null).IsFailure.ShouldBeTrue(); // no core binary is installed in the test root
    }

    [Fact]
    public void TheAppPathsEnsureTheirDirectoriesExist()
    {
        using var provider = Build();

        var paths = provider.GetRequiredService<IAppPaths>();

        // EnsureCreated() is called by the registration, before anything can try to write.
        Directory.Exists(paths.StateDirectory).ShouldBeTrue();
        Directory.Exists(paths.ConfigDirectory).ShouldBeTrue();
        Directory.Exists(paths.LogDirectory).ShouldBeTrue();
        Directory.Exists(paths.GeoDataDirectory).ShouldBeTrue();
        Directory.Exists(paths.GeoBackupDirectory).ShouldBeTrue();
    }

    [Fact]
    public void TheDiagnosticRunnerIsWiredToTheStandardCheckSet()
    {
        using var provider = Build();

        var runner = provider.GetRequiredService<DiagnosticRunner>();

        // The full default set, not an empty list: a diagnostics screen wired to nothing would
        // render an empty report and look like it had passed.
        runner.Checks.Count.ShouldBe(DiagnosticRunner.CreateDefaultChecks().Count());
        runner.Checks.Count.ShouldBeGreaterThan(0);
    }

    [Fact]
    public void EveryPlatformPortTheFactoryProvidesIsRegistered()
    {
        using var provider = Build();

        var platform = provider.GetRequiredService<Lazy<IPlatformServices>>().Value;
        var ports = provider.GetRequiredService<ServiceCollectionExtensions.PlatformPorts>();

        // Resolved individually rather than as IPlatformServices, because the point is that the
        // session can reach each one through its port without the graph naming a concrete type.
        ports.KillSwitch.ShouldBeSameAs(platform.KillSwitch);
        ports.SystemProxy.ShouldBeSameAs(platform.SystemProxy);
        ports.Routes.ShouldBeSameAs(platform.Routes);
        ports.Dns.ShouldBeSameAs(platform.Dns);
    }

    [Fact]
    public void APlatformWithoutExecutorsStillBuildsASession()
    {
        // The honest case for a build or platform with no Kill Switch, routes, DNS or proxy: the
        // session must still be constructible and must report the absence rather than pretend.
        using var provider = Build(new VpnCompositionOptions
        {
            StateDirectory = _root,
            PlatformServicesFactory = () => new BarePlatformServices(),
        });

        var session = provider.GetRequiredService<IVpnSession>();
        session.ShouldBeOfType<VpnSession>();

        var ports = provider.GetRequiredService<ServiceCollectionExtensions.PlatformPorts>();
        ports.KillSwitch.ShouldBeNull();
        ports.SystemProxy.ShouldBeNull();
        ports.Routes.ShouldBeNull();
        ports.Dns.ShouldBeNull();
    }

    [Fact]
    public void TheMainViewModelResolvesFromTheContainer()
    {
        using var provider = Build();

        var viewModel = provider.GetRequiredService<MainWindowViewModel>();

        // The view models are resolved exactly as App.OnFrameworkInitializationCompleted does it.
        viewModel.Servers.ShouldNotBeNull();
        viewModel.Subscription.ShouldNotBeNull();
        viewModel.Diagnostics.ShouldNotBeNull();
        viewModel.Settings.ShouldNotBeNull();

        viewModel.StatusText.ShouldBe(
            provider.GetRequiredService<LocalizationService>().Get("status.disconnected"));
        viewModel.IsBusy.ShouldBeFalse();
    }

    private ServiceProvider Build(VpnCompositionOptions? options = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Warning));
        services.AddMyVpn(options ?? new VpnCompositionOptions
        {
            StateDirectory = _root,
            PlatformServicesFactory = null,
        });

        // ValidateOnBuild is the substantive check: it forces the container to prove every
        // registration can be constructed, which is what catches a missing port or a captured
        // dependency before the window is ever shown.
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
    }

    /// <summary>A platform that provides nothing beyond its declared capabilities.</summary>
    /// <remarks>
    /// The four executor properties return <c>null</c> even though the contract is non-nullable:
    /// that is precisely the shape the composition root has to survive, and the only way to
    /// reproduce it without a machine that genuinely lacks a firewall backend. The session then
    /// has to warn rather than claim protection it does not have.
    /// </remarks>
    private sealed class BarePlatformServices : IPlatformServices
    {
        public PlatformCapabilities Capabilities { get; } = new()
        {
            Kind = PlatformKind.Linux,
            SupportsTun = false,
            RequiresElevationForTun = true,
            KillSwitchMechanism = KillSwitchMechanism.None,
            SupportsFailClosedKillSwitch = false,
            SupportsBootPersistentKillSwitch = false,
            SupportsIpv6KillSwitch = false,
            ProcessRouting = ProcessRoutingCapability.Unsupported,
            SupportsSystemProxy = false,
            SupportsSplitDns = false,
            SupportsDnsChangeNotifications = false,
        };

        public IPrivilegedHost PrivilegedHost { get; } = new UnavailablePrivilegedHost();

        public IKillSwitch KillSwitch => null!;

        public IRouteManager Routes => null!;

        public IDnsConfigurator Dns => null!;

        public ISystemProxy SystemProxy => null!;

        public IProcessRouter ProcessRouter { get; } = new BareProcessRouter();

        public ITunDeviceManager Tun { get; } = new BareTunDeviceManager();

        public INetworkStateManager NetworkState { get; } = new BareNetworkStateManager();

        public string PathSeparator => "/";

        public IReadOnlyList<string> DefaultCoreSearchPaths { get; } = Array.Empty<string>();
    }

    private sealed class BareProcessRouter : ProcessRouterBase
    {
        public BareProcessRouter() : base(ProcessRoutingCapability.Unsupported)
        {
        }
    }

    private sealed class BareTunDeviceManager : ITunDeviceManager
    {
        public bool IsSupported => false;

        public string DefaultInterfaceName => "myvpn0";

        public Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<IReadOnlyList<string>> GetAddressesAsync(
            string interfaceName,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }

    private sealed class BareNetworkStateManager : INetworkStateManager
    {
        public Task<CleanupReport> EmergencyCleanupAsync(CancellationToken cancellationToken) =>
            Task.FromResult(CleanupReport.FromSteps(Array.Empty<CleanupStep>()));

        public Task<NetworkLeftovers> DetectLeftoversAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new NetworkLeftovers());
    }
}
