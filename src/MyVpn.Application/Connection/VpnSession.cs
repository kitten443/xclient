using Microsoft.Extensions.Logging;
using MyVpn.Application.Abstractions;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Xray;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Application.Connection;

/// <summary>A request to establish a tunnel.</summary>
public sealed record ConnectRequest
{
    public required ServerProfile Profile { get; init; }

    public required AppSettings Settings { get; init; }

    /// <summary>Explicit core binary chosen by the user; <c>null</c> uses the search order.</summary>
    public string? CoreBinaryPath { get; init; }

    /// <summary>
    /// Skip the real-traffic verification.
    /// </summary>
    /// <remarks>
    /// Exists for offline diagnostics only. Verification is what distinguishes "the process
    /// started" from "the tunnel carries traffic", so turning it off must be an explicit choice.
    /// </remarks>
    public bool SkipVerification { get; init; }
}

/// <summary>A complete picture of the session, for the UI and for diagnostics.</summary>
public sealed record ConnectionSnapshot
{
    public required VpnConnectionState State { get; init; }

    public Guid? ProfileId { get; init; }

    public string? ProfileName { get; init; }

    public DateTimeOffset? ConnectedAt { get; init; }

    public string? ConfigPath { get; init; }

    public string? CoreVersion { get; init; }

    public int? CoreProcessId { get; init; }

    /// <summary>Evidence that traffic traverses the tunnel, once established.</summary>
    public ConnectionVerification? Verification { get; init; }

    public IReadOnlyList<MyVpnError> Warnings { get; init; } = Array.Empty<MyVpnError>();

    public MyVpnError? LastError { get; init; }

    public bool KillSwitchArmed { get; init; }

    /// <summary>Geo routing features that were actually available when the config was built.</summary>
    public GeoRuleAvailability GeoAvailability { get; init; }
}

public interface IVpnSession
{
    VpnConnectionState State { get; }

    event EventHandler<VpnStateChange>? StateChanged;

    event EventHandler<ConnectionSnapshot>? SnapshotChanged;

    ConnectionSnapshot Snapshot { get; }

    Task<Result<ConnectionSnapshot>> ConnectAsync(ConnectRequest request, CancellationToken cancellationToken);

    Task<Result> DisconnectAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Owns the connect and disconnect sequences.
/// </summary>
/// <remarks>
/// <para><b>Ordering is a security property.</b> The sequence is:</para>
/// <list type="number">
/// <item><description>resolve the server, inspect geo data, generate and stage the config — all
/// before anything touches the network;</description></item>
/// <item><description>arm the Kill Switch, so nothing can leak while the core is coming up;</description></item>
/// <item><description>start the core;</description></item>
/// <item><description>verify with real traffic.</description></item>
/// </list>
/// <para>
/// Teardown runs in exactly the reverse order. Arming before starting is what closes the leak
/// window during connect; if the core then fails, we roll back rather than leaving the machine
/// fenced off.
/// </para>
/// <para><b>A failed first connect returns to Disconnected, not Faulted.</b> The domain rule that
/// <c>Faulted</c> keeps the Kill Switch engaged is about losing an established session. Applying
/// it to a connection that never came up would brick the network on a typo, so a failed connect
/// disarms, cleans up, and reports the error — leaving the user exactly where they started,
/// free to retry.
/// </para>
/// </remarks>
public sealed class VpnSession : IVpnSession
{
    private readonly VpnStateMachine _stateMachine;
    private readonly IAppPaths _paths;
    private readonly IConfigFileStore _files;
    private readonly ICoreLocator _locator;
    private readonly ICoreSupervisor _core;
    private readonly IGeoDataProvider _geo;
    private readonly IServerEndpointResolver _resolver;
    private readonly IConnectionVerifier _verifier;
    private readonly IKillSwitch? _killSwitch;
    private readonly ILogger<VpnSession> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private ConnectionSnapshot _snapshot;
    private KillSwitchPlan? _armedPlan;

    public VpnSession(
        VpnStateMachine stateMachine,
        IAppPaths paths,
        IConfigFileStore files,
        ICoreLocator locator,
        ICoreSupervisor core,
        IGeoDataProvider geo,
        IServerEndpointResolver resolver,
        IConnectionVerifier verifier,
        IKillSwitch? killSwitch,
        ILogger<VpnSession> logger)
    {
        _stateMachine = stateMachine ?? throw new ArgumentNullException(nameof(stateMachine));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _files = files ?? throw new ArgumentNullException(nameof(files));
        _locator = locator ?? throw new ArgumentNullException(nameof(locator));
        _core = core ?? throw new ArgumentNullException(nameof(core));
        _geo = geo ?? throw new ArgumentNullException(nameof(geo));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _killSwitch = killSwitch;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _snapshot = new ConnectionSnapshot { State = _stateMachine.Current };
        _stateMachine.StateChanged += (_, change) =>
        {
            _snapshot = _snapshot with { State = change.To };
            StateChanged?.Invoke(this, change);
            RaiseSnapshot();
        };
    }

    public VpnConnectionState State => _stateMachine.Current;

    public event EventHandler<VpnStateChange>? StateChanged;

    public event EventHandler<ConnectionSnapshot>? SnapshotChanged;

    public ConnectionSnapshot Snapshot => _snapshot;

    public async Task<Result<ConnectionSnapshot>> ConnectAsync(
        ConnectRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Serialize connect/disconnect: two concurrent connects would fight over one config file
        // and one core process.
        if (!await _gate.WaitAsync(TimeSpan.Zero, cancellationToken).ConfigureAwait(false))
        {
            return Result<ConnectionSnapshot>.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.session.busy",
                ErrorSeverity.Warning,
                "A connection operation is already in progress."));
        }

        try
        {
            return await ConnectCoreAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<Result<ConnectionSnapshot>> ConnectCoreAsync(
        ConnectRequest request,
        CancellationToken cancellationToken)
    {
        var settings = request.Settings;
        var profile = request.Profile;
        var warnings = new List<MyVpnError>();

        _snapshot = _snapshot with
        {
            LastError = null,
            Warnings = Array.Empty<MyVpnError>(),
            Verification = null,
            ProfileId = profile.Id,
            ProfileName = profile.DisplayName,
        };

        // ---- 1. validate before touching anything --------------------------------
        if (!_stateMachine.TryTransitionTo(VpnConnectionState.Preparing, "connect").IsSuccess)
        {
            return Fail(
                new MyVpnError(ErrorCodes.ConfigInvalid, "error.session.cannot_connect_from_state",
                    ErrorSeverity.Warning, $"Cannot start a connection while {_stateMachine.Current}."),
                warnings);
        }

        var profileValidation = profile.Validate();
        if (profileValidation.IsFailure)
        {
            return Fail(profileValidation.Error!, warnings);
        }

        var settingsValidation = settings.Validate();
        if (settingsValidation.IsFailure)
        {
            return Fail(settingsValidation.Error!, warnings);
        }

        // ---- 2. locate the core -------------------------------------------------
        var located = _locator.Locate(request.CoreBinaryPath);
        if (located.IsFailure)
        {
            return Fail(located.Error!, warnings);
        }

        var binaryPath = located.Value;
        string? coreVersion = null;

        var versionProbe = await _locator.ProbeVersionAsync(binaryPath, cancellationToken);
        if (versionProbe.IsSuccess)
        {
            coreVersion = versionProbe.Value;

            if (XrayVersion.TryParse(coreVersion, out var parsed))
            {
                var support = XrayVersionPolicy.Evaluate(
                    parsed,
                    tunRequired: settings.TunnelMode == TunnelMode.Tun);

                if (!support.IsUsable)
                {
                    return Fail(
                        support.ToResult().Error ?? new MyVpnError(
                            ErrorCodes.XrayVersionUnsupported, "error.xray.version_unsupported"),
                        warnings);
                }

                if (!support.IsRecommended)
                {
                    warnings.Add(new MyVpnError(
                        ErrorCodes.XrayVersionUnsupported,
                        "diagnostics.warning.core_version_old",
                        ErrorSeverity.Warning,
                        $"Detected Xray {coreVersion}; {XrayVersionPolicy.Recommended} is recommended.")
                        .WithArg("version", coreVersion));
                }
            }
        }
        else
        {
            // An unreadable version is a warning, not a stop: the core may still work, and the
            // pre-flight will catch a config it cannot parse.
            warnings.Add(versionProbe.Error!);
        }

        // ---- 3. resolve the server (needed for the Kill Switch) -----------------
        IReadOnlyList<ServerEndpoint> endpoints = Array.Empty<ServerEndpoint>();
        var resolution = await _resolver.ResolveAsync(profile, cancellationToken).ConfigureAwait(false);

        if (resolution.IsSuccess)
        {
            endpoints = resolution.Value;
        }
        else if (settings.KillSwitch != KillSwitchMode.Disabled)
        {
            // The Kill Switch cannot be armed without a pinned address, and connecting without the
            // protection the user asked for is worse than refusing. Fail closed.
            return Fail(resolution.Error!, warnings);
        }
        else
        {
            warnings.Add(resolution.Error!);
        }

        // ---- 4. geo data --------------------------------------------------------
        // Seed the writable working copy first. The directory exported as XRAY_LOCATION_ASSET must
        // be the one that actually holds the files: resolving assets from a seed directory while
        // pointing the core at an empty working copy is the issue #9765 failure reproduced
        // exactly, and it makes the core reject the whole routing configuration.
        var geoStatus = await _geo.EnsureWorkingCopyAsync(cancellationToken).ConfigureAwait(false);
        if (geoStatus.RequiresRepair)
        {
            foreach (var asset in geoStatus.ProblemAssets)
            {
                var error = asset.ToError();
                if (error is not null)
                {
                    warnings.Add(error);
                }
            }

            // Not fatal by design: the config builder omits geo-dependent rules when the asset is
            // unusable, so the tunnel still comes up with a reduced routing policy.
            _logger.LogWarning(
                "Geo data is degraded (geoip={GeoIp}, geosite={GeoSite}); geo-dependent routing rules will be omitted.",
                geoStatus.GeoIp.Health,
                geoStatus.GeoSite.Health);
        }

        var availability = GeoRuleAvailability.From(geoStatus);

        // ---- 5. build and stage the configuration -------------------------------
        var build = XrayConfigBuilder.Build(new XrayConfigRequest
        {
            Profile = profile,
            Settings = settings,
            GeoAvailability = availability,
            ResolvedServerEndpoints = endpoints,
            AssetDirectory = _paths.GeoDataDirectory,
            CoreVersion = XrayVersion.TryParse(coreVersion, out var v) ? v : XrayVersionPolicy.Recommended,
            Platform = DetectPlatform(),
            SocksPort = settings.Proxy.ListenPort,
            HttpPort = settings.Proxy.ListenPort + 1,
        });

        if (build.IsFailure)
        {
            return Fail(build.Error!, warnings);
        }

        warnings.AddRange(build.Value.Warnings);

        var configPath = _paths.ActiveConfigPath;
        var written = await _files
            .WriteAtomicAsync(configPath, XrayConfigBuilder.Serialize(build.Value.Config), cancellationToken)
            .ConfigureAwait(false);

        if (written.IsFailure)
        {
            return Fail(written.Error!, warnings);
        }

        // The pre-launch assertion from issue #9765: confirm the core will resolve the same asset
        // directory MyVpn validated, rather than falling back to its own.
        var assetCheck = _geo.VerifyBeforeLaunch(binaryPath);
        if (assetCheck.IsFailure)
        {
            warnings.Add(assetCheck.Error!);
        }

        _snapshot = _snapshot with
        {
            ConfigPath = configPath,
            CoreVersion = coreVersion,
            Warnings = warnings.ToArray(),
            GeoAvailability = availability,
        };

        RaiseSnapshot();

        // ---- 6. arm the Kill Switch BEFORE the core starts ----------------------
        var armed = await ArmKillSwitchAsync(settings, profile, endpoints, binaryPath, warnings, cancellationToken)
            .ConfigureAwait(false);

        if (armed.IsFailure)
        {
            await RollbackAsync(disarmKillSwitch: true, stopCore: false, deleteConfig: true, cancellationToken)
                .ConfigureAwait(false);

            return Fail(armed.Error!, warnings);
        }

        // ---- 7. start the core ---------------------------------------------------
        if (!_stateMachine.TryTransitionTo(VpnConnectionState.Connecting, "core-start").IsSuccess)
        {
            await RollbackAsync(disarmKillSwitch: true, stopCore: false, deleteConfig: true, cancellationToken)
                .ConfigureAwait(false);

            return Fail(
                new MyVpnError(ErrorCodes.XrayStartFailed, "error.session.cannot_connect_from_state",
                    ErrorSeverity.Error, $"Unexpected state {_stateMachine.Current} before start."),
                warnings);
        }

        var started = await _core.StartAsync(new CoreStartRequest
        {
            BinaryPath = binaryPath,
            ConfigPath = configPath,
            WorkingDirectory = _paths.ConfigDirectory,
            AssetDirectory = _paths.GeoDataDirectory,
            Environment = _geo.BuildCoreEnvironment(),
        }, cancellationToken).ConfigureAwait(false);

        if (started.IsFailure)
        {
            await RollbackAsync(disarmKillSwitch: true, stopCore: true, deleteConfig: true, cancellationToken)
                .ConfigureAwait(false);

            return Fail(started.Error!, warnings);
        }

        var coreStatus = _core.GetStatus();
        _snapshot = _snapshot with { CoreProcessId = coreStatus.ProcessId };
        RaiseSnapshot();

        // ---- 8. verify with real traffic ---------------------------------------
        ConnectionVerification? verification = null;

        if (!request.SkipVerification)
        {
            var direct = await _verifier
                .MeasureDirectAddressAsync(ConnectionDefaults.DirectAddressTimeout, cancellationToken)
                .ConfigureAwait(false);

            var verified = await _verifier.VerifyAsync(
                settings.TunnelMode,
                settings.Proxy,
                ConnectionDefaults.VerificationTimeout,
                cancellationToken);

            if (verified.IsFailure)
            {
                // A core that runs but carries nothing is the single most common failure report.
                // Treating it as success would be the most misleading thing this class could do.
                await RollbackAsync(disarmKillSwitch: true, stopCore: true, deleteConfig: true, cancellationToken)
                    .ConfigureAwait(false);

                return Fail(verified.Error!, warnings);
            }

            verification = verified.Value with { DirectAddress = direct };

            warnings.AddRange(BuildVerificationWarnings(verification, endpoints));
        }

        // ---- 9. connected -------------------------------------------------------
        _stateMachine.TryTransitionTo(VpnConnectionState.Connected, "verified");

        _snapshot = _snapshot with
        {
            ConnectedAt = DateTimeOffset.UtcNow,
            Verification = verification,
            Warnings = warnings.ToArray(),
            KillSwitchArmed = _armedPlan is not null,
        };

        RaiseSnapshot();

        _logger.LogInformation(
            "Connected to {Profile} via {Transport}/{Security}; exit {Exit}.",
            profile.DisplayName,
            profile.Transport,
            profile.Security,
            verification?.ExitAddress ?? "unverified");

        return Result<ConnectionSnapshot>.Ok(_snapshot);
    }

    public async Task<Result> DisconnectAsync(CancellationToken cancellationToken)
    {
        if (!await _gate.WaitAsync(TimeSpan.Zero, cancellationToken).ConfigureAwait(false))
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid, "error.session.busy", ErrorSeverity.Warning,
                "A connection operation is already in progress."));
        }

        try
        {
            if (_stateMachine.Current == VpnConnectionState.Disconnected)
            {
                return Result.Ok();
            }

            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnecting, "user-disconnect");

            await RollbackAsync(disarmKillSwitch: true, stopCore: true, deleteConfig: true, cancellationToken)
                .ConfigureAwait(false);

            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnected, "disconnected");

            _snapshot = _snapshot with
            {
                ConnectedAt = null,
                Verification = null,
                CoreProcessId = null,
                KillSwitchArmed = false,
                ConfigPath = null,
            };

            RaiseSnapshot();
            return Result.Ok();
        }
        finally
        {
            _gate.Release();
        }
    }

    // ------------------------------------------------------------------ helpers

    private async Task<Result> ArmKillSwitchAsync(
        AppSettings settings,
        ServerProfile profile,
        IReadOnlyList<ServerEndpoint> endpoints,
        string binaryPath,
        ICollection<MyVpnError> warnings,
        CancellationToken cancellationToken)
    {
        if (settings.KillSwitch == KillSwitchMode.Disabled)
        {
            return Result.Ok();
        }

        if (_killSwitch is null || !_killSwitch.IsSupported)
        {
            // No executor for this platform or build. Report it loudly rather than silently
            // connecting without the protection the user selected.
            warnings.Add(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.not_available",
                ErrorSeverity.Warning,
                "No Kill Switch implementation is available in this build; connecting without it."));

            _logger.LogWarning("Kill Switch requested but no implementation is available.");
            return Result.Ok();
        }

        var built = KillSwitchPlanBuilder.Build(new KillSwitchPlanRequest
        {
            Mode = settings.KillSwitch,
            Identifier = "myvpn_ks",
            TunnelInterface = string.IsNullOrWhiteSpace(settings.Tun.InterfaceName)
                ? "myvpn0"
                : settings.Tun.InterfaceName!,
            ResolvedServerEndpoints = endpoints,
            ConfiguredServerEndpoints = new[] { profile.ToEndpoint() },
            CoreExecutablePath = binaryPath,
            ResolverAddresses = settings.Dns.Mode == DnsMode.System
                ? Array.Empty<string>()
                : settings.Dns.Servers,
            Ipv6 = settings.Ipv6,
            AllowLan = settings.Routing.BypassLan,
            LocalInboundPort = settings.Proxy.ListenPort,
        });

        if (built.IsFailure)
        {
            return Result.Fail(built.Error!);
        }

        var applied = await _killSwitch.ApplyAsync(built.Value, cancellationToken);
        if (!applied.Succeeded)
        {
            return Result.Fail(applied.Error ?? new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed, "error.killswitch.apply_failed", ErrorSeverity.Error,
                applied.PlatformOutput));
        }

        _armedPlan = built.Value;

        // Read back what the platform actually holds. A firewall helper that trusts its own exit
        // code will eventually report success while the rules were silently dropped.
        var state = await _killSwitch.InspectAsync(built.Value, cancellationToken).ConfigureAwait(false);
        if (!state.IsArmed)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.KillSwitchVerificationFailed,
                "error.killswitch.verification_failed",
                ErrorSeverity.Error,
                "The Kill Switch rules were reported as applied but are not present on the system."));
        }

        _logger.LogInformation("Kill Switch armed via {Mechanism}.", _killSwitch.MechanismName);
        return Result.Ok();
    }

    private async Task RollbackAsync(
        bool disarmKillSwitch,
        bool stopCore,
        bool deleteConfig,
        CancellationToken cancellationToken)
    {
        // Every step is attempted even if an earlier one fails: a cleanup that stops at the first
        // error is exactly the situation the user is trying to escape.
        if (stopCore && _core.State != CoreState.Stopped)
        {
            var stopped = await _core.StopAsync(cancellationToken).ConfigureAwait(false);
            if (stopped.IsFailure)
            {
                _logger.LogError("Failed to stop the core during rollback: {Error}", stopped.Error);
            }
        }

        if (disarmKillSwitch && _armedPlan is not null && _killSwitch is not null)
        {
            var removed = await _killSwitch.RemoveAsync(_armedPlan.Identifier, cancellationToken)
                .ConfigureAwait(false);

            if (!removed.Succeeded)
            {
                _logger.LogError("Failed to disarm the Kill Switch during rollback: {Error}", removed.Error);
            }

            _armedPlan = null;
        }

        if (deleteConfig && _files.Exists(_paths.ActiveConfigPath))
        {
            await _files.DeleteAsync(_paths.ActiveConfigPath, cancellationToken).ConfigureAwait(false);
        }
    }

    private static IEnumerable<MyVpnError> BuildVerificationWarnings(
        ConnectionVerification verification,
        IReadOnlyList<ServerEndpoint> endpoints)
    {
        // The most valuable thing verification can tell us: traffic is flowing, but it is not
        // going where we think it is.
        if (verification.DirectAddress is not null && !verification.ExitDiffersFromDirect)
        {
            if (endpoints.Count > 0
                && string.Equals(verification.ExitAddress, endpoints[0].Address, StringComparison.Ordinal))
            {
                yield break;
            }

            yield return new MyVpnError(
                ErrorCodes.KillSwitchVerificationFailed,
                "error.session.exit_matches_direct",
                ErrorSeverity.Warning,
                $"The exit address {verification.ExitAddress} is the same as the direct address, "
                + "so traffic may not be traversing the tunnel.")
                .WithArg("address", verification.ExitAddress);
        }
    }

    /// <summary>
    /// Returns the session to a clean Disconnected state and reports why the connect failed.
    /// </summary>
    /// <remarks>
    /// Callers must already have rolled back any resources. Doing it here as well would risk
    /// double-cleanup, and the ordering guarantees come from the explicit rollback calls.
    /// </remarks>
    private Result<ConnectionSnapshot> Fail(MyVpnError error, IReadOnlyList<MyVpnError> warnings)
    {
        if (_stateMachine.Current != VpnConnectionState.Disconnected)
        {
            // Connecting -> Disconnecting -> Disconnected is the only legal path back; going
            // straight to Disconnected is deliberately impossible so no code can skip teardown.
            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnecting, "connect-failed");
            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnected, "connect-failed");
        }

        _snapshot = _snapshot with
        {
            LastError = error,
            Warnings = warnings.ToArray(),
            ConnectedAt = null,
            Verification = null,
            KillSwitchArmed = false,
        };

        RaiseSnapshot();
        _logger.LogError("Connect failed: {Error}", error);

        return Result<ConnectionSnapshot>.Fail(error);
    }

    private void RaiseSnapshot() => SnapshotChanged?.Invoke(this, _snapshot);

    private static PlatformTarget DetectPlatform()
    {
        if (OperatingSystem.IsWindows())
        {
            return PlatformTarget.Windows;
        }

        return OperatingSystem.IsMacOS() ? PlatformTarget.MacOS : PlatformTarget.Linux;
    }
}
