using System.Net.Sockets;
using System.Text.Json;
using MyVpn.Core.Diagnostics;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Xray;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Infrastructure.Diagnostics;

/// <summary>Checks that the Xray core binary exists, is executable and is a usable version.</summary>
public sealed class CoreBinaryDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "core-binary";

    public string TitleKey => "diagnostics.check.core_binary";

    public int Order => 10;

    public string SkipReasonKey => "diagnostics.skip.not_applicable";

    public bool IsApplicable(DiagnosticContext context) => true;

    public Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var located = XrayBinaryLocator.Locate(
            userSelectedPath: context.CoreBinaryPath,
            applicationBaseDirectory: AppContext.BaseDirectory,
            packageManagerDirectories: context.Platform?.DefaultCoreSearchPaths,
            isWindows: OperatingSystem.IsWindows(),
            fileExists: File.Exists,
            isExecutable: XrayBinaryLocator.IsExecutableOnUnix);

        if (located.IsFailure)
        {
            return Task.FromResult(DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                located.Error!.MessageKey,
                located.Error.TechnicalDetail,
                located.Error.RemediationKey ?? "xray.select_binary"));
        }

        return Task.FromResult(DiagnosticCheckResult.Ok(
            Id,
            TitleKey,
            $"found at {located.Value.AbsolutePath} (source: {located.Value.Source})"));
    }
}

/// <summary>Checks that the generated configuration file exists and is valid JSON.</summary>
/// <remarks>
/// Deliberately only validates JSON syntax. Schema correctness is the core's job, and it is
/// checked by the pre-flight rather than duplicated here.
/// </remarks>
public sealed class ConfigFileDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "config-file";

    public string TitleKey => "diagnostics.check.config_file";

    public int Order => 20;

    public string SkipReasonKey => "diagnostics.skip.no_config";

    public bool IsApplicable(DiagnosticContext context) => !string.IsNullOrWhiteSpace(context.ConfigPath);

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var path = context.ConfigPath!;

        if (!File.Exists(path))
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.config.file_missing",
                $"No file at '{path}'.",
                "diagnostics.reconnect")
                .WithEvidence($"path: {path}");
        }

        try
        {
            await using var stream = File.OpenRead(path);
            using var document = await JsonDocument.ParseAsync(stream, default, cancellationToken)
                .ConfigureAwait(false);

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return DiagnosticCheckResult.Error(
                    Id,
                    TitleKey,
                    "error.config.invalid",
                    "The configuration root is not a JSON object.");
            }

            var size = new FileInfo(path).Length;
            return DiagnosticCheckResult.Ok(Id, TitleKey, $"{size} bytes, valid JSON at '{path}'");
        }
        catch (JsonException ex)
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.config.invalid",
                ex.Message,
                "diagnostics.reconnect");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DiagnosticCheckResult.Error(Id, TitleKey, "error.config.write_failed", ex.Message);
        }
    }
}

/// <summary>Checks geo data health — the diagnostic surface for the issue #9765 class of failure.</summary>
public sealed class GeoDataDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "geodata";

    public string TitleKey => "diagnostics.check.geodata";

    public int Order => 30;

    public string SkipReasonKey => "diagnostics.skip.no_geodata_manager";

    public bool IsApplicable(DiagnosticContext context) => context.GeoData is not null;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var status = await context.GeoData!.InspectAsync(cancellationToken).ConfigureAwait(false);

        var evidence = new List<string>
        {
            $"asset directory: {status.AssetDirectory}",
            $"absolute: {status.IsAssetDirectoryAbsolute}",
            $"writable: {status.IsAssetDirectoryWritable}",
            $"source: {status.ResolvedFrom ?? "unknown"}",
        };

        foreach (var asset in status.Assets)
        {
            evidence.Add(
                $"{asset.Kind.FileName()}: health={asset.Health} size={asset.SizeBytes} "
                + $"entries={asset.EntryCount} path={asset.AbsolutePath}");
        }

        if (status.AllUsable && status.IsAssetDirectoryAbsolute)
        {
            var summary = string.Join(
                ", ",
                status.Assets.Select(a => $"{a.Kind.FileName()} ({a.EntryCount} entries)"));

            return DiagnosticCheckResult.Ok(Id, TitleKey, summary) with { Evidence = evidence };
        }

        var error = status.ToWorstError();

        return DiagnosticCheckResult.Error(
            Id,
            TitleKey,
            error?.MessageKey ?? "error.geodata.unusable",
            error?.TechnicalDetail,
            error?.RemediationKey ?? "geodata.repair",
            error?.Arguments) with { Evidence = evidence };
    }
}

/// <summary>Checks whether the core process is running and what version it is.</summary>
public sealed class XrayProcessDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "core-process";

    public string TitleKey => "diagnostics.check.core_process";

    public int Order => 40;

    public string SkipReasonKey => "diagnostics.skip.no_engine";

    public bool IsApplicable(DiagnosticContext context) => context.Engine is not null;

    // Evaluation is entirely synchronous — it reads a snapshot from the engine — so it is a
    // plain method wrapped in a completed task rather than a fake async method.
    public Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken) =>
        Task.FromResult(Evaluate(context));

    private DiagnosticCheckResult Evaluate(DiagnosticContext context)
    {
        var engine = context.Engine!;
        var status = engine.GetStatus();

        var evidence = new List<string>
        {
            $"state: {status.State}",
            $"pid: {(status.ProcessId?.ToString() ?? "none")}",
            $"restarts: {status.RestartCount} ({status.RestartLimiterSummary})",
            $"last stop: {status.LastStopReason?.ToString() ?? "n/a"}",
        };

        if (status.LastDiagnostic is not null)
        {
            evidence.Add($"last output: {status.LastDiagnostic}");
        }

        // Restart-loop blocking is the most important state to surface: the tunnel is down and
        // the user must be told why rather than watching it retry forever.
        if (status.State == XrayEngineState.RestartLoopBlocked)
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.xray.restart_loop_detected",
                status.LastDiagnostic,
                "diagnostics.run") with { Evidence = evidence };
        }

        if (status.State == XrayEngineState.Faulted)
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.xray.stopped_unexpectedly",
                status.LastDiagnostic,
                "diagnostics.run") with { Evidence = evidence };
        }

        if (!status.IsRunning)
        {
            // Not running is expected when the user is disconnected, so it is a warning only.
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.core_not_running",
                status.LastDiagnostic) with { Evidence = evidence };
        }

        // Version policy is applied here because it is only meaningful once a binary is known
        // to be present.
        if (status.Version is { } version)
        {
            var support = XrayVersionPolicy.Evaluate(version, tunRequired: context.Settings.TunnelMode == TunnelMode.Tun);
            evidence.Add($"version: {version} (recommended: {XrayVersionPolicy.Recommended})");

            if (!support.IsUsable)
            {
                return DiagnosticCheckResult.Error(
                    Id,
                    TitleKey,
                    support.MessageKey ?? "error.xray.version_unsupported",
                    $"Detected {version}; TUN requires >= {XrayVersionPolicy.MinimumForTun}.",
                    support.RemediationKey) with { Evidence = evidence };
            }

            if (!support.IsRecommended)
            {
                return DiagnosticCheckResult.Warning(
                    Id,
                    TitleKey,
                    "diagnostics.warning.core_version_old",
                    $"Detected {version}; {XrayVersionPolicy.Recommended} is recommended.",
                    "xray.update") with { Evidence = evidence };
            }
        }
        else
        {
            evidence.Add("version: unknown (not probed)");
        }

        return DiagnosticCheckResult.Ok(Id, TitleKey, $"running with PID {status.ProcessId}") with { Evidence = evidence };
    }
}

/// <summary>Checks that the tunnel interface exists.</summary>
public sealed class TunInterfaceDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "tun-interface";

    public string TitleKey => "diagnostics.check.tun_interface";

    public int Order => 50;

    public string SkipReasonKey => "diagnostics.skip.tun_not_selected";

    public bool IsApplicable(DiagnosticContext context) =>
        context.Platform is not null && context.Settings.TunnelMode == TunnelMode.Tun;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var platform = context.Platform!;
        var tun = platform.Tun;

        if (!tun.IsSupported)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "error.platform.unsupported",
                "This platform does not support a TUN device through MyVpn.");
        }

        var name = string.IsNullOrWhiteSpace(context.Settings.Tun.InterfaceName)
            ? tun.DefaultInterfaceName
            : context.Settings.Tun.InterfaceName!;

        var exists = await tun.ExistsAsync(name, cancellationToken).ConfigureAwait(false);
        var addresses = exists
            ? await tun.GetAddressesAsync(name, cancellationToken).ConfigureAwait(false)
            : Array.Empty<string>();

        var evidence = new List<string> { $"interface: {name}", $"exists: {exists}" };
        evidence.AddRange(addresses.Select(a => $"address: {a}"));

        if (!exists)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.tun_missing",
                $"Interface '{name}' does not exist.") with { Evidence = evidence };
        }

        if (addresses.Count == 0)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.tun_no_address",
                $"Interface '{name}' exists but has no address.") with { Evidence = evidence };
        }

        return DiagnosticCheckResult.Ok(Id, TitleKey, $"{name} up with {addresses.Count} address(es)")
            with { Evidence = evidence };
    }
}

/// <summary>Checks the Kill Switch state.</summary>
public sealed class KillSwitchDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "kill-switch";

    public string TitleKey => "diagnostics.check.killswitch";

    public int Order => 60;

    public string SkipReasonKey => "diagnostics.skip.killswitch_disabled";

    public bool IsApplicable(DiagnosticContext context) =>
        context.Platform is not null
        && context.Settings.KillSwitch != KillSwitchMode.Disabled
        && context.Platform.KillSwitch.IsSupported;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var killSwitch = context.Platform!.KillSwitch;
        var state = await killSwitch.InspectAsync(null, cancellationToken).ConfigureAwait(false);

        var evidence = new List<string>
        {
            $"mechanism: {killSwitch.MechanismName}",
            $"armed: {state.IsArmed}",
            $"drifted: {state.IsDrifted}",
        };

        evidence.AddRange(state.OrphanedRules.Select(r => $"orphan: {r}"));

        if (state.IsDrifted)
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.killswitch.verification_failed",
                "Rules are present but do not match the intended state.",
                "killswitch.reapply") with { Evidence = evidence };
        }

        if (state.IsArmed)
        {
            return DiagnosticCheckResult.Ok(Id, TitleKey, $"armed via {killSwitch.MechanismName}")
                with { Evidence = evidence };
        }

        // Not armed while disconnected is normal; only worth a note.
        return DiagnosticCheckResult.Ok(Id, TitleKey, "not armed")
            with { Evidence = evidence };
    }
}

/// <summary>Checks the resolver configuration for leaks.</summary>
public sealed class DnsDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "dns";

    public string TitleKey => "diagnostics.check.dns";

    public int Order => 70;

    public string SkipReasonKey => "diagnostics.skip.dns_unsupported";

    public bool IsApplicable(DiagnosticContext context) =>
        context.Platform is not null && context.Platform.Dns.IsSupported;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var state = await context.Platform!.Dns.InspectAsync(cancellationToken).ConfigureAwait(false);

        var evidence = new List<string>
        {
            $"interface: {state.InterfaceName ?? "unknown"}",
            $"servers: {(state.ActiveServers.Count == 0 ? "none" : string.Join(", ", state.ActiveServers))}",
            $"plain DNS reachable outside tunnel: {state.PlainDnsReachableOutsideTunnel}",
            $"ipv6 resolver present: {state.HasIpv6Resolver}",
        };

        evidence.AddRange(state.PotentialLeaks.Select(l => $"potential leak: {l}"));

        if (state.PotentialLeaks.Count > 0)
        {
            return DiagnosticCheckResult.Error(
                Id,
                TitleKey,
                "error.dns.leak_detected",
                string.Join("; ", state.PotentialLeaks),
                "dns.reapply") with { Evidence = evidence };
        }

        if (state.ActiveServers.Count == 0)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.no_dns_servers",
                "No active resolver was detected.") with { Evidence = evidence };
        }

        return DiagnosticCheckResult.Ok(Id, TitleKey, $"{state.ActiveServers.Count} resolver(s) active")
            with { Evidence = evidence };
    }
}

/// <summary>Checks the system proxy configuration.</summary>
public sealed class SystemProxyDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "system-proxy";

    public string TitleKey => "diagnostics.check.system_proxy";

    public int Order => 80;

    public string SkipReasonKey => "diagnostics.skip.proxy_not_selected";

    public bool IsApplicable(DiagnosticContext context) =>
        context.Platform is not null
        && context.Settings.TunnelMode == TunnelMode.SystemProxy
        && context.Platform.SystemProxy.IsSupported;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var state = await context.Platform!.SystemProxy.InspectAsync(cancellationToken).ConfigureAwait(false);

        var evidence = new List<string>
        {
            $"configured: {state.IsConfigured}",
            $"points at MyVpn: {state.PointsAtMyVpn}",
            $"proxy: {state.ActiveProxy ?? "none"}",
            $"pac: {state.PacUrl ?? "none"}",
        };

        if (!state.IsConfigured)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.proxy_not_set",
                "No system proxy is configured while system-proxy mode is selected.")
                with { Evidence = evidence };
        }

        if (!state.PointsAtMyVpn)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.proxy_foreign",
                $"The system proxy points at '{state.ActiveProxy}', which is not MyVpn.",
                "proxy.reapply") with { Evidence = evidence };
        }

        return DiagnosticCheckResult.Ok(Id, TitleKey, $"proxy set to {state.ActiveProxy}")
            with { Evidence = evidence };
    }
}

/// <summary>
/// Checks whether the configured server accepts a TCP connection.
/// </summary>
/// <remarks>
/// A warning rather than an error on failure: while the Kill Switch is armed the server is
/// explicitly allow-listed, but a transient network problem, a laptop that just resumed, or a
/// server-side rate limit can all produce a false negative. Diagnostics must not cry wolf.
/// </remarks>
public sealed class ServerReachabilityDiagnosticCheck : IDiagnosticCheck
{
    public string Id => "server-reachability";

    public string TitleKey => "diagnostics.check.server_reachability";

    public int Order => 90;

    public string SkipReasonKey => "diagnostics.skip.no_server";

    public bool IsApplicable(DiagnosticContext context) =>
        context.AllowNetworkChecks && context.Profile is not null;

    public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var profile = context.Profile!;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));

        try
        {
            using var client = new TcpClient();

            await client.ConnectAsync(profile.Address, profile.Port, timeoutCts.Token).ConfigureAwait(false);

            return DiagnosticCheckResult.Ok(
                Id,
                TitleKey,
                $"TCP connection to {profile.Endpoint} succeeded")
                with { Evidence = new[] { $"endpoint: {profile.Endpoint}" } };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                "diagnostics.warning.server_timeout",
                $"No TCP connection to {profile.Endpoint} within 5s.",
                "diagnostics.retry")
                with { Evidence = new[] { $"endpoint: {profile.Endpoint}" } };
        }
        catch (SocketException ex)
        {
            var guidance = ex.SocketErrorCode switch
            {
                SocketError.HostNotFound => "error.diagnostics.host_not_resolved",
                SocketError.ConnectionRefused => "error.diagnostics.connection_refused",
                SocketError.NetworkUnreachable or SocketError.HostUnreachable => "error.diagnostics.network_unreachable",
                _ => "diagnostics.warning.server_unreachable",
            };

            var remediation = ex.SocketErrorCode == SocketError.HostNotFound
                ? "diagnostics.check_dns"
                : "diagnostics.retry";

            return DiagnosticCheckResult.Warning(
                Id,
                TitleKey,
                guidance,
                $"{profile.Endpoint}: {ex.SocketErrorCode} — {ex.Message}",
                remediation)
                with { Evidence = new[] { $"endpoint: {profile.Endpoint}", $"socket error: {ex.SocketErrorCode}" } };
        }
    }
}

/// <summary>Attaches the raw technical detail and evidence to a check result.</summary>
internal static class DiagnosticCheckResultExtensions
{
    public static DiagnosticCheckResult WithEvidence(
        this DiagnosticCheckResult result,
        params string[] evidence) =>
        result with { Evidence = evidence };
}
