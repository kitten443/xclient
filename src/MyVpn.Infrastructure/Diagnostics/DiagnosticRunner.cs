using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;
using MyVpn.Core.Diagnostics;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Abstractions.Platform;

namespace MyVpn.Infrastructure.Diagnostics;

/// <summary>Everything the diagnostic checks may inspect.</summary>
public sealed record DiagnosticContext
{
    public required AppSettings Settings { get; init; }

    public ServerProfile? Profile { get; init; }

    public string? CoreBinaryPath { get; init; }

    public string? ConfigPath { get; init; }

    public string? AssetDirectory { get; init; }

    public string? WorkingDirectory { get; init; }

    public IXrayEngine? Engine { get; init; }

    public GeoDataManager? GeoData { get; init; }

    public IPlatformServices? Platform { get; init; }

    /// <summary>Skip checks that need the network. Used by the offline diagnostics mode.</summary>
    public bool AllowNetworkChecks { get; init; } = true;
}

/// <summary>One diagnostic check.</summary>
/// <remarks>
/// Implementations must be non-throwing in practice — the runner converts an exception into an
/// Error result — but they must also be honest: a check that cannot determine an answer should
/// return <see cref="DiagnosticStatus.Skipped"/> with a reason, not Success.
/// </remarks>
public interface IDiagnosticCheck
{
    string Id { get; }

    /// <summary>Localization key naming the check.</summary>
    string TitleKey { get; }

    /// <summary>Execution order; lower runs first.</summary>
    int Order { get; }

    /// <summary>False when the check does not apply to the current configuration.</summary>
    bool IsApplicable(DiagnosticContext context);

    /// <summary>Localization key explaining why the check was skipped.</summary>
    string SkipReasonKey { get; }

    Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken);
}

/// <summary>
/// Runs the diagnostic checks and aggregates the result.
/// </summary>
/// <remarks>
/// Isolation is the important property: one check that throws or hangs must not prevent the
/// others from reporting. A diagnostics screen that itself fails is worse than useless, because
/// it removes the user's only means of finding out what is wrong.
/// </remarks>
public sealed class DiagnosticRunner
{
    /// <summary>Per-check budget. A check exceeding it is reported rather than allowed to hang.</summary>
    public static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(10);

    private readonly IReadOnlyList<IDiagnosticCheck> _checks;
    private readonly ILogger<DiagnosticRunner> _logger;
    private readonly TimeSpan _checkTimeout;

    public DiagnosticRunner(
        IEnumerable<IDiagnosticCheck> checks,
        ILogger<DiagnosticRunner> logger,
        TimeSpan? checkTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(checks);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Injectable so the timeout path is testable without a ten-second test.
        _checkTimeout = checkTimeout ?? CheckTimeout;

        _checks = checks.OrderBy(c => c.Order).ThenBy(c => c.Id, StringComparer.Ordinal).ToArray();
    }

    /// <summary>The checks this runner will execute, in order.</summary>
    public IReadOnlyList<IDiagnosticCheck> Checks => _checks;

    /// <summary>Runs every applicable check.</summary>
    public async Task<DiagnosticReport> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var started = Stopwatch.GetTimestamp();
        var results = new List<DiagnosticCheckResult>(_checks.Count);

        foreach (var check in _checks)
        {
            if (!check.IsApplicable(context))
            {
                results.Add(DiagnosticCheckResult.Skipped(check.Id, check.TitleKey, check.SkipReasonKey));
                continue;
            }

            results.Add(await RunOneAsync(check, context, cancellationToken).ConfigureAwait(false));
        }

        return new DiagnosticReport
        {
            Checks = results,
            GeneratedAt = DateTimeOffset.UtcNow,
            TotalDuration = Stopwatch.GetElapsedTime(started),
        };
    }

    private async Task<DiagnosticCheckResult> RunOneAsync(
        IDiagnosticCheck check,
        DiagnosticContext context,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_checkTimeout);

        try
        {
            var task = check.RunAsync(context, timeoutCts.Token);

            // WhenAny rather than a bare await: a check that ignores its token would otherwise
            // hang the whole report. Well-behaved checks are awaited normally and this is a no-op.
            var completed = await Task.WhenAny(task, Task.Delay(_checkTimeout, cancellationToken))
                .ConfigureAwait(false);

            if (completed != task)
            {
                return DiagnosticCheckResult.Error(
                    check.Id,
                    check.TitleKey,
                    "diagnostics.error.check_timeout",
                    $"The check did not finish within {_checkTimeout.TotalSeconds:0}s.",
                    remediationKey: "diagnostics.retry")
                    with { Duration = Stopwatch.GetElapsedTime(started) };
            }

            var result = await task.ConfigureAwait(false);
            return result with { Duration = Stopwatch.GetElapsedTime(started) };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return DiagnosticCheckResult.Error(
                check.Id,
                check.TitleKey,
                "diagnostics.error.check_timeout",
                $"The check exceeded its {_checkTimeout.TotalSeconds:0}s budget.")
                with { Duration = Stopwatch.GetElapsedTime(started) };
        }
        catch (Exception ex)
        {
            // A failing check is itself diagnostic information, not a reason to lose the report.
            _logger.LogWarning(ex, "Diagnostic check {CheckId} threw.", check.Id);

            return DiagnosticCheckResult.Error(
                check.Id,
                check.TitleKey,
                "diagnostics.error.check_failed",
                $"{ex.GetType().Name}: {ex.Message}")
                with { Duration = Stopwatch.GetElapsedTime(started) };
        }
    }

    /// <summary>The standard check set.</summary>
    public static IEnumerable<IDiagnosticCheck> CreateDefaultChecks() => new IDiagnosticCheck[]
    {
        new CoreBinaryDiagnosticCheck(),
        new ConfigFileDiagnosticCheck(),
        new GeoDataDiagnosticCheck(),
        new XrayProcessDiagnosticCheck(),
        new TunInterfaceDiagnosticCheck(),
        new KillSwitchDiagnosticCheck(),
        new DnsDiagnosticCheck(),
        new SystemProxyDiagnosticCheck(),
        new ServerReachabilityDiagnosticCheck(),
    };
}

/// <summary>Formats localization arguments shared by several checks.</summary>
internal static class DiagnosticArgs
{
    public static IReadOnlyDictionary<string, string> Of(params (string Name, string Value)[] pairs)
    {
        var dictionary = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in pairs)
        {
            dictionary[name] = value;
        }

        return dictionary;
    }

    public static string Format(TimeSpan value) =>
        value.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture) + "s";
}
