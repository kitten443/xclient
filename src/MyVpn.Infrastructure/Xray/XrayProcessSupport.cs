using System.Globalization;
using MyVpn.Core.Xray;

namespace MyVpn.Infrastructure.Xray;

/// <summary>
/// Xray exit codes MyVpn acts on.
/// </summary>
/// <remarks>
/// The value that matters is <see cref="ConfigError"/>. Xray validates a configuration with
/// <c>xray run -test -c &lt;file&gt;</c>, which exits <c>23</c> when the config is rejected. That
/// exit code is the difference between "the core crashed, retry it" and "the config is wrong,
/// retrying will fail identically forever" — so a supervisor that restarts blindly turns a
/// configuration typo into an endless crash loop that hammers the machine and buries the real
/// error. MyVpn distinguishes the two.
/// </remarks>
public static class XrayExitCodes
{
    /// <summary>Normal termination.</summary>
    public const int Success = 0;

    /// <summary>The configuration was rejected by the core's own validator.</summary>
    public const int ConfigError = 23;

    /// <summary>Termination by SIGTERM (128 + 15), i.e. an orderly shutdown.</summary>
    public const int SigTerm = 143;

    /// <summary>Termination by SIGKILL (128 + 9), i.e. a forced stop.</summary>
    public const int SigKill = 137;
}

/// <summary>Why the core stopped, as far as can be determined.</summary>
public enum XrayStopReason
{
    /// <summary>MyVpn asked it to stop.</summary>
    Requested = 0,

    /// <summary>The configuration was rejected; restarting cannot help.</summary>
    InvalidConfiguration = 1,

    /// <summary>The core exited with an unexpected non-zero code.</summary>
    Crash = 2,

    /// <summary>The core exited cleanly without being asked to.</summary>
    UnexpectedExit = 3,

    /// <summary>A stop was requested but the process had to be killed.</summary>
    ForcedShutdown = 4,
}

/// <summary>Interprets a config pre-flight run.</summary>
public static class XrayTestRunInterpreter
{
    /// <summary>
    /// Interprets the outcome of <c>xray run -test -c &lt;file&gt;</c>.
    /// </summary>
    /// <param name="exitCode">Process exit code.</param>
    /// <param name="standardError">Captured stderr; Xray writes its diagnosis here.</param>
    /// <param name="expectedVersion">Version the config was generated for, used for context.</param>
    public static XrayPreflightResult Interpret(int exitCode, string? standardError, XrayVersion? expectedVersion = null)
    {
        var diagnostic = ExtractDiagnostic(standardError);

        if (exitCode == XrayExitCodes.Success)
        {
            return new XrayPreflightResult
            {
                IsValid = true,
                ExitCode = exitCode,
                Diagnostic = diagnostic,
            };
        }

        if (exitCode == XrayExitCodes.ConfigError)
        {
            return new XrayPreflightResult
            {
                IsValid = false,
                ExitCode = exitCode,
                IsConfigurationError = true,
                Diagnostic = diagnostic,
                MessageKey = "error.xray.config_rejected_by_core",
                RemediationKey = "diagnostics.run",
            };
        }

        // Any other non-zero code means the pre-flight itself failed (wrong binary, missing
        // library, unsupported flag). That is not a config problem, and it must not be reported
        // as one — the user would go looking in entirely the wrong place.
        return new XrayPreflightResult
        {
            IsValid = false,
            ExitCode = exitCode,
            IsConfigurationError = false,
            Diagnostic = diagnostic,
            MessageKey = "error.xray.preflight_failed",
            RemediationKey = "xray.select_binary",
        };
    }

    /// <summary>
    /// Pulls the last meaningful line out of Xray's stderr.
    /// </summary>
    /// <remarks>
    /// Xray prints a banner of start-up lines before the actual failure. Taking the last
    /// non-empty line yields the specific complaint ("failed to open geosite.dat") rather than
    /// the generic preamble, which is what makes the diagnostics view useful.
    /// </remarks>
    internal static string? ExtractDiagnostic(string? standardError)
    {
        if (string.IsNullOrWhiteSpace(standardError))
        {
            return null;
        }

        var lines = standardError
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.Length > 0)
            .ToArray();

        if (lines.Length == 0)
        {
            return null;
        }

        var last = lines[^1];

        // Bound the stored diagnostic so a pathological stderr cannot bloat a log line.
        return last.Length <= 500 ? last : last[..500] + "…";
    }

    /// <summary>
    /// Classifies an unexpected exit, so the supervisor can decide whether to restart.
    /// </summary>
    public static XrayStopReason ClassifyExit(int exitCode, bool stopWasRequested)
    {
        if (stopWasRequested)
        {
            return exitCode == XrayExitCodes.SigKill
                ? XrayStopReason.ForcedShutdown
                : XrayStopReason.Requested;
        }

        return exitCode switch
        {
            XrayExitCodes.ConfigError => XrayStopReason.InvalidConfiguration,

            // A clean exit that nobody asked for is still an unexpected termination; the tunnel
            // is down either way and the user must be told.
            XrayExitCodes.Success => XrayStopReason.UnexpectedExit,
            _ => XrayStopReason.Crash,
        };
    }
}

/// <summary>Outcome of a configuration pre-flight.</summary>
public sealed record XrayPreflightResult
{
    public required bool IsValid { get; init; }

    public required int ExitCode { get; init; }

    /// <summary>
    /// True only for exit code 23. Callers must not restart on this: the config will be
    /// rejected identically every time.
    /// </summary>
    public bool IsConfigurationError { get; init; }

    /// <summary>The core's own explanation, if it produced one.</summary>
    public string? Diagnostic { get; init; }

    public string? MessageKey { get; init; }

    public string? RemediationKey { get; init; }
}

/// <summary>
/// Sliding-window limiter that stops the supervisor from restarting a crashing core forever.
/// </summary>
/// <remarks>
/// A plain attempt counter is not enough: a core that crashes once an hour is healthy enough to
/// keep restarting, while a core that crashes five times in ten seconds is in a loop and must be
/// given up on. The window expresses that distinction, and it is a pure function so the policy is
/// testable without spawning anything.
/// </remarks>
public sealed class RestartLimiter
{
    private readonly int _maxAttempts;
    private readonly TimeSpan _window;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Queue<DateTimeOffset> _attempts = new();

    public RestartLimiter(int maxAttempts, TimeSpan window, Func<DateTimeOffset>? clock = null)
    {
        if (maxAttempts < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        }

        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window));
        }

        _maxAttempts = maxAttempts;
        _window = window;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Attempts recorded inside the current window.</summary>
    public int AttemptsInWindow
    {
        get
        {
            Prune();
            return _attempts.Count;
        }
    }

    /// <summary>
    /// True when another restart is permitted. Does not record the attempt; call
    /// <see cref="RecordAttempt"/> when actually restarting.
    /// </summary>
    public bool CanRestart()
    {
        Prune();
        return _attempts.Count < _maxAttempts;
    }

    /// <summary>Records a restart attempt.</summary>
    public void RecordAttempt()
    {
        Prune();
        _attempts.Enqueue(_clock());
    }

    /// <summary>Clears the window; call after a sustained healthy period.</summary>
    public void Reset() => _attempts.Clear();

    /// <summary>How long until the oldest attempt leaves the window.</summary>
    public TimeSpan TimeUntilNextAllowed()
    {
        Prune();

        if (_attempts.Count < _maxAttempts)
        {
            return TimeSpan.Zero;
        }

        var oldest = _attempts.Peek();
        var remaining = oldest + _window - _clock();
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// <summary>Human-readable summary for diagnostics.</summary>
    public string Describe() =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{_attempts.Count}/{_maxAttempts} restarts in the last {_window.TotalSeconds:0}s");

    private void Prune()
    {
        var cutoff = _clock() - _window;
        while (_attempts.Count > 0 && _attempts.Peek() < cutoff)
        {
            _attempts.Dequeue();
        }
    }
}
