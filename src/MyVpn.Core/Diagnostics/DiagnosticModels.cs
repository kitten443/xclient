namespace MyVpn.Core.Diagnostics;

/// <summary>Outcome of a single diagnostic check.</summary>
public enum DiagnosticStatus
{
    /// <summary>Everything is as expected.</summary>
    Success = 0,

    /// <summary>Usable, but something is off and the user should know.</summary>
    Warning = 1,

    /// <summary>The check failed; the feature will not work.</summary>
    Error = 2,

    /// <summary>Not relevant in the current configuration, so it was not run.</summary>
    Skipped = 3,
}

/// <summary>
/// Result of one diagnostic check.
/// </summary>
/// <remarks>
/// <para>
/// The contract that matters: <see cref="MessageKey"/> is a localization key, never a raw
/// sentence. The requirement is that a user sees "не удалось найти geoip.dat" rather than
/// "Asset initialization failed". <see cref="TechnicalDetail"/> exists alongside it for the
/// diagnostics bundle and is never rendered as the primary explanation.
/// </para>
/// </remarks>
public sealed record DiagnosticCheckResult
{
    public required string Id { get; init; }

    /// <summary>Localization key for the check's name.</summary>
    public required string TitleKey { get; init; }

    public required DiagnosticStatus Status { get; init; }

    /// <summary>Localization key for the plain-language explanation.</summary>
    public string? MessageKey { get; init; }

    /// <summary>Arguments for the localized message.</summary>
    public IReadOnlyDictionary<string, string> Args { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Raw technical context: command output, paths, exit codes. Bundle only.</summary>
    public string? TechnicalDetail { get; init; }

    /// <summary>Localization key of a suggested fix, when there is one.</summary>
    public string? RemediationKey { get; init; }

    /// <summary>Raw evidence lines, gathered for the diagnostics bundle.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();

    public TimeSpan Duration { get; init; }

    public bool IsProblem => Status is DiagnosticStatus.Warning or DiagnosticStatus.Error;

    public static DiagnosticCheckResult Ok(string id, string titleKey, string? detail = null) => new()
    {
        Id = id,
        TitleKey = titleKey,
        Status = DiagnosticStatus.Success,
        MessageKey = "diagnostics.result.ok",
        TechnicalDetail = detail,
    };

    public static DiagnosticCheckResult Skipped(string id, string titleKey, string reasonKey) => new()
    {
        Id = id,
        TitleKey = titleKey,
        Status = DiagnosticStatus.Skipped,
        MessageKey = reasonKey,
    };

    public static DiagnosticCheckResult Warning(
        string id,
        string titleKey,
        string messageKey,
        string? detail = null,
        string? remediationKey = null,
        IReadOnlyDictionary<string, string>? args = null) => new()
    {
        Id = id,
        TitleKey = titleKey,
        Status = DiagnosticStatus.Warning,
        MessageKey = messageKey,
        TechnicalDetail = detail,
        RemediationKey = remediationKey,
        Args = args ?? new Dictionary<string, string>(StringComparer.Ordinal),
    };

    public static DiagnosticCheckResult Error(
        string id,
        string titleKey,
        string messageKey,
        string? detail = null,
        string? remediationKey = null,
        IReadOnlyDictionary<string, string>? args = null) => new()
    {
        Id = id,
        TitleKey = titleKey,
        Status = DiagnosticStatus.Error,
        MessageKey = messageKey,
        TechnicalDetail = detail,
        RemediationKey = remediationKey,
        Args = args ?? new Dictionary<string, string>(StringComparer.Ordinal),
    };
}

/// <summary>Aggregate diagnostics report.</summary>
public sealed record DiagnosticReport
{
    public required IReadOnlyList<DiagnosticCheckResult> Checks { get; init; }

    public required DateTimeOffset GeneratedAt { get; init; }

    public TimeSpan TotalDuration { get; init; }

    /// <summary>Worst status across all checks.</summary>
    public DiagnosticStatus Overall =>
        Checks.Any(c => c.Status == DiagnosticStatus.Error) ? DiagnosticStatus.Error
        : Checks.Any(c => c.Status == DiagnosticStatus.Warning) ? DiagnosticStatus.Warning
        : Checks.Count == 0 ? DiagnosticStatus.Skipped
        : DiagnosticStatus.Success;

    public bool HasErrors => Checks.Any(c => c.Status == DiagnosticStatus.Error);

    public IReadOnlyList<DiagnosticCheckResult> Problems =>
        Checks.Where(c => c.IsProblem).ToArray();

    public int ErrorCount => Checks.Count(c => c.Status == DiagnosticStatus.Error);

    public int WarningCount => Checks.Count(c => c.Status == DiagnosticStatus.Warning);

    /// <summary>
    /// Plain-text rendering for the CLI and for copy-to-clipboard.
    /// </summary>
    /// <remarks>
    /// Emits message <i>keys</i> deliberately: this method has no localization service and must
    /// not invent English text. The caller resolves the keys, which keeps the "no hard-coded
    /// user-facing strings" rule intact even in the diagnostics path.
    /// </remarks>
    public string ToPlainTextSummary()
    {
        var lines = new List<string>
        {
            $"MyVpn diagnostics — {GeneratedAt:u}",
            $"overall: {Overall} (errors={ErrorCount}, warnings={WarningCount}, total={Checks.Count})",
            new string('-', 60),
        };

        foreach (var check in Checks)
        {
            lines.Add($"[{check.Status,-7}] {check.Id} ({check.Duration.TotalMilliseconds:0} ms)");

            if (check.MessageKey is not null)
            {
                lines.Add($"          message: {check.MessageKey}");
            }

            if (check.RemediationKey is not null)
            {
                lines.Add($"          fix:     {check.RemediationKey}");
            }

            if (check.TechnicalDetail is not null)
            {
                lines.Add($"          detail:  {check.TechnicalDetail}");
            }

            foreach (var evidence in check.Evidence)
            {
                lines.Add($"          > {evidence}");
            }
        }

        return string.Join(Environment.NewLine, lines);
    }
}
