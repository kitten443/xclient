namespace MyVpn.Core.Results;

/// <summary>
/// How bad a failure is. This drives UI presentation (a <see cref="Warning"/> is a
/// banner, a <see cref="Critical"/> escalates to a modal with a repair action) and
/// is deliberately part of the error value rather than something the UI infers.
/// </summary>
public enum ErrorSeverity
{
    /// <summary>The operation completed with reduced functionality.</summary>
    Warning = 0,

    /// <summary>The operation failed but the application is still usable.</summary>
    Error = 1,

    /// <summary>The operation failed and the user's network may be in a broken state.</summary>
    Critical = 2,
}

/// <summary>
/// A structured, localizable failure.
/// </summary>
/// <remarks>
/// Two design rules matter here and are enforced by tests:
/// <list type="bullet">
/// <item><description>
/// <see cref="MessageKey"/> is a localization key, never a user-visible English
/// sentence. Requirement: the UI must never surface raw technical text such as
/// "Asset initialization failed". A <see cref="MyVpnError"/> therefore carries the
/// key and the arguments needed to render a plain-language message in the user's
/// language.
/// </description></item>
/// <item><description>
/// <see cref="TechnicalDetail"/> may contain paths, exit codes and stderr excerpts.
/// It is for logs and the diagnostics bundle only, and the diagnostics exporter is
/// responsible for redacting secrets from it before export.
/// </description></item>
/// </list>
/// </remarks>
public sealed record MyVpnError(
    string Code,
    string MessageKey,
    ErrorSeverity Severity = ErrorSeverity.Error,
    string? TechnicalDetail = null,
    string? RemediationKey = null,
    IReadOnlyDictionary<string, string>? Args = null)
{
    private static readonly IReadOnlyDictionary<string, string> NoArgs =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Arguments used to format the localized message.</summary>
    public IReadOnlyDictionary<string, string> Arguments => Args ?? NoArgs;

    /// <summary>Returns a copy with an extra message-formatting argument.</summary>
    public MyVpnError WithArg(string name, string value)
    {
        var copy = new Dictionary<string, string>(Arguments, StringComparer.Ordinal) { [name] = value };
        return this with { Args = copy };
    }

    /// <summary>Returns a copy with several extra message-formatting arguments.</summary>
    public MyVpnError WithArgs(params (string Name, string Value)[] pairs)
    {
        var copy = new Dictionary<string, string>(Arguments, StringComparer.Ordinal);
        foreach (var (name, value) in pairs)
        {
            copy[name] = value;
        }

        return this with { Args = copy };
    }

    public override string ToString() =>
        TechnicalDetail is null
            ? $"{Code} ({MessageKey})"
            : $"{Code} ({MessageKey}): {TechnicalDetail}";
}
