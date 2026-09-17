using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Subscriptions;

namespace MyVpn.UI.ViewModels;

/// <summary>
/// A parsed subscription, shaped for the UI.
/// </summary>
/// <remarks>
/// <b>The subscription URL is returned but must never be rendered.</b> It carries a provider
/// token: anyone holding it can read the user's server list, so it is displayed only in a masked
/// form and never written to a log. It is returned at all because the accepted import has to
/// persist it — retyping it on every launch is not a reasonable thing to ask.
/// </remarks>
public sealed record SubscriptionImportResult
{
    /// <summary>The URL the response actually came from, after redirects. Never display verbatim.</summary>
    public required string SubscriptionUrl { get; init; }

    /// <summary>Provider title, when the provider supplied one (gate A: display metadata).</summary>
    public string? Title { get; init; }

    /// <summary>Provider announcement, when supplied.</summary>
    public string? Announce { get; init; }

    /// <summary>Profiles that parsed successfully.</summary>
    public required IReadOnlyList<Core.Domain.ServerProfile> Profiles { get; init; }

    /// <summary>Lines that looked like share links but could not be parsed.</summary>
    public required IReadOnlyList<ShareLinkFailure> Failures { get; init; }

    /// <summary>
    /// Headers that were recognised and are never applied, with the reasons.
    /// </summary>
    /// <remarks>
    /// Gate C of ADR-0008: raw tunnel config, routing imports and provider/telemetry identifiers
    /// are surfaced as a notice so the user knows the provider asked, and are dropped. They are
    /// never offered for one-click acceptance, because "accept this arbitrary routing config" is
    /// not a choice a user can meaningfully evaluate.
    /// </remarks>
    public required IReadOnlyList<string> RefusedHeaders { get; init; }

    /// <summary>Gate B: changes that require explicit, value-bound consent before anything is applied.</summary>
    public required IReadOnlyList<PendingChange> PendingChanges { get; init; }

    /// <summary>Parser diagnostics (isolation failures, schema violations).</summary>
    public required IReadOnlyList<MyVpnError> Errors { get; init; }
}

/// <summary>Fetches and interprets a subscription.</summary>
/// <remarks>
/// A port so the import view model can be tested without a network. The implementation is the
/// only thing in the UI that performs an outbound request the user did not type into a server
/// field, and it goes through <c>SubscriptionFetcher</c>, which enforces HTTPS, a body-size cap
/// and the SSRF guard.
/// </remarks>
public interface ISubscriptionImporter
{
    Task<Result<SubscriptionImportResult>> ImportAsync(
        string url,
        Core.Settings.SubscriptionSettings settings,
        CancellationToken cancellationToken);
}
