using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.Infrastructure.Subscriptions;

namespace MyVpn.UI.ViewModels;

/// <summary>
/// The real importer: fetch, then interpret through the header registry.
/// </summary>
/// <remarks>
/// This mirrors the CLI's <c>connect</c> path exactly, and that is the point — if the GUI and the
/// CLI interpreted a subscription differently, one of them would be applying changes the other
/// refuses. Order is fixed: fetch (bounded, HTTPS-enforced), build a bounded header bag, run the
/// registry (which is what enforces the three gates), then parse the share links.
/// </remarks>
public sealed class SubscriptionImporter : ISubscriptionImporter
{
    private readonly SubscriptionFetcher _fetcher;
    private readonly SubscriptionHeaderRegistry _registry;

    public SubscriptionImporter(SubscriptionFetcher fetcher, SubscriptionHeaderRegistry registry)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public async Task<Result<SubscriptionImportResult>> ImportAsync(
        string url,
        SubscriptionSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var fetched = await _fetcher.FetchAsync(url, settings, cancellationToken).ConfigureAwait(false);
        if (fetched.IsFailure)
        {
            return Result<SubscriptionImportResult>.Fail(fetched.Error!);
        }

        var response = fetched.Value;

        var bag = _registry.CreateBag(response.Headers);
        var parsed = _registry.Parse(new HeaderParseContext
        {
            // The subscription id participates in the consent token. The URL itself is used
            // because it is the only stable identifier the client has for this subscription at
            // this point; the token is a hash, so the URL does not travel in the clear.
            Headers = bag,
            SubscriptionId = response.FinalUrl,
            SubscriptionUrl = Uri.TryCreate(response.FinalUrl, UriKind.Absolute, out var uri) ? uri : null,
            AllowInsecureHttp = settings.AllowInsecureHttp,
        });

        var batch = ShareLinkParser.ParseMany(response.Body);

        return Result<SubscriptionImportResult>.Ok(new SubscriptionImportResult
        {
            SubscriptionUrl = response.FinalUrl,
            Title = parsed.Metadata.Title,
            Announce = parsed.Metadata.Announce,
            Profiles = batch.Profiles,
            Failures = batch.Failures,
            RefusedHeaders = parsed.RefusedHeaders,
            PendingChanges = parsed.PendingChanges,
            Errors = parsed.Errors,
        });
    }
}

/// <summary>
/// Applies a consented <see cref="PendingChange"/> to a settings snapshot.
/// </summary>
/// <remarks>
/// <para>
/// Only headers whose meaning is unambiguous are mapped. A change the mapper does not understand
/// is reported as unapplied rather than guessed at: silently writing a value into the wrong field
/// is worse than telling the user the client cannot honour it.
/// </para>
/// <para>
/// Nothing here writes to live settings. It returns a proposed snapshot, and the caller only
/// adopts it after the user has consented to the specific value — the consent token binds the
/// decision to <c>(subscription, header, value)</c>, so a provider that changes the value on a
/// later refresh cannot reuse a stored "yes".
/// </para>
/// </remarks>
public static class PendingChangeApplier
{
    /// <summary>
    /// Recomputes the consent token for a change.
    /// </summary>
    /// <remarks>
    /// Calls <see cref="MyVpn.Core.Subscriptions.ConsentToken.Compute"/> rather than
    /// reimplementing it. The algorithm was previously mirrored here because the original helper
    /// was internal, which meant two copies of a security-relevant function where a change to one
    /// would silently invalidate every stored consent in the other. The core type is public now,
    /// so there is exactly one implementation.
    /// </remarks>
    public static string ConsentToken(string subscriptionId, string headerName, string valueFingerprint) =>
        MyVpn.Core.Subscriptions.ConsentToken.Compute(subscriptionId, headerName, valueFingerprint);

    /// <summary>Outcome of applying one change.</summary>
    public enum Outcome
    {
        /// <summary>The change was written into the proposed snapshot.</summary>
        Applied = 0,

        /// <summary>The client has no mapping for this header.</summary>
        Unsupported = 1,

        /// <summary>The header is mapped but the value is not usable.</summary>
        InvalidValue = 2,
    }

    public static Outcome Apply(ref AppSettings settings, PendingChange change)
    {
        ArgumentNullException.ThrowIfNull(change);

        var toggle = Toggle(change.Value);

        switch (change.HeaderName.ToLowerInvariant())
        {
            case "subscription-auto-update-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Subscriptions = settings.Subscriptions with { AutoUpdate = toggle.Value },
                };
                return Outcome.Applied;

            case "tun-enable":
            case "xray-tun-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    TunnelMode = toggle.Value ? TunnelMode.Tun : TunnelMode.SystemProxy,
                };
                return Outcome.Applied;

            case "proxy-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    TunnelMode = toggle.Value ? TunnelMode.SystemProxy : TunnelMode.Disabled,
                };
                return Outcome.Applied;

            case "routing-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Routing = settings.Routing with { BlockAds = toggle.Value },
                };
                return Outcome.Applied;

            case "sniffing-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Routing = settings.Routing with { EnableSniffing = toggle.Value },
                };
                return Outcome.Applied;

            case "mux-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Mux = settings.Mux with { Enabled = toggle.Value },
                };
                return Outcome.Applied;

            case "dns-from-json-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                // "Use the provider's DNS block" is only expressible as taking the provider's
                // resolver list through the tunnel; the client does not import a provider DNS
                // object verbatim, because that is arbitrary-config injection by another name.
                settings = settings with
                {
                    Dns = settings.Dns with
                    {
                        Mode = toggle.Value ? DnsMode.ThroughTunnel : DnsMode.System,
                    },
                };
                return Outcome.Applied;

            case "block-bind-to-tunnel-enable":
                if (toggle is null)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Connectivity = settings.Connectivity with { BindToPhysicalInterface = toggle.Value },
                };
                return Outcome.Applied;

            case "change-user-agent":
                if (string.IsNullOrWhiteSpace(change.Value) || change.Value.Length > 256)
                {
                    return Outcome.InvalidValue;
                }

                settings = settings with
                {
                    Subscriptions = settings.Subscriptions with { UserAgent = change.Value },
                };
                return Outcome.Applied;

            case "proxy-ping-timeout":
            case "subscription-request-timeout":
                return int.TryParse(
                    change.Value.Trim(),
                    System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var seconds) && seconds is >= 5 and <= 60
                    ? ApplyRequestTimeout(ref settings, seconds)
                    : Outcome.InvalidValue;

            default:
                // Everything else in gate B is either mobile-only, cosmetic, or a feature this
                // client does not have. Reported, not guessed.
                return Outcome.Unsupported;
        }
    }

    private static Outcome ApplyRequestTimeout(ref AppSettings settings, int seconds)
    {
        settings = settings with
        {
            Subscriptions = settings.Subscriptions with { TimeoutSeconds = seconds },
        };

        return Outcome.Applied;
    }

    /// <summary>Documented toggle semantics: <c>true</c>/<c>1</c> on, any other non-empty value off.</summary>
    private static bool? Toggle(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1";
    }
}
