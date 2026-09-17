using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MyVpn.Core.Net;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;

namespace MyVpn.Core.Subscriptions;

/// <summary>The three states a documented "toggle" header can express.</summary>
public enum ToggleState
{
    /// <summary>Header absent, or present with an empty value. Nothing should change.</summary>
    Unspecified = 0,

    On = 1,
    Off = 2,
}

/// <summary>Value decoding shared by the header parsers.</summary>
internal static class HeaderValueParsing
{
    /// <summary>
    /// Evaluates a documented toggle.
    /// </summary>
    /// <remarks>
    /// The documented semantics are presence-with-exception rather than a boolean:
    /// <c>true</c> or <c>1</c> enables the feature, <i>any other non-empty value</i>
    /// disables it, and an <i>empty</i> value means "unspecified" and must leave the
    /// setting untouched. Folding empty into "off" would let a provider reset a user's
    /// configuration by sending an empty header, so the distinction is load-bearing.
    /// </remarks>
    public static ToggleState Evaluate(string? value)
    {
        if (value is null || value.Length == 0)
        {
            return ToggleState.Unspecified;
        }

        return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1"
            ? ToggleState.On
            : ToggleState.Off;
    }

    /// <summary>Decodes <c>base64:&lt;payload&gt;</c> or returns the value unchanged.</summary>
    public static bool TryDecodeBase64OrPlain(string value, int maxLength, out string decoded, out string? failureCode)
    {
        decoded = string.Empty;
        failureCode = null;

        if (value.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
        {
            if (!Base64Tolerant.TryDecodeToString(value["base64:".Length..], out decoded))
            {
                failureCode = "base64_invalid";
                return false;
            }
        }
        else
        {
            decoded = value;
        }

        if (decoded.Length > maxLength)
        {
            // Truncate rather than reject: a long announcement is not a reason to lose
            // the title or the quota readout that accompanies it.
            decoded = decoded[..maxLength];
        }

        return true;
    }

    public static bool IsHexColor(string? value) =>
        value is not null
        && value.Length == 7
        && value[0] == '#'
        && Uri.IsHexDigit(value[1])
        && Uri.IsHexDigit(value[2])
        && Uri.IsHexDigit(value[3])
        && Uri.IsHexDigit(value[4])
        && Uri.IsHexDigit(value[5])
        && Uri.IsHexDigit(value[6]);

    public static bool TryInteger(string value, long min, long max, out long result)
    {
        result = 0;

        if (!long.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return false;
        }

        if (parsed < min || parsed > max)
        {
            return false;
        }

        result = parsed;
        return true;
    }

    /// <summary>Validates a comma-separated CIDR list, rejecting the whole value if any entry is bad.</summary>
    public static bool TryCidrList(string value, out string? badEntry)
    {
        badEntry = null;

        foreach (var part in value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var entry = part.Trim();
            if (entry.Length == 0)
            {
                continue;
            }

            if (!CidrBlock.TryParse(entry, out _))
            {
                badEntry = entry;
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Computes the consent token binding a change to one exact value.
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="Subscriptions.ConsentToken"/> rather than implementing it. There
    /// used to be two copies of this algorithm -- one here and a mirror in the UI, because this
    /// helper is internal -- and a change to either would have silently invalidated every stored
    /// consent in the other. One implementation, reachable from both.
    /// </remarks>
    public static string ConsentToken(string subscriptionId, string headerName, string valueFingerprint) =>
        Subscriptions.ConsentToken.Compute(subscriptionId, headerName, valueFingerprint);
}

/// <summary>
/// The declarative schema of every header MyVpn recognises.
/// </summary>
/// <remarks>
/// <para>
/// Derived from the publicly documented Happ subscription headers. Two of them are
/// worth calling out because they are easy to get wrong:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>subscription-userinfo</c> is a single header carrying
/// <c>upload=…; download=…; total=…; expire=…</c>, not four separate headers.
/// </description></item>
/// <item><description>
/// There is no device-limit header. The documented mechanism is a URL parameter plus a
/// provider-side check, so MyVpn must not invent one.
/// </description></item>
/// </list>
/// <para>
/// A header absent from this table is not an error: it is preserved as inert raw
/// metadata by <see cref="RawHeaderBag"/> and never interpreted.
/// </para>
/// </remarks>
public static class HeaderCatalog
{
    /// <summary>All recognised headers, keyed by lowercase name.</summary>
    public static readonly IReadOnlyDictionary<string, HeaderDescriptor> All = Build();

    public static HeaderDescriptor? Find(string headerName) =>
        headerName is not null && All.TryGetValue(headerName, out var descriptor) ? descriptor : null;

    private static Dictionary<string, HeaderDescriptor> Build()
    {
        var list = new List<HeaderDescriptor>
        {
            // ---- gate A: display and metadata only -------------------------------

            new()
            {
                Name = "profile-title",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Base64OrPlain,
                MaxLength = 25,
                LabelKey = "header.profile_title",
                DescriptionKey = "header.profile_title.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "content-disposition",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.String,
                MaxLength = 260,
                LabelKey = "header.content_disposition",
                DescriptionKey = "header.content_disposition.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscription-userinfo",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.String,
                MaxLength = 256,
                LabelKey = "header.userinfo",
                DescriptionKey = "header.userinfo.desc",
                Duplicates = DuplicatePolicy.RejectOnConflict,
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "support-url",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                LabelKey = "header.support_url",
                DescriptionKey = "header.support_url.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "profile-web-page-url",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                LabelKey = "header.web_page_url",
                DescriptionKey = "header.web_page_url.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "announce",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Base64OrPlain,
                MaxLength = 200,
                LabelKey = "header.announce",
                DescriptionKey = "header.announce.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "sub-info-color",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.String,
                MaxLength = 7,
                LabelKey = "header.announce_color",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "sub-info-text",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Base64OrPlain,
                MaxLength = 200,
                LabelKey = "header.announce_text",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "sub-info-button-text",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Base64OrPlain,
                MaxLength = 25,
                LabelKey = "header.announce_button_text",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "sub-info-button-link",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                LabelKey = "header.announce_button_link",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "profile-update-interval",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Integer,
                MaxLength = 8,
                MinValue = 1,
                MaxValue = 720,
                LabelKey = "header.update_interval",
                DescriptionKey = "header.update_interval.desc",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscription-request-timeout",
                Gate = HeaderApplyGate.Auto,
                Kind = HeaderValueKind.Integer,
                MaxLength = 4,
                MinValue = 5,
                MaxValue = 15,
                LabelKey = "header.request_timeout",
                DescriptionKey = "header.request_timeout.desc",
                Risk = ChangeRisk.Low,
            },

            // ---- gate B: requires explicit, value-bound confirmation --------------

            new()
            {
                Name = "subscription-auto-update-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.auto_update",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscription-auto-update-open-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.auto_update_open",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "tun-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.tun_enable",
                DescriptionKey = "header.tun_enable.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "proxy-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.proxy_enable",
                DescriptionKey = "header.proxy_enable.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "xray-tun-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.xray_tun_enable",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "xray-tun-mtu",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Integer,
                MaxLength = 6,
                MinValue = 576,
                MaxValue = 9000,
                LabelKey = "header.xray_tun_mtu",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "tun-type",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 64,
                LabelKey = "header.tun_type",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "tun-mode",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 64,
                LabelKey = "header.tun_mode",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "routing-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.routing_enable",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "exclude-routes",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.CidrList,
                MaxLength = 2048,
                Duplicates = DuplicatePolicy.JoinList,
                LabelKey = "header.exclude_routes",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "exclude-routes-set",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.exclude_routes_set",
                DescriptionKey = "header.exclude_routes_set.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "include-all-networks-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.include_all_networks",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "exclude-local-networks-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.exclude_local_networks",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "exclude-apns-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.exclude_apns",
                MobileOnly = true,
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "dns-from-json-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.dns_from_json",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "block-bind-to-tunnel-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.block_bind_to_tunnel",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "mux-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.mux_enable",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "mux-tcp-connections",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Integer,
                MaxLength = 4,
                MinValue = -1,
                MaxValue = 1024,
                LabelKey = "header.mux_tcp_connections",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "mux-xudp-connections",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Integer,
                MaxLength = 4,
                MinValue = -1,
                MaxValue = 1024,
                LabelKey = "header.mux_xudp_connections",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "mux-quic",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Enum,
                MaxLength = 16,
                AllowedValues = new[] { "reject", "allow", "skip" },
                LabelKey = "header.mux_quic",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "sniffing-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.sniffing_enable",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "inbound-http-enable",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.inbound_http_enable",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "no-limit-enabled",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.no_limit",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "no-limit-xhttp-enabled",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.no_limit_xhttp",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "per-app-proxy-mode",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Enum,
                MaxLength = 16,
                AllowedValues = new[] { "off", "on", "bypass" },
                LabelKey = "header.per_app_mode",
                MobileOnly = true,
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "per-app-proxy-list",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 4096,
                Duplicates = DuplicatePolicy.JoinList,
                LabelKey = "header.per_app_list",
                MobileOnly = true,
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "per-app-proxy-list-invert",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.per_app_list_invert",
                MobileOnly = true,
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "per-app-proxy-list-set",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.per_app_list_set",
                MobileOnly = true,
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "socks-auth-mode",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Enum,
                MaxLength = 16,
                AllowedValues = new[] { "auto", "manual", "from-json", "disable" },
                LabelKey = "header.socks_auth_mode",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "socks-auth-user",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 128,
                LabelKey = "header.socks_auth_user",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "socks-auth-password",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 128,
                LabelKey = "header.socks_auth_password",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "http-auth-mode",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Enum,
                MaxLength = 16,
                AllowedValues = new[] { "auto", "manual", "from-json", "disable" },
                LabelKey = "header.http_auth_mode",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "http-auth-user",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 128,
                LabelKey = "header.http_auth_user",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "http-auth-password",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 128,
                LabelKey = "header.http_auth_password",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "change-user-agent",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.UserAgent,
                MaxLength = 256,
                LabelKey = "header.change_user_agent",
                DescriptionKey = "header.change_user_agent.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "new-url",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                LabelKey = "header.new_url",
                DescriptionKey = "header.new_url.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "new-domain",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 253,
                LabelKey = "header.new_domain",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "fallback-url",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                Duplicates = DuplicatePolicy.JoinList,
                LabelKey = "header.fallback_url",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "app-auto-start",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.app_auto_start",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscription-autoconnect",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.autoconnect",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "check-url-via-proxy",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Url,
                MaxLength = 2048,
                LabelKey = "header.check_url",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "proxy-ping-timeout",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Integer,
                MaxLength = 4,
                MinValue = 5,
                MaxValue = 15,
                LabelKey = "header.ping_timeout",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscriptions-sort-type",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 32,
                LabelKey = "header.sort_type",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscriptions-collapse",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.subscriptions_collapse",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "subscription-pin",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.subscription_pin",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "hide-settings",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.hide_settings",
                Risk = ChangeRisk.Medium,
            },
            new()
            {
                Name = "color-profile",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.String,
                MaxLength = 32,
                LabelKey = "header.color_profile",
                Risk = ChangeRisk.Low,
            },
            new()
            {
                Name = "user-agent-geo-files",
                Gate = HeaderApplyGate.RequiresConfirmation,
                Kind = HeaderValueKind.UserAgent,
                MaxLength = 256,
                LabelKey = "header.user_agent_geo",
                Risk = ChangeRisk.Low,
            },

            // ---- gate C: recognised but never applied ---------------------------

            new()
            {
                Name = "custom-tunnel-config",
                Gate = HeaderApplyGate.Refused,
                Kind = HeaderValueKind.Json,
                MaxLength = 16_384,
                LabelKey = "header.custom_tunnel_config",
                DescriptionKey = "header.custom_tunnel_config.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "routing",
                Gate = HeaderApplyGate.Refused,
                Kind = HeaderValueKind.String,
                MaxLength = 4096,
                LabelKey = "header.routing",
                DescriptionKey = "header.routing.desc",
                Duplicates = DuplicatePolicy.JoinList,
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "providerid",
                Gate = HeaderApplyGate.Refused,
                Kind = HeaderValueKind.String,
                MaxLength = 128,
                LabelKey = "header.provider_id",
                DescriptionKey = "header.provider_id.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "subscription-always-hwid-enable",
                Gate = HeaderApplyGate.Refused,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.always_hwid",
                DescriptionKey = "header.always_hwid.desc",
                Risk = ChangeRisk.High,
            },
            new()
            {
                Name = "subscription-alternative-hwid-enabled",
                Gate = HeaderApplyGate.Refused,
                Kind = HeaderValueKind.Toggle,
                MaxLength = 8,
                LabelKey = "header.alternative_hwid",
                DescriptionKey = "header.alternative_hwid.desc",
                Risk = ChangeRisk.High,
            },
        };

        var map = new Dictionary<string, HeaderDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (var descriptor in list)
        {
            // A duplicate name would make the schema ambiguous; fail loudly instead.
            if (!map.TryAdd(descriptor.Name, descriptor))
            {
                throw new InvalidOperationException($"Duplicate header descriptor: {descriptor.Name}");
            }
        }

        return map;
    }
}

/// <summary>
/// Runs an ordered, isolated set of <see cref="ISubscriptionHeaderParser"/> instances
/// over a header bag.
/// </summary>
/// <remarks>
/// <para>
/// The registry is the only supported entry point for interpreting subscription
/// headers. It provides three guarantees:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Total, stable ordering.</b> Parsers run in <c>(Priority, Id)</c> order, so
/// results do not depend on reflection order or registration order.
/// </description></item>
/// <item><description>
/// <b>Isolation.</b> A parser that throws, returns null or exceeds its time budget is
/// reported as a diagnostic and skipped; the remaining parsers still run. A broken
/// parser cannot take down the subscription refresh.
/// </description></item>
/// <item><description>
/// <b>Gate enforcement.</b> The registry re-checks every emitted
/// <see cref="PendingChange"/> against the catalog. A buggy parser cannot smuggle a
/// gate-B change into the auto-applied metadata, because the registry validates the
/// declared gate rather than trusting the parser.
/// </description></item>
/// </list>
/// </remarks>
public sealed class SubscriptionHeaderRegistry
{
    /// <summary>Per-parser time budget, matching the documented isolation requirement.</summary>
    public static readonly TimeSpan ParserBudget = TimeSpan.FromMilliseconds(250);

    private readonly Dictionary<string, ISubscriptionHeaderParser> _parserByHeader;
    private readonly HashSet<string> _knownHeaderNames;

    public SubscriptionHeaderRegistry(IEnumerable<ISubscriptionHeaderParser> parsers)
    {
        ArgumentNullException.ThrowIfNull(parsers);

        Parsers = parsers
            .OrderBy(p => p.Priority)
            .ThenBy(p => p.Id, StringComparer.Ordinal)
            .ToArray();

        _parserByHeader = new Dictionary<string, ISubscriptionHeaderParser>(StringComparer.OrdinalIgnoreCase);
        foreach (var parser in Parsers)
        {
            foreach (var name in parser.HeaderNames)
            {
                _parserByHeader.TryAdd(name, parser);
            }
        }

        _knownHeaderNames = new HashSet<string>(_parserByHeader.Keys, StringComparer.OrdinalIgnoreCase);
        Catalog = HeaderCatalog.All;
    }

    /// <summary>Parsers in their frozen execution order.</summary>
    public IReadOnlyList<ISubscriptionHeaderParser> Parsers { get; }

    /// <summary>The header schema.</summary>
    public IReadOnlyDictionary<string, HeaderDescriptor> Catalog { get; }

    /// <summary>Header names this registry recognises.</summary>
    public ISet<string> KnownHeaderNames => _knownHeaderNames;

    /// <summary>Builds a bounded bag that already knows which headers are recognised.</summary>
    public RawHeaderBag CreateBag(
        IEnumerable<KeyValuePair<string, string>>? headers,
        HeaderLimits? limits = null) =>
        RawHeaderBag.FromPairs(headers, _knownHeaderNames, limits ?? HeaderLimits.Default);

    /// <summary>Runs every applicable parser and merges the results.</summary>
    public ParseResult Parse(HeaderParseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = ParseResult.Empty;
        var errors = new List<MyVpnError>();
        var refused = new List<string>();

        foreach (var parser in Parsers)
        {
            if (!parser.HeaderNames.Any(context.Headers.Contains))
            {
                continue;
            }

            ParseResult parsed;
            var start = System.Diagnostics.Stopwatch.GetTimestamp();

            try
            {
                parsed = parser.Parse(context) ?? ParseResult.Empty;
            }
            catch (Exception ex)
            {
                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.parser_failed",
                    ErrorSeverity.Warning,
                    $"Parser '{parser.Id}' v{parser.Version} threw {ex.GetType().Name}: {ex.Message}"));

                continue;
            }

            var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(start);
            if (elapsed > ParserBudget)
            {
                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.parser_budget_exceeded",
                    ErrorSeverity.Warning,
                    $"Parser '{parser.Id}' took {elapsed.TotalMilliseconds:F1} ms (budget {ParserBudget.TotalMilliseconds:F0} ms)."));

                continue;
            }

            // Gate enforcement: a change is only accepted if the catalog agrees that the
            // header it came from is confirmation-gated.
            var (accepted, violations) = EnforceGates(parsed);
            errors.AddRange(violations);

            result = result.Merge(accepted with { Errors = Array.Empty<MyVpnError>() });
            errors.AddRange(accepted.Errors);
            refused.AddRange(accepted.RefusedHeaders);
        }

        return result with
        {
            Errors = errors,
            RefusedHeaders = refused.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
        };
    }

    private (ParseResult Accepted, IReadOnlyList<MyVpnError> Violations) EnforceGates(ParseResult parsed)
    {
        var violations = new List<MyVpnError>();
        var accepted = new List<PendingChange>();

        foreach (var change in parsed.PendingChanges)
        {
            var descriptor = HeaderCatalog.Find(change.HeaderName);

            if (descriptor is null)
            {
                violations.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.change_for_unknown_header",
                    ErrorSeverity.Warning,
                    $"A parser emitted a change for unrecognised header '{change.HeaderName}'; it was dropped."));

                continue;
            }

            if (descriptor.Gate != HeaderApplyGate.RequiresConfirmation)
            {
                violations.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.gate_violation",
                    ErrorSeverity.Warning,
                    $"Header '{change.HeaderName}' has gate {descriptor.Gate} but a parser emitted an applicable change; it was dropped."));

                continue;
            }

            accepted.Add(change with { MobileOnly = descriptor.MobileOnly });
        }

        return (parsed with { PendingChanges = accepted }, violations);
    }

    /// <summary>The registry MyVpn uses at runtime.</summary>
    public static SubscriptionHeaderRegistry CreateDefault() => new(new ISubscriptionHeaderParser[]
    {
        new ProfileIdentityParser(),
        new UserInfoHeaderParser(),
        new LinkHeaderParser(),
        new AnnouncementParser(),
        new ScheduleParser(),
        new ConfirmationGatedParser(),
        new RefusedHeaderParser(),
    });
}
