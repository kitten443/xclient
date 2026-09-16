using System.Globalization;
using MyVpn.Core.Net;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;

namespace MyVpn.Core.Subscriptions;

/// <summary>
/// Shared base for header parsers: implements the duplicate policy and value bounds from
/// the catalog so that each parser only has to describe meaning, not mechanics.
/// </summary>
public abstract class SubscriptionHeaderParserBase : ISubscriptionHeaderParser
{
    private readonly HeaderDescriptor[] _descriptors;

    protected SubscriptionHeaderParserBase(params string[] headerNames)
    {
        _descriptors = headerNames
            .Select(HeaderCatalog.Find)
            .Where(d => d is not null)
            .Select(d => d!)
            .ToArray();

        HeaderNames = _descriptors.Select(d => d.Name).ToArray();
    }

    public abstract string Id { get; }

    public abstract int Version { get; }

    public abstract int Priority { get; }

    public abstract HeaderApplyGate Gate { get; }

    public IReadOnlyCollection<string> HeaderNames { get; }

    public int MaxValueLength => _descriptors.Length == 0 ? 0 : _descriptors.Max(d => d.MaxLength);

    protected IReadOnlyList<HeaderDescriptor> Descriptors => _descriptors;

    public bool CanParse(string headerName) =>
        _descriptors.Any(d => d.Name.Equals(headerName, StringComparison.OrdinalIgnoreCase));

    public abstract ParseResult Parse(HeaderParseContext context);

    /// <summary>
    /// Reads a single, validated value for a header.
    /// </summary>
    /// <remarks>
    /// Applies the descriptor's duplicate policy and length bound. Returns
    /// <see cref="ToggleState.Unspecified"/>-like emptiness for a header that is absent,
    /// empty, duplicated in disagreement, or over-length — never a partially-valid value.
    /// </remarks>
    protected string? TryReadValue(
        HeaderParseContext context,
        HeaderDescriptor descriptor,
        ICollection<MyVpnError> errors)
    {
        var entries = context.Headers.GetEntries(descriptor.Name);
        if (entries.Count == 0)
        {
            return null;
        }

        var values = entries.Select(e => e.Value).ToArray();

        // An empty value means "unspecified" for every header kind: leave the setting alone.
        if (values.All(v => v.Length == 0))
        {
            return null;
        }

        if (values.Length > 1)
        {
            var distinct = values.Distinct(StringComparer.Ordinal).ToArray();

            switch (descriptor.Duplicates)
            {
                case DuplicatePolicy.RejectOnConflict:
                case DuplicatePolicy.Unanimous when distinct.Length > 1:
                    errors.Add(new MyVpnError(
                        ErrorCodes.SubscriptionHeaderInvalid,
                        "error.header.duplicate_conflict",
                        ErrorSeverity.Warning,
                        $"Header '{descriptor.Name}' appeared {values.Length} times with conflicting values.")
                        .WithArg("header", descriptor.Name));

                    return null;

                case DuplicatePolicy.JoinList:
                    return string.Join(",", values.Where(v => v.Length > 0));

                default:
                    break;
            }
        }

        var value = values[0];

        // For Base64OrPlain headers the schema limit bounds the *decoded* text, not the
        // raw header: a `base64:` payload is inherently longer than what it decodes to,
        // and the decoder below truncates an over-long result rather than rejecting it
        // (a long announcement must not cost us the title). Applying the raw limit here
        // as well would reject exactly the values the decoder is designed to truncate.
        if (descriptor.Kind != HeaderValueKind.Base64OrPlain && value.Length > descriptor.MaxLength)
        {
            errors.Add(new MyVpnError(
                ErrorCodes.SubscriptionHeaderInvalid,
                "error.header.value_over_schema_limit",
                ErrorSeverity.Warning,
                $"Header '{descriptor.Name}' value is {value.Length} chars; schema limit is {descriptor.MaxLength}.")
                .WithArg("header", descriptor.Name));

            return null;
        }

        return value;
    }
}

/// <summary>Parses <c>profile-title</c> and <c>content-disposition</c>.</summary>
public sealed class ProfileIdentityParser : SubscriptionHeaderParserBase
{
    public ProfileIdentityParser()
        : base("profile-title", "content-disposition")
    {
    }

    public override string Id => "profile-identity";

    public override int Version => 1;

    public override int Priority => 10;

    public override HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();
        string? title = null;

        var titleDescriptor = HeaderCatalog.Find("profile-title")!;
        var rawTitle = TryReadValue(context, titleDescriptor, errors);
        if (rawTitle is not null)
        {
            if (HeaderValueParsing.TryDecodeBase64OrPlain(rawTitle, titleDescriptor.MaxLength, out var decoded, out var failure))
            {
                title = decoded;
            }
            else
            {
                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.base64_invalid",
                    ErrorSeverity.Warning,
                    $"profile-title could not be decoded ({failure})."));
            }
        }

        // content-disposition: extract filename from the documented form.
        var dispositionDescriptor = HeaderCatalog.Find("content-disposition")!;
        var disposition = TryReadValue(context, dispositionDescriptor, errors);
        var fileName = disposition is null ? null : ExtractFileName(disposition);

        return new ParseResult
        {
            Metadata = new SubscriptionMetadata { Title = title, SuggestedFileName = fileName },
            Errors = errors,
        };
    }

    /// <summary>
    /// Extracts the file name from a <c>Content-Disposition</c> value without interpreting
    /// the rest of the header, and without ever returning a path.
    /// </summary>
    /// <remarks>
    /// Path separators and <c>..</c> are stripped rather than sanitized into something
    /// plausible: a file name here is cosmetic (a suggested name for an export), so the
    /// safe move is to reduce it to a bare leaf name.
    /// </remarks>
    internal static string? ExtractFileName(string value)
    {
        foreach (var segment in value.Split(';'))
        {
            var trimmed = segment.Trim();
            const string prefix = "filename=";
            const string prefixStar = "filename*=";

            string? candidate = null;

            if (trimmed.StartsWith(prefixStar, StringComparison.OrdinalIgnoreCase))
            {
                candidate = trimmed[prefixStar.Length..];
            }
            else if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                candidate = trimmed[prefix.Length..];
            }

            if (candidate is null)
            {
                continue;
            }

            candidate = candidate.Trim().Trim('"');

            // RFC 5987 form: charset'lang'percent-encoded-value
            var parts = candidate.Split('\'');
            if (parts.Length == 3)
            {
                candidate = Base64Tolerant.TryDecodeToString(parts[2], out var dec) ? dec : ParseUnescape(parts[2]);
            }

            var leaf = candidate.Replace('\\', '/').Split('/').LastOrDefault() ?? string.Empty;
            if (leaf is "." or "..")
            {
                return null;
            }

            leaf = leaf.Trim();
            return leaf.Length is > 0 and <= 260 ? leaf : null;
        }

        return null;
    }

    private static string ParseUnescape(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}

/// <summary>Parses <c>subscription-userinfo</c>.</summary>
public sealed class UserInfoHeaderParser : SubscriptionHeaderParserBase
{
    public UserInfoHeaderParser()
        : base("subscription-userinfo")
    {
    }

    public override string Id => "subscription-userinfo";

    public override int Version => 1;

    public override int Priority => 20;

    public override HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();
        var descriptor = Descriptors[0];
        var raw = TryReadValue(context, descriptor, errors);

        if (raw is null)
        {
            return new ParseResult { Errors = errors };
        }

        if (!SubscriptionUserInfo.TryParse(raw, out var info, out var failure))
        {
            errors.Add(new MyVpnError(
                ErrorCodes.SubscriptionHeaderInvalid,
                "error.header.userinfo_malformed",
                ErrorSeverity.Warning,
                $"subscription-userinfo could not be parsed ({failure}).")
                .WithArg("header", descriptor.Name));

            return new ParseResult { Errors = errors };
        }

        return new ParseResult
        {
            Metadata = new SubscriptionMetadata { UserInfo = info },
            Errors = errors,
        };
    }
}

/// <summary>Parses <c>support-url</c> and <c>profile-web-page-url</c>.</summary>
public sealed class LinkHeaderParser : SubscriptionHeaderParserBase
{
    public LinkHeaderParser()
        : base("support-url", "profile-web-page-url")
    {
    }

    public override string Id => "links";

    public override int Version => 1;

    public override int Priority => 30;

    public override HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();

        var support = ReadSafeUrl(context, "support-url", errors);
        var webPage = ReadSafeUrl(context, "profile-web-page-url", errors);

        return new ParseResult
        {
            Metadata = new SubscriptionMetadata { SupportUrl = support, WebPageUrl = webPage },
            Errors = errors,
        };
    }

    private string? ReadSafeUrl(HeaderParseContext context, string headerName, ICollection<MyVpnError> errors)
    {
        var descriptor = HeaderCatalog.Find(headerName)!;
        var raw = TryReadValue(context, descriptor, errors);
        if (raw is null)
        {
            return null;
        }

        // A provider-supplied link is displayed and may be opened. Refusing loopback,
        // private and metadata addresses here is what stops "click support" from becoming
        // a request forgery against the user's own machine.
        if (!UrlSafety.IsSafeHttpUrl(raw, context.AllowInsecureHttp, out var reason))
        {
            errors.Add(new MyVpnError(
                ErrorCodes.SubscriptionHeaderInvalid,
                "error.header.url_rejected",
                ErrorSeverity.Warning,
                $"Header '{headerName}' URL rejected: {reason}.")
                .WithArg("header", headerName));

            return null;
        }

        return raw;
    }
}

/// <summary>Parses the announcement and info-banner headers.</summary>
public sealed class AnnouncementParser : SubscriptionHeaderParserBase
{
    public AnnouncementParser()
        : base(
            "announce",
            "sub-info-color",
            "sub-info-text",
            "sub-info-button-text",
            "sub-info-button-link")
    {
    }

    public override string Id => "announcement";

    public override int Version => 1;

    public override int Priority => 40;

    public override HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();

        var announce = ReadText(context, "announce", errors);
        var text = ReadText(context, "sub-info-text", errors);

        // "0" is a documented sentinel meaning "clear the banner", not literal text.
        if (text is "0")
        {
            text = null;
        }

        if (announce is "0")
        {
            announce = null;
        }

        var colorDescriptor = HeaderCatalog.Find("sub-info-color")!;
        var color = TryReadValue(context, colorDescriptor, errors);
        if (color is not null && !HeaderValueParsing.IsHexColor(color))
        {
            // An invalid colour is cosmetic only; drop it quietly and keep the text.
            color = null;
        }

        var buttonText = ReadText(context, "sub-info-button-text", errors);
        var buttonLink = ReadText(context, "sub-info-button-link", errors);

        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (text is not null)
        {
            extra["sub-info-text"] = text;
        }

        if (buttonText is not null)
        {
            extra["sub-info-button-text"] = buttonText;
        }

        if (buttonLink is not null && UrlSafety.IsSafeHttpUrl(buttonLink, context.AllowInsecureHttp, out _))
        {
            extra["sub-info-button-link"] = buttonLink;
        }

        return new ParseResult
        {
            Metadata = new SubscriptionMetadata
            {
                Announce = announce ?? text,
                AnnounceColor = color,
                Extra = extra,
            },
            Errors = errors,
        };
    }

    private string? ReadText(HeaderParseContext context, string headerName, ICollection<MyVpnError> errors)
    {
        var descriptor = HeaderCatalog.Find(headerName)!;
        var raw = TryReadValue(context, descriptor, errors);
        if (raw is null)
        {
            return null;
        }

        return HeaderValueParsing.TryDecodeBase64OrPlain(raw, descriptor.MaxLength, out var decoded, out var failure)
            ? decoded
            : null;
    }
}

/// <summary>Parses <c>profile-update-interval</c> and <c>subscription-request-timeout</c>.</summary>
public sealed class ScheduleParser : SubscriptionHeaderParserBase
{
    public ScheduleParser()
        : base("profile-update-interval", "subscription-request-timeout")
    {
    }

    public override string Id => "schedule";

    public override int Version => 1;

    public override int Priority => 50;

    public override HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();

        TimeSpan? interval = null;
        var intervalDescriptor = HeaderCatalog.Find("profile-update-interval")!;
        var rawInterval = TryReadValue(context, intervalDescriptor, errors);

        if (rawInterval is not null)
        {
            if (HeaderValueParsing.TryInteger(rawInterval, 1, 720, out var hours))
            {
                interval = TimeSpan.FromHours(hours);
            }
            else
            {
                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.update_interval_range",
                    ErrorSeverity.Warning,
                    $"profile-update-interval '{rawInterval}' is outside 1..720 hours."));
            }
        }

        int? timeout = null;
        var timeoutDescriptor = HeaderCatalog.Find("subscription-request-timeout")!;
        var rawTimeout = TryReadValue(context, timeoutDescriptor, errors);

        if (rawTimeout is not null)
        {
            if (HeaderValueParsing.TryInteger(rawTimeout, 5, 15, out var seconds))
            {
                timeout = (int)seconds;
            }
            else
            {
                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.request_timeout_range",
                    ErrorSeverity.Warning,
                    $"subscription-request-timeout '{rawTimeout}' is outside 5..15 seconds."));
            }
        }

        return new ParseResult
        {
            Metadata = new SubscriptionMetadata
            {
                UpdateInterval = interval,
                RequestTimeoutSeconds = timeout,
            },
            Errors = errors,
        };
    }
}

/// <summary>
/// Turns every confirmation-gated header into a <see cref="PendingChange"/>.
/// </summary>
/// <remarks>
/// One generic parser rather than fifty hand-written ones: the differences between these
/// headers are pure schema (kind, bounds, allowed values), which already lives in
/// <see cref="HeaderCatalog"/>. Adding a header is then a catalog entry, not new code —
/// and there is exactly one place where a change can be constructed, which is auditable.
/// </remarks>
public sealed class ConfirmationGatedParser : SubscriptionHeaderParserBase
{
    public ConfirmationGatedParser()
        : base(HeaderCatalog.All.Values
            .Where(d => d.Gate == HeaderApplyGate.RequiresConfirmation)
            .Select(d => d.Name)
            .ToArray())
    {
    }

    public override string Id => "confirmation-gated";

    public override int Version => 1;

    public override int Priority => 60;

    public override HeaderApplyGate Gate => HeaderApplyGate.RequiresConfirmation;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var errors = new List<MyVpnError>();
        var changes = new List<PendingChange>();

        foreach (var descriptor in Descriptors)
        {
            var raw = TryReadValue(context, descriptor, errors);
            if (raw is null)
            {
                continue;
            }

            var normalized = Normalize(raw, descriptor, errors);
            if (normalized is null)
            {
                continue;
            }

            var entry = context.Headers.GetEntries(descriptor.Name).FirstOrDefault();

            changes.Add(new PendingChange
            {
                Id = descriptor.Name,
                HeaderName = descriptor.Name,
                Value = normalized,
                ValueFingerprint = entry?.ValueFingerprint ?? string.Empty,
                Risk = descriptor.Risk,
                LabelKey = descriptor.LabelKey,
                DescriptionKey = descriptor.DescriptionKey,
                MobileOnly = descriptor.MobileOnly,
                ConsentToken = HeaderValueParsing.ConsentToken(
                    context.SubscriptionId,
                    descriptor.Name,
                    entry?.ValueFingerprint ?? string.Empty),
            });
        }

        return new ParseResult { PendingChanges = changes, Errors = errors };
    }

    /// <summary>Validates and canonicalizes a value against its declared kind.</summary>
    private static string? Normalize(string raw, HeaderDescriptor descriptor, ICollection<MyVpnError> errors)
    {
        switch (descriptor.Kind)
        {
            case HeaderValueKind.Toggle:
            {
                var state = HeaderValueParsing.Evaluate(raw);
                return state switch
                {
                    ToggleState.Unspecified => null,
                    ToggleState.On => "true",
                    _ => "false",
                };
            }

            case HeaderValueKind.Integer:
            {
                var min = descriptor.MinValue ?? long.MinValue;
                var max = descriptor.MaxValue ?? long.MaxValue;

                if (HeaderValueParsing.TryInteger(raw, min, max, out var value))
                {
                    return value.ToString(CultureInfo.InvariantCulture);
                }

                errors.Add(RangeError(descriptor, raw, min, max));
                return null;
            }

            case HeaderValueKind.Enum:
            {
                var allowed = descriptor.AllowedValues ?? Array.Empty<string>();
                var match = allowed.FirstOrDefault(a => a.Equals(raw.Trim(), StringComparison.OrdinalIgnoreCase));

                if (match is not null)
                {
                    return match;
                }

                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.value_not_allowed",
                    ErrorSeverity.Warning,
                    $"Header '{descriptor.Name}' value '{Sanitize(raw)}' is not one of {string.Join(", ", allowed)}.")
                    .WithArg("header", descriptor.Name));

                return null;
            }

            case HeaderValueKind.CidrList:
            {
                if (HeaderValueParsing.TryCidrList(raw, out var bad))
                {
                    return raw;
                }

                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.cidr_invalid",
                    ErrorSeverity.Warning,
                    $"Header '{descriptor.Name}' contains an invalid CIDR '{Sanitize(bad)}'.")
                    .WithArg("header", descriptor.Name));

                return null;
            }

            case HeaderValueKind.Url:
            {
                if (UrlSafety.IsSafeHttpUrl(raw, allowInsecureHttp: false, out var reason))
                {
                    return raw;
                }

                errors.Add(new MyVpnError(
                    ErrorCodes.SubscriptionHeaderInvalid,
                    "error.header.url_rejected",
                    ErrorSeverity.Warning,
                    $"Header '{descriptor.Name}' URL rejected: {reason}.")
                    .WithArg("header", descriptor.Name));

                return null;
            }

            case HeaderValueKind.UserAgent:
            {
                // Control characters were already rejected by the bag; bound the length
                // and canonicalise whitespace so the value cannot smuggle header structure.
                var trimmed = raw.Trim();
                return trimmed.Length is > 0 and <= 256 ? trimmed : null;
            }

            default:
                return raw;
        }
    }

    private static MyVpnError RangeError(HeaderDescriptor descriptor, string raw, long min, long max) =>
        new MyVpnError(
            ErrorCodes.SubscriptionHeaderInvalid,
            "error.header.value_out_of_range",
            ErrorSeverity.Warning,
            $"Header '{descriptor.Name}' value '{Sanitize(raw)}' is outside {min}..{max}.")
            .WithArg("header", descriptor.Name);

    /// <summary>Keeps a rejected value short and control-free before it reaches a log.</summary>
    private static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var trimmed = value.Length <= 40 ? value : value[..40] + "...";
        return new string(trimmed.Select(c => c < 0x20 || c == 0x7F ? '?' : c).ToArray());
    }
}

/// <summary>
/// Recognises refused headers and reports them without ever applying them.
/// </summary>
/// <remarks>
/// These are the headers that would let a provider inject a raw tunnel configuration,
/// rewrite routing, or receive a hardware identifier. They are surfaced in the UI as a
/// security notice — <i>not</i> as an accept/reject prompt — because there is no safe
/// way to accept them automatically and no reason the user should have to adjudicate a
/// JSON blob.
/// </remarks>
public sealed class RefusedHeaderParser : SubscriptionHeaderParserBase
{
    public RefusedHeaderParser()
        : base(HeaderCatalog.All.Values
            .Where(d => d.Gate == HeaderApplyGate.Refused)
            .Select(d => d.Name)
            .ToArray())
    {
    }

    public override string Id => "refused";

    public override int Version => 1;

    public override int Priority => 70;

    public override HeaderApplyGate Gate => HeaderApplyGate.Refused;

    public override ParseResult Parse(HeaderParseContext context)
    {
        var refused = new List<string>();

        foreach (var descriptor in Descriptors)
        {
            if (context.Headers.Contains(descriptor.Name))
            {
                refused.Add(descriptor.Name);
            }
        }

        if (refused.Count == 0)
        {
            return ParseResult.Empty;
        }

        // One warning per refused header kind, so diagnostics name exactly what was sent.
        var error = new MyVpnError(
            ErrorCodes.SubscriptionHeaderInvalid,
            "error.header.refused_for_security",
            ErrorSeverity.Warning,
            $"The subscription sent headers MyVpn will not apply: {string.Join(", ", refused)}.")
            .WithArg("headers", string.Join(", ", refused));

        return new ParseResult
        {
            RefusedHeaders = refused,
            Errors = new[] { error },
        };
    }
}
