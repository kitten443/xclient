using MyVpn.Core.Results;

namespace MyVpn.Core.Subscriptions;

/// <summary>
/// What the client is allowed to do with a header it understands.
/// </summary>
/// <remarks>
/// The gate is a property of the <i>header</i>, enforced by the registry, not a
/// convention that individual parsers are trusted to follow. This is the central
/// security decision of the subscription subsystem: a subscription response is
/// attacker-influenced input, and the client must not let a provider reconfigure
/// routing, the tunnel, DNS or credentials on its own authority.
/// </remarks>
public enum HeaderApplyGate
{
    /// <summary>
    /// Applied automatically. Restricted to display and metadata only: a title, a quota
    /// readout, a link to show, an announcement. Nothing here can change how traffic
    /// flows.
    /// </summary>
    Auto = 0,

    /// <summary>
    /// Parsed into a <see cref="PendingChange"/> and surfaced to the user for explicit,
    /// value-bound confirmation. Never written into live settings by the parser.
    /// </summary>
    RequiresConfirmation = 1,

    /// <summary>
    /// Recognised and reported, but never applied and never offered for one-click
    /// acceptance — raw tunnel config, routing imports and telemetry identifiers.
    /// </summary>
    Refused = 2,
}

/// <summary>How to behave when a header appears more than once.</summary>
public enum DuplicatePolicy
{
    /// <summary>All values must be identical, otherwise the header is rejected.</summary>
    Unanimous = 0,

    /// <summary>Values are combined into a list (order preserved).</summary>
    JoinList = 1,

    /// <summary>Any disagreement rejects the header outright.</summary>
    RejectOnConflict = 2,
}

/// <summary>The value shape a header must have, used for validation and for UI rendering.</summary>
public enum HeaderValueKind
{
    String = 0,
    Toggle = 1,
    Integer = 2,
    Enum = 3,
    CidrList = 4,
    DomainList = 5,
    Json = 6,
    Url = 7,

    /// <summary>Plain text, or text encoded as <c>base64:&lt;payload&gt;</c>.</summary>
    Base64OrPlain = 8,

    UserAgent = 9,
}

/// <summary>How disruptive accepting a change would be, for UI emphasis.</summary>
public enum ChangeRisk
{
    Low = 0,
    Medium = 1,
    High = 2,
}

/// <summary>
/// Declarative schema for one recognised header.
/// </summary>
/// <remarks>
/// Having the schema as data rather than as code inside each parser is what makes the
/// registry reviewable: the complete set of things a provider can influence is one
/// table, and the gate for each is visible in a single screen.
/// </remarks>
public sealed record HeaderDescriptor
{
    /// <summary>Lowercase canonical header name.</summary>
    public required string Name { get; init; }

    public required HeaderApplyGate Gate { get; init; }

    public DuplicatePolicy Duplicates { get; init; } = DuplicatePolicy.Unanimous;

    public HeaderValueKind Kind { get; init; } = HeaderValueKind.String;

    /// <summary>Maximum accepted value length in characters, applied on top of the bag limit.</summary>
    public int MaxLength { get; init; } = 512;

    /// <summary>Localization key for the human-readable name.</summary>
    public required string LabelKey { get; init; }

    public string? DescriptionKey { get; init; }

    /// <summary>Permitted values for <see cref="HeaderValueKind.Enum"/>.</summary>
    public IReadOnlyList<string>? AllowedValues { get; init; }

    public long? MinValue { get; init; }

    public long? MaxValue { get; init; }

    public ChangeRisk Risk { get; init; } = ChangeRisk.Medium;

    /// <summary>
    /// True when this header is only meaningful on a mobile platform. It is still
    /// parsed and reported on desktop, but the UI explains that it does not apply here
    /// instead of silently ignoring it.
    /// </summary>
    public bool MobileOnly { get; init; }
}

/// <summary>
/// Metadata a subscription is allowed to set automatically (gate <see cref="HeaderApplyGate.Auto"/>).
/// </summary>
public sealed record SubscriptionMetadata
{
    /// <summary>Provider-chosen display title.</summary>
    public string? Title { get; init; }

    /// <summary>Support page shown in the UI.</summary>
    public string? SupportUrl { get; init; }

    /// <summary>Provider home page.</summary>
    public string? WebPageUrl { get; init; }

    /// <summary>Announcement or notice text.</summary>
    public string? Announce { get; init; }

    /// <summary>Accent colour for the announcement, as <c>#RRGGBB</c>.</summary>
    public string? AnnounceColor { get; init; }

    public SubscriptionUserInfo? UserInfo { get; init; }

    /// <summary>Provider-suggested refresh interval.</summary>
    public TimeSpan? UpdateInterval { get; init; }

    /// <summary>Provider-suggested request timeout in seconds.</summary>
    public int? RequestTimeoutSeconds { get; init; }

    /// <summary>Filename suggested by <c>content-disposition</c>, when present.</summary>
    public string? SuggestedFileName { get; init; }

    /// <summary>Everything that was parsed but has no dedicated field, keyed by header name.</summary>
    public IReadOnlyDictionary<string, string> Extra { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public bool IsEmpty => Title is null && SupportUrl is null && WebPageUrl is null
                           && Announce is null && UserInfo is null && UpdateInterval is null
                           && SuggestedFileName is null && Extra.Count == 0;
}

/// <summary>
/// A settings change a provider is asking for, awaiting explicit user consent.
/// </summary>
/// <remarks>
/// <see cref="ConsentToken"/> binds the consent to the exact
/// <c>(subscription, header, value)</c> triple. Without it, a provider could present a
/// harmless-looking request, obtain a one-time confirmation, and then change the value
/// on the next refresh while the client kept applying the stored "yes".
/// </remarks>
public sealed record PendingChange
{
    public required string Id { get; init; }

    public required string HeaderName { get; init; }

    /// <summary>Validated value, ready to apply once consented to.</summary>
    public required string Value { get; init; }

    /// <summary>SHA-256 of the raw value.</summary>
    public required string ValueFingerprint { get; init; }

    public required ChangeRisk Risk { get; init; }

    public required string LabelKey { get; init; }

    public string? DescriptionKey { get; init; }

    /// <summary>Opaque token that must be echoed back to apply this change.</summary>
    public required string ConsentToken { get; init; }

    /// <summary>True when the change targets a mobile-only feature.</summary>
    public bool MobileOnly { get; init; }
}

/// <summary>Outcome of running every parser over a header bag.</summary>
public sealed record ParseResult
{
    public static ParseResult Empty { get; } = new();

    public SubscriptionMetadata Metadata { get; init; } = new();

    public IReadOnlyList<PendingChange> PendingChanges { get; init; } = Array.Empty<PendingChange>();

    /// <summary>Problems worth telling the user about. Warnings use <see cref="ErrorSeverity.Warning"/>.</summary>
    public IReadOnlyList<MyVpnError> Errors { get; init; } = Array.Empty<MyVpnError>();

    /// <summary>Headers that were recognised but deliberately not applied.</summary>
    public IReadOnlyList<string> RefusedHeaders { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Merges another result into this one. Metadata fields already set are kept, because
    /// the first parser to claim a field wins and later parsers must not silently
    /// overwrite an established value.
    /// </summary>
    public ParseResult Merge(ParseResult other)
    {
        ArgumentNullException.ThrowIfNull(other);

        var extra = new Dictionary<string, string>(Metadata.Extra, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in other.Metadata.Extra)
        {
            extra[pair.Key] = pair.Value;
        }

        var metadata = Metadata with
        {
            Title = Metadata.Title ?? other.Metadata.Title,
            SupportUrl = Metadata.SupportUrl ?? other.Metadata.SupportUrl,
            WebPageUrl = Metadata.WebPageUrl ?? other.Metadata.WebPageUrl,
            Announce = Metadata.Announce ?? other.Metadata.Announce,
            AnnounceColor = Metadata.AnnounceColor ?? other.Metadata.AnnounceColor,
            UserInfo = Metadata.UserInfo ?? other.Metadata.UserInfo,
            UpdateInterval = Metadata.UpdateInterval ?? other.Metadata.UpdateInterval,
            RequestTimeoutSeconds = Metadata.RequestTimeoutSeconds ?? other.Metadata.RequestTimeoutSeconds,
            SuggestedFileName = Metadata.SuggestedFileName ?? other.Metadata.SuggestedFileName,
            Extra = extra,
        };

        return new ParseResult
        {
            Metadata = metadata,
            PendingChanges = PendingChanges.Concat(other.PendingChanges).ToArray(),
            Errors = Errors.Concat(other.Errors).ToArray(),
            RefusedHeaders = RefusedHeaders.Concat(other.RefusedHeaders).ToArray(),
        };
    }
}

/// <summary>Everything a parser is allowed to see.</summary>
public sealed record HeaderParseContext
{
    public required RawHeaderBag Headers { get; init; }

    /// <summary>Stable identifier of the owning subscription; part of the consent token.</summary>
    public required string SubscriptionId { get; init; }

    /// <summary>URL the response came from, used to resolve relative links.</summary>
    public Uri? SubscriptionUrl { get; init; }

    /// <summary>Whether plain HTTP was permitted for this subscription.</summary>
    public bool AllowInsecureHttp { get; init; }

    /// <summary>Limits applied when the bag was built; parsers may consult the same bounds.</summary>
    public HeaderLimits Limits { get; init; } = HeaderLimits.Default;
}

/// <summary>
/// A parser for one logical group of subscription headers.
/// </summary>
/// <remarks>
/// Implementations must be pure and non-blocking: they receive an already-bounded header
/// bag and return a result. They must not perform I/O. The registry measures the time
/// each parser takes and rejects a parser that exceeds its budget, but it cannot
/// pre-empt a blocking call, so non-blocking is a hard contract rather than a
/// best-effort guideline.
/// </remarks>
public interface ISubscriptionHeaderParser
{
    /// <summary>Stable identifier, used for ordering and for diagnostics.</summary>
    string Id { get; }

    /// <summary>Schema version of this parser; bumped when its interpretation changes.</summary>
    int Version { get; }

    /// <summary>Lower numbers run first. Used as the primary key of the total order.</summary>
    int Priority { get; }

    /// <summary>The strictest gate this parser can emit.</summary>
    HeaderApplyGate Gate { get; }

    /// <summary>Header names (lowercase) this parser claims.</summary>
    IReadOnlyCollection<string> HeaderNames { get; }

    /// <summary>Largest value this parser will look at.</summary>
    int MaxValueLength { get; }

    bool CanParse(string headerName);

    ParseResult Parse(HeaderParseContext context);
}
