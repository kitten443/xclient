using MyVpn.Core.Results;

namespace MyVpn.Core.Geo;

/// <summary>Health of a single geo data asset.</summary>
public enum GeoAssetHealth
{
    /// <summary>Not inspected yet.</summary>
    Unknown = 0,

    /// <summary>Exists, is structurally valid and (when a checksum is known) matches it.</summary>
    Valid = 1,

    /// <summary>The file does not exist.</summary>
    Missing = 2,

    /// <summary>The file exists but is zero bytes.</summary>
    Empty = 3,

    /// <summary>The file exists but could not be opened (permissions, locked, bad path).</summary>
    Unreadable = 4,

    /// <summary>Present but implausibly small to be a real database.</summary>
    TooSmall = 5,

    /// <summary>Present and large enough, but not a valid geo data protobuf.</summary>
    Corrupt = 6,

    /// <summary>Content is valid but does not match the recorded SHA-256.</summary>
    ChecksumMismatch = 7,

    /// <summary>
    /// The configured path was not rooted. This is a guard against a *different* failure
    /// mode than issue #9765, not the cause of #9765 itself.
    /// </summary>
    PathNotAbsolute = 8,
}

/// <summary>
/// Everything known about one geo data asset, including the *absolute* path it was
/// resolved to.
/// </summary>
/// <remarks>
/// <para>
/// Storing the resolved absolute path (rather than recomputing a relative path at each
/// use site) is deliberate: relative-path resolution silently changes meaning depending
/// on the process working directory, which differs between a dev run, an installed
/// build, a portable extraction, an AppImage mount and a macOS app bundle. The path is
/// resolved once, validated as absolute, and then only ever used in its absolute form.
/// </para>
/// <para>
/// <b>Recorded root cause of v2rayN issue #9765, for the avoidance of doubt.</b> The
/// defect was <i>not</i> a relative path. On macOS and Linux, v2rayN's TUN path launched
/// Xray elevated through <c>exec sudo -S -- &lt;xray&gt; run -c &lt;cfg&gt;</c> while
/// building the process with <c>environmentVars: null</c>, so <c>XRAY_LOCATION_ASSET</c>
/// (and the rest of the inherited environment) never reached the child —
/// <c>sudo</c>'s default <c>env_reset</c> would have stripped it regardless. Xray then
/// fell back to its built-in default asset directory, which is the <i>directory of the
/// Xray executable</i> rather than the directory holding the <c>.dat</c> files, failed
/// to <c>stat</c> them, and refused to start. The intended path was already absolute;
/// it was simply never delivered. <see cref="GeoAssetHealth.PathNotAbsolute"/> would
/// therefore not have caught it.
/// </para>
/// <para>
/// The corresponding design rule MyVpn enforces is that the asset location is injected
/// through <i>two</i> independent channels — a real process environment variable, with
/// the core launched by argv and never through a shell, and the root <c>env</c> object
/// in the generated config (which requires Xray &gt;= v26.7.11) — and that a pre-launch
/// assertion mirrors Xray's own asset lookup so a mismatch is caught before the core is
/// started rather than surfacing as an opaque <c>EOF</c> from inside Xray.
/// </para>
/// </remarks>
public sealed record GeoAssetInfo
{
    public GeoAssetKind Kind { get; init; }

    /// <summary>Resolved absolute path to the asset file.</summary>
    public string AbsolutePath { get; init; } = string.Empty;

    public GeoAssetHealth Health { get; init; } = GeoAssetHealth.Unknown;

    public long SizeBytes { get; init; }

    /// <summary>SHA-256 of the file, lowercase hex. <c>null</c> when not computed.</summary>
    public string? Sha256 { get; init; }

    /// <summary>Number of geo entries decoded during validation.</summary>
    public int EntryCount { get; init; }

    /// <summary>A few decoded codes, for display in diagnostics.</summary>
    public IReadOnlyList<string> SampleCodes { get; init; } = Array.Empty<string>();

    /// <summary>Where the file came from, when it was downloaded by MyVpn.</summary>
    public string? SourceUrl { get; init; }

    /// <summary>Upstream release tag/version, when known.</summary>
    public string? Version { get; init; }

    public DateTimeOffset? UpdatedAt { get; init; }

    /// <summary>Machine-readable failure code, matching <see cref="ErrorCodes"/>.</summary>
    public string? ErrorCode { get; init; }

    /// <summary>Localization key for the plain-language explanation.</summary>
    public string? MessageKey { get; init; }

    /// <summary>Localization key of a suggested repair action.</summary>
    public string? RemediationKey { get; init; }

    /// <summary>Human-readable technical context for the diagnostics bundle.</summary>
    public string? FailureDetail { get; init; }

    /// <summary>True when Xray can be pointed at this file.</summary>
    public bool IsUsable => Health == GeoAssetHealth.Valid;

    /// <summary>
    /// Builds an <see cref="MyVpnError"/> describing this asset's problem, or
    /// <c>null</c> when it is healthy.
    /// </summary>
    public MyVpnError? ToError() =>
        IsUsable
            ? null
            : new MyVpnError(
                ErrorCode ?? ErrorCodes.GeoAssetCorrupt,
                MessageKey ?? "error.geodata.unusable",
                SeverityFor(Health),
                FailureDetail,
                RemediationKey ?? "geodata.repair");

    /// <summary>
    /// Unreadable/missing assets are errors rather than warnings because a missing
    /// geo asset breaks routing rules that reference it; the connection may still be
    /// established, but the user's traffic policy is not what they asked for.
    /// </summary>
    public static ErrorSeverity SeverityFor(GeoAssetHealth health) => health switch
    {
        GeoAssetHealth.Valid => ErrorSeverity.Warning,
        GeoAssetHealth.Unknown => ErrorSeverity.Warning,
        GeoAssetHealth.Missing => ErrorSeverity.Error,
        GeoAssetHealth.Empty => ErrorSeverity.Error,
        GeoAssetHealth.TooSmall => ErrorSeverity.Error,
        GeoAssetHealth.Corrupt => ErrorSeverity.Error,
        GeoAssetHealth.ChecksumMismatch => ErrorSeverity.Warning,
        GeoAssetHealth.Unreadable => ErrorSeverity.Error,
        GeoAssetHealth.PathNotAbsolute => ErrorSeverity.Critical,
        _ => ErrorSeverity.Error,
    };

    /// <summary>Maps a structural validation failure onto a health value and error code.</summary>
    public static (GeoAssetHealth Health, string ErrorCode, string MessageKey) MapValidationFailure(
        GeoAssetKind kind,
        string failureCode) => failureCode switch
    {
        "empty" => (GeoAssetHealth.Empty, ErrorCodes.GeoAssetEmpty, "error.geodata.empty"),
        "too_small" => (GeoAssetHealth.TooSmall, ErrorCodes.GeoAssetCorrupt, "error.geodata.too_small"),
        "no_entries" or "entry_without_code" =>
            (GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt, "error.geodata.wrong_format"),
        "truncated_tag" or "truncated_entry" or "malformed_entry" or "malformed_field" or "wrong_wire_type" =>
            (GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt, "error.geodata.truncated"),
        _ => (GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt, "error.geodata.corrupt"),
    };
}
