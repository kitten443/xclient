using MyVpn.Core.Results;

namespace MyVpn.Core.Geo;

/// <summary>
/// The complete geo data picture for this installation: absolute paths, per-asset
/// health, and whether the directory is usable for updates.
/// </summary>
/// <remarks>
/// Produced by <c>IGeoDataManager</c> and consumed by (a) the Xray config builder,
/// which must not reference an unavailable asset, (b) the environment builder, which
/// exports <c>XRAY_LOCATION_ASSET</c>, and (c) diagnostics.
/// </remarks>
public sealed record GeoDataStatus
{
    /// <summary>Absolute directory that will be exported as <c>XRAY_LOCATION_ASSET</c>.</summary>
    public string AssetDirectory { get; init; } = string.Empty;

    /// <summary>
    /// False when <see cref="AssetDirectory"/> is not rooted. A relative value changes meaning
    /// with the process working directory, so it is surfaced as a first-class health signal
    /// rather than being silently resolved.
    /// </summary>
    /// <remarks>
    /// This is a guard against a different failure mode than issue #9765. For that issue the
    /// configured value was already absolute but was never delivered to the child process, so
    /// <c>IsAssetDirectoryAbsolute</c> would have been <c>true</c> throughout. The defences
    /// against #9765 are the dual-channel environment injection, the pre-launch resolution
    /// assertion, and the structural content validation — not this flag.
    /// </remarks>
    public bool IsAssetDirectoryAbsolute { get; init; }

    /// <summary>False when updates/repairs cannot be written (read-only AppImage, system path).</summary>
    public bool IsAssetDirectoryWritable { get; init; }

    public GeoAssetInfo GeoIp { get; init; } = new() { Kind = GeoAssetKind.GeoIp, Health = GeoAssetHealth.Unknown };

    public GeoAssetInfo GeoSite { get; init; } = new() { Kind = GeoAssetKind.GeoSite, Health = GeoAssetHealth.Unknown };

    /// <summary>Where the assets were loaded from, for diagnostics.</summary>
    public string? ResolvedFrom { get; init; }

    /// <summary>True when a known-good backup generation is available for rollback.</summary>
    public bool HasBackupGeneration { get; init; }

    public DateTimeOffset InspectedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Both assets usable.</summary>
    public bool AllUsable => GeoIp.IsUsable && GeoSite.IsUsable;

    /// <summary>At least one asset usable.</summary>
    public bool AnyUsable => GeoIp.IsUsable || GeoSite.IsUsable;

    /// <summary>Routing features that may safely be emitted into the config.</summary>
    public GeoRuleAvailability Availability => GeoRuleAvailability.From(this);

    /// <summary>True when the user should be prompted to repair.</summary>
    public bool RequiresRepair => !AllUsable || !IsAssetDirectoryAbsolute;

    public IEnumerable<GeoAssetInfo> Assets
    {
        get
        {
            yield return GeoIp;
            yield return GeoSite;
        }
    }

    /// <summary>All non-fatal-but-noteworthy problems, in display order.</summary>
    public IReadOnlyList<GeoAssetInfo> ProblemAssets =>
        Assets.Where(a => !a.IsUsable).ToArray();

    /// <summary>
    /// A single error summarizing the worst problem, or <c>null</c> when everything is
    /// healthy. Used to attach a structured failure to the connect flow without
    /// aborting it.
    /// </summary>
    public MyVpnError? ToWorstError()
    {
        if (IsAssetDirectoryAbsolute == false)
        {
            return new MyVpnError(
                ErrorCodes.GeoAssetPathNotAbsolute,
                "error.geodata.path_not_absolute",
                ErrorSeverity.Critical,
                $"XRAY_LOCATION_ASSET resolved to a non-absolute value: '{AssetDirectory}'.",
                "geodata.repair");
        }

        var problems = ProblemAssets;
        if (problems.Count == 0)
        {
            return null;
        }

        var worst = problems
            .OrderByDescending(p => GeoAssetInfo.SeverityFor(p.Health))
            .First();

        return worst.ToError();
    }

    /// <summary>Creates an empty status for a single asset, used by tests and first-run.</summary>
    public static GeoDataStatus Empty(string assetDirectory, bool isAbsolute = true) => new()
    {
        AssetDirectory = assetDirectory,
        IsAssetDirectoryAbsolute = isAbsolute,
        IsAssetDirectoryWritable = false,
        ResolvedFrom = "none",
    };
}
