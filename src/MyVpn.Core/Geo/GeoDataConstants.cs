namespace MyVpn.Core.Geo;

/// <summary>Names Xray uses to locate geo data.</summary>
public static class GeoDataConstants
{
    /// <summary>
    /// Environment variable Xray reads to find the directory that holds
    /// <c>geoip.dat</c> and <c>geosite.dat</c>.
    /// </summary>
    /// <remarks>
    /// MyVpn always sets this explicitly on the spawned Xray process, with an
    /// absolute path. Relying on Xray's default (the executable's own directory) is
    /// the second half of the issue #9765 failure mode: it breaks as soon as the
    /// binary and the assets are not co-located, which is exactly what happens in a
    /// macOS app bundle, a read-only AppImage mount or an rpm/deb install that puts
    /// assets under <c>/usr/share</c>.
    /// </remarks>
    public const string AssetLocationEnvironmentVariable = "XRAY_LOCATION_ASSET";

    /// <summary>Directory name used inside the MyVpn state directory.</summary>
    public const string DefaultAssetDirectoryName = "geodata";

    /// <summary>Sub-directory holding the previous known-good generation.</summary>
    public const string BackupDirectoryName = "geodata-backup";

    /// <summary>Suffix for in-progress downloads, kept on the same filesystem for atomic rename.</summary>
    public const string TemporaryFileSuffix = ".download";
}

/// <summary>
/// Availability of geo-dependent routing features, derived from
/// <see cref="GeoDataStatus"/>.
/// </summary>
/// <remarks>
/// This type is the mechanism that satisfies "do not break the connection when geo
/// data is corrupt". The config builder never emits a <c>geoip:</c>/<c>geosite:</c>
/// rule unless the corresponding asset is known-good; when it is not, the builder
/// substitutes an explicit fallback rule set and the UI shows a repair prompt. The
/// user stays connected instead of facing a core that refuses to start.
/// </remarks>
public readonly record struct GeoRuleAvailability(bool GeoIpAvailable, bool GeoSiteAvailable)
{
    /// <summary>Neither asset usable — geo rules must be omitted entirely.</summary>
    public static GeoRuleAvailability None => new(false, false);

    public static GeoRuleAvailability From(GeoDataStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        return new GeoRuleAvailability(status.GeoIp.IsUsable, status.GeoSite.IsUsable);
    }

    public bool CanUse(GeoAssetKind kind) => kind switch
    {
        GeoAssetKind.GeoIp => GeoIpAvailable,
        GeoAssetKind.GeoSite => GeoSiteAvailable,
        _ => false,
    };

    /// <summary>True when at least one geo asset can be referenced.</summary>
    public bool Any => GeoIpAvailable || GeoSiteAvailable;

    /// <summary>True when every geo asset is available.</summary>
    public bool All => GeoIpAvailable && GeoSiteAvailable;
}
