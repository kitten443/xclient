namespace MyVpn.Core.Geo;

/// <summary>
/// The two geo data assets Xray consumes.
/// </summary>
/// <remarks>
/// They are tracked independently on purpose. v2rayN issue #9765 and its relatives
/// are frequently caused by treating geo data as one indivisible blob: an update
/// that refreshes <c>geosite.dat</c> but fails on <c>geoip.dat</c> leaves the user
/// with a half-broken asset pair. Separate state, separate checksums, separate
/// rollback.
/// </remarks>
public enum GeoAssetKind
{
    /// <summary><c>geoip.dat</c> — IP CIDR lists, referenced as <c>geoip:xx</c>.</summary>
    GeoIp = 0,

    /// <summary><c>geosite.dat</c> — domain lists, referenced as <c>geosite:xx</c>.</summary>
    GeoSite = 1,
}

public static class GeoAssetKindExtensions
{
    /// <summary>Canonical file name exactly as Xray expects it.</summary>
    public static string FileName(this GeoAssetKind kind) => kind switch
    {
        GeoAssetKind.GeoIp => "geoip.dat",
        GeoAssetKind.GeoSite => "geosite.dat",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>Routing-rule prefix used in an Xray config (<c>geoip:</c> / <c>geosite:</c>).</summary>
    public static string RulePrefix(this GeoAssetKind kind) => kind switch
    {
        GeoAssetKind.GeoIp => "geoip",
        GeoAssetKind.GeoSite => "geosite",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>Localization key for the user-facing asset name.</summary>
    public static string DisplayNameKey(this GeoAssetKind kind) => kind switch
    {
        GeoAssetKind.GeoIp => "geodata.geoip.name",
        GeoAssetKind.GeoSite => "geodata.geosite.name",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static GeoAssetKind ParseFileName(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return Path.GetFileName(fileName).ToLowerInvariant() switch
        {
            "geoip.dat" => GeoAssetKind.GeoIp,
            "geosite.dat" => GeoAssetKind.GeoSite,
            _ => throw new ArgumentException($"Not a geo asset file name: {fileName}", nameof(fileName)),
        };
    }
}
