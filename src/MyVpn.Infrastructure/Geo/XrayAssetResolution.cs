using MyVpn.Core.Geo;

namespace MyVpn.Infrastructure.Geo;

/// <summary>Result of mirroring Xray's own asset-directory lookup.</summary>
public sealed record AssetResolution
{
    /// <summary>The directory Xray would use, or <c>null</c> when no candidate is usable.</summary>
    public string? Directory { get; init; }

    /// <summary>Directories that were tried, in order.</summary>
    public required IReadOnlyList<string> SearchedDirectories { get; init; }

    /// <summary>Files that were missing from the chosen candidate, if any.</summary>
    public IReadOnlyList<string> MissingFiles { get; init; } = Array.Empty<string>();

    /// <summary>Which candidate index succeeded; -1 when none did.</summary>
    public int ResolvedIndex { get; init; } = -1;

    public bool Succeeded => Directory is not null;

    /// <summary>Localization key explaining the failure.</summary>
    public string? MessageKey { get; init; }

    /// <summary>Human-readable technical detail for the diagnostics bundle.</summary>
    public string? TechnicalDetail { get; init; }
}

/// <summary>
/// Mirrors Xray's own geo-asset directory lookup as a pure, testable function.
/// </summary>
/// <remarks>
/// <para>
/// This exists so MyVpn can assert, <i>before</i> launching the core, that Xray will find
/// the assets it is about to be told to use. Without it, a path mismatch surfaces only as a
/// failure from deep inside Xray — and, as upstream issue #10153 shows, sometimes as a
/// misleading <c>EOF</c> rather than a clear "file not found".
/// </para>
/// <para><b>Xray's lookup order</b>, as implemented upstream: the directory named by the
/// <c>XRAY_LOCATION_ASSET</c> environment variable; failing that, the directory containing
/// the Xray executable; and, on non-Windows platforms, the fixed system locations
/// <c>/usr/local/share/xray</c>, <c>/usr/share/xray</c> and <c>/opt/share/xray</c>. Note
/// that the published documentation says the fallback is <c>./</c> (the current working
/// directory) while the code uses the executable's directory; MyVpn follows the code,
/// because that is what actually happens.</para>
/// <para>
/// <c>XRAY_LOCATION_ASSET</c> names a <i>directory</i>, not a file. Both
/// <c>geoip.dat</c> and <c>geosite.dat</c> are read from within it.
/// </para>
/// </remarks>
public static class XrayAssetResolution
{
    /// <summary>Fixed fallback directories used on non-Windows platforms.</summary>
    public static readonly IReadOnlyList<string> UnixSystemDirectories = new[]
    {
        "/usr/local/share/xray",
        "/usr/share/xray",
        "/opt/share/xray",
    };

    /// <summary>
    /// Builds the ordered candidate list exactly as Xray would consider it.
    /// </summary>
    /// <param name="configuredDirectory">Value of <c>XRAY_LOCATION_ASSET</c>, if set.</param>
    /// <param name="executableDirectory">Directory containing the Xray binary.</param>
    /// <param name="isWindows">Whether to include the Unix system directories.</param>
    public static IReadOnlyList<string> BuildCandidateList(
        string? configuredDirectory,
        string executableDirectory,
        bool isWindows)
    {
        var candidates = new List<string>(6);

        if (!string.IsNullOrWhiteSpace(configuredDirectory))
        {
            candidates.Add(configuredDirectory);
        }

        if (!string.IsNullOrWhiteSpace(executableDirectory))
        {
            candidates.Add(executableDirectory);
        }

        if (!isWindows)
        {
            candidates.AddRange(UnixSystemDirectories);
        }

        // De-duplicate while preserving order, comparing the way the OS would.
        var seen = new HashSet<string>(isWindows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        return candidates.Where(c => seen.Add(c)).ToArray();
    }

    /// <summary>
    /// Resolves the directory Xray will actually use.
    /// </summary>
    /// <param name="candidates">Ordered candidates from <see cref="BuildCandidateList"/>.</param>
    /// <param name="fileExists">Existence predicate; injected so the logic is pure and testable.</param>
    /// <param name="requiredKinds">
    /// Assets that must be present. Both are required by default, because a routing rule
    /// referencing an absent asset makes Xray fail to build its config.
    /// </param>
    public static AssetResolution Resolve(
        IReadOnlyList<string> candidates,
        Func<string, bool> fileExists,
        IReadOnlyList<GeoAssetKind>? requiredKinds = null)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(fileExists);

        var required = requiredKinds ?? new[] { GeoAssetKind.GeoIp, GeoAssetKind.GeoSite };
        var missingFromFirst = new List<string>();

        for (var index = 0; index < candidates.Count; index++)
        {
            var candidate = candidates[index];
            var missing = required
                .Select(kind => kind.FileName())
                .Where(fileName => !fileExists(Path.Combine(candidate, fileName)))
                .ToArray();

            if (missing.Length == 0)
            {
                return new AssetResolution
                {
                    Directory = candidate,
                    SearchedDirectories = candidates,
                    ResolvedIndex = index,
                };
            }

            if (index == 0)
            {
                missingFromFirst.AddRange(missing);
            }
        }

        var searched = string.Join(", ", candidates);
        var detail = candidates.Count == 0
            ? "No candidate asset directories were available."
            : $"Searched: {searched}. Missing from the first candidate: {string.Join(", ", missingFromFirst)}.";

        return new AssetResolution
        {
            Directory = null,
            SearchedDirectories = candidates,
            MissingFiles = missingFromFirst,
            MessageKey = "error.geodata.not_found_anywhere",
            TechnicalDetail = detail,
        };
    }

    /// <summary>
    /// Compares what MyVpn intends to export with what Xray would resolve, and reports a
    /// mismatch before the core is started.
    /// </summary>
    /// <remarks>
    /// This is the pre-launch assertion that closes the issue #9765 class of defect. It is
    /// deliberately a comparison rather than a check: the interesting failure is not
    /// "nothing was found" but "the directory Xray will use is not the directory MyVpn
    /// validated", which is exactly what happens when an environment variable is dropped on
    /// the way to an elevated child process.
    /// </remarks>
    public static AssetResolution VerifyConsistency(
        string? intendedDirectory,
        string executablePath,
        Func<string, bool> fileExists,
        bool isWindows)
    {
        ArgumentNullException.ThrowIfNull(fileExists);

        var executableDirectory = string.IsNullOrWhiteSpace(executablePath)
            ? string.Empty
            : Path.GetDirectoryName(Path.GetFullPath(executablePath)) ?? string.Empty;

        var candidates = BuildCandidateList(intendedDirectory, executableDirectory, isWindows);
        var resolution = Resolve(candidates, fileExists);

        if (!resolution.Succeeded)
        {
            return resolution;
        }

        if (!string.IsNullOrWhiteSpace(intendedDirectory))
        {
            var intendedFull = Path.GetFullPath(intendedDirectory);
            var resolvedFull = Path.GetFullPath(resolution.Directory!);

            var comparison = isWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            if (!string.Equals(intendedFull, resolvedFull, comparison))
            {
                return resolution with
                {
                    MessageKey = "error.geodata.resolution_mismatch",
                    TechnicalDetail =
                        $"MyVpn intended XRAY_LOCATION_ASSET='{intendedFull}' but Xray would resolve "
                        + $"'{resolvedFull}'. This is the issue #9765 failure mode: the asset directory "
                        + "was not delivered to the child process, so Xray fell back to its own default.",
                };
            }
        }

        return resolution;
    }
}
