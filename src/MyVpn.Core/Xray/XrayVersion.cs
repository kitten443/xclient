using System.Globalization;
using MyVpn.Core.Results;

namespace MyVpn.Core.Xray;

/// <summary>
/// A parsed Xray-core version, comparable and total-ordered.
/// </summary>
/// <remarks>
/// Xray's <c>version</c> command prints a line such as
/// <c>Xray 26.9.9 (go1.24.0 linux/amd64)</c>, but older builds and third-party
/// repackages use <c>Xray 1.8.24 (...) </c> or a bare version string. The parser
/// therefore scans for the first token that looks like <c>major.minor.patch</c>
/// instead of assuming a fixed prefix.
/// </remarks>
public readonly record struct XrayVersion(int Major, int Minor, int Patch)
    : IComparable<XrayVersion>
{
    public static readonly XrayVersion Unknown = new(0, 0, 0);

    public bool IsKnown => this != Unknown;

    /// <summary>Parses the output of <c>xray version</c>.</summary>
    public static bool TryParse(string? text, out XrayVersion version)
    {
        version = Unknown;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        // Scan whitespace- and punctuation-separated tokens for the first x.y.z.
        var token = new System.Text.StringBuilder(16);

        foreach (var c in text)
        {
            if (char.IsAsciiDigit(c) || c == '.')
            {
                token.Append(c);
                continue;
            }

            if (TryParseToken(token.ToString(), out version))
            {
                return true;
            }

            token.Clear();

            // Do not keep scanning past the first line's version area; the rest of the
            // output contains Go and OS versions that must not be mistaken for it.
            if (c == '\n')
            {
                break;
            }
        }

        return TryParseToken(token.ToString(), out version);
    }

    private static bool TryParseToken(string token, out XrayVersion version)
    {
        version = Unknown;

        if (token.Length == 0)
        {
            return false;
        }

        // Trim a trailing dot produced by "26.9.9." at end of a sentence.
        token = token.TrimEnd('.');

        var parts = token.Split('.');
        if (parts.Length < 2 || parts.Length > 4)
        {
            return false;
        }

        var numbers = new int[3];
        for (var i = 0; i < parts.Length && i < 3; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
            {
                return false;
            }
        }

        // Require at least major.minor to be present and non-degenerate; this is what
        // rejects the "1" in "go1.24.0" being read as a version on its own.
        if (token.Length < 3)
        {
            return false;
        }

        version = new XrayVersion(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    public static XrayVersion Parse(string text) =>
        TryParse(text, out var version)
            ? version
            : throw new FormatException($"Cannot parse an Xray version from '{text}'.");

    public int CompareTo(XrayVersion other)
    {
        var major = Major.CompareTo(other.Major);
        if (major != 0)
        {
            return major;
        }

        var minor = Minor.CompareTo(other.Minor);
        return minor != 0 ? minor : Patch.CompareTo(other.Patch);
    }

    public static bool operator <(XrayVersion left, XrayVersion right) => left.CompareTo(right) < 0;

    public static bool operator <=(XrayVersion left, XrayVersion right) => left.CompareTo(right) <= 0;

    public static bool operator >(XrayVersion left, XrayVersion right) => left.CompareTo(right) > 0;

    public static bool operator >=(XrayVersion left, XrayVersion right) => left.CompareTo(right) >= 0;

    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}");
}

/// <summary>How a discovered Xray version relates to what MyVpn needs.</summary>
public sealed record XrayVersionSupport
{
    public required XrayVersion Version { get; init; }

    /// <summary>Native TUN inbound is compiled in and its schema is usable.</summary>
    public required bool TunSupported { get; init; }

    /// <summary>Version is at or above the recommended baseline.</summary>
    public required bool IsRecommended { get; init; }

    /// <summary>Known-broken release that must be rejected outright.</summary>
    public required bool IsKnownBroken { get; init; }

    /// <summary>Error code when not usable, otherwise <c>null</c>.</summary>
    public string? ErrorCode { get; init; }

    /// <summary>Localization key explaining the problem.</summary>
    public string? MessageKey { get; init; }

    /// <summary>Localization key for a suggested fix.</summary>
    public string? RemediationKey { get; init; }

    public bool IsUsable => TunSupported && !IsKnownBroken;

    public Result ToResult() =>
        IsUsable
            ? Result.Ok()
            : Result.Fail(new MyVpnError(
                ErrorCode ?? ErrorCodes.XrayVersionUnsupported,
                MessageKey ?? "error.xray.version_unsupported",
                ErrorSeverity.Error,
                $"Detected Xray {Version}; TUN requires >= {XrayVersionPolicy.MinimumForTun}.",
                RemediationKey ?? "xray.update"));
}

/// <summary>
/// The Xray-core version requirements MyVpn enforces.
/// </summary>
/// <remarks>
/// <para>
/// These bounds are not guesses. They were derived from the upstream repository and
/// re-verified directly against the primary source:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>proxy/tun/config.proto</c> returns HTTP 404 at tag <c>v25.12.8</c> and HTTP 200
/// at <c>v26.1.13</c>, which is when the native TUN inbound first appeared.
/// </description></item>
/// <item><description>
/// At <c>v26.4.13</c> the field is declared <c>repeated uint32 MTU = 2;</c> while
/// <c>proxy/tun/tun_linux.go</c> reads <c>options.MTU[0]</c>; a scalar
/// <c>"mtu": 1500</c> is therefore invalid on that release. At <c>v26.4.15</c> it is
/// back to <c>uint32 MTU = 2;</c>. This is why <c>v26.4.13</c> is rejected by exact
/// version rather than by a range.
/// </description></item>
/// <item><description>
/// The JSON field names used by the config builder come from the <c>json</c> struct
/// tags in <c>infra/conf/tun.go</c>: <c>name</c>, <c>desc</c>, <c>mtu</c>,
/// <c>gateway</c>, <c>dns</c>, <c>userLevel</c>, <c>autoSystemRoutingTable</c>,
/// <c>autoOutboundsInterface</c>. Fields such as <c>address</c>, <c>autoRoute</c>,
/// <c>strictRoute</c> and <c>sniffingOverride</c> do not exist on the TUN inbound and
/// emitting them produces a config Xray rejects.
/// </description></item>
/// </list>
/// </remarks>
public static class XrayVersionPolicy
{
    /// <summary>First release with a native TUN inbound at all.</summary>
    public static readonly XrayVersion FirstWithTun = new(26, 1, 13);

    /// <summary>
    /// Oldest release whose TUN schema MyVpn targets. Below this, the CLI contract
    /// differs from what we generate.
    /// </summary>
    public static readonly XrayVersion MinimumForTun = new(26, 4, 15);

    /// <summary>Version MyVpn is developed and tested against.</summary>
    public static readonly XrayVersion Recommended = new(26, 9, 9);

    /// <summary>
    /// Releases that must never be used for TUN even though they fall inside the
    /// supported range.
    /// </summary>
    public static readonly IReadOnlyList<XrayVersion> KnownBroken = new[]
    {
        // `repeated uint32 MTU` regression: scalar mtu is rejected by the config loader.
        new XrayVersion(26, 4, 13),
    };

    /// <summary>Evaluates a version against the policy.</summary>
    public static XrayVersionSupport Evaluate(XrayVersion version, bool tunRequired = true)
    {
        if (!version.IsKnown)
        {
            return new XrayVersionSupport
            {
                Version = version,
                TunSupported = false,
                IsRecommended = false,
                IsKnownBroken = false,
                ErrorCode = ErrorCodes.XrayVersionProbeFailed,
                MessageKey = "error.xray.version_unknown",
                RemediationKey = "xray.select_binary",
            };
        }

        if (KnownBroken.Contains(version))
        {
            return new XrayVersionSupport
            {
                Version = version,
                TunSupported = false,
                IsRecommended = false,
                IsKnownBroken = true,
                ErrorCode = ErrorCodes.XrayVersionUnsupported,
                MessageKey = "error.xray.version_known_broken",
                RemediationKey = "xray.update",
            };
        }

        if (tunRequired && version < MinimumForTun)
        {
            var hadTun = version >= FirstWithTun;

            return new XrayVersionSupport
            {
                Version = version,
                TunSupported = false,
                IsRecommended = false,
                IsKnownBroken = false,
                ErrorCode = ErrorCodes.XrayVersionUnsupported,
                MessageKey = hadTun
                    ? "error.xray.version_tun_schema_too_old"
                    : "error.xray.version_no_tun_support",
                RemediationKey = "xray.update",
            };
        }

        return new XrayVersionSupport
        {
            Version = version,
            TunSupported = true,
            IsRecommended = version >= Recommended,
            IsKnownBroken = false,
        };
    }
}
