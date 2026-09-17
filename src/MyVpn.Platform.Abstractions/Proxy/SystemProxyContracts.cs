using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Abstractions.Proxy;

/// <summary>Which proxy protocols the local inbound should expose.</summary>
public sealed record SystemProxyPlan
{
    /// <summary>Local SOCKS port.</summary>
    public int SocksPort { get; init; } = 10808;

    /// <summary>Local HTTP port.</summary>
    public int HttpPort { get; init; } = 10809;

    public bool EnableSocks { get; init; } = true;

    public bool EnableHttp { get; init; } = true;

    public bool UsePac { get; init; }

    /// <summary>PAC URL or file path, when <see cref="UsePac"/> is set.</summary>
    public string? PacUrl { get; init; }

    /// <summary>Hosts that bypass the proxy.</summary>
    public IReadOnlyList<string> BypassDomains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<CidrBlock> BypassNetworks { get; init; } = Array.Empty<CidrBlock>();

    /// <summary>Interfaces to configure; empty means "the primary service".</summary>
    public IReadOnlyList<string> TargetInterfaces { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Settings captured before MyVpn changed anything, so they can be restored exactly.
    /// Losing the user's original proxy configuration is a real support burden.
    /// </summary>
    public SystemProxySnapshot? Previous { get; init; }

    public Result Validate()
    {
        if (!EnableSocks && !EnableHttp)
        {
            return Result.Fail(ErrorCodes.SystemProxySetFailed, "error.proxy.no_listener");
        }

        if (EnableSocks && SocksPort is < 1024 or > 65535)
        {
            return Result.Fail(ErrorCodes.SystemProxySetFailed, "error.proxy.port_range");
        }

        if (EnableHttp && HttpPort is < 1024 or > 65535)
        {
            return Result.Fail(ErrorCodes.SystemProxySetFailed, "error.proxy.port_range");
        }

        if (UsePac && !string.IsNullOrWhiteSpace(PacUrl)
            && !UrlSafety.IsSafeHttpUrl(PacUrl, allowInsecureHttp: true, out _)
            && !PacUrl.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            return Result.Fail(ErrorCodes.SystemProxySetFailed, "error.proxy.pac_url_invalid");
        }

        return Result.Ok();
    }
}

/// <summary>A snapshot of the platform's proxy configuration.</summary>
/// <remarks>
/// <see cref="Mode"/> is carried separately from <see cref="Enabled"/> because the platforms
/// distinguish "off", "manual" and "automatic" — GNOME stores exactly that triad. Collapsing it
/// into a boolean would make restoring a user's PAC configuration impossible to do faithfully,
/// and a wrong restore leaves the machine pointing at a dead proxy after the VPN exits.
/// </remarks>
public sealed record SystemProxySnapshot
{
    /// <summary>Platform-native mode string: <c>none</c>, <c>manual</c> or <c>auto</c>.</summary>
    public string? Mode { get; init; }

    public bool Enabled { get; init; }

    public string? PacUrl { get; init; }

    public string? HttpProxy { get; init; }

    public string? HttpsProxy { get; init; }

    public string? SocksProxy { get; init; }

    public string? BypassList { get; init; }
}

/// <summary>Observed system proxy state.</summary>
public sealed record SystemProxyState
{
    public required bool IsConfigured { get; init; }

    public string? ActiveProxy { get; init; }

    public string? PacUrl { get; init; }

    public bool PointsAtMyVpn { get; init; }
}

public interface ISystemProxy
{
    bool IsSupported { get; }

    /// <summary>Reads the current configuration so it can be restored later.</summary>
    Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken);

    Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken);

    Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken);

    Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken);
}
