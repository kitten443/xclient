using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Abstractions.Routing;

/// <summary>A single route that must exist for the tunnel to work.</summary>
public sealed record RouteEntry
{
    public required CidrBlock Destination { get; init; }

    /// <summary>Gateway address, or <c>null</c> for an on-link route.</summary>
    public string? Gateway { get; init; }

    /// <summary>Outgoing interface name.</summary>
    public required string Interface { get; init; }

    /// <summary>Route metric; lower wins.</summary>
    public int Metric { get; init; } = 1;

    /// <summary>Localization key explaining why the route exists.</summary>
    public required string ReasonKey { get; init; }

    /// <summary>
    /// True when this route must be installed even if it displaces a pre-existing route,
    /// and the displaced route must be restored on teardown.
    /// </summary>
    public bool DisplacesDefaultRoute { get; init; }

    public override string ToString() =>
        Gateway is null
            ? $"{Destination} dev {Interface} metric {Metric}"
            : $"{Destination} via {Gateway} dev {Interface} metric {Metric}";
}

/// <summary>
/// The complete routing state MyVpn needs, as data.
/// </summary>
/// <remarks>
/// <para>
/// Split into <see cref="TunnelRoutes"/> (what must be installed to carry traffic into
/// the tunnel) and <see cref="BypassRoutes"/> (uplink host routes that keep the core's own
/// connection to the server off the tunnel, preventing a routing loop).
/// </para>
/// <para>
/// <see cref="BypassRoutes"/> is not optional. Without a host route to the server via the
/// original gateway, the tunnel's own packets are routed back into the tunnel: the classic
/// loop that presents as "connects, then immediately stalls".
/// </para>
/// </remarks>
public sealed record RoutePlan
{
    public required string TunnelInterface { get; init; }

    public required IReadOnlyList<RouteEntry> TunnelRoutes { get; init; }

    public required IReadOnlyList<RouteEntry> BypassRoutes { get; init; }

    /// <summary>Routes excluded from the tunnel even when the default prefix is captured.</summary>
    public IReadOnlyList<CidrBlock> ExcludedDestinations { get; init; } = Array.Empty<CidrBlock>();

    /// <summary>Interface used for the tunnel's own uplink traffic.</summary>
    public string? PhysicalInterface { get; init; }

    public Result Validate()
    {
        if (string.IsNullOrWhiteSpace(TunnelInterface))
        {
            return Result.Fail(ErrorCodes.RouteAddFailed, "error.route.no_tunnel_interface");
        }

        if (TunnelRoutes.Count == 0)
        {
            return Result.Fail(ErrorCodes.RouteAddFailed, "error.route.no_tunnel_routes");
        }

        // Fail-closed check: a full-tunnel plan with no bypass route would loop.
        var capturesDefault = TunnelRoutes.Any(r => r.Destination.PrefixLength == 0);
        if (capturesDefault && BypassRoutes.Count == 0)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.RouteAddFailed,
                "error.route.missing_bypass_route",
                ErrorSeverity.Error,
                "The plan captures the default route but installs no uplink host route, which "
                + "would route the core's own connection to the server back into the tunnel."));
        }

        foreach (var route in TunnelRoutes.Concat(BypassRoutes))
        {
            if (route.Gateway is not null && !NetworkText.IsIpAddress(route.Gateway))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.RouteAddFailed,
                    "error.route.gateway_not_ip",
                    ErrorSeverity.Error,
                    $"Gateway '{route.Gateway}' is not an IP literal."));
            }
        }

        return Result.Ok();
    }
}

/// <summary>Current routing state as observed on the host.</summary>
public sealed record RouteState
{
    public required bool TunnelRoutesPresent { get; init; }

    public required bool BypassRoutesPresent { get; init; }

    /// <summary>A default route that MyVpn displaced and must restore.</summary>
    public string? DisplacedDefaultRoute { get; init; }

    public IReadOnlyList<string> OrphanedRoutes { get; init; } = Array.Empty<string>();
}

public interface IRouteManager
{
    bool IsSupported { get; }

    Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken);

    Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken);

    Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken);

    /// <summary>Best-effort discovery of the current default interface and gateway.</summary>
    Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken);
}

/// <summary>The host's real uplink, needed to keep the core's own traffic off the tunnel.</summary>
public sealed record PhysicalUplink(string InterfaceName, string? GatewayAddress, bool IsIpv6 = false);
