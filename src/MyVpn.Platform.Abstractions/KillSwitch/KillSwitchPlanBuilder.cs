using System.Net;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Abstractions.KillSwitch;

/// <summary>
/// Inputs required to build a <see cref="KillSwitchPlan"/>.
/// </summary>
/// <remarks>
/// The server appears here as a list of <i>already resolved</i> endpoints. Resolution is a
/// separate step on purpose: a Kill Switch rule can only pin an IP address, and resolving a
/// hostname after the block is armed is impossible by construction.
/// </remarks>
public sealed record KillSwitchPlanRequest
{
    public required KillSwitchMode Mode { get; init; }

    public required string Identifier { get; init; }

    public required string TunnelInterface { get; init; }

    /// <summary>Resolved server endpoints. Empty when resolution failed.</summary>
    public required IReadOnlyList<ServerEndpoint> ResolvedServerEndpoints { get; init; }

    /// <summary>Server endpoints as configured, used only to produce a better error message.</summary>
    public IReadOnlyList<ServerEndpoint> ConfiguredServerEndpoints { get; init; } = Array.Empty<ServerEndpoint>();

    /// <summary>Absolute path of the Xray executable, which must stay exempt.</summary>
    public required string CoreExecutablePath { get; init; }

    /// <summary>Resolvers that must remain reachable so name resolution does not deadlock.</summary>
    public required IReadOnlyList<string> ResolverAddresses { get; init; }

    public Ipv6Mode Ipv6 { get; init; } = Ipv6Mode.DisableWhileConnected;

    public bool AllowLan { get; init; }

    /// <summary>Additional destinations to keep reachable.</summary>
    public IReadOnlyList<CidrBlock> ExtraAllowedDestinations { get; init; } = Array.Empty<CidrBlock>();

    /// <summary>Port the core listens on for its local inbound.</summary>
    public int LocalInboundPort { get; init; } = 10808;

    public int FirewallMark { get; init; } = 0x0CA6C;

    public int RoutingTableId { get; init; } = 100;
}

/// <summary>
/// Builds a validated <see cref="KillSwitchPlan"/> from user settings and resolved state.
/// </summary>
/// <remarks>
/// Pure and side-effect free, so every branch — including the ones that must refuse to arm
/// — is unit-tested without a firewall. The builder's most important job is knowing when to
/// say no: arming a default-drop ruleset without a pinned server address would cut the user
/// off from the tunnel itself.
/// </remarks>
public static class KillSwitchPlanBuilder
{
    /// <summary>Builds the plan, or explains why a safe plan cannot be produced.</summary>
    public static Result<KillSwitchPlan> Build(KillSwitchPlanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Mode == KillSwitchMode.Disabled)
        {
            return Result<KillSwitchPlan>.Ok(new KillSwitchPlan
            {
                Identifier = request.Identifier,
                Mode = KillSwitchMode.Disabled,
                TunnelInterface = request.TunnelInterface,
                AllowedEndpoints = Array.Empty<AllowedEndpoint>(),
                AllowedApplications = Array.Empty<string>(),
                AllowedDestinations = Array.Empty<AllowedEndpoint>(),
                FirewallMark = request.FirewallMark,
                RoutingTableId = request.RoutingTableId,
            });
        }

        if (request.ResolvedServerEndpoints.Count == 0)
        {
            // Distinguish "the profile has no server" from "the server is a name we could not
            // resolve". The second case is actionable and common on a fresh boot.
            var unresolved = request.ConfiguredServerEndpoints
                .Where(e => !e.IsIpLiteral)
                .Select(e => e.Address)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (unresolved.Length > 0)
            {
                return Result<KillSwitchPlan>.Fail(new MyVpnError(
                    ErrorCodes.KillSwitchApplyFailed,
                    "error.killswitch.server_not_resolved",
                    ErrorSeverity.Error,
                    $"Cannot arm the Kill Switch: the server name(s) {string.Join(", ", unresolved)} "
                    + "did not resolve to an address, and firewall rules can only pin IP addresses.")
                    .WithArg("hosts", string.Join(", ", unresolved)));
            }

            return Result<KillSwitchPlan>.Fail(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.no_server_endpoint",
                ErrorSeverity.Error,
                "No resolved server endpoint is available."));
        }

        var allowedEndpoints = new List<AllowedEndpoint>();
        foreach (var endpoint in request.ResolvedServerEndpoints)
        {
            if (!IPAddress.TryParse(endpoint.Address, out _))
            {
                return Result<KillSwitchPlan>.Fail(new MyVpnError(
                    ErrorCodes.KillSwitchApplyFailed,
                    "error.killswitch.server_not_resolved",
                    ErrorSeverity.Error,
                    $"Endpoint '{endpoint.Address}' is not an IP literal.")
                    .WithArg("hosts", endpoint.Address));
            }

            allowedEndpoints.Add(AllowedEndpoint.FromEndpoint(endpoint, "killswitch.reason.vpn_server"));
        }

        // Resolvers are exempt so that name resolution keeps working. Note that this is an
        // exemption for the *configured* resolvers only; a rogue resolver is still blocked.
        var allowedDestinations = new List<AllowedEndpoint>();
        foreach (var resolver in request.ResolverAddresses)
        {
            if (!IPAddress.TryParse(resolver, out var address))
            {
                // A non-literal resolver cannot be pinned; skip it rather than fail the whole
                // plan, but it will not be reachable, which the DNS plan validation catches.
                continue;
            }

            var prefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            allowedDestinations.Add(new AllowedEndpoint
            {
                Destination = new CidrBlock(address, prefix),
                Port = 53,
                Network = "tcp,udp",
                ReasonKey = "killswitch.reason.resolver",
            });
        }

        foreach (var extra in request.ExtraAllowedDestinations)
        {
            allowedDestinations.Add(new AllowedEndpoint
            {
                Destination = extra,
                Port = 0, // 0 means "any port"
                Network = "tcp,udp",
                ReasonKey = "killswitch.reason.user_exemption",
            });
        }

        var plan = new KillSwitchPlan
        {
            Identifier = request.Identifier,
            Mode = request.Mode,
            TunnelInterface = request.TunnelInterface,
            AllowedEndpoints = allowedEndpoints,
            AllowedApplications = new[] { request.CoreExecutablePath },
            AllowedDestinations = allowedDestinations,

            // Disabling IPv6 while connected is the only mode that is leak-free on every
            // platform, so every other mode is an explicit user choice.
            BlockIpv6 = request.Ipv6 != Ipv6Mode.FullTunnel,

            AllowLan = request.AllowLan,
            AllowLoopback = true,
            AllowDhcp = true,
            AllowIcmp = true,
            FirewallMark = request.FirewallMark,
            RoutingTableId = request.RoutingTableId,
        };

        var validation = plan.Validate();
        return validation.IsSuccess
            ? Result<KillSwitchPlan>.Ok(plan)
            : Result<KillSwitchPlan>.Fail(validation.Error!);
    }
}
