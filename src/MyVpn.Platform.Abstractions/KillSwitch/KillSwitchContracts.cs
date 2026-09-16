using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Abstractions.KillSwitch;

/// <summary>An endpoint that must stay reachable while the Kill Switch is armed.</summary>
/// <remarks>
/// The VPN server itself is the critical case: if outbound traffic to it is blocked, the
/// tunnel can never come up, and a fail-closed Kill Switch becomes a total network
/// outage. Every server IP must therefore be allow-listed *before* the block is armed.
/// </remarks>
public sealed record AllowedEndpoint
{
    public required CidrBlock Destination { get; init; }

    public required int Port { get; init; }

    /// <summary><c>tcp</c>, <c>udp</c> or <c>tcp,udp</c>.</summary>
    public string Network { get; init; } = "tcp,udp";

    /// <summary>Localization key explaining why this endpoint is exempt.</summary>
    public required string ReasonKey { get; init; }

    public static AllowedEndpoint FromEndpoint(ServerEndpoint endpoint, string reasonKey)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        if (!System.Net.IPAddress.TryParse(endpoint.Address, out var address))
        {
            throw new ArgumentException(
                $"Kill Switch allow-listing requires a resolved IP literal, got '{endpoint.Address}'.",
                nameof(endpoint));
        }

        return new AllowedEndpoint
        {
            Destination = new CidrBlock(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128),
            Port = endpoint.Port,
            ReasonKey = reasonKey,
        };
    }
}

/// <summary>
/// A complete, platform-neutral description of the firewall state needed to protect a
/// session.
/// </summary>
/// <remarks>
/// This is a value object, not a set of commands. Each platform renders it into its own
/// dialect (nftables text, WFP filter descriptors, a PF anchor) and each renderer is a
/// pure function, which is what makes the firewall logic unit-testable on a machine with
/// no privileges.
/// </remarks>
public sealed record KillSwitchPlan
{
    /// <summary>Identifier used for the platform's own table/anchor/sublayer name.</summary>
    public required string Identifier { get; init; }

    public required KillSwitchMode Mode { get; init; }

    /// <summary>Name of the tunnel interface, e.g. <c>myvpn0</c>.</summary>
    public required string TunnelInterface { get; init; }

    /// <summary>Server endpoints that must remain reachable.</summary>
    public required IReadOnlyList<AllowedEndpoint> AllowedEndpoints { get; init; }

    /// <summary>Absolute paths of processes allowed to send traffic outside the tunnel.</summary>
    public required IReadOnlyList<string> AllowedApplications { get; init; }

    /// <summary>Destinations that stay reachable regardless of the tunnel (e.g. resolvers).</summary>
    public required IReadOnlyList<AllowedEndpoint> AllowedDestinations { get; init; }

    /// <summary>Extra destinations to block explicitly.</summary>
    public IReadOnlyList<CidrBlock> BlockedDestinations { get; init; } = Array.Empty<CidrBlock>();

    /// <summary>
    /// Block IPv6 entirely. Defaults to true: an IPv6 leak is the single most common way a
    /// Kill Switch fails open, because the tunnel frequently carries only IPv4.
    /// </summary>
    public bool BlockIpv6 { get; init; } = true;

    /// <summary>Keep local network destinations reachable directly.</summary>
    public bool AllowLan { get; init; }

    /// <summary>Keep the loopback interface usable (needed for the local proxy inbound).</summary>
    public bool AllowLoopback { get; init; } = true;

    /// <summary>Allow DHCP/NDP so the machine keeps its own address.</summary>
    public bool AllowDhcp { get; init; } = true;

    /// <summary>Allow ICMP so path-MTU discovery and diagnostics keep working.</summary>
    public bool AllowIcmp { get; init; } = true;

    /// <summary>Firewall mark used to steer the tunnel's own traffic (Linux policy routing).</summary>
    public int FirewallMark { get; init; } = 0x0CA6C;

    /// <summary>Routing table id used with <see cref="FirewallMark"/>.</summary>
    public int RoutingTableId { get; init; } = 100;

    /// <summary>
    /// Validates that the plan is safe to arm. A plan that would blackhole the tunnel is
    /// rejected rather than applied.
    /// </summary>
    public Result Validate()
    {
        if (Mode == KillSwitchMode.Disabled)
        {
            return Result.Ok();
        }

        if (string.IsNullOrWhiteSpace(TunnelInterface))
        {
            return Result.Fail(ErrorCodes.KillSwitchApplyFailed, "error.killswitch.no_tunnel_interface");
        }

        if (AllowedEndpoints.Count == 0)
        {
            // The decisive safety rule: without at least one allow-listed server endpoint,
            // arming a default-drop ruleset would cut off the tunnel itself and leave the
            // user with no network at all. Refuse, and let the caller explain.
            return Result.Fail(ErrorCodes.KillSwitchApplyFailed, "error.killswitch.no_server_endpoint");
        }

        if (AllowedApplications.Count == 0)
        {
            return Result.Fail(ErrorCodes.KillSwitchApplyFailed, "error.killswitch.no_allowed_application");
        }

        foreach (var application in AllowedApplications)
        {
            if (!Path.IsPathRooted(application))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.KillSwitchApplyFailed,
                    "error.killswitch.application_path_not_absolute",
                    ErrorSeverity.Error,
                    $"Allowed application path is not absolute: '{application}'. A relative path would "
                    + "let an attacker satisfy the exemption by placing a same-named binary elsewhere."));
            }

            if (application.Contains("..", StringComparison.Ordinal))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.KillSwitchApplyFailed,
                    "error.killswitch.application_path_traversal",
                    ErrorSeverity.Error,
                    $"Allowed application path contains '..': '{application}'."));
            }
        }

        if (FirewallMark is < 1 or > 0x7FFFFFFF)
        {
            return Result.Fail(ErrorCodes.KillSwitchApplyFailed, "error.killswitch.invalid_mark");
        }

        return Result.Ok();
    }

    /// <summary>Localization keys describing what this plan will do, for the confirmation UI.</summary>
    public IReadOnlyList<string> DescribeEffects()
    {
        var effects = new List<string>();

        if (Mode == KillSwitchMode.Disabled)
        {
            effects.Add("killswitch.effect.none");
            return effects;
        }

        effects.Add("killswitch.effect.block_all_outside_tunnel");

        if (BlockIpv6)
        {
            effects.Add("killswitch.effect.block_ipv6");
        }

        if (!AllowLan)
        {
            effects.Add("killswitch.effect.block_lan");
        }

        if (AllowedApplications.Count > 0)
        {
            effects.Add("killswitch.effect.allow_core_only");
        }

        if (Mode == KillSwitchMode.AlwaysOn)
        {
            effects.Add("killswitch.effect.persist_after_reboot");
        }

        return effects;
    }
}

/// <summary>Observed state of the platform firewall with respect to MyVpn's own rules.</summary>
public sealed record KillSwitchState
{
    public required bool IsArmed { get; init; }

    /// <summary>True when MyVpn's rules exist but do not match the desired plan.</summary>
    public required bool IsDrifted { get; init; }

    /// <summary>Rules present in the platform that MyVpn no longer owns.</summary>
    public IReadOnlyList<string> OrphanedRules { get; init; } = Array.Empty<string>();

    public string? MechanismName { get; init; }

    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;

    public static KillSwitchState Disarmed { get; } = new() { IsArmed = false, IsDrifted = false };
}

/// <summary>Result of applying or removing a plan.</summary>
public sealed record KillSwitchApplyResult
{
    public required bool Succeeded { get; init; }

    public MyVpnError? Error { get; init; }

    /// <summary>Raw platform output, kept for diagnostics (never shown verbatim to the user).</summary>
    public string? PlatformOutput { get; init; }

    public static KillSwitchApplyResult Ok(string? output = null) =>
        new() { Succeeded = true, PlatformOutput = output };

    public static KillSwitchApplyResult Failed(MyVpnError error, string? output = null) =>
        new() { Succeeded = false, Error = error, PlatformOutput = output };
}

/// <summary>Applies and removes the Kill Switch on the host platform.</summary>
/// <remarks>
/// Implementations must be idempotent: applying an already-applied plan succeeds, and
/// removing a non-existent plan succeeds. Crash recovery depends on this, because after a
/// hard kill the service cannot know how far the previous attempt got.
/// </remarks>
public interface IKillSwitch
{
    /// <summary>Human-readable mechanism in use, e.g. "nftables".</summary>
    string MechanismName { get; }

    /// <summary>True when this mechanism can enforce a fail-closed rule set.</summary>
    bool IsSupported { get; }

    Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken);

    Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Reads back the live platform state and compares it with <paramref name="expected"/>.
    /// </summary>
    /// <remarks>
    /// This is the verification step that distinguishes "we issued the command" from "the
    /// rules are actually in force". A firewall helper that trusts its own exit code will
    /// eventually report success while the platform silently dropped the rules.
    /// </remarks>
    Task<KillSwitchState> InspectAsync(KillSwitchPlan? expected, CancellationToken cancellationToken);
}
