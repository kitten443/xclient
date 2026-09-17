using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Abstractions.Dns;

/// <summary>One resolver to configure.</summary>
public sealed record DnsServerEntry
{
    /// <summary>IP literal. Hostnames are rejected: an unresolvable resolver is a leak risk.</summary>
    public required string Address { get; init; }

    public int Port { get; init; } = 53;

    /// <summary><c>udp</c>, <c>tcp</c>, <c>tls</c> or <c>https</c>.</summary>
    public string Protocol { get; init; } = "udp";

    /// <summary>Domains this resolver is authoritative for, when split DNS is used.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Everything needed to point the host's resolver at the tunnel, as data.
/// </summary>
/// <remarks>
/// The plan records the <i>previous</i> state so it can be restored. Losing the original
/// resolver configuration is a common and very annoying failure mode: the VPN is gone but
/// DNS still points at a resolver that is no longer reachable, so the machine appears to
/// have no internet at all.
/// </remarks>
public sealed record DnsPlan
{
    public required string TunnelInterface { get; init; }

    public required IReadOnlyList<DnsServerEntry> Servers { get; init; }

    /// <summary>Domains that must bypass the tunnel resolver.</summary>
    public IReadOnlyList<string> SplitDnsDomains { get; init; } = Array.Empty<string>();

    /// <summary>Block cleartext DNS that would escape the tunnel.</summary>
    public bool BlockPlainDnsLeaks { get; init; } = true;

    public bool EnableFakeDns { get; init; }

    /// <summary>Search domains to restore afterwards.</summary>
    public IReadOnlyList<string> SearchDomains { get; init; } = Array.Empty<string>();

    /// <summary>Resolvers observed before MyVpn touched anything.</summary>
    public IReadOnlyList<string> PreviousServers { get; init; } = Array.Empty<string>();

    /// <summary>Name of the manager that owned DNS before MyVpn, e.g. <c>systemd-resolved</c>.</summary>
    public string? PreviousManager { get; init; }

    public Result Validate()
    {
        if (string.IsNullOrWhiteSpace(TunnelInterface))
        {
            return Result.Fail(ErrorCodes.DnsConfigureFailed, "error.dns.no_tunnel_interface");
        }

        foreach (var server in Servers)
        {
            if (!NetworkText.IsIpAddress(server.Address))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.DnsConfigureFailed,
                    "error.dns.server_not_ip",
                    ErrorSeverity.Error,
                    $"Resolver '{server.Address}' is not an IP literal. A resolver hostname must be "
                    + "resolved before it can be configured, and resolving it through the tunnel is "
                    + "circular."));
            }

            if (server.Port is < 1 or > 65535)
            {
                return Result.Fail(ErrorCodes.DnsConfigureFailed, "error.dns.port_range");
            }
        }

        if (Servers.Count == 0 && BlockPlainDnsLeaks)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.leak_block_without_resolver",
                ErrorSeverity.Error,
                "Plaintext DNS is set to be blocked but no resolver is configured, which would "
                + "leave the user unable to resolve any name."));
        }

        return Result.Ok();
    }
}

/// <summary>Observed DNS state, used by the leak check.</summary>
public sealed record DnsState
{
    public required IReadOnlyList<string> ActiveServers { get; init; }

    public required string? InterfaceName { get; init; }

    /// <summary>True when a resolver is reachable outside the tunnel.</summary>
    public required bool PlainDnsReachableOutsideTunnel { get; init; }

    public bool HasIpv6Resolver { get; init; }

    /// <summary>Localization keys for detected potential leaks.</summary>
    public IReadOnlyList<string> PotentialLeaks { get; init; } = Array.Empty<string>();
}

public interface IDnsConfigurator
{
    bool IsSupported { get; }

    /// <summary>
    /// Applies the plan and returns the plan that was actually applied.
    /// </summary>
    /// <remarks>
    /// The returned plan carries the state captured <i>before</i> the change, which the caller
    /// must hold in order to restore it. Returning it is the whole point: <see cref="DnsPlan"/> is
    /// immutable and <see cref="Result"/> carries no value, so an implementation that captured the
    /// prior state internally would have to expose it some other way, and the caller would have to
    /// know the concrete type. A session must be able to restore DNS through the abstraction
    /// alone.
    /// </remarks>
    Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken);

    /// <summary>Restores the configuration recorded in the plan.</summary>
    Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken);

    /// <summary>
    /// Removes every DNS override MyVpn owns, restoring the system's own resolver.
    /// </summary>
    /// <remarks>
    /// Used by emergency cleanup, where the original plan is not available. Losing a stale
    /// override matters more than preserving it: a resolver pointing at a tunnel that no longer
    /// exists makes the machine appear to have no internet at all.
    /// </remarks>
    Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken);

    Task<DnsState> InspectAsync(CancellationToken cancellationToken);
}
