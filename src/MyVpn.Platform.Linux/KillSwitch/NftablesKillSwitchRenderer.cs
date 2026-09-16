using System.Globalization;
using System.Text;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Platform.Linux.KillSwitch;

/// <summary>
/// Renders a <see cref="KillSwitchPlan"/> into an nftables ruleset.
/// </summary>
/// <remarks>
/// <para>
/// Pure function: no process execution, no file system. That is deliberate, because it
/// makes the firewall logic testable without privileges by asserting on the generated text.
/// </para>
/// <para><b>How the output is actually validated.</b> There is a widespread belief that
/// <c>nft --check</c> works unprivileged. It does <i>not</i>: on nftables 1.0.2, even
/// <c>nft -c -f file</c> opens an nfnetlink socket and fails with
/// <c>Operation not permitted (you must be root)</c> when the process lacks
/// <c>CAP_NET_ADMIN</c>. The verification that <i>does</i> work unprivileged is to enter a
/// throwaway user+network namespace, which grants the needed capability inside an isolated
/// netns and touches nothing on the host:</para>
/// <code>
/// unshare -rn nft -c -f ruleset.nft          # syntax
/// unshare -rn nft -f ruleset.nft             # actually install, in the netns only
/// </code>
/// <para>
/// That path is exercised by <c>NftablesKillSwitchRendererTests</c> and is the reason the
/// tests are able to prove the ruleset loads rather than merely parses.
/// </para>
/// <para><b>Transaction shape.</b> The script opens with the idempotent idiom</para>
/// <code>
/// table inet myvpn_ks
/// delete table inet myvpn_ks
/// table inet myvpn_ks { ... }
/// </code>
/// <para>
/// The bare <c>table</c> line creates the table if it is missing, so the following
/// <c>delete</c> never fails, and the whole file is applied as a single atomic
/// transaction. The alternative, <c>destroy table</c>, is documented in newer nftables
/// manuals but is <i>rejected</i> by the nftables 1.0.x shipped on current LTS
/// distributions, so it must not be used. Applying the replacement as one transaction also
/// matters for security: it means there is no window in which the old rules have been
/// deleted and the new ones have not yet been added.
/// </para>
/// <para><b>Chain priority.</b> The chains run at priority 100, i.e. after the standard
/// <c>filter</c> chains at priority 0. In nftables a terminal verdict is final and cannot
/// be reversed by a later chain, so running last means our default-deny verdict has the
/// last word while an accept we emit cannot resurrect traffic another chain already
/// dropped. That asymmetry is exactly the fail-closed direction we want.</para>
/// </remarks>
public static class NftablesKillSwitchRenderer
{
    /// <summary>Table name, namespaced so it can never collide with a distribution ruleset.</summary>
    public const string TableName = "myvpn_ks";

    private const string CommentPrefix = "myvpn:";

    /// <summary>Hook priority; positive so the chain runs after the standard filter chains.</summary>
    private const int HookPriority = 100;

    /// <summary>Default interface name used when the plan carries none.</summary>
    public const string DefaultInterfaceName = "myvpn0";

    /// <summary>
    /// Renders the full ruleset that installs the Kill Switch.
    /// </summary>
    public static string RenderInstall(KillSwitchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (plan.Mode == KillSwitchMode.Disabled)
        {
            return RenderRemove();
        }

        var builder = new StringBuilder(4096);

        builder.AppendLine("# MyVpn Kill Switch — generated file, do not edit by hand.");
        builder.AppendLine("# Source of truth: KillSwitchPlan; see ADR-0006.");
        builder.AppendLine(CultureInfo.InvariantCulture, $"# mode: {plan.Mode}");

        // Idempotent, atomic replacement.
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"delete table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName} {{");

        AppendOutputChain(builder, plan);
        builder.AppendLine();
        AppendInputChain(builder, plan);
        builder.AppendLine();
        AppendForwardChain(builder);

        builder.AppendLine("}");
        return builder.ToString();
    }

    /// <summary>Renders the removal script; safe to run when nothing is installed.</summary>
    public static string RenderRemove()
    {
        var builder = new StringBuilder(256);
        builder.AppendLine("# MyVpn Kill Switch — teardown, idempotent.");
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"delete table inet {TableName}");
        return builder.ToString();
    }

    /// <summary>Renders a read-only status query used by verification.</summary>
    public static string RenderInspect() =>
        string.Create(CultureInfo.InvariantCulture, $"list table inet {TableName}") + "\n";

    private static void AppendOutputChain(StringBuilder builder, KillSwitchPlan plan)
    {
        builder.AppendLine("  chain output {");
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    type filter hook output priority {HookPriority}; policy drop;");

        // 1. Loopback first: the local SOCKS/HTTP inbound and inter-process traffic depend
        //    on it, and it cannot leak to the network.
        if (plan.AllowLoopback)
        {
            builder.AppendLine("    oifname \"lo\" accept comment \"myvpn: loopback\"");
        }

        // 2. IPv6 is blocked before the tunnel accept, because "disable IPv6 while
        //    connected" means exactly that, including inside the tunnel. Leaving it after
        //    the tunnel accept would silently permit IPv6 over the tunnel.
        if (plan.BlockIpv6)
        {
            builder.AppendLine("    meta nfproto ipv6 counter drop comment \"myvpn: ipv6 disabled\"");
        }

        // 3. The tunnel itself.
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    oifname \"{Escape(plan.TunnelInterface)}\" accept comment \"myvpn: tunnel\"");

        // 4. VPN server endpoints, so the tunnel can actually be established.
        foreach (var endpoint in plan.AllowedEndpoints)
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    {MatchDestination(endpoint)}{AcceptSuffix(endpoint, "vpn server")}");
        }

        // 5. Configured resolvers and user exemptions, so name resolution does not deadlock.
        foreach (var endpoint in plan.AllowedDestinations)
        {
            var label = endpoint.ReasonKey switch
            {
                "killswitch.reason.resolver" => "resolver",
                "killswitch.reason.user_exemption" => "user exemption",
                _ => "allowed destination",
            };

            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    {MatchDestination(endpoint)}{AcceptSuffix(endpoint, label)}");
        }

        // 6. DHCP/NDP: without these the interface can lose its own address.
        if (plan.AllowDhcp)
        {
            builder.AppendLine("    udp sport 67-68 accept comment \"myvpn: dhcp reply\"");
            builder.AppendLine("    udp dport 67-68 accept comment \"myvpn: dhcp request\"");
            builder.AppendLine("    ip6 nexthdr ipv6-icmp accept comment \"myvpn: ndp\"");
        }

        // 7. ICMP so path-MTU discovery keeps working; blocking it causes the classic
        //    "large downloads stall" symptom.
        if (plan.AllowIcmp)
        {
            builder.AppendLine("    ip protocol icmp accept comment \"myvpn: icmp\"");
            builder.AppendLine("    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept comment \"myvpn: icmpv6\"");
        }

        // 8. Local network, when the user asked for it.
        if (plan.AllowLan)
        {
            builder.AppendLine("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept comment \"myvpn: lan\"");
            builder.AppendLine("    ip6 daddr { fc00::/7, fe80::/10 } accept comment \"myvpn: lan v6\"");
        }

        // 9. Explicit extra blocks, then the counting default deny.
        foreach (var blocked in SortBlocks(plan.BlockedDestinations))
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    {MatchAddress(blocked.IsIPv4 ? "ip daddr" : "ip6 daddr", blocked)} counter drop comment \"myvpn: blocked destination\"");
        }

        builder.AppendLine("    counter drop comment \"myvpn: default deny\"");
        builder.AppendLine("  }");
    }

    private static void AppendInputChain(StringBuilder builder, KillSwitchPlan plan)
    {
        builder.AppendLine("  chain input {");
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    type filter hook input priority {HookPriority}; policy drop;");

        // Established/related must be permitted or every connection dies the moment the
        // ruleset is installed.
        builder.AppendLine("    ct state established,related accept comment \"myvpn: established\"");

        if (plan.AllowLoopback)
        {
            builder.AppendLine("    iifname \"lo\" accept comment \"myvpn: loopback\"");
        }

        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    iifname \"{Escape(plan.TunnelInterface)}\" accept comment \"myvpn: tunnel\"");

        if (plan.AllowDhcp)
        {
            builder.AppendLine("    udp sport 67-68 accept comment \"myvpn: dhcp reply\"");
            builder.AppendLine("    ip6 nexthdr ipv6-icmp accept comment \"myvpn: ndp\"");
        }

        if (plan.AllowIcmp)
        {
            builder.AppendLine("    ip protocol icmp accept comment \"myvpn: icmp\"");
        }

        builder.AppendLine("    counter drop comment \"myvpn: unsolicited inbound\"");
        builder.AppendLine("  }");
    }

    private static void AppendForwardChain(StringBuilder builder)
    {
        // A host is not a router. Dropping forwarded traffic prevents the machine from
        // becoming an accidental leak path if IP forwarding happens to be enabled.
        builder.AppendLine("  chain forward {");
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    type filter hook forward priority {HookPriority}; policy drop;");
        builder.AppendLine("    counter drop comment \"myvpn: forwarding disabled\"");
        builder.AppendLine("  }");
    }

    /// <summary>Builds the address match for an allowed endpoint.</summary>
    private static string MatchDestination(AllowedEndpoint endpoint)
    {
        var family = endpoint.Destination.IsIPv4 ? "ip" : "ip6";
        var address = endpoint.Destination.PrefixLength == (endpoint.Destination.IsIPv4 ? 32 : 128)
            ? endpoint.Destination.Network.ToString()
            : endpoint.Destination.ToString();

        return string.Create(CultureInfo.InvariantCulture, $"{family} daddr {address}");
    }

    /// <summary>Builds the protocol/port match for an allowed endpoint, or a bare accept.</summary>
    /// <remarks>
    /// A note on a bug this method exists to avoid: nftables joins statements on one line
    /// with a logical AND. Emitting <c>tcp dport 443 udp dport 443 accept</c> therefore
    /// describes a packet that is simultaneously TCP and UDP, which is never true, so the
    /// rule silently never matches and the tunnel never comes up. Multiple protocols must
    /// be expressed as a single set match, <c>meta l4proto { tcp, udp } th dport 443</c>.
    /// </remarks>
    private static string AcceptSuffix(AllowedEndpoint endpoint, string label)
    {
        var comment = $"{CommentPrefix} {label}";

        // Port 0 means "any port".
        if (endpoint.Port <= 0)
        {
            return $" accept comment \"{comment}\"";
        }

        var protocols = endpoint.Network
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        var port = endpoint.Port.ToString(CultureInfo.InvariantCulture);

        var match = protocols switch
        {
            ["tcp"] => $"tcp dport {port}",
            ["udp"] => $"udp dport {port}",

            // Both (or an unrecognised value): one set match covering either protocol.
            _ => $"meta l4proto {{ tcp, udp }} th dport {port}",
        };

        return string.Create(CultureInfo.InvariantCulture, $" {match} accept comment \"{comment}\"");
    }

    /// <summary>
    /// Builds an address match. A <see cref="CidrBlock"/> always renders as
    /// <c>network/prefix</c>, which nftables accepts for host routes too.
    /// </summary>
    private static string MatchAddress(string keyword, CidrBlock block) =>
        string.Create(CultureInfo.InvariantCulture, $"{keyword} {block}");

    /// <summary>Deterministic ordering keeps rendered output stable for snapshot tests.</summary>
    private static IEnumerable<CidrBlock> SortBlocks(IEnumerable<CidrBlock> blocks) =>
        blocks
            .OrderBy(b => b.IsIPv4 ? 0 : 1)
            .ThenBy(b => b.PrefixLength)
            .ThenBy(b => b.Network.ToString(), StringComparer.Ordinal);

    /// <summary>
    /// Escapes a value destined for a quoted nftables string. Interface names come from
    /// settings, so they are validated input, but escaping here means a future caller
    /// cannot turn a name into ruleset syntax.
    /// </summary>
    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
             .Replace("\"", "\\\"", StringComparison.Ordinal)
             .Replace("\n", string.Empty, StringComparison.Ordinal)
             .Replace("\r", string.Empty, StringComparison.Ordinal);

    /// <summary>
    /// Converts a plan into the set of interface names it references; used by the executor to
    /// pre-flight that the tunnel interface actually exists before arming a default-deny
    /// ruleset.
    /// </summary>
    public static IReadOnlyList<string> ReferencedInterfaces(KillSwitchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var names = new List<string> { plan.TunnelInterface };
        if (plan.AllowLoopback)
        {
            names.Add("lo");
        }

        return names.Distinct(StringComparer.Ordinal).ToArray();
    }
}
