using System.Globalization;
using System.Text;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Platform.MacOS.KillSwitch;

/// <summary>
/// Renders a <see cref="KillSwitchPlan"/> into a macOS Packet Filter (PF) ruleset.
/// </summary>
/// <remarks>
/// <para>
/// Pure function: no process execution, no file system, no platform probe. Every part of the
/// firewall that can be decided from the plan alone is decided here, so the ruleset text can be
/// asserted by unit tests that run anywhere. The executor
/// (<see cref="MacPfKillSwitch"/>) only feeds this text to <c>pfctl</c> and reads the kernel back.
/// </para>
/// <para>
/// <b>Best effort, and Apple says so.</b> Apple Technote TN3165, "Packet Filter is not API",
/// states verbatim that PF <i>"is not considered API. Do not use Packet Filter in a software
/// product that you distribute to a wide audience"</i> and directs developers to Network
/// Extension instead. It remains the only way to get a fail-closed kill switch without the
/// Network Extension entitlement, so MyVpn ships it as an explicitly best-effort mechanism:
/// <c>PlatformCapabilities.KillSwitchIsBestEffort</c> is set on macOS, and the generated ruleset
/// says the same thing in its header so the caveat travels with the artefact. TN3165 names the
/// things to test against: Internet Sharing, AirDrop, Continuity, Xcode device debugging and Mac
/// Virtual Display.
/// </para>
/// <para>
/// <b>The ruleset replaces the main ruleset, so Apple's anchor point is re-declared.</b>
/// <c>pfctl -f</c> flushes the rules added by the system at startup (the man page warns about
/// this in as many words). The startup file's own header tells system services to insert their
/// anchors into it, which only keeps working while the anchor point exists — so the rendered file
/// re-establishes <c>scrub-anchor</c>, <c>nat-anchor</c>, <c>rdr-anchor</c>,
/// <c>dummynet-anchor</c>, <c>anchor</c> and <c>load anchor</c> for <c>com.apple/*</c>. Omitting
/// them breaks Internet Sharing and anything else that installs an anchor dynamically.
/// </para>
/// <para>
/// <b>Ordering is a safety property.</b> Every rule here is <c>quick</c>, so the first match wins
/// and the order in the file is the order of evaluation: loopback, then the blocks that must not
/// be overridable (explicit blocked destinations, then IPv6), then the permits, and finally the
/// terminal <c>block drop quick all</c>. A block written after a permit would never be reached.
/// </para>
/// <para>
/// <b>The tunnel interface name is templated, never assumed, and never trusted.</b> macOS assigns
/// <c>utunN</c> numbers dynamically and PF <i>accepts a name for an interface that does not exist
/// yet</i> (XNU creates a <c>pfi_kif</c> entry at load time and binds it when the interface
/// attaches). A wrong name therefore produces no error at all: the tunnel pass matches nothing and
/// the terminal block catches everything — fail-closed but VPN-broken, and silent. The executor
/// resolves the real name at runtime; this renderer only refuses a name that cannot be placed into
/// the file safely, because the file is parsed by <c>pfctl</c> running as root.
/// </para>
/// <para>
/// <b>What is deliberately not rendered.</b>
/// <list type="bullet">
/// <item><description>
/// <see cref="KillSwitchPlan.AllowedApplications"/>: PF <c>user</c>/<c>group</c> are match criteria
/// only — they cannot appear on <c>nat</c>/<c>rdr</c>, they cover TCP and UDP only, and the
/// credentials are frozen at socket creation. Per-process tunnelling is not achievable for a
/// self-distributed client on macOS; see the class remarks on <see cref="MacPfKillSwitch"/> and
/// <c>docs/research/08-macos-networking.md</c> §1.4.7.
/// </description></item>
/// <item><description>
/// <see cref="KillSwitchPlan.AllowedDestinations"/> entries whose
/// <see cref="AllowedEndpoint.ReasonKey"/> is <c>killswitch.reason.resolver</c>: DNS is permitted
/// <i>only</i> through the tunnel. A direct pass to port 53 outside the tunnel is exactly the
/// plaintext leak this ruleset exists to prevent, and it would not help resolution anyway —
/// mDNSResponder binds its sockets with <c>IP_BOUND_IF</c> and the "Super" client prefers the
/// primary service's resolvers, so the fix is resolver configuration, not a packet exemption.
/// </description></item>
/// <item><description>
/// <see cref="KillSwitchPlan.AllowIcmp"/>: the researched fail-closed ruleset does not pass
/// ICMPv4 outside the tunnel. ICMP inside the tunnel is already covered by the tunnel pass, and a
/// global ICMP pass would reopen a (small) exfiltration path. The plan value is recorded in a
/// comment instead of being silently dropped.
/// </description></item>
/// </list>
/// </para>
/// </remarks>
public static class PfAnchorRenderer
{
    /// <summary>
    /// Name of the PF table holding the VPN server addresses.
    /// </summary>
    /// <remarks>
    /// Kept in sync with the executor, which uses it for live table updates
    /// (<c>pfctl -t myvpn_server -T replace …</c>) and as the ownership marker when it reads the
    /// loaded ruleset back.
    /// </remarks>
    public const string ServerTableName = "myvpn_server";

    /// <summary>Substring that identifies MyVpn's rules in <c>pfctl -s rules</c> output.</summary>
    public const string OwnershipMarker = "<" + ServerTableName + ">";

    /// <summary>Label attached to MyVpn's rules; shown by <c>pfctl -s labels</c>.</summary>
    public const string OwnershipLabel = "myvpn";

    /// <summary>Loopback interface name on macOS.</summary>
    public const string LoopbackInterface = "lo0";

    /// <summary>Apple's anchor namespace, which must keep its attachment point.</summary>
    public const string AppleAnchorName = "com.apple";

    /// <summary>Apple's anchor file, loaded by the stock startup ruleset.</summary>
    public const string AppleAnchorFile = "/etc/pf.anchors/com.apple";

    /// <summary>
    /// Apple's startup ruleset, which is also the documented restoration path for teardown.
    /// </summary>
    public const string StartupRulesetPath = "/etc/pf.conf";

    /// <summary>Name the rest of the application asks Xray for on macOS.</summary>
    public const string DefaultTunnelInterfaceName = "utun0";

    /// <summary>
    /// Maximum accepted interface name length, <c>IFNAMSIZ - 1</c>. macOS's utun names are short
    /// (<c>utun0</c>…<c>utun255</c>); anything longer is not a name the kernel would have.
    /// </summary>
    public const int MaxInterfaceNameLength = 15;

    /// <summary>Private address ranges kept reachable when the plan asks for LAN access.</summary>
    private static readonly string[] LanV4Blocks =
    {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    };

    private static readonly string[] LanV6Blocks = { "fc00::/7", "fe80::/10" };

    /// <summary>
    /// Renders the ruleset that installs the Kill Switch.
    /// </summary>
    /// <remarks>
    /// Returns a failure rather than text when the plan cannot be armed safely: a plan with no
    /// allow-listed server endpoint would make the terminal block cut off the tunnel itself, and a
    /// tunnel interface name that is not a plain interface identifier must never reach a file that
    /// <c>pfctl</c> parses as root. A plan whose mode is <see cref="KillSwitchMode.Disabled"/>
    /// renders the permissive ruleset from <see cref="RenderDisarm"/>; the executor routes that
    /// case to removal instead.
    /// </remarks>
    public static Result<string> RenderInstall(KillSwitchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (plan.Mode == KillSwitchMode.Disabled)
        {
            return RenderDisarm();
        }

        if (plan.AllowedEndpoints.Count == 0)
        {
            // The decisive safety rule, shared with the other platforms: arming a default-drop
            // ruleset without a pinned server address blackholes the tunnel and leaves the user
            // with no network at all.
            return Result<string>.Fail(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.no_server_endpoint",
                ErrorSeverity.Critical,
                "Refusing to render a PF ruleset that ends in 'block drop quick all' without at "
                + "least one allow-listed server endpoint: the tunnel could never be established.",
                "killswitch.reapply"));
        }

        if (!TryGetSafeInterfaceName(plan.TunnelInterface, out var tunnelInterface))
        {
            return Result<string>.Fail(TunnelInterfaceInvalid(plan.TunnelInterface));
        }

        var builder = new StringBuilder(2048);

        AppendHeader(builder, plan, tunnelInterface);
        AppendOptions(builder);
        AppendAppleAnchors(builder);
        AppendServerTable(builder, plan);

        // (1) Loopback first: the local SOCKS/HTTP inbound and the core's own IPC depend on it,
        //     and it cannot leak to the network. 'set skip on lo0' above is the primary mechanism;
        //     this explicit pass is the belt-and-braces form the research keeps because a 'set'
        //     option is global to the main ruleset and may be ignored in an anchor context.
        builder.Append('\n');
        builder.Append("# --- Loopback: explicit, in case `set skip` was ignored in an anchor context.\n");
        if (plan.AllowLoopback)
        {
            builder.Append(CultureInfo.InvariantCulture, $"pass quick on {LoopbackInterface} all\n");
        }
        else
        {
            // macOS cannot express "filter loopback": the researched ruleset sets 'set skip on lo0'
            // unconditionally, and dropping it would break the local inbound. Say so instead of
            // silently pretending the plan was honoured.
            builder.Append("# NOTE: AllowLoopback is false, but `set skip on lo0` above still bypasses PF on\n");
            builder.Append("#       loopback. macOS has no supported way to filter lo0 in this design.\n");
        }

        // (2) Blocks that must not be overridable, before every permit.
        AppendBlockedDestinations(builder, plan);
        AppendIpv6Policy(builder, plan);

        // (3) Permits.
        AppendServerPasses(builder, plan);
        AppendDhcpPasses(builder, plan);
        AppendDnsPass(builder, tunnelInterface);
        AppendUserExemptions(builder, plan);
        AppendLanPasses(builder, plan);
        AppendTunnelPass(builder, tunnelInterface);

        // (4) The terminal, fail-closed rule. 'quick' is load-bearing: without it a later pass
        //     wins, and PF's default action for an unmatched packet is to pass.
        builder.Append('\n');
        builder.Append("# --- Everything else: dead (fail closed).  'quick' is required: without it a later rule wins.\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"block drop quick all label \"{OwnershipLabel}\"\n");

        return Result<string>.Ok(builder.ToString());
    }

    /// <summary>
    /// Renders the permissive ruleset used when MyVpn stops filtering.
    /// </summary>
    /// <remarks>
    /// Apple's anchors only; no default drop and no tunnel rules. PF's default action for a packet
    /// that matches no rule is to pass, so this is equivalent to "PF is running but MyVpn is not
    /// filtering". It is the fallback for teardown when <c>/etc/pf.conf</c> cannot be reloaded —
    /// the machine must not be left blocked by a ruleset whose owner is going away.
    /// </remarks>
    public static Result<string> RenderDisarm()
    {
        var builder = new StringBuilder(768);

        builder.Append("# MyVpn Kill Switch — teardown ruleset, generated file, do not edit by hand.\n");
        builder.Append("# Loaded when /etc/pf.conf cannot be restored. No filtering rules are installed.\n");
        builder.Append("# PF's default action is to pass, so the machine is back online the moment this loads.\n");
        builder.Append('\n');

        AppendOptions(builder);
        AppendAppleAnchors(builder);

        return Result<string>.Ok(builder.ToString());
    }

    /// <summary>
    /// Converts a plan into the interface names its ruleset references; used by the executor to
    /// pre-flight that the tunnel interface exists before arming a default-deny ruleset.
    /// </summary>
    public static IReadOnlyList<string> ReferencedInterfaces(KillSwitchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var names = new List<string>();
        if (TryGetSafeInterfaceName(plan.TunnelInterface, out var tunnelInterface))
        {
            names.Add(tunnelInterface);
        }

        if (plan.AllowLoopback)
        {
            names.Add(LoopbackInterface);
        }

        return names.Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// True when <paramref name="name"/> can be written into the ruleset as a bare interface token.
    /// </summary>
    /// <remarks>
    /// The allow-list is deliberately narrower than what PF accepts. The name is templated into a
    /// file that <c>pfctl</c> reads as root, so anything that could terminate the token — whitespace,
    /// a newline, a quote, a brace, a bracket, a semicolon — is refused instead of escaped: PF has no
    /// quoting form that both stays injective and keeps the name recognisable in
    /// <c>pfctl -s rules</c> output, which the executor's read-back depends on.
    /// </remarks>
    public static bool IsSafeInterfaceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxInterfaceNameLength)
        {
            return false;
        }

        if (name[0] is '-' or '.' || name == "." || name == "..")
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns the interface token to place in the ruleset, or <c>false</c> when the name must be
    /// refused.
    /// </summary>
    public static bool TryGetSafeInterfaceName(string? name, out string safeName)
    {
        if (IsSafeInterfaceName(name))
        {
            safeName = name!;
            return true;
        }

        safeName = string.Empty;
        return false;
    }

    /// <summary>
    /// Flattens a value for use in a <c>#</c> comment, so plan data can never add or replace a
    /// ruleset line.
    /// </summary>
    /// <remarks>
    /// Control characters — above all <c>\n</c> and <c>\r</c> — are the entire injection risk in a
    /// comment, so they are dropped and the value is bounded. Plan data placed in comments (the
    /// identifier, for instance) goes through here.
    /// </remarks>
    public static string SanitizeComment(string? value, int maxLength = 96)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "(none)";
        }

        var builder = new StringBuilder(Math.Min(value.Length, maxLength) + 1);

        foreach (var c in value)
        {
            if (builder.Length >= maxLength)
            {
                builder.Append('…');
                break;
            }

            builder.Append(char.IsControl(c) ? ' ' : c);
        }

        return builder.ToString();
    }

    // ------------------------------------------------------------------ sections

    private static void AppendHeader(StringBuilder builder, KillSwitchPlan plan, string tunnelInterface)
    {
        builder.Append("# MyVpn Kill Switch — generated PF ruleset, do not edit by hand.\n");
        builder.Append("# Source of truth: KillSwitchPlan; see docs/research/08-macos-networking.md §1.3.\n");
        builder.Append(CultureInfo.InvariantCulture, $"# mode: {plan.Mode}\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"# identifier: {SanitizeComment(plan.Identifier, 48)}\n");
        builder.Append(CultureInfo.InvariantCulture, $"# tunnel interface: {tunnelInterface}\n");
        builder.Append("#\n");
        builder.Append("# BEST EFFORT, NOT API. Apple TN3165 (\"Packet Filter is not API\") says verbatim:\n");
        builder.Append("#   \"It is not considered API. Do not use Packet Filter in a software product that\n");
        builder.Append("#    you distribute to a wide audience.\"  It directs developers to Network Extension.\n");
        builder.Append("# MyVpn uses PF because a fail-closed kill switch is otherwise unavailable without the\n");
        builder.Append("# Network Extension entitlement. Expect conflicts with other firewalls and with Apple\n");
        builder.Append("# services; test with Internet Sharing, AirDrop, Continuity and Xcode.\n");
        builder.Append("#\n");
        builder.Append("# Safety properties of this file:\n");
        builder.Append("#   * pfctl -d is never used by MyVpn: XNU's DIOCSTOP zeroes the enable reference count\n");
        builder.Append("#     and invalidates every token, which would disable the Application Firewall's own\n");
        builder.Append("#     com.apple/250.ApplicationFirewall rules. Only 'pfctl -X <our token>' is used.\n");
        builder.Append("#   * This file is loaded with -f, which replaces the MAIN ruleset, so Apple's anchors\n");
        builder.Append("#     are re-declared below.\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"#   * <{ServerTableName}> is 'persist' and is NEVER initialised with an empty list:\n");
        builder.Append("#     a table initialised with { } is cleared on load.\n");
        builder.Append("#   * The tunnel interface name must be resolved at runtime. PF accepts a name for an\n");
        builder.Append("#     interface that does not exist yet, so a wrong name fails closed and silent.\n");
        builder.Append("#   * DNS is permitted only on the tunnel. That makes a leaked query FAIL rather than\n");
        builder.Append("#     redirect it; the resolver configuration is the other half of the fix (§1.5).\n");

        if (!plan.AllowIcmp)
        {
            builder.Append("#   * AllowIcmp is false in this plan.\n");
        }
        else
        {
            builder.Append("#   * AllowIcmp is true in this plan, but no ICMP pass is rendered outside the\n");
            builder.Append("#     tunnel: the researched fail-closed ruleset permits ICMP only inside it.\n");
        }
    }

    private static void AppendOptions(StringBuilder builder)
    {
        builder.Append('\n');
        builder.Append("# --- Options. 'set' options are global to the MAIN ruleset; if this file were loaded\n");
        builder.Append("#     into an anchor, `set skip on lo0` could be silently ignored, which is why the\n");
        builder.Append("#     loopback pass below exists as well. Both forms are deliberate.\n");
        builder.Append(CultureInfo.InvariantCulture, $"set skip on {LoopbackInterface}\n");
        builder.Append("set block-policy drop\n");
        builder.Append("# Keep the loaded rules 1:1 with this text: the executor reads `pfctl -s rules` back to\n");
        builder.Append("# verify what is actually in force, and the optimizer would rewrite it.\n");
        builder.Append("set ruleset-optimization none\n");
    }

    private static void AppendAppleAnchors(StringBuilder builder)
    {
        builder.Append('\n');
        builder.Append("# --- Apple's own anchors, required because -f replaces the main ruleset.\n");
        builder.Append("#     Omitting them breaks services that insert anchors at runtime (Internet Sharing).\n");
        builder.Append(CultureInfo.InvariantCulture, $"scrub-anchor \"{AppleAnchorName}/*\"\n");
        builder.Append(CultureInfo.InvariantCulture, $"nat-anchor \"{AppleAnchorName}/*\"\n");
        builder.Append(CultureInfo.InvariantCulture, $"rdr-anchor \"{AppleAnchorName}/*\"\n");
        builder.Append(CultureInfo.InvariantCulture, $"dummynet-anchor \"{AppleAnchorName}/*\"\n");
        builder.Append(CultureInfo.InvariantCulture, $"anchor \"{AppleAnchorName}/*\"\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"load anchor \"{AppleAnchorName}\" from \"{AppleAnchorFile}\"\n");
    }

    private static void AppendServerTable(StringBuilder builder, KillSwitchPlan plan)
    {
        var addresses = plan.AllowedEndpoints
            .Select(e => e.Destination)
            .Distinct()
            .OrderBy(b => b.IsIPv4 ? 0 : 1)
            .ThenBy(b => b.PrefixLength)
            .ThenBy(b => b.Network.ToString(), StringComparer.Ordinal)
            .Select(RenderTableAddress)
            .ToArray();

        builder.Append('\n');
        builder.Append("# --- Bootstrap: the VPN transport must reach the server OUTSIDE the tunnel.\n");
        builder.Append("#     The addresses live in a persistent table so re-resolving the server hostname is\n");
        builder.Append("#     a `pfctl -t myvpn_server -T replace …`, not a ruleset reload that flushes states.\n");
        builder.Append("#     `persist` keeps the table when no rule refers to it. The list is always non-empty:\n");
        builder.Append("#     a table initialised with { } is cleared on load, which would black-hole the tunnel.\n");

        if (addresses.Length == 0)
        {
            // Unreachable: RenderInstall refuses an empty endpoint list first. Kept as a hard
            // guard so a future edit cannot emit an empty table literal.
            builder.Append(CultureInfo.InvariantCulture, $"table <{ServerTableName}> persist\n");
            return;
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"table <{ServerTableName}> persist {{ {string.Join(", ", addresses)} }}\n");

        if (plan.BlockIpv6 && plan.AllowedEndpoints.Any(e => e.Destination.IsIPv6))
        {
            builder.Append("#     NOTE: the table contains IPv6 endpoint(s), and IPv6 is dropped below, so\n");
            builder.Append("#     those endpoints are unreachable while the kill switch is armed.\n");
        }
    }

    private static void AppendBlockedDestinations(StringBuilder builder, KillSwitchPlan plan)
    {
        var blocked = plan.BlockedDestinations
            .Distinct()
            .OrderBy(b => b.IsIPv4 ? 0 : 1)
            .ThenBy(b => b.PrefixLength)
            .ThenBy(b => b.Network.ToString(), StringComparer.Ordinal)
            .ToArray();

        if (blocked.Length == 0)
        {
            return;
        }

        builder.Append('\n');
        builder.Append("# --- Destinations the plan blocks explicitly. Emitted BEFORE the permits because\n");
        builder.Append("#     every rule here is `quick`: a block after a permit would never be reached.\n");

        foreach (var block in blocked)
        {
            var family = block.IsIPv4 ? "inet" : "inet6";
            builder.Append(CultureInfo.InvariantCulture,
                $"block drop quick {family} from any to {block}\n");
        }
    }

    private static void AppendIpv6Policy(StringBuilder builder, KillSwitchPlan plan)
    {
        builder.Append('\n');

        if (plan.BlockIpv6)
        {
            builder.Append("# --- IPv6: no leaks. Drop everything v6 while the tunnel is v4-only. This sits before\n");
            builder.Append("#     every permit, so the tunnel pass cannot re-permit IPv6 inside the tunnel.\n");
            builder.Append("block drop quick inet6 all\n");
            return;
        }

        builder.Append("# --- IPv6 is carried by this plan, so the requirements that come with carrying it are\n");
        builder.Append("#     met explicitly: DHCPv6 and neighbour discovery are passed, and ICMPv6 is passed so\n");
        builder.Append("#     that Packet Too Big (type 2) still reaches us — blocking it breaks path-MTU\n");
        builder.Append("#     discovery. The protocol-level pass is a deliberate superset of types 2 and 133-136\n");
        builder.Append("#     because the pf.conf(5) man page snapshot does not document a brace list for\n");
        builder.Append("#     `icmp6-type`; narrowing it would risk a ruleset pfctl rejects.\n");
        builder.Append("pass out quick inet6 proto udp from any port 546 to any port 547\n");
        builder.Append("pass in quick inet6 proto udp from any port 547 to any port 546\n");
        builder.Append("pass quick inet6 proto ipv6-icmp from any to any\n");
    }

    private static void AppendServerPasses(StringBuilder builder, KillSwitchPlan plan)
    {
        builder.Append('\n');
        builder.Append("# --- The VPN transport itself, out to the server table.\n");

        foreach (var (protocols, port) in AllowedPorts(plan.AllowedEndpoints))
        {
            var portMatch = port > 0
                ? string.Create(CultureInfo.InvariantCulture, $" port {port}")
                : string.Empty;

            builder.Append(CultureInfo.InvariantCulture,
                $"pass out quick proto {protocols} from any to <{ServerTableName}>{portMatch}\n");
        }
    }

    private static void AppendDhcpPasses(StringBuilder builder, KillSwitchPlan plan)
    {
        if (!plan.AllowDhcp)
        {
            return;
        }

        builder.Append('\n');
        builder.Append("# --- DHCPv4 bootstrap (ports 67/68) so the machine keeps its own address. Scoped by\n");
        builder.Append("#     port and direction rather than by interface: the plan carries no physical\n");
        builder.Append("#     interface, and the DHCP exchange is the only traffic this permits.\n");
        builder.Append("pass out quick proto udp from any port 68 to any port 67\n");
        builder.Append("pass in quick proto udp from any port 67 to any port 68\n");
    }

    private static void AppendDnsPass(StringBuilder builder, string tunnelInterface)
    {
        builder.Append('\n');
        builder.Append("# --- DNS: only through the tunnel. This prevents the packet-level leak; it does NOT\n");
        builder.Append("#     redirect a leaked query, it makes it fail, which is why the resolver\n");
        builder.Append("#     configuration must be fixed too (§1.5).\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"pass out quick on {tunnelInterface} proto {{ tcp, udp }} from any to any port 53\n");
    }

    private static void AppendUserExemptions(StringBuilder builder, KillSwitchPlan plan)
    {
        var exemptions = plan.AllowedDestinations
            .Where(e => !string.Equals(e.ReasonKey, "killswitch.reason.resolver", StringComparison.Ordinal))
            .OrderBy(e => e.Destination.IsIPv4 ? 0 : 1)
            .ThenBy(e => e.Destination.PrefixLength)
            .ThenBy(e => e.Destination.Network.ToString(), StringComparer.Ordinal)
            .ThenBy(e => e.Port)
            .ToArray();

        var resolvers = plan.AllowedDestinations
            .Where(e => string.Equals(e.ReasonKey, "killswitch.reason.resolver", StringComparison.Ordinal))
            .ToArray();

        if (exemptions.Length == 0 && resolvers.Length == 0)
        {
            return;
        }

        builder.Append('\n');

        if (exemptions.Length > 0)
        {
            builder.Append("# --- Destinations the plan keeps reachable directly (user exemptions).\n");
            foreach (var endpoint in exemptions)
            {
                foreach (var (protocols, port) in AllowedPorts(new[] { endpoint }))
                {
                    var portMatch = port > 0
                        ? string.Create(CultureInfo.InvariantCulture, $" port {port}")
                        : string.Empty;

                    builder.Append(CultureInfo.InvariantCulture,
                        $"pass out quick proto {protocols} from any to {endpoint.Destination}{portMatch}\n");
                }
            }
        }

        if (resolvers.Length > 0)
        {
            builder.Append("# --- AllowedDestinations entries marked 'killswitch.reason.resolver' are NOT rendered\n");
            builder.Append("#     as direct passes: DNS is reachable only through the tunnel, and a direct pass to\n");
            builder.Append("#     port 53 outside it would reintroduce exactly the leak this ruleset prevents.\n");
            builder.Append(CultureInfo.InvariantCulture,
                $"#     ({resolvers.Length} resolver exemption(s) were supplied by the plan.)\n");
        }
    }

    private static void AppendLanPasses(StringBuilder builder, KillSwitchPlan plan)
    {
        if (!plan.AllowLan)
        {
            return;
        }

        builder.Append('\n');
        builder.Append("# --- Local network, kept reachable because the plan asks for it. This filters; it does\n");
        builder.Append("#     not route. LAN destinations must also be excluded from the tunnel routes.\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"pass out quick inet from any to {{ {string.Join(", ", LanV4Blocks)} }}\n");

        if (!plan.BlockIpv6)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"pass out quick inet6 from any to {{ {string.Join(", ", LanV6Blocks)} }}\n");
        }
    }

    private static void AppendTunnelPass(StringBuilder builder, string tunnelInterface)
    {
        builder.Append('\n');
        builder.Append("# --- The tunnel itself. The name is resolved at runtime (UTUN_OPT_IFNAME) and must be\n");
        builder.Append("#     the real utunN: PF accepts a name that does not exist, so a wrong one is silent.\n");
        builder.Append(CultureInfo.InvariantCulture, $"pass quick on {tunnelInterface} all\n");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Renders a table member. A host route is written without its prefix, which is the form the
    /// research uses and the form a human expects when reading the file.
    /// </summary>
    private static string RenderTableAddress(CidrBlock block)
    {
        var hostPrefix = block.IsIPv4 ? 32 : 128;
        return block.PrefixLength == hostPrefix ? block.Network.ToString() : block.ToString();
    }

    /// <summary>
    /// Collapses the plan's endpoints into the distinct protocol/port matches the ruleset needs.
    /// </summary>
    /// <remarks>
    /// All endpoints share one table, so a rule is emitted per distinct port. The consequence is
    /// documented rather than hidden: an address listed in the table is reachable on every port the
    /// plan lists, which is the price of keeping a single table that
    /// <c>pfctl -t myvpn_server -T replace</c> can update live. One table per endpoint would make
    /// server-address churn a ruleset reload again.
    /// </remarks>
    private static IEnumerable<(string Protocols, int Port)> AllowedPorts(
        IReadOnlyList<AllowedEndpoint> endpoints) =>
        endpoints
            .Select(e => (Protocols: RenderProtocols(e.Network), e.Port))
            .Distinct()
            .OrderBy(p => p.Port)
            .ThenBy(p => p.Protocols, StringComparer.Ordinal);

    /// <summary>Renders the protocol match for an endpoint's <c>Network</c> value.</summary>
    private static string RenderProtocols(string? network)
    {
        var protocols = (network ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToLowerInvariant())
            .Where(p => p is "tcp" or "udp")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        // An unrecognised or empty value means "both": emitting nothing would leave the server
        // unreachable and turn the kill switch into a black hole.
        return protocols.Length switch
        {
            1 => protocols[0],
            _ => "{ tcp, udp }",
        };
    }

    private static MyVpnError TunnelInterfaceInvalid(string? interfaceName) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.tunnel_interface_invalid",
            ErrorSeverity.Error,
            $"'{DescribeForLog(interfaceName)}' is not a usable PF interface name: 1 to "
            + $"{MaxInterfaceNameLength} characters, letters, digits, '_', '-' or '.', and no leading "
            + "'-' or '.'. The name is written into a file that pfctl parses as root, so it is refused "
            + "rather than escaped.",
            "diagnostics.run");

    /// <summary>Renders a rejected value for a log line without letting control characters forge one.</summary>
    private static string DescribeForLog(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "(empty)";
        }

        var builder = new StringBuilder(Math.Min(value.Length, 40) + 1);

        foreach (var c in value)
        {
            if (builder.Length >= 40)
            {
                builder.Append('…');
                break;
            }

            builder.Append(char.IsControl(c) ? '?' : c);
        }

        return builder.ToString();
    }
}
