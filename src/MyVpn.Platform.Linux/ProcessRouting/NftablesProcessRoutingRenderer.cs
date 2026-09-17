using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using MyVpn.Core.Domain;
using MyVpn.Platform.Abstractions.Processes;

namespace MyVpn.Platform.Linux.ProcessRouting;

/// <summary>The physical uplink a bypass rule must point at.</summary>
/// <param name="Device">Uplink interface, e.g. <c>eth0</c>.</param>
/// <param name="Gateway">Next hop, when the uplink's default route has one.</param>
public sealed record PhysicalUplinkRoute(string Device, string? Gateway);

/// <summary>
/// Everything the renderer needs that a <see cref="ProcessRoutingPlan"/> does not carry.
/// </summary>
/// <remarks>
/// The plan is a settings-shaped value: it knows which processes and which mark/table, but not which
/// interface the tunnel will appear as, which slices exist, or where the VPN server is. Those are
/// runtime facts owned by <c>CgroupV2ProcessRouter</c>, which fills this in and keeps the renderer
/// itself a pure function.
/// </remarks>
public sealed record ProcessRoutingRenderContext
{
    /// <summary>Interface the core's TUN inbound creates; must match the core's configuration.</summary>
    public string TunnelInterface { get; init; } = NftablesProcessRoutingRenderer.DefaultTunnelInterface;

    /// <summary>Slice holding processes that must use the tunnel.</summary>
    public string TunnelSlice { get; init; } = CgroupV2Manager.DefaultSliceName;

    /// <summary>Slice holding processes that must bypass the tunnel.</summary>
    public string BypassSlice { get; init; } = CgroupV2Manager.BypassSliceName;

    /// <summary>
    /// Resolved VPN server addresses. Used to pin the server to the physical uplink, which is the
    /// outermost layer of loop prevention.
    /// </summary>
    public IReadOnlyList<string> VpnServerEndpoints { get; init; } = Array.Empty<string>();

    /// <summary>
    /// The uplink's own default route, required when any selector bypasses the tunnel. The router
    /// obtains it by reading <c>ip route show default</c>; the renderer never probes anything itself.
    /// </summary>
    public PhysicalUplinkRoute? PhysicalUplink { get; init; }

    /// <summary>The defaults used when no runtime facts are supplied (tests, dry runs).</summary>
    public static ProcessRoutingRenderContext Default { get; } = new();
}

/// <summary>One external command, as an argv vector. Never a shell string.</summary>
public sealed record IpArgv(IReadOnlyList<string> Arguments)
{
    /// <summary>Space-joined form, for logs and test assertions.</summary>
    public override string ToString() => string.Join(' ', Arguments);
}

/// <summary>
/// The complete, ready-to-execute output of the renderer.
/// </summary>
/// <param name="NftablesText">
/// The ruleset for <c>nft --file</c>; already escaped and deterministic.
/// </param>
/// <param name="InstallCommands">
/// <c>ip</c> argv vectors in the order they must run. Empty when the plan tears down.
/// </param>
/// <param name="RemoveCommands">
/// <c>ip</c> argv vectors that undo <paramref name="InstallCommands"/>. Every one of them is safe to
/// run when nothing was installed, which is what makes teardown and crash recovery repeatable.
/// </param>
/// <param name="IsTeardown">True when the plan asked for <see cref="ProcessRoutingMode.Off"/>.</param>
public sealed record ProcessRoutingRuleset(
    string NftablesText,
    IReadOnlyList<IpArgv> InstallCommands,
    IReadOnlyList<IpArgv> RemoveCommands,
    bool IsTeardown)
{
    /// <summary>True when the ruleset contains at least one marking rule.</summary>
    public bool HasMarkingRules =>
        NftablesText.Contains("meta mark set", StringComparison.Ordinal);
}

/// <summary>
/// Renders a <see cref="ProcessRoutingPlan"/> into an nftables ruleset and <c>ip</c> argv vectors.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure function: no process execution, no file system, no clock.</b> That is what makes the
/// enforcement logic testable without privileges, and it mirrors
/// <c>NftablesKillSwitchRenderer</c>. The executor
/// (<c>CgroupV2ProcessRouter</c>) does I/O; this class only decides what the kernel should be told.
/// </para>
/// <para><b>The mechanism.</b> Selected processes are members of a cgroup v2 slice. An nftables rule
/// matching <c>socket cgroupv2 level N "component"</c> stamps a firewall mark on their packets; an
/// <c>ip rule fwmark</c> sends marked traffic to a dedicated routing table; that table's default
/// route points at the tunnel. Nothing here touches the <c>main</c> table, so an aborted teardown
/// leaves at most an unused table rather than a machine without a default route.</para>
/// <para><b>Both directions.</b> A selector with <see cref="ResolvedProcessSelector.ThroughTunnel"/>
/// set is marked into the table whose default route is the tunnel
/// (<see cref="ProcessRoutingMode.VpnOnly"/>, the tunnel half of <see cref="ProcessRoutingMode.Rules"/>).
/// A selector that must bypass gets its own slice, mark and table, whose default route is the
/// <i>physical</i> uplink's own default — supplied by the caller, because the renderer never probes.
/// That is what makes <see cref="ProcessRoutingMode.BypassVpn"/> enforceable with the same
/// primitives instead of silently inverting the user's intent. Everything else on the machine is left
/// alone: "everything through the tunnel" is the core's own default route, which this mechanism
/// deliberately does not modify.</para>
/// <para><b>Chain type.</b> The marking chain is <c>type route hook output</c>, not
/// <c>type filter</c>. Only a <c>route</c> chain re-runs the route lookup after the packet mark
/// changes, and without that re-lookup the mark is set but never consulted — a rule that loads
/// perfectly and does nothing.</para>
/// <para><b>Loop prevention.</b> The mark must never be applied to the core's own traffic: the core's
/// connection to the VPN server leaves through the physical uplink, and a marked packet is routed
/// into the tunnel that is carrying it, so its own peer would have to be reached through itself. The
/// rendered rules contribute two of the three guards — <c>oifname &lt;tunnel&gt; return</c> so traffic
/// already on the tunnel is never re-marked, and an <c>ip rule to &lt;server&gt; lookup main</c> at a
/// higher precedence than the mark rule so the server stays reachable through the uplink even if
/// something else goes wrong. The third is structural and lives in the executor: the core is never a
/// member of a slice, because only selector-matched processes are moved into one.</para>
/// <para><b>Child processes.</b> A cgroup is inherited by every child a member forks, and the
/// cgroupv2 match covers the whole subtree, so <see cref="ResolvedProcessSelector.IncludeChildren"/>
/// is honoured by construction here. That is exactly what Windows cannot do: WFP's <c>ALE_APP_ID</c>
/// identifies the connecting process, so a browser that hands a request to a child process leaves a
/// hole unless the child is matched separately. On Linux the child is in the slice before it opens a
/// socket.</para>
/// <para><b>Re-apply.</b> The generated text is idempotent (bare <c>table</c> line, then
/// <c>delete table</c>, then the definition — one atomic transaction, no window without rules) and
/// every <c>ip</c> command is either a <c>replace</c> or tolerated as already-present on re-run.
/// Re-applying is required after the slice is re-created, because the match resolves a cgroup ID
/// rather than a path.</para>
/// </remarks>
public static class NftablesProcessRoutingRenderer
{
    /// <summary>Table name, namespaced so it cannot collide with a distribution ruleset.</summary>
    public const string TableName = "myvpn_route";

    /// <summary>Interface the core's TUN inbound is configured to create.</summary>
    public const string DefaultTunnelInterface = "myvpn0";

    /// <summary>
    /// Precedence of the "VPN server stays on the physical uplink" rules. Lower is checked first, so
    /// this deliberately outranks <see cref="MarkRulePriority"/>.
    /// </summary>
    public const int EndpointRulePriority = 900;

    /// <summary>Precedence of the <c>fwmark</c> rule that sends selected traffic into the tunnel.</summary>
    public const int MarkRulePriority = 1000;

    /// <summary>
    /// Precedence of the fail-closed <c>prohibit</c> rule. It is only reached when the mark rule's
    /// table has no usable route — that is, when the tunnel is down — and it turns what would be a
    /// silent fall-through to the physical uplink into a visible connection failure.
    /// </summary>
    public const int FailClosedRulePriority = 1100;

    /// <summary>Bypass traffic gets its own mark and table so the two directions cannot collide.</summary>
    public const int BypassMarkOffset = 1;

    /// <summary>Bypass traffic gets its own mark and table so the two directions cannot collide.</summary>
    public const int BypassTableIdOffset = 1;

    private const string CommentPrefix = "myvpn:";

    /// <summary>
    /// Renders the whole enforcement plan.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// When a selector bypasses the tunnel but the context carries no physical uplink route: a bypass
    /// mark with nowhere to send the traffic would load successfully and silently fail open, so it is
    /// refused instead. The executor checks the same condition and reports it as a localized error
    /// before it runs anything.
    /// </exception>
    public static ProcessRoutingRuleset Render(
        ProcessRoutingPlan plan,
        ProcessRoutingRenderContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(plan);

        ValidateNumbers(plan);

        var ctx = context ?? ProcessRoutingRenderContext.Default;
        var tunnelMark = plan.FirewallMark;
        var bypassMark = plan.FirewallMark + BypassMarkOffset;
        var tunnelTable = plan.RoutingTableId;
        var bypassTable = plan.RoutingTableId + BypassTableIdOffset;

        // Teardown removes both directions unconditionally: the plan may have been edited since it
        // was applied, and every removal command tolerates "not there", so being generous costs
        // nothing and being precise risks leaving a stale rule behind.
        var remove = BuildRemoveCommands(
            ctx, tunnelMark, bypassMark, tunnelTable, bypassTable);

        if (plan.Mode == ProcessRoutingMode.Off)
        {
            // "Off" is a teardown, not a no-op: leaving marks and policy rules behind would keep the
            // previous selection in force while the UI says per-app routing is disabled.
            return new ProcessRoutingRuleset(RenderTeardown(), remove, remove, IsTeardown: true);
        }

        var needsTunnel = plan.Selectors.Any(selector => selector.ThroughTunnel);
        var needsBypass = plan.Selectors.Any(selector => !selector.ThroughTunnel);

        if (needsBypass && ctx.PhysicalUplink is null)
        {
            throw new ArgumentException(
                "A selector bypasses the tunnel, which needs the physical uplink's default route in "
                + nameof(ProcessRoutingRenderContext.PhysicalUplink) + "; without it the bypass mark "
                + "would have no route and the traffic would fall back to the tunnel.",
                nameof(context));
        }

        return new ProcessRoutingRuleset(
            RenderRuleset(plan, ctx, needsTunnel, needsBypass, tunnelMark, bypassMark),
            BuildInstallCommands(ctx, needsTunnel, needsBypass, tunnelMark, bypassMark, tunnelTable, bypassTable),
            remove,
            IsTeardown: false);
    }

    /// <summary>Renders only the nftables text, for callers that just need the ruleset.</summary>
    public static string RenderNftables(
        ProcessRoutingPlan plan,
        ProcessRoutingRenderContext? context = null) => Render(plan, context).NftablesText;

    /// <summary>
    /// Finalises a rendered ruleset.
    /// </summary>
    /// <remarks>
    /// <see cref="StringBuilder.AppendLine()"/> emits <see cref="Environment.NewLine"/>, which is
    /// <c>\r\n</c> on Windows. A ruleset is a file for nft — a Linux tool — not text for the host
    /// that happened to render it: its separator is <c>\n</c> on every operating system this code
    /// is compiled or unit-tested on, so the host's convention must not leak into the file. On
    /// Linux the replace is a no-op, which is what keeps the Linux assertions byte-identical.
    /// </remarks>
    private static string Finish(StringBuilder builder) =>
        builder.Replace(Environment.NewLine, "\n").ToString();

    /// <summary>
    /// Renders the idempotent teardown ruleset: create-if-missing, then delete.
    /// </summary>
    /// <remarks>
    /// <c>destroy table</c> would express this in one line, but nftables 1.0.x — what current LTS
    /// distributions ship — rejects it with a syntax error even though newer manuals document it. The
    /// two-line form works everywhere and is atomic, because the whole file is one transaction.
    /// </remarks>
    public static string RenderTeardown()
    {
        var builder = new StringBuilder(256);
        builder.AppendLine("# MyVpn process routing — teardown, idempotent.");
        builder.AppendLine("# Safe to run when nothing is installed: the bare table line creates it if missing.");
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"delete table inet {TableName}");
        return Finish(builder);
    }

    /// <summary>Renders a read-only query used by verification.</summary>
    public static string RenderInspect() =>
        string.Create(CultureInfo.InvariantCulture, $"list table inet {TableName}") + "\n";

    /// <summary>Renders a mark the way both nftables and <c>ip</c> accept it: lowercase hex.</summary>
    public static string RenderMark(int mark) =>
        string.Create(CultureInfo.InvariantCulture, $"0x{mark:x}");

    /// <summary>Renders the <c>fwmark value/mask</c> token, with every bit significant.</summary>
    public static string RenderMarkSpec(int mark) =>
        string.Create(CultureInfo.InvariantCulture, $"{RenderMark(mark)}/{RenderMark(mark)}");

    // ------------------------------------------------------------------ nftables

    private static string RenderRuleset(
        ProcessRoutingPlan plan,
        ProcessRoutingRenderContext context,
        bool needsTunnel,
        bool needsBypass,
        int tunnelMark,
        int bypassMark)
    {
        var builder = new StringBuilder(2048);

        builder.AppendLine("# MyVpn process routing — generated file, do not edit by hand.");
        builder.AppendLine("# Source of truth: ProcessRoutingPlan; design: docs/research/07-linux-networking.md §2.3.");
        builder.AppendLine(CultureInfo.InvariantCulture, $"# mode: {plan.Mode}");
        builder.AppendLine("#");
        builder.AppendLine("# socket cgroupv2 level N \"component\" resolves the socket's cgroup to a numeric ID when");
        builder.AppendLine("# this file is loaded. The slice must therefore exist first, and these rules stop matching");
        builder.AppendLine("# if it is destroyed and re-created with a new ID — re-apply after any slice recreation.");
        builder.AppendLine("#");
        builder.AppendLine("# LOOP PREVENTION: the mark must never be applied to the core's own traffic. The core's");
        builder.AppendLine("# connection to the VPN server leaves through the physical uplink; marking it would route it");
        builder.AppendLine("# into the tunnel it is building, so its own peer would have to be reached through itself.");

        // Atomic, idempotent replacement: the bare table line makes the delete unconditional, and the
        // whole file commits or aborts as one transaction, so no packet ever sees a half-built ruleset.
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"delete table inet {TableName}");
        builder.AppendLine(CultureInfo.InvariantCulture, $"table inet {TableName} {{");

        AppendMarkingChain(builder, "mark_output", "route", "output", context, needsTunnel, needsBypass, tunnelMark, bypassMark, "the tunnel's own traffic");
        builder.AppendLine();
        AppendMarkingChain(builder, "mark_prerouting", "filter", "prerouting", context, needsTunnel, needsBypass, tunnelMark, bypassMark, "tunnel-originated traffic");
        builder.AppendLine();
        AppendClearMarkChain(builder, context, needsBypass);

        builder.AppendLine("}");
        return Finish(builder);
    }

    /// <summary>
    /// Emits a marking chain. <c>mark_output</c> is a <c>route</c> chain so the mark triggers a fresh
    /// route lookup; <c>mark_prerouting</c> covers traffic forwarded out of containers or other
    /// network namespaces, where a socket-cgroup match still identifies the sender.
    /// </summary>
    private static void AppendMarkingChain(
        StringBuilder builder,
        string chainName,
        string chainType,
        string hook,
        ProcessRoutingRenderContext context,
        bool needsTunnel,
        bool needsBypass,
        int tunnelMark,
        int bypassMark,
        string alreadyMarkedLabel)
    {
        builder.AppendLine(CultureInfo.InvariantCulture, $"  chain {chainName} {{");
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    type {chainType} hook {hook} priority mangle; policy accept;");

        var prefix = hook == "output" ? "oifname" : "iifname";

        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    {prefix} \"{Escape(context.TunnelInterface)}\" return comment \"{CommentPrefix} never re-mark {alreadyMarkedLabel}\"");

        if (needsTunnel)
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    {CgroupV2Manager.ResolveMatch(context.TunnelSlice).RenderNft()} meta mark set {RenderMark(tunnelMark)} comment \"{CommentPrefix} selected processes through the tunnel\"");
        }

        if (needsBypass)
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    {CgroupV2Manager.ResolveMatch(context.BypassSlice).RenderNft()} meta mark set {RenderMark(bypassMark)} comment \"{CommentPrefix} selected processes bypassing the tunnel\"");
        }

        builder.AppendLine("  }");
    }

    /// <summary>
    /// Strips the mark on egress, so it is purely a local routing decision and cannot be cached into
    /// a decision that outlives the configuration that produced it.
    /// </summary>
    private static void AppendClearMarkChain(
        StringBuilder builder,
        ProcessRoutingRenderContext context,
        bool needsBypass)
    {
        builder.AppendLine("  chain clear_mark {");
        builder.AppendLine("    type filter hook postrouting priority mangle; policy accept;");
        builder.AppendLine(CultureInfo.InvariantCulture,
            $"    oifname \"{Escape(context.TunnelInterface)}\" meta mark set 0 comment \"{CommentPrefix} strip the mark on tunnel egress\"");

        if (needsBypass && context.PhysicalUplink is not null)
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"    oifname \"{Escape(context.PhysicalUplink.Device)}\" meta mark set 0 comment \"{CommentPrefix} strip the bypass mark on the physical uplink\"");
        }

        builder.AppendLine("  }");
    }

    // ------------------------------------------------------------------ ip argv

    private static IReadOnlyList<IpArgv> BuildInstallCommands(
        ProcessRoutingRenderContext context,
        bool needsTunnel,
        bool needsBypass,
        int tunnelMark,
        int bypassMark,
        int tunnelTable,
        int bypassTable)
    {
        var commands = new List<IpArgv>();
        var endpoints = NormalizeEndpoints(context.VpnServerEndpoints);

        if (needsTunnel)
        {
            // (1) The route exists before the rule that uses it, so marked traffic never observes an
            //     empty table. `replace` makes a re-apply exact instead of an "already exists" error.
            commands.Add(Ip(
                "route", "replace", "default", "dev", context.TunnelInterface, "table", Table(tunnelTable)));

            // (2) Loop prevention, at the highest precedence: the VPN server must be reachable through
            //     the normal table even while marked traffic is being sent to the tunnel.
            foreach (var endpoint in endpoints)
            {
                commands.Add(Ip(
                    "rule", "add", "to", endpoint, "lookup", "main",
                    "priority", Priority(EndpointRulePriority)));
            }

            // (3) Selected traffic goes to the tunnel's table.
            commands.Add(Ip(
                "rule", "add", "fwmark", RenderMarkSpec(tunnelMark),
                "lookup", Table(tunnelTable), "priority", Priority(MarkRulePriority)));

            // (4) Fail closed: when the tunnel is down the route in the table is unusable, and without
            //     this rule the lookup falls through to the physical default — a silent leak of exactly
            //     the traffic the user asked to be tunnelled.
            commands.Add(Ip(
                "rule", "add", "fwmark", RenderMarkSpec(tunnelMark),
                "prohibit", "priority", Priority(FailClosedRulePriority)));
        }

        if (needsBypass && context.PhysicalUplink is not null)
        {
            var uplink = context.PhysicalUplink;
            var route = new List<string> { "route", "replace", "default" };

            if (!string.IsNullOrWhiteSpace(uplink.Gateway))
            {
                route.Add("via");
                route.Add(uplink.Gateway);
            }

            route.Add("dev");
            route.Add(uplink.Device);
            route.Add("table");
            route.Add(Table(bypassTable));
            commands.Add(new IpArgv(route));

            commands.Add(Ip(
                "rule", "add", "fwmark", RenderMarkSpec(bypassMark),
                "lookup", Table(bypassTable), "priority", Priority(MarkRulePriority)));

            commands.Add(Ip(
                "rule", "add", "fwmark", RenderMarkSpec(bypassMark),
                "prohibit", "priority", Priority(FailClosedRulePriority)));
        }

        return commands;
    }

    /// <summary>
    /// The reverse of installation, and deliberately tolerant: every command here is expected to find
    /// nothing at all when the state was never applied, and that is success.
    /// </summary>
    private static IReadOnlyList<IpArgv> BuildRemoveCommands(
        ProcessRoutingRenderContext context,
        int tunnelMark,
        int bypassMark,
        int tunnelTable,
        int bypassTable)
    {
        var commands = new List<IpArgv>();
        var endpoints = NormalizeEndpoints(context.VpnServerEndpoints);

        // Rules first, routes second: the mark rule is what points traffic at the table, so removing
        // the table's route while the rule is still live would send marked packets to a table with no
        // route. Failing over to the physical uplink during teardown is a leak, not a convenience.
        commands.Add(Ip(
            "rule", "del", "fwmark", RenderMarkSpec(tunnelMark),
            "prohibit", "priority", Priority(FailClosedRulePriority)));
        commands.Add(Ip(
            "rule", "del", "fwmark", RenderMarkSpec(tunnelMark),
            "lookup", Table(tunnelTable), "priority", Priority(MarkRulePriority)));

        foreach (var endpoint in endpoints)
        {
            commands.Add(Ip(
                "rule", "del", "to", endpoint, "lookup", "main", "priority", Priority(EndpointRulePriority)));
        }

        commands.Add(Ip("route", "flush", "table", Table(tunnelTable)));

        commands.Add(Ip(
            "rule", "del", "fwmark", RenderMarkSpec(bypassMark),
            "prohibit", "priority", Priority(FailClosedRulePriority)));
        commands.Add(Ip(
            "rule", "del", "fwmark", RenderMarkSpec(bypassMark),
            "lookup", Table(bypassTable), "priority", Priority(MarkRulePriority)));
        commands.Add(Ip("route", "flush", "table", Table(bypassTable)));

        return commands;
    }

    private static IpArgv Ip(params string[] arguments) => new(arguments);

    private static string Table(int tableId) => tableId.ToString(CultureInfo.InvariantCulture);

    private static string Priority(int priority) => priority.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Parses, validates and orders the server endpoints.
    /// </summary>
    /// <remarks>
    /// Only IP literals are accepted: a hostname here would be an argument to a privileged command
    /// derived from configuration, and it would also be wrong, because the rule has to match the
    /// packet the core actually sends. Ordering is by address family and then by address, so the same
    /// input always renders the same argv.
    /// </remarks>
    private static IReadOnlyList<string> NormalizeEndpoints(IReadOnlyList<string> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var parsed = new List<IPAddress>(endpoints.Count);

        foreach (var endpoint in endpoints)
        {
            if (!IPAddress.TryParse(endpoint, out var address))
            {
                throw new ArgumentException(
                    $"'{endpoint}' is not an IP address literal. The VPN server endpoints written into "
                    + "policy rules must be resolved addresses, never host names.",
                    nameof(endpoints));
            }

            parsed.Add(address);
        }

        return parsed
            .Distinct()
            .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ThenBy(address => address, Comparer<IPAddress>.Create(CompareAddresses))
            .Select(address => address.ToString())
            .ToArray();
    }

    /// <summary>Byte-wise comparison, so ordering does not depend on the runtime's IPAddress ordering.</summary>
    private static int CompareAddresses(IPAddress left, IPAddress right) =>
        left.GetAddressBytes().AsSpan().SequenceCompareTo(right.GetAddressBytes());

    private static void ValidateNumbers(ProcessRoutingPlan plan)
    {
        // A mark is a 32-bit packet field, but it is also rendered as hex into a rule and used as a
        // mask; restricting it to a positive value below the sign bit keeps the rendering exact and
        // leaves room for the bypass mark derived from it.
        if (plan.FirewallMark is <= 0 or > 0x3FFF_FFFE)
        {
            throw new ArgumentException(
                $"FirewallMark {plan.FirewallMark} is out of range; it must be a positive 30-bit value.",
                nameof(plan));
        }

        if (plan.RoutingTableId is <= 0 or >= 0x7FFF_FFFF)
        {
            throw new ArgumentException(
                $"RoutingTableId {plan.RoutingTableId} is out of range; it must be a positive table id "
                + "with room for the bypass table derived from it.",
                nameof(plan));
        }
    }

    /// <summary>
    /// Escapes a value destined for a quoted nftables string. Interface names and slice components
    /// come from settings and are validated upstream, but escaping here means a future caller cannot
    /// turn a name into ruleset syntax.
    /// </summary>
    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
             .Replace("\"", "\\\"", StringComparison.Ordinal)
             .Replace("\n", string.Empty, StringComparison.Ordinal)
             .Replace("\r", string.Empty, StringComparison.Ordinal);
}
