using System.Globalization;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Platform.Windows.KillSwitch;

/// <summary>A filtering layer this translator emits filters for.</summary>
public enum WfpLayer
{
    /// <summary><c>FWPM_LAYER_ALE_AUTH_CONNECT_V4</c> — outbound IPv4 connection authorization.</summary>
    AleAuthConnectV4 = 0,

    /// <summary><c>FWPM_LAYER_ALE_AUTH_CONNECT_V6</c> — outbound IPv6 connection authorization.</summary>
    AleAuthConnectV6 = 1,
}

public enum WfpAction
{
    /// <summary><c>FWP_ACTION_PERMIT</c>.</summary>
    Permit = 0,

    /// <summary><c>FWP_ACTION_BLOCK</c>.</summary>
    Block = 1,
}

/// <summary>
/// Object lifetime flag a descriptor must be added with.
/// </summary>
/// <remarks>
/// <b>The persistence trap this enum exists to make visible:</b>
/// <c>FWPM_FILTER_FLAG_PERSISTENT</c> and <c>FWPM_FILTER_FLAG_BOOTTIME</c> are
/// <i>mutually exclusive on the same filter</i>, so an always-on rule set needs
/// <b>two equivalent filters</b>, one with each flag — the transition between them is
/// documented as atomic, so there is never a window with neither in force. Keeping the
/// flag on the descriptor (rather than as a parameter of the install loop) is what makes
/// the doubled set a pure, testable property of the translation.
/// </remarks>
public enum WfpFilterFlags
{
    /// <summary>No lifetime flag: the filter lives as long as the engine session (dynamic).</summary>
    None = 0,

    /// <summary><c>FWPM_FILTER_FLAG_PERSISTENT</c> — survives BFE stop/start and reboot.</summary>
    Persistent = 1,

    /// <summary><c>FWPM_FILTER_FLAG_BOOTTIME</c> — enforced from <c>tcpip.sys</c> start until BFE initializes.</summary>
    BootTime = 2,
}

/// <summary>Kinds of match condition this translator emits.</summary>
public enum WfpConditionKind
{
    /// <summary><c>FWPM_CONDITION_ALE_APP_ID</c> — the executable's device path.</summary>
    ApplicationPath = 0,

    /// <summary>
    /// <c>FWPM_CONDITION_ALE_USER_ID</c> — the security descriptor of the token that owns
    /// the connection. Always paired with <see cref="ApplicationPath"/>.
    /// </summary>
    ProcessUserScope = 1,

    /// <summary><c>FWPM_CONDITION_IP_REMOTE_ADDRESS</c>, rendered as a CIDR block.</summary>
    RemoteAddress = 2,

    /// <summary><c>FWPM_CONDITION_IP_REMOTE_PORT</c>.</summary>
    RemotePort = 3,

    /// <summary><c>FWPM_CONDITION_IP_PROTOCOL</c>: <c>tcp</c>, <c>udp</c>, <c>icmp</c> or <c>icmpv6</c>.</summary>
    Protocol = 4,

    /// <summary>
    /// <c>FWPM_CONDITION_FLAGS</c> matched with <c>FWP_MATCH_FLAGS_ALL_SET</c> against
    /// <c>FWP_CONDITION_FLAG_IS_LOOPBACK</c>.
    /// </summary>
    IsLoopback = 5,

    /// <summary>
    /// <c>FWPM_CONDITION_IP_LOCAL_INTERFACE</c> matched against the tunnel adapter's LUID.
    /// </summary>
    /// <remarks>
    /// Carried symbolically as the interface <i>name</i>: a LUID is only valid for the
    /// lifetime of the adapter, so the executor resolves name → LUID with
    /// <c>GetAdaptersAddresses</c> at apply time. This is the predicate that makes the
    /// rule set split-tunnel-safe — Windows Firewall's COM API cannot express it at all,
    /// because <c>INetFwRule.Interfaces</c> takes friendly names, not interface identity.
    /// </remarks>
    LocalInterface = 6,
}

/// <summary>One match condition of a filter descriptor.</summary>
public sealed record WfpCondition
{
    public required WfpConditionKind Kind { get; init; }

    /// <summary>Path, CIDR block, protocol name or interface name, depending on <see cref="Kind"/>.</summary>
    public string? Value { get; init; }

    /// <summary>Port number for <see cref="WfpConditionKind.RemotePort"/>.</summary>
    public int? Port { get; init; }

    public static WfpCondition AppId(string executablePath) => new()
    {
        Kind = WfpConditionKind.ApplicationPath,
        Value = executablePath,
    };

    /// <summary>
    /// "The connection belongs to this process's token" — resolved by the executor from its
    /// own token, which is why it carries no value here.
    /// </summary>
    public static WfpCondition UserScope() => new() { Kind = WfpConditionKind.ProcessUserScope };

    public static WfpCondition RemoteAddress(CidrBlock block) => new()
    {
        Kind = WfpConditionKind.RemoteAddress,
        Value = block.ToString(),
    };

    public static WfpCondition RemotePort(int port) => new()
    {
        Kind = WfpConditionKind.RemotePort,
        Port = port,
    };

    public static WfpCondition Protocol(string protocol) => new()
    {
        Kind = WfpConditionKind.Protocol,
        Value = protocol,
    };

    public static WfpCondition Loopback() => new() { Kind = WfpConditionKind.IsLoopback };

    public static WfpCondition LocalInterface(string interfaceName) => new()
    {
        Kind = WfpConditionKind.LocalInterface,
        Value = interfaceName,
    };

    /// <summary>Stable text form, used for descriptor names and diagnostics.</summary>
    public override string ToString() => Kind switch
    {
        WfpConditionKind.ApplicationPath => $"app={Value}",
        WfpConditionKind.ProcessUserScope => "user=<own-token>",
        WfpConditionKind.RemoteAddress => $"remote={Value}",
        WfpConditionKind.RemotePort => $"remote-port={Port?.ToString(CultureInfo.InvariantCulture)}",
        WfpConditionKind.Protocol => $"proto={Value}",
        WfpConditionKind.IsLoopback => "loopback",
        WfpConditionKind.LocalInterface => $"local-interface={Value}",
        _ => Kind.ToString(),
    };
}

/// <summary>
/// One WFP filter, exactly as much of <c>FWPM_FILTER0</c> as MyVpn sets.
/// </summary>
/// <remarks>
/// A descriptor is data, not a call: the translator that produces it is pure, which is what
/// makes the fail-closed property of the rule set unit-testable on a machine with no
/// privileges and no Windows at all.
/// </remarks>
public sealed record WfpFilterDescriptor
{
    /// <summary>Human-readable, stable name; also the display name of the native filter.</summary>
    public required string Name { get; init; }

    /// <summary>Localization key explaining why the filter exists.</summary>
    public required string ReasonKey { get; init; }

    public required WfpLayer Layer { get; init; }

    /// <summary>
    /// Filter weight within the sub-layer. Arbitration evaluates matching filters from the
    /// highest weight down and stops at the first terminating action, so a permit must have
    /// a strictly higher weight than the catch-all block for the rule set to fail closed
    /// <i>and</i> keep the tunnel alive.
    /// </summary>
    public required byte Weight { get; init; }

    public required WfpAction Action { get; init; }

    /// <summary>Lifetime flags. Two descriptors with the same name suffix differ only here.</summary>
    public WfpFilterFlags Flags { get; init; }

    /// <summary>
    /// Match conditions. An empty list is the unconditional catch-all.
    /// </summary>
    public IReadOnlyList<WfpCondition> Conditions { get; init; } = Array.Empty<WfpCondition>();

    public bool IsCatchAll => Conditions.Count == 0;

    public override string ToString() =>
        $"{Layer} w{Weight.ToString(CultureInfo.InvariantCulture)} {Action} {Name}";
}

/// <summary>
/// The complete, ordered filter set for one Kill Switch plan.
/// </summary>
public sealed record WfpFilterSet
{
    /// <summary>Sublayer/provider key name; also the identity teardown matches.</summary>
    public required string Identifier { get; init; }

    /// <summary>The tunnel interface whose LUID the interface permit must resolve at apply time.</summary>
    public required string TunnelInterface { get; init; }

    /// <summary>True when IPv6 is blocked outright rather than tunnelled.</summary>
    public required bool BlockIpv6 { get; init; }

    /// <summary>True when the set must be installed as persistent + boot-time pairs.</summary>
    public required bool PersistAcrossReboot { get; init; }

    /// <summary>Ordered highest weight first, with the catch-all block last.</summary>
    public required IReadOnlyList<WfpFilterDescriptor> Filters { get; init; }

    /// <summary>The unconditional IPv4 block, or <c>null</c> when the translation is broken.</summary>
    public WfpFilterDescriptor? CatchAllBlockV4 =>
        Filters.FirstOrDefault(f => f.Action == WfpAction.Block && f.IsCatchAll
                                    && f.Layer == WfpLayer.AleAuthConnectV4);

    /// <summary>The unconditional IPv6 block, or <c>null</c>.</summary>
    public WfpFilterDescriptor? CatchAllBlockV6 =>
        Filters.FirstOrDefault(f => f.Action == WfpAction.Block && f.IsCatchAll
                                    && f.Layer == WfpLayer.AleAuthConnectV6);

    /// <summary>Every permit in the set.</summary>
    public IEnumerable<WfpFilterDescriptor> Permits =>
        Filters.Where(f => f.Action == WfpAction.Permit);
}

/// <summary>
/// Translates a <see cref="KillSwitchPlan"/> into WFP filter descriptors.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure function.</b> No P/Invoke, no registry, no command execution: it takes a plan and
/// returns data. The executor in <c>WindowsWfpKillSwitch</c> is then only responsible for
/// resolving names (app paths → app-id blobs, interface name → LUID) and for calling
/// <c>FwpmFilterAdd0</c> inside one transaction. That split is what lets the firewall
/// logic — the part where a mistake means either a leak or a locked-out machine — be
/// verified here on Linux.
/// </para>
/// <para>
/// <b>Why WFP and not the Windows Firewall COM API.</b> Recorded here because the choice is
/// load-bearing and easy to revisit wrongly: explicit block rules beat allow rules with no
/// weighted ordering, so "block everything except the tunnel" is expressible through
/// <c>INetFwPolicy2</c> only by mutating the machine-wide
/// <c>DefaultOutboundAction</c> — a visible, GPO-overridable change to the host's firewall
/// posture. <c>INetFwRule</c> has no interface-LUID condition (so it cannot express "only
/// through the tunnel"), its edits are committed rule by rule rather than transactionally,
/// and <c>Windows.Networking.Vpn</c> would require the <c>networkingVpnProvider</c>
/// restricted capability in a packaged app. There is also no managed
/// <c>Microsoft.Windows.WFP</c> namespace, so <c>fwpuclnt.dll</c> P/Invoke is the only
/// supported route.
/// </para>
/// <para>
/// <b>The recipe.</b> One sub-layer at maximum weight (<c>0xFFFF</c>) so MyVpn's arbitration
/// runs first, containing permits above an unconditional weight-0 block:
/// </para>
/// <list type="number">
/// <item><description>weight 15 — the tunnel client's <c>ALE_APP_ID</c> <b>and</b> an
/// <c>ALE_USER_ID</c> condition, so a same-path copy of the binary cannot inherit the
/// exemption (<c>ALE_APP_ID</c> is a path, not a process identity);</description></item>
/// <item><description>weight 14 — DNS to the configured resolvers, so name resolution
/// cannot deadlock or leak;</description></item>
/// <item><description>weight 13 — loopback, for the local SOCKS/HTTP inbound;</description></item>
/// <item><description>weight 12 — <c>IP_LOCAL_INTERFACE</c> equal to the TUN adapter's
/// LUID, i.e. anything already routed into the tunnel;</description></item>
/// <item><description>weight 12 — DHCP and LAN/ICMP exemptions as the plan requests;</description></item>
/// <item><description>weight 0 — an unconditional block, the fail-closed catch-all.</description></item>
/// </list>
/// <para>
/// A plan with no allow-listed server endpoint is <b>refused</b>, not translated: the
/// catch-all block would otherwise cut off the tunnel's own transport and leave the user
/// with no network at all. <see cref="KillSwitchPlan.Validate"/> already encodes that rule
/// and is re-run here so the translator cannot be called around it.
/// </para>
/// </remarks>
public static class WfpKillSwitchPlanTranslator
{
    /// <summary>Default sublayer/provider identity; matches <c>WindowsNetworkStateManager</c>.</summary>
    public const string DefaultIdentifier = "myvpn_ks";

    /// <summary>Localization keys carried by descriptors, for the UI's rule explanation.</summary>
    public static class Reason
    {
        public const string CoreApplication = "killswitch.reason.core_application";
        public const string ServerEndpoint = "killswitch.reason.server_endpoint";
        public const string Resolver = "killswitch.reason.resolver";
        public const string Loopback = "killswitch.reason.loopback";
        public const string TunnelInterface = "killswitch.reason.tunnel_interface";
        public const string Dhcp = "killswitch.reason.dhcp";
        public const string Icmp = "killswitch.reason.icmp";
        public const string Lan = "killswitch.reason.lan";
        public const string BlockedDestination = "killswitch.reason.blocked_destination";
        public const string DefaultDeny = "killswitch.reason.default_deny";
    }

    /// <summary>IPv4 LAN ranges kept reachable when <see cref="KillSwitchPlan.AllowLan"/> is set.</summary>
    private static readonly string[] LanV4 = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16" };

    /// <summary>IPv6 LAN ranges (unique-local and link-local).</summary>
    private static readonly string[] LanV6 = { "fc00::/7", "fe80::/10" };

    /// <summary>
    /// Translates a plan, or returns the reason it must not be installed.
    /// </summary>
    /// <remarks>
    /// The returned list is ordered by descending weight — the order WFP arbitrates in — and
    /// the ordering is stable, so the persistent/boot-time pair of one logical filter stays
    /// adjacent. The unconditional block is therefore always the last entry.
    /// </remarks>
    public static Result<WfpFilterSet> Translate(KillSwitchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (plan.Mode == KillSwitchMode.Disabled)
        {
            // "Disabled" has no filter set by definition. Returning an empty set would be
            // worse than refusing: an empty set installs nothing and would make a caller
            // believe the machine is protected by rules that do not exist.
            return Result<WfpFilterSet>.Fail(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.not_available",
                ErrorSeverity.Warning,
                "A disabled Kill Switch plan has no WFP filter set; call RemoveAsync instead of "
                + "translating it."));
        }

        // Defence in depth: the safety rule ("never arm a default-drop rule set with no
        // allow-listed server endpoint") lives in the plan, and re-running it here means the
        // translator cannot be reached around it.
        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Result<WfpFilterSet>.Fail(validation.Error!);
        }

        var blocked = Normalize(plan.BlockedDestinations);
        var persistent = plan.Mode == KillSwitchMode.AlwaysOn;

        var filters = new List<WfpFilterDescriptor>();

        // ---- weight 15: the core's own identity, and the server endpoints it must reach ---
        foreach (var layer in Layers(plan))
        {
            foreach (var application in Distinct(plan.AllowedApplications))
            {
                filters.Add(CoreApplicationPermit(plan, layer, application));
            }

            foreach (var endpoint in plan.AllowedEndpoints.Where(e => e.Destination.AddressFamily == layer.Family))
            {
                if (IsBlocked(endpoint.Destination, blocked))
                {
                    // A destination the plan explicitly blocks must not also be permitted;
                    // the permit is dropped rather than left for arbitration to resolve.
                    continue;
                }

                filters.Add(EndpointPermit(layer, endpoint));
            }
        }

        // ---- weight 14: resolvers, so DNS cannot deadlock and cannot leak -----------------
        foreach (var layer in Layers(plan))
        {
            foreach (var destination in plan.AllowedDestinations.Where(d => d.Destination.AddressFamily == layer.Family))
            {
                if (IsBlocked(destination.Destination, blocked))
                {
                    continue;
                }

                filters.Add(DestinationPermit(layer, destination));
            }
        }

        // ---- weight 13: loopback, for the local inbound -----------------------------------
        if (plan.AllowLoopback)
        {
            foreach (var layer in Layers(plan))
            {
                filters.Add(Permit(
                    layer.Layer,
                    WfpWeights.LoopbackPermit,
                    "loopback",
                    Reason.Loopback,
                    WfpCondition.Loopback()));
            }
        }

        // ---- weight 12: the tunnel interface, DHCP, ICMP and LAN --------------------------
        foreach (var layer in Layers(plan))
        {
            filters.Add(Permit(
                layer.Layer,
                WfpWeights.TunnelPermit,
                "tunnel-interface",
                Reason.TunnelInterface,
                WfpCondition.LocalInterface(plan.TunnelInterface)));

            if (plan.AllowDhcp)
            {
                filters.Add(DhcpPermit(layer));
            }

            if (plan.AllowIcmp)
            {
                filters.Add(Permit(
                    layer.Layer,
                    WfpWeights.IcmpPermit,
                    "icmp",
                    Reason.Icmp,
                    WfpCondition.Protocol(layer.IsIpv6 ? "icmpv6" : "icmp")));
            }

            if (plan.AllowLan)
            {
                foreach (var permit in LanPermits(layer))
                {
                    filters.Add(permit);
                }
            }
        }

        // ---- weight 1: explicit blocks ----------------------------------------------------
        foreach (var layer in Layers(plan))
        {
            foreach (var block in blocked.Where(b => b.AddressFamily == layer.Family))
            {
                filters.Add(new WfpFilterDescriptor
                {
                    Name = $"blocked:{block}",
                    ReasonKey = Reason.BlockedDestination,
                    Layer = layer.Layer,
                    Weight = WfpWeights.ExplicitBlock,
                    Action = WfpAction.Block,
                    Conditions = new[] { WfpCondition.RemoteAddress(block) },
                });
            }
        }

        // ---- weight 0: the fail-closed catch-all, one per family --------------------------
        foreach (var layer in new[] { WfpLayer.AleAuthConnectV4, WfpLayer.AleAuthConnectV6 })
        {
            filters.Add(new WfpFilterDescriptor
            {
                Name = "default-deny",
                ReasonKey = Reason.DefaultDeny,
                Layer = layer,
                Weight = WfpWeights.DefaultBlock,
                Action = WfpAction.Block,

                // No conditions at all: this matches 0.0.0.0/0 and ::/0 respectively. It is
                // the rule that makes the set fail closed — every flow that no permit above
                // it matched terminates here.
                Conditions = Array.Empty<WfpCondition>(),
            });
        }

        // Stable ordering: LINQ's OrderBy is documented as stable, so equal-weight
        // descriptors keep the generation order established above and the persistent /
        // boot-time pair of one logical filter stays adjacent.
        var ordered = filters
            .OrderByDescending(f => f.Weight)
            .SelectMany(f => persistent ? WithLifetimePair(f) : new[] { f })
            .ToArray();

        return Result<WfpFilterSet>.Ok(new WfpFilterSet
        {
            Identifier = string.IsNullOrWhiteSpace(plan.Identifier) ? DefaultIdentifier : plan.Identifier,
            TunnelInterface = plan.TunnelInterface,
            BlockIpv6 = plan.BlockIpv6,
            PersistAcrossReboot = persistent,
            Filters = ordered,
        });
    }

    /// <summary>
    /// The layers a plan needs, honouring "block IPv6 outright".
    /// </summary>
    /// <remarks>
    /// When <see cref="KillSwitchPlan.BlockIpv6"/> is set, the IPv6 layer carries the
    /// catch-all block <i>and nothing else</i> — including no tunnel permit. That mirrors
    /// the nftables reference, where the <c>ipv6</c> drop is emitted before the tunnel
    /// accept, and it is the whole point of the option: an IPv6 leak is the most common way
    /// a Kill Switch fails open, so "disable IPv6 while connected" must also mean inside the
    /// tunnel rather than only outside it.
    /// </remarks>
    private static IEnumerable<LayerFamily> Layers(KillSwitchPlan plan)
    {
        yield return new LayerFamily(WfpLayer.AleAuthConnectV4, false);

        if (!plan.BlockIpv6)
        {
            yield return new LayerFamily(WfpLayer.AleAuthConnectV6, true);
        }
    }

    private static WfpFilterDescriptor CoreApplicationPermit(
        KillSwitchPlan plan,
        LayerFamily layer,
        string application) =>
        new()
        {
            Name = $"core-app:{application}",
            ReasonKey = Reason.CoreApplication,
            Layer = layer.Layer,
            Weight = WfpWeights.ApplicationPermit,
            Action = WfpAction.Permit,
            Conditions = new[]
            {
                WfpCondition.AppId(application),

                // Second condition, not decoration: ALE_APP_ID is a path, so every process
                // running that image would otherwise inherit the tunnel exemption. Matching
                // the token's identity as well is what the reference implementation does and
                // what makes a same-path copy useless to an attacker.
                WfpCondition.UserScope(),
            },
        };

    private static WfpFilterDescriptor EndpointPermit(LayerFamily layer, AllowedEndpoint endpoint)
    {
        var conditions = new List<WfpCondition> { WfpCondition.RemoteAddress(endpoint.Destination) };

        if (endpoint.Port > 0)
        {
            conditions.Add(WfpCondition.RemotePort(endpoint.Port));
        }

        foreach (var protocol in Protocols(endpoint.Network))
        {
            conditions.Add(WfpCondition.Protocol(protocol));
        }

        return new WfpFilterDescriptor
        {
            Name = $"endpoint:{endpoint.Destination}:{endpoint.Port.ToString(CultureInfo.InvariantCulture)}",
            ReasonKey = Reason.ServerEndpoint,
            Layer = layer.Layer,
            Weight = WfpWeights.ApplicationPermit,
            Action = WfpAction.Permit,
            Conditions = conditions,
        };
    }

    private static WfpFilterDescriptor DestinationPermit(LayerFamily layer, AllowedEndpoint destination)
    {
        var conditions = new List<WfpCondition> { WfpCondition.RemoteAddress(destination.Destination) };

        if (destination.Port > 0)
        {
            conditions.Add(WfpCondition.RemotePort(destination.Port));
        }

        foreach (var protocol in Protocols(destination.Network))
        {
            conditions.Add(WfpCondition.Protocol(protocol));
        }

        return new WfpFilterDescriptor
        {
            Name = $"resolver:{destination.Destination}:{destination.Port.ToString(CultureInfo.InvariantCulture)}",
            ReasonKey = Reason.Resolver,
            Layer = layer.Layer,
            Weight = WfpWeights.DnsPermit,
            Action = WfpAction.Permit,
            Conditions = conditions,
        };
    }

    /// <summary>
    /// DHCP and IPv6 neighbour discovery, so the interface keeps its own address.
    /// </summary>
    /// <remarks>
    /// Rendered as ordinary protocol/port/address conditions rather than a bespoke condition
    /// kind, because that is exactly what they are: UDP 68 → 67 to the broadcast address for
    /// IPv4, UDP 546 → 547 to <c>ff02::1:2</c> for IPv6. Without them a lease renewal fails
    /// while the tunnel is up, and the machine loses its address on the physical link.
    /// </remarks>
    private static WfpFilterDescriptor DhcpPermit(LayerFamily layer) =>
        layer.IsIpv6
            ? Permit(
                layer.Layer,
                WfpWeights.DhcpPermit,
                "dhcpv6",
                Reason.Dhcp,
                WfpCondition.Protocol("udp"),
                WfpCondition.RemotePort(547),
                WfpCondition.RemoteAddress(CidrBlock.Parse("ff02::1:2/128")))
            : Permit(
                layer.Layer,
                WfpWeights.DhcpPermit,
                "dhcpv4",
                Reason.Dhcp,
                WfpCondition.Protocol("udp"),
                WfpCondition.RemotePort(67),
                WfpCondition.RemoteAddress(CidrBlock.Parse("255.255.255.255/32")));

    /// <summary>
    /// One permit per LAN range.
    /// </summary>
    /// <remarks>
    /// A single filter carrying four <c>IP_REMOTE_ADDRESS</c> conditions would match nothing:
    /// WFP ANDs the conditions of one filter, so a packet would have to be in all four ranges
    /// at once. The ranges are therefore separate filters, which is also how the nftables
    /// renderer's set match behaves.
    /// </remarks>
    private static IEnumerable<WfpFilterDescriptor> LanPermits(LayerFamily layer)
    {
        foreach (var range in layer.IsIpv6 ? LanV6 : LanV4)
        {
            yield return Permit(
                layer.Layer,
                WfpWeights.LanPermit,
                $"lan:{range}",
                Reason.Lan,
                WfpCondition.RemoteAddress(CidrBlock.Parse(range)));
        }
    }

    /// <summary>The one place a permit descriptor is constructed, so weights stay consistent.</summary>
    private static WfpFilterDescriptor Permit(
        WfpLayer layer,
        byte weight,
        string name,
        string reasonKey,
        params WfpCondition[] conditions) =>
        new()
        {
            Name = name,
            ReasonKey = reasonKey,
            Layer = layer,
            Weight = weight,
            Action = WfpAction.Permit,
            Conditions = conditions,
        };

    /// <summary>
    /// Splits a descriptor into its persistent and boot-time twin for always-on plans.
    /// </summary>
    /// <remarks>
    /// The two lifetime flags cannot be combined on one filter, so the equivalent second
    /// filter is added instead; the documented transition between the boot-time and
    /// persistent sets is atomic, so there is never a window in which neither is enforced.
    /// A persistent set additionally requires <c>FWPM_PROVIDER0.serviceName</c> to name an
    /// auto-start service — without it BFE silently adds the objects as <i>disabled</i> at
    /// boot, which is a fail-open that looks like success. The executor sets that field and
    /// reports any <c>FWPM_*_FLAG_DISABLED</c> object it observes on inspection.
    /// </remarks>
    private static IEnumerable<WfpFilterDescriptor> WithLifetimePair(WfpFilterDescriptor descriptor)
    {
        yield return descriptor with
        {
            Name = descriptor.Name + "/persistent",
            Flags = WfpFilterFlags.Persistent,
        };

        yield return descriptor with
        {
            Name = descriptor.Name + "/boottime",
            Flags = WfpFilterFlags.BootTime,
        };
    }

    private static IReadOnlyList<string> Protocols(string? network)
    {
        var protocols = (network ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToLowerInvariant())
            .Where(p => p is "tcp" or "udp")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        // An unset or unrecognised network means "either transport": DNS and the tunnel
        // transport both use TCP and UDP, and narrowing it by guess would break the tunnel.
        return protocols.Length > 0 ? protocols : new[] { "tcp", "udp" };
    }

    private static IReadOnlyList<string> Distinct(IReadOnlyList<string> values) =>
        values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>Deterministic, deduplicated ordering of the explicit block list.</summary>
    private static IReadOnlyList<CidrBlock> Normalize(IReadOnlyList<CidrBlock> blocks) =>
        blocks
            .Distinct()
            .OrderBy(b => b.IsIPv4 ? 0 : 1)
            .ThenBy(b => b.PrefixLength)
            .ThenBy(b => b.Network.ToString(), StringComparer.Ordinal)
            .ToArray();

    /// <summary>True when an allowed destination falls inside a destination the plan blocks.</summary>
    private static bool IsBlocked(CidrBlock allowed, IReadOnlyList<CidrBlock> blocked) =>
        blocked.Any(block => block.AddressFamily == allowed.AddressFamily && block.Contains(allowed));

    /// <summary>One address family and the layer that authorizes its outbound connections.</summary>
    private sealed record LayerFamily(WfpLayer Layer, bool IsIpv6)
    {
        public System.Net.Sockets.AddressFamily Family =>
            IsIpv6 ? System.Net.Sockets.AddressFamily.InterNetworkV6
                   : System.Net.Sockets.AddressFamily.InterNetwork;
    }
}

/// <summary>
/// Filter weights, in one place because the fail-closed property depends on their ordering.
/// </summary>
/// <remarks>
/// 0–15 is the documented partition of the weight space into sixteen ranges, which is what
/// the reference implementation uses; values within a range are auto-weighted by WFP. The
/// invariant that must never be broken: <b>every permit is strictly above
/// <see cref="DefaultBlock"/></b>, and the permits the tunnel depends on are at the top.
/// </remarks>
public static class WfpWeights
{
    /// <summary>The tunnel client's own identity — nothing may outrank it.</summary>
    public const byte ApplicationPermit = 15;

    /// <summary>Configured resolvers, below the core but above everything else.</summary>
    public const byte DnsPermit = 14;

    /// <summary>Loopback, needed by the local inbound.</summary>
    public const byte LoopbackPermit = 13;

    /// <summary>The TUN interface, and the housekeeping protocols that keep it addressable.</summary>
    public const byte TunnelPermit = 12;

    public const byte DhcpPermit = 12;

    public const byte IcmpPermit = 12;

    public const byte LanPermit = 12;

    /// <summary>
    /// Explicit blocks for destinations the plan names. Above the catch-all so they are
    /// evaluated first and produce an address-specific rule in the enumeration, below every
    /// permit — a blocked destination that overlaps a permit is handled by dropping the
    /// permit during translation, not by arbitration.
    /// </summary>
    public const byte ExplicitBlock = 1;

    /// <summary>The unconditional catch-all. Everything unmatched terminates here.</summary>
    public const byte DefaultBlock = 0;
}
