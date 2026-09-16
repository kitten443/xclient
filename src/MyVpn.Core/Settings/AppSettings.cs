using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;

namespace MyVpn.Core.Settings;

/// <summary>How UDP/443 (QUIC) is handled by XUDP. Mirrors Xray's tri-state field.</summary>
public enum XudpUdp443Handling
{
    /// <summary>Do not transport QUIC over XUDP; the client falls back to TCP.</summary>
    Reject = 0,

    /// <summary>Transport QUIC over XUDP.</summary>
    Allow = 1,

    /// <summary>Leave UDP/443 to the ordinary UDP path.</summary>
    Skip = 2,
}

/// <summary>Log verbosity exposed to the user.</summary>
public enum LogVerbosity
{
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// <summary>Which release channel updates are taken from.</summary>
public enum UpdateChannel
{
    Stable = 0,
    Prerelease = 1,
}

/// <summary>Preferred transport strategy for UDP-sensitive traffic.</summary>
public enum TransportStrategy
{
    /// <summary>Pick based on measured conditions. Recommended default.</summary>
    Auto = 0,

    /// <summary>Always use plain UDP over the tunnel.</summary>
    UdpAlways = 1,

    /// <summary>Force UDP-over-TCP tunnelling.</summary>
    UdpOverTcp = 2,

    /// <summary>Never tunnel UDP; drop it. Used in locked-down networks.</summary>
    TcpOnly = 3,
}

/// <summary>
/// The complete, serializable user configuration.
/// </summary>
/// <remarks>
/// <para>
/// A single immutable snapshot rather than scattered mutable properties: the connect
/// use case takes an <see cref="AppSettings"/> value, so a settings change made from
/// the UI cannot mutate the configuration a running tunnel was built from. That
/// removes an entire class of "the tunnel is using half of the old config" bugs.
/// </para>
/// <para>
/// Every nested record validates itself; <see cref="Validate"/> aggregates so the UI
/// can highlight each offending field instead of failing on the first one.
/// </para>
/// </remarks>
public sealed record AppSettings
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    // ---- appearance / localization --------------------------------------

    public AppLanguage Language { get; init; } = AppLanguage.System;

    public AppTheme Theme { get; init; } = AppTheme.System;

    public UiDensity Density { get; init; } = UiDensity.Comfortable;

    /// <summary>UI scale factor, 0.75..2.0.</summary>
    public double UiScale { get; init; } = 1.0;

    /// <summary>Accent colour as <c>#RRGGBB</c>, or <c>null</c> for the theme default.</summary>
    public string? AccentColor { get; init; }

    /// <summary>Reveals the Advanced Mode sections.</summary>
    public bool AdvancedMode { get; init; }

    public bool OnboardingCompleted { get; init; }

    // ---- connection ------------------------------------------------------

    public TunnelMode TunnelMode { get; init; } = TunnelMode.Tun;

    public KillSwitchMode KillSwitch { get; init; } = KillSwitchMode.OnDemand;

    /// <summary>
    /// Default is <see cref="Ipv6Mode.DisableWhileConnected"/>: the only mode that is
    /// leak-free on every supported platform regardless of whether the server has
    /// IPv6 connectivity.
    /// </summary>
    public Ipv6Mode Ipv6 { get; init; } = Ipv6Mode.DisableWhileConnected;

    public ProcessRoutingMode ProcessRouting { get; init; } = ProcessRoutingMode.Off;

    public Guid? SelectedProfileId { get; init; }

    public bool AutoSelectEnabled { get; init; }

    /// <summary>Automatically reconnect when the core exits unexpectedly.</summary>
    public bool AutoReconnect { get; init; } = true;

    /// <summary>Seconds to wait between reconnect attempts.</summary>
    public int ReconnectDelaySeconds { get; init; } = 3;

    /// <summary>Maximum consecutive core restarts before giving up and staying in Faulted.</summary>
    public int MaxRestartAttempts { get; init; } = 5;

    public DnsSettings Dns { get; init; } = new();

    public RoutingSettings Routing { get; init; } = new();

    public TunSettings Tun { get; init; } = new();

    public MuxSettings Mux { get; init; } = new();

    public ProxySettings Proxy { get; init; } = new();

    public ProcessRoutingSettings ProcessRoutingSettings { get; init; } = new();

    public ConnectivitySettings Connectivity { get; init; } = new();

    public UpdateSettings Updates { get; init; } = new();

    public LoggingSettings Logging { get; init; } = new();

    public SubscriptionSettings Subscriptions { get; init; } = new();

    public PrivacySettings Privacy { get; init; } = new();

    /// <summary>Validates the whole tree, returning every problem found.</summary>
    public Result Validate()
    {
        var errors = new List<MyVpnError>();

        if (SchemaVersion is < 1 or > CurrentSchemaVersion)
        {
            errors.Add(new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.schema_unsupported")
                .WithArg("version", SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        if (UiScale is < 0.75 or > 2.0)
        {
            errors.Add(new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.ui_scale_range"));
        }

        if (AccentColor is not null && !IsHexColor(AccentColor))
        {
            errors.Add(new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.accent_color_format"));
        }

        if (ReconnectDelaySeconds is < 0 or > 300)
        {
            errors.Add(new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.reconnect_delay_range"));
        }

        if (MaxRestartAttempts is < 0 or > 100)
        {
            errors.Add(new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.max_restarts_range"));
        }

        errors.AddRange(Dns.Validate());
        errors.AddRange(Routing.Validate());
        errors.AddRange(Tun.Validate());
        errors.AddRange(Mux.Validate());
        errors.AddRange(Proxy.Validate());
        errors.AddRange(ProcessRoutingSettings.Validate());
        errors.AddRange(Connectivity.Validate());
        errors.AddRange(Updates.Validate());
        errors.AddRange(Logging.Validate());
        errors.AddRange(Subscriptions.Validate());

        return errors.Count == 0
            ? Result.Ok()
            : Result.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.settings.invalid",
                ErrorSeverity.Error,
                string.Join("; ", errors.Select(e => e.ToString())))
            {
                Args = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["count"] = errors.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                },
            });
    }

    /// <summary>
    /// Returns a copy with out-of-range values clamped to their nearest legal value.
    /// </summary>
    /// <remarks>
    /// Used when loading a settings file written by a newer or a corrupted build: the
    /// user should end up with a working app rather than a hard failure, and the
    /// original file is preserved for recovery.
    /// </remarks>
    public AppSettings Normalize() => this with
    {
        SchemaVersion = CurrentSchemaVersion,
        UiScale = Math.Clamp(UiScale, 0.75, 2.0),
        ReconnectDelaySeconds = Math.Clamp(ReconnectDelaySeconds, 0, 300),
        MaxRestartAttempts = Math.Clamp(MaxRestartAttempts, 0, 100),
        AccentColor = AccentColor is not null && IsHexColor(AccentColor) ? AccentColor : null,
        Tun = Tun.Normalize(),
        Mux = Mux.Normalize(),
        Logging = Logging.Normalize(),
        Subscriptions = Subscriptions.Normalize(),
    };

    private static bool IsHexColor(string value)
    {
        if (value.Length != 7 || value[0] != '#')
        {
            return false;
        }

        for (var i = 1; i < value.Length; i++)
        {
            if (!Uri.IsHexDigit(value[i]))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>DNS behaviour.</summary>
public sealed record DnsSettings
{
    public DnsMode Mode { get; init; } = DnsMode.ThroughTunnel;

    /// <summary>Resolver addresses for <see cref="DnsMode.Custom"/> / through-tunnel.</summary>
    public IReadOnlyList<string> Servers { get; init; } = new[] { "1.1.1.1", "8.8.8.8" };

    /// <summary>DoH endpoint; must be HTTPS.</summary>
    public string? DohUrl { get; init; }

    /// <summary>DoT host name.</summary>
    public string? DotHost { get; init; }

    public int DotPort { get; init; } = 853;

    /// <summary>
    /// Block cleartext DNS that would escape the tunnel. On by default; turning it off
    /// is the single most common way to create a DNS leak, so it is surfaced as an
    /// Advanced Mode toggle with an explicit warning.
    /// </summary>
    public bool BlockPlainDnsLeaks { get; init; } = true;

    /// <summary>
    /// FakeDNS. Off by default. It improves some connection- establishment patterns but
    /// breaks captive portals and some local development workflows, and it is an
    /// Advanced Mode feature.
    /// </summary>
    public bool EnableFakeDns { get; init; }

    /// <summary>Honour the OS hosts file.</summary>
    public bool RespectSystemHosts { get; init; } = true;

    /// <summary>Domains resolved by the system resolver rather than through the tunnel.</summary>
    public IReadOnlyList<string> SplitDnsDomains { get; init; } = Array.Empty<string>();

    public IEnumerable<MyVpnError> Validate()
    {
        if (Mode == DnsMode.Custom && Servers.Count == 0)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.custom_requires_servers");
        }

        foreach (var server in Servers)
        {
            if (!NetworkText.IsIpAddress(server))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.server_not_ip")
                    .WithArg("server", server);
            }
        }

        if (Mode == DnsMode.Doh)
        {
            if (string.IsNullOrWhiteSpace(DohUrl)
                || !Uri.TryCreate(DohUrl, UriKind.Absolute, out var uri)
                || uri.Scheme != Uri.UriSchemeHttps)
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.doh_requires_https");
            }
        }

        if (Mode == DnsMode.Dot && !NetworkText.IsValidHostName(DotHost))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.dot_requires_host");
        }

        if (DotPort is < 1 or > 65535)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.dot_port_range");
        }

        foreach (var domain in SplitDnsDomains)
        {
            if (!NetworkText.IsValidHostName(domain))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.dns.split_domain_invalid")
                    .WithArg("domain", domain);
            }
        }
    }
}

/// <summary>A user-defined routing rule.</summary>
public sealed record CustomRoutingRule
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");

    public bool Enabled { get; init; } = true;

    /// <summary>Localization key for the rule's purpose, or a user-provided label.</summary>
    public string? Label { get; init; }

    /// <summary>Domain patterns; see <see cref="NetworkText.IsValidDomainPattern"/>.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> IpCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<int> Ports { get; init; } = Array.Empty<int>();

    /// <summary><c>tcp</c>, <c>udp</c> or empty for both.</summary>
    public string? Network { get; init; }

    /// <summary>Process names or absolute paths this rule applies to.</summary>
    public IReadOnlyList<string> Processes { get; init; } = Array.Empty<string>();

    /// <summary>True to send matching traffic through the tunnel, false to send it direct.</summary>
    public bool Proxy { get; init; } = true;

    /// <summary>The Xray outbound tag this rule targets.</summary>
    public string OutboundTag => Proxy ? "proxy" : "direct";

    public IEnumerable<MyVpnError> Validate()
    {
        if (Domains.Count == 0 && IpCidrs.Count == 0 && Ports.Count == 0 && Processes.Count == 0)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.rule_empty")
                .WithArg("rule", Label ?? Id);
        }

        foreach (var domain in Domains)
        {
            if (!NetworkText.IsValidDomainPattern(domain))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.domain_invalid")
                    .WithArg("domain", domain);
            }
        }

        foreach (var cidr in IpCidrs)
        {
            if (!NetworkText.IsIpOrCidr(cidr))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.cidr_invalid")
                    .WithArg("cidr", cidr);
            }
        }

        foreach (var port in Ports)
        {
            if (port is < 1 or > 65535)
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.port_range")
                    .WithArg("port", port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        if (Network is not (null or "" or "tcp" or "udp" or "tcp,udp"))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.network_invalid")
                .WithArg("network", Network);
        }
    }
}

/// <summary>Routing behaviour.</summary>
public sealed record RoutingSettings
{
    /// <summary>Keep RFC1918/LAN destinations off the tunnel.</summary>
    public bool BypassLan { get; init; } = true;

    public bool BypassLocalhost { get; init; } = true;

    /// <summary>Block ad/tracker domains using the geosite ad list.</summary>
    public bool BlockAds { get; init; }

    /// <summary>Route by destination country using geoip.</summary>
    public bool RouteByGeoIp { get; init; }

    /// <summary>Country codes to route directly, e.g. <c>ru</c>.</summary>
    public IReadOnlyList<string> DirectGeoIpCountries { get; init; } = Array.Empty<string>();

    /// <summary>Country codes to route through the tunnel.</summary>
    public IReadOnlyList<string> ProxyGeoIpCountries { get; init; } = Array.Empty<string>();

    /// <summary>geosite tags routed directly, e.g. <c>category-ads-all</c>.</summary>
    public IReadOnlyList<string> DirectGeoSites { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DirectDomains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> ProxyDomains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DirectIpCidrs { get; init; } = Array.Empty<string>();

    /// <summary>Xray <c>domainStrategy</c> for the routing section.</summary>
    public string DomainStrategy { get; init; } = "IPIfNonMatch";

    /// <summary>Enable Xray domain sniffing so domain rules work for raw-IP connections.</summary>
    public bool EnableSniffing { get; init; } = true;

    public IReadOnlyList<CustomRoutingRule> CustomRules { get; init; } = Array.Empty<CustomRoutingRule>();

    public IEnumerable<MyVpnError> Validate()
    {
        if (DomainStrategy is not ("AsIs" or "IPIfNonMatch" or "IPOnDemand"))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.domain_strategy_invalid")
                .WithArg("strategy", DomainStrategy);
        }

        foreach (var domain in DirectDomains.Concat(ProxyDomains))
        {
            if (!NetworkText.IsValidDomainPattern(domain))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.domain_invalid")
                    .WithArg("domain", domain);
            }
        }

        foreach (var cidr in DirectIpCidrs)
        {
            if (!NetworkText.IsIpOrCidr(cidr))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.cidr_invalid")
                    .WithArg("cidr", cidr);
            }
        }

        foreach (var country in DirectGeoIpCountries.Concat(ProxyGeoIpCountries))
        {
            if (!IsGeoCode(country))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.geo_code_invalid")
                    .WithArg("code", country);
            }
        }

        foreach (var site in DirectGeoSites)
        {
            if (!IsGeoCode(site))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.routing.geo_code_invalid")
                    .WithArg("code", site);
            }
        }

        foreach (var rule in CustomRules)
        {
            foreach (var error in rule.Validate())
            {
                yield return error;
            }
        }
    }

    private static bool IsGeoCode(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 64
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '!' or '+' or '.');
}

/// <summary>Native Xray TUN inbound behaviour.</summary>
public sealed record TunSettings
{
    /// <summary>MTU, or <c>0</c> to let the platform choose. Recommended: Auto.</summary>
    public int Mtu { get; init; }

    /// <summary>Interface name, or <c>null</c> for the platform default.</summary>
    public string? InterfaceName { get; init; }

    /// <summary>Install routes automatically for the whole default prefix.</summary>
    public bool AutoRoute { get; init; } = true;

    /// <summary>
    /// Refuse to leak around the tunnel when a route cannot be installed. On by default:
    /// with this off a failed route add silently falls back to direct egress.
    /// </summary>
    public bool StrictRoute { get; init; } = true;

    /// <summary>Destinations excluded from the tunnel even in TUN mode.</summary>
    public IReadOnlyList<string> ExcludedRoutes { get; init; } = Array.Empty<string>();

    /// <summary>Xray sniffing inside the TUN inbound.</summary>
    public bool Sniffing { get; init; } = true;

    /// <summary>Sniff for routing decisions only, without overriding the destination.</summary>
    public bool RouteOnly { get; init; }

    public IEnumerable<MyVpnError> Validate()
    {
        if (Mtu != 0 && (Mtu < 576 || Mtu > 9000))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.tun.mtu_range")
                .WithArg("mtu", Mtu.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        // 1280 is the IPv6 minimum link MTU; anything lower breaks IPv6 entirely.
        if (Mtu is > 0 and < 1280)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.tun.mtu_ipv6_minimum")
                .WithArg("mtu", Mtu.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        if (InterfaceName is not null && !NetworkText.IsValidHostName(InterfaceName))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.tun.interface_name_invalid");
        }

        foreach (var route in ExcludedRoutes)
        {
            if (!NetworkText.IsIpOrCidr(route))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.tun.excluded_route_invalid")
                    .WithArg("route", route);
            }
        }
    }

    public TunSettings Normalize()
    {
        if (Mtu == 0 || (Mtu >= 576 && Mtu <= 9000))
        {
            return this;
        }

        return this with { Mtu = 0 };
    }
}

/// <summary>Outbound multiplexing.</summary>
public sealed record MuxSettings
{
    /// <summary>
    /// Off by default. Mux reduces handshake overhead but interacts badly with some
    /// server configurations and can hurt throughput on fast links, so it is an
    /// Advanced Mode option rather than a default.
    /// </summary>
    public bool Enabled { get; init; }

    public int Concurrency { get; init; } = 8;

    /// <summary>XUDP concurrency; <c>-1</c> disables XUDP multiplexing.</summary>
    public int XudpConcurrency { get; init; } = 8;

    /// <summary>
    /// How UDP/443 (QUIC) is treated when XUDP multiplexing is active.
    /// </summary>
    /// <remarks>
    /// Modelled as a tri-state rather than a boolean because Xray's corresponding field is the
    /// string <c>"reject" | "allow" | "skip"</c>. A boolean cannot express <c>skip</c>, and
    /// collapsing it into one of the other two would silently change QUIC behaviour.
    /// </remarks>
    public XudpUdp443Handling XudpProxyUdp443 { get; init; } = XudpUdp443Handling.Reject;

    public IEnumerable<MyVpnError> Validate()
    {
        if (Enabled && Concurrency is < 1 or > 1024)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.mux.concurrency_range");
        }

        if (XudpConcurrency is < -1 or > 1024 || XudpConcurrency == 0)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.mux.xudp_concurrency_range");
        }
    }

    public MuxSettings Normalize() => this with
    {
        Concurrency = Math.Clamp(Concurrency, 1, 1024),
        XudpConcurrency = XudpConcurrency == 0 ? 8 : Math.Clamp(XudpConcurrency, -1, 1024),
    };
}

/// <summary>System proxy behaviour used in <see cref="TunnelMode.SystemProxy"/>.</summary>
public sealed record ProxySettings
{
    /// <summary>Local inbound port for the SOCKS/HTTP listener.</summary>
    public int ListenPort { get; init; } = 10808;

    /// <summary>Expose SOCKS as well as HTTP.</summary>
    public bool EnableSocks { get; init; } = true;

    public bool EnableHttp { get; init; } = true;

    /// <summary>Use a PAC script instead of a global proxy.</summary>
    public bool UsePac { get; init; }

    /// <summary>User-supplied PAC URL or file path. Validated before use.</summary>
    public string? CustomPacUrl { get; init; }

    /// <summary>Domains that bypass the proxy (direct connection).</summary>
    public IReadOnlyList<string> BypassDomains { get; init; } = new[] { "localhost", "127.0.0.1" };

    /// <summary>Address ranges that bypass the proxy (direct connection).</summary>
    public IReadOnlyList<string> BypassIpCidrs { get; init; } = new[] { "::1" };

    public IEnumerable<MyVpnError> Validate()
    {
        if (ListenPort is < 1024 or > 65535)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.proxy.port_range")
                .WithArg("port", ListenPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        if (!EnableSocks && !EnableHttp)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.proxy.no_listener");
        }

        if (UsePac && !string.IsNullOrWhiteSpace(CustomPacUrl))
        {
            if (!Uri.TryCreate(CustomPacUrl, UriKind.Absolute, out var uri)
                || uri.Scheme is not ("http" or "https" or "file"))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.proxy.pac_url_invalid");
            }
        }

        foreach (var domain in BypassDomains)
        {
            if (!NetworkText.IsValidHostName(domain))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.proxy.bypass_domain_invalid")
                    .WithArg("domain", domain);
            }
        }

        foreach (var cidr in BypassIpCidrs)
        {
            if (!NetworkText.IsIpOrCidr(cidr))
            {
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.proxy.bypass_cidr_invalid")
                    .WithArg("cidr", cidr);
            }
        }
    }
}

/// <summary>A named, reusable process-routing profile ("Games Direct", "Work VPN", ...).</summary>
public sealed record ProcessRoutingProfile
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");

    public string Name { get; init; } = string.Empty;

    /// <summary>Built-in profiles cannot be deleted, only detached.</summary>
    public bool IsBuiltIn { get; init; }

    public ProcessRoutingMode Mode { get; init; } = ProcessRoutingMode.BypassVpn;

    public IReadOnlyList<ProcessSelector> Selectors { get; init; } = Array.Empty<ProcessSelector>();
}

/// <summary>
/// How a process is identified for routing.
/// </summary>
/// <remarks>
/// Selectors are matched on stable identifiers, never on a user-typed command line.
/// <see cref="ExecutablePath"/> is always compared as a full, normalized absolute path
/// so that a rule for <c>C:\Games\game.exe</c> cannot be satisfied by
/// <c>C:\Temp\game.exe</c>.
/// </remarks>
public sealed record ProcessSelector
{
    public ProcessSelectorKind Kind { get; init; } = ProcessSelectorKind.ExecutableName;

    /// <summary>Executable file name without a directory, e.g. <c>game.exe</c>.</summary>
    public string? ExecutableName { get; init; }

    /// <summary>Absolute path to the executable or to a containing directory.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Apply this selector to processes started by a matching process.</summary>
    public bool MatchChildren { get; init; }

    public IEnumerable<MyVpnError> Validate()
    {
        switch (Kind)
        {
            case ProcessSelectorKind.ExecutableName:
                if (string.IsNullOrWhiteSpace(ExecutableName) || ExecutableName.Contains('/')
                    || ExecutableName.Contains('\\'))
                {
                    yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.process.name_invalid");
                }

                break;
            case ProcessSelectorKind.ExecutablePath:
            case ProcessSelectorKind.Directory:
                if (string.IsNullOrWhiteSpace(ExecutablePath) || !Path.IsPathRooted(ExecutablePath))
                {
                    yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.process.path_not_absolute");
                }

                break;
            default:
                yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.process.selector_unsupported");
                break;
        }
    }
}

public enum ProcessSelectorKind
{
    ExecutableName = 0,
    ExecutablePath = 1,
    Directory = 2,
}

/// <summary>Per-process routing configuration.</summary>
public sealed record ProcessRoutingSettings
{
    public ProcessRoutingMode Mode { get; init; } = ProcessRoutingMode.Off;

    /// <summary>Inline selectors for <see cref="ProcessRoutingMode.BypassVpn"/> / <see cref="ProcessRoutingMode.VpnOnly"/>.</summary>
    public IReadOnlyList<ProcessSelector> Selectors { get; init; } = Array.Empty<ProcessSelector>();

    /// <summary>Named profiles shown as one-click presets.</summary>
    public IReadOnlyList<ProcessRoutingProfile> Profiles { get; init; } = Array.Empty<ProcessRoutingProfile>();

    public string? ActiveProfileId { get; init; }

    /// <summary>Apply rules to child processes of a matched process.</summary>
    public bool TrackChildProcesses { get; init; } = true;

    public IEnumerable<MyVpnError> Validate()
    {
        foreach (var selector in Selectors)
        {
            foreach (var error in selector.Validate())
            {
                yield return error;
            }
        }

        foreach (var selector in Profiles.SelectMany(p => p.Selectors))
        {
            foreach (var error in selector.Validate())
            {
                yield return error;
            }
        }

        if (Mode != ProcessRoutingMode.Off && Selectors.Count == 0 && ActiveProfileId is null
            && Profiles.Count == 0)
        {
            yield return new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.process.mode_without_selection",
                ErrorSeverity.Warning);
        }
    }
}

/// <summary>Transport/NAT behaviour.</summary>
public sealed record ConnectivitySettings
{
    public TransportStrategy Transport { get; init; } = TransportStrategy.Auto;

    /// <summary>
    /// Request full-cone UDP behaviour from the core. Off by default because it is only
    /// honoured by compatible servers and can otherwise mask failures.
    /// </summary>
    public bool FullConeUdp { get; init; }

    /// <summary>Bind outbound sockets to the physical interface to avoid loops.</summary>
    public bool BindToPhysicalInterface { get; init; } = true;

    /// <summary>Preferred physical interface, or <c>null</c> to auto-detect the default route.</summary>
    public string? PhysicalInterface { get; init; }

    /// <summary>TCP keep-alive interval in seconds; 0 disables.</summary>
    public int TcpKeepAliveSeconds { get; init; } = 15;

    /// <summary>Fall back to TCP-only when UDP is detected as blocked.</summary>
    public bool AutoFallbackOnUdpBlock { get; init; } = true;

    /// <summary>How long to wait for the tunnel to become healthy before failing.</summary>
    public int ConnectTimeoutSeconds { get; init; } = 30;

    public IEnumerable<MyVpnError> Validate()
    {
        if (TcpKeepAliveSeconds is < 0 or > 3600)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.connectivity.keepalive_range");
        }

        if (ConnectTimeoutSeconds is < 5 or > 300)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.connectivity.timeout_range");
        }

        if (PhysicalInterface is not null && !NetworkText.IsValidHostName(PhysicalInterface))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.connectivity.interface_invalid");
        }
    }
}

/// <summary>Update behaviour.</summary>
public sealed record UpdateSettings
{
    public bool AutoCheckForAppUpdates { get; init; } = true;

    public bool AutoUpdateCore { get; init; } = true;

    public bool AutoUpdateGeoData { get; init; } = true;

    public UpdateChannel Channel { get; init; } = UpdateChannel.Stable;

    /// <summary>Hours between automatic checks; 0 disables the timer.</summary>
    public int CheckIntervalHours { get; init; } = 24;

    public DateTimeOffset? LastCheckedAt { get; init; }

    /// <summary>
    /// Verify a detached signature on app update packages in addition to the checksum.
    /// Off only when the distribution channel cannot provide one; checksums are always
    /// verified regardless.
    /// </summary>
    public bool RequireSignature { get; init; } = true;

    /// <summary>Base URL of the release feed.</summary>
    public string? FeedUrl { get; init; }

    public IEnumerable<MyVpnError> Validate()
    {
        if (CheckIntervalHours is < 0 or > 24 * 30)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.updates.interval_range");
        }

        if (FeedUrl is not null
            && (!Uri.TryCreate(FeedUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.updates.feed_requires_https");
        }
    }
}

/// <summary>Logging behaviour.</summary>
public sealed record LoggingSettings
{
    public LogVerbosity Verbosity { get; init; } = LogVerbosity.Info;

    /// <summary>Maximum size of a single log file in megabytes before rotation.</summary>
    public int MaxFileSizeMb { get; init; } = 10;

    /// <summary>Number of rotated files kept.</summary>
    public int MaxFiles { get; init; } = 5;

    /// <summary>Days to retain rotated logs.</summary>
    public int RetentionDays { get; init; } = 14;

    public IEnumerable<MyVpnError> Validate()
    {
        if (MaxFileSizeMb is < 1 or > 1024)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.logging.file_size_range");
        }

        if (MaxFiles is < 1 or > 100)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.logging.files_range");
        }

        if (RetentionDays is < 1 or > 365)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.logging.retention_range");
        }
    }

    public LoggingSettings Normalize() => this with
    {
        MaxFileSizeMb = Math.Clamp(MaxFileSizeMb, 1, 1024),
        MaxFiles = Math.Clamp(MaxFiles, 1, 100),
        RetentionDays = Math.Clamp(RetentionDays, 1, 365),
    };
}

/// <summary>Subscription behaviour.</summary>
public sealed record SubscriptionSettings
{
    public bool AutoUpdate { get; init; } = true;

    /// <summary>Hours between automatic subscription refreshes; 0 disables.</summary>
    public int UpdateIntervalHours { get; init; } = 12;

    /// <summary>User-Agent sent when fetching a subscription.</summary>
    public string UserAgent { get; init; } = "MyVpn/0.1";

    /// <summary>Allow subscription URLs over plain HTTP. Off by default.</summary>
    public bool AllowInsecureHttp { get; init; }

    /// <summary>Time to wait for a subscription response.</summary>
    public int TimeoutSeconds { get; init; } = 30;

    /// <summary>Maximum accepted subscription body size in megabytes.</summary>
    public int MaxBodySizeMb { get; init; } = 16;

    /// <summary>Maximum accepted size of a single response header value, in bytes.</summary>
    public int MaxHeaderValueBytes { get; init; } = 8192;

    public IEnumerable<MyVpnError> Validate()
    {
        if (UpdateIntervalHours is < 0 or > 24 * 30)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.subscriptions.interval_range");
        }

        if (TimeoutSeconds is < 5 or > 600)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.subscriptions.timeout_range");
        }

        if (MaxBodySizeMb is < 1 or > 256)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.subscriptions.body_size_range");
        }

        if (MaxHeaderValueBytes is < 256 or > 65536)
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.subscriptions.header_size_range");
        }

        if (string.IsNullOrWhiteSpace(UserAgent))
        {
            yield return new MyVpnError(ErrorCodes.ConfigInvalid, "error.subscriptions.user_agent_required");
        }
    }

    public SubscriptionSettings Normalize() => this with
    {
        UpdateIntervalHours = Math.Clamp(UpdateIntervalHours, 0, 24 * 30),
        TimeoutSeconds = Math.Clamp(TimeoutSeconds, 5, 600),
        MaxBodySizeMb = Math.Clamp(MaxBodySizeMb, 1, 256),
        MaxHeaderValueBytes = Math.Clamp(MaxHeaderValueBytes, 256, 65536),
        UserAgent = string.IsNullOrWhiteSpace(UserAgent) ? "MyVpn/0.1" : UserAgent,
    };
}

/// <summary>
/// Privacy switches. All off by default and there is no way for the application to
/// enable them without an explicit user action.
/// </summary>
public sealed record PrivacySettings
{
    /// <summary>Anonymous usage statistics. Default: disabled.</summary>
    public bool TelemetryEnabled { get; init; }

    /// <summary>Automatic crash upload. Default: disabled.</summary>
    public bool CrashReportsEnabled { get; init; }

    /// <summary>
    /// Include subscription URLs and credentials in an exported diagnostics bundle.
    /// Default: disabled — export redacts them.
    /// </summary>
    public bool IncludeSecretsInDiagnostics { get; init; }
}
