using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Xray;

namespace MyVpn.Core.Configuration;

/// <summary>Everything the config builder needs, as a single immutable input.</summary>
public sealed record XrayConfigRequest
{
    public required ServerProfile Profile { get; init; }

    public required AppSettings Settings { get; init; }

    /// <summary>Which geo assets are actually usable; geo rules are omitted otherwise.</summary>
    public required GeoRuleAvailability GeoAvailability { get; init; }

    /// <summary>Resolved server addresses, needed for direct-routing exemptions.</summary>
    public IReadOnlyList<ServerEndpoint> ResolvedServerEndpoints { get; init; } = Array.Empty<ServerEndpoint>();

    /// <summary>Absolute geo asset directory, when the core is new enough to accept the <c>env</c> object.</summary>
    public string? AssetDirectory { get; init; }

    /// <summary>Detected core version; gates the <c>env</c> object and TUN schema choices.</summary>
    public XrayVersion CoreVersion { get; init; } = XrayVersionPolicy.Recommended;

    /// <summary>Interface name to request for the TUN device.</summary>
    public string TunnelInterfaceName { get; init; } = "myvpn0";

    /// <summary>Local inbound ports used in system-proxy mode.</summary>
    public int SocksPort { get; init; } = 10808;

    public int HttpPort { get; init; } = 10809;

    /// <summary>Path for the core's own error log, or <c>null</c> to use stderr.</summary>
    public string? ErrorLogPath { get; init; }

    public PlatformTarget Platform { get; init; } = PlatformTarget.Linux;
}

public enum PlatformTarget
{
    Windows = 0,
    Linux = 1,
    MacOS = 2,
}

/// <summary>Build result: the config plus anything the user should be told.</summary>
public sealed record XrayConfigBuildResult
{
    public required XrayConfig Config { get; init; }

    /// <summary>Non-fatal notes, e.g. "geo rules were omitted".</summary>
    public IReadOnlyList<MyVpnError> Warnings { get; init; } = Array.Empty<MyVpnError>();

    /// <summary>True when the config references geo data.</summary>
    public bool UsesGeoData { get; init; }
}

/// <summary>
/// Builds an Xray configuration from a profile and user settings.
/// </summary>
/// <remarks>
/// <para>
/// Pure and side-effect free: it reads no files and starts no processes, so every branch is
/// unit-testable. The two behaviours that matter most are defensive:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Geo data is never referenced unless it is usable.</b> A routing rule naming
/// <c>geoip:cn</c> when <c>geoip.dat</c> is missing makes Xray refuse to start at all. Instead
/// the rule is omitted, a warning is produced, and the tunnel still comes up — which is the
/// requirement that a damaged geo database must not break the connection.
/// </description></item>
/// <item><description>
/// <b>Values are validated before they reach the core.</b> A malformed gateway or DNS entry
/// panics the Windows TUN path inside Xray (<c>netip.MustParsePrefix</c>), so it is rejected
/// here with a clear error rather than crashing the core.
/// </description></item>
/// </list>
/// </remarks>
public static class XrayConfigBuilder
{
    /// <summary>Outbound tag carrying proxied traffic.</summary>
    public const string ProxyTag = "proxy";

    /// <summary>Outbound tag for direct connections.</summary>
    public const string DirectTag = "direct";

    /// <summary>Outbound tag that drops traffic.</summary>
    public const string BlockTag = "block";

    /// <summary>Outbound tag used to hijack DNS queries.</summary>
    public const string DnsOutTag = "dns-out";

    public const string TunInboundTag = "tun-in";
    public const string SocksInboundTag = "socks-in";
    public const string HttpInboundTag = "http-in";

    /// <summary>
    /// The Xray version that introduced the root <c>env</c> object. Below this, the asset
    /// directory can only be delivered as a real process environment variable.
    /// </summary>
    public static readonly XrayVersion MinimumVersionForRootEnv = new(26, 7, 11);

    public static Result<XrayConfigBuildResult> Build(XrayConfigRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var profileValidation = request.Profile.Validate();
        if (profileValidation.IsFailure)
        {
            return Result<XrayConfigBuildResult>.Fail(profileValidation.Error!);
        }

        var settingsValidation = request.Settings.Validate();
        if (settingsValidation.IsFailure)
        {
            return Result<XrayConfigBuildResult>.Fail(settingsValidation.Error!);
        }

        var warnings = new List<MyVpnError>();

        // ---- inbounds ----------------------------------------------------
        var inbounds = BuildInbounds(request, warnings);
        if (inbounds.IsFailure)
        {
            return Result<XrayConfigBuildResult>.Fail(inbounds.Error!);
        }

        // ---- outbounds ---------------------------------------------------
        var outbounds = BuildOutbounds(request, warnings);
        if (outbounds.IsFailure)
        {
            return Result<XrayConfigBuildResult>.Fail(outbounds.Error!);
        }

        // ---- routing -----------------------------------------------------
        var routing = BuildRouting(request, warnings);

        var config = new XrayConfig
        {
            Env = BuildEnv(request),
            Log = BuildLog(request),
            Dns = BuildDns(request, warnings),
            Inbounds = inbounds.Value,
            Outbounds = outbounds.Value,
            Routing = routing,
            Policy = BuildPolicy(),
            Stats = new JsonObject(),
        };

        return Result<XrayConfigBuildResult>.Ok(new XrayConfigBuildResult
        {
            Config = config,
            Warnings = warnings,
            UsesGeoData = routing.Rules.Any(r => r.Domain?.Any(d => d.StartsWith("geosite:", StringComparison.Ordinal)) == true
                                                 || r.Ip?.Any(i => i.StartsWith("geoip:", StringComparison.Ordinal)) == true),
        });
    }

    /// <summary>Serializes a config with the options Xray expects.</summary>
    public static string Serialize(XrayConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return JsonSerializer.Serialize(config, SerializerOptions);
    }

    internal static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Xray's loader is case-insensitive by accident; we still want deterministic output.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    // ------------------------------------------------------------------ env

    private static IReadOnlyDictionary<string, string>? BuildEnv(XrayConfigRequest request)
    {
        // The root `env` object does not exist before v26.7.11: an older core rejects the key
        // outright, so the entire object must be omitted for it. Returning early here (rather
        // than only gating the asset variable) is what keeps XRAY_JSON_STRICT from making the
        // object appear on a core that cannot parse it.
        if (request.CoreVersion < MinimumVersionForRootEnv)
        {
            return null;
        }

        var env = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!string.IsNullOrWhiteSpace(request.AssetDirectory))
        {
            env[GeoDataConstants.AssetLocationEnvironmentVariable] = request.AssetDirectory!;
        }

        // Ask the core to treat unknown JSON keys as errors rather than ignoring them. This
        // turns a typo in a MyVpn release into a startup failure instead of a silently
        // different configuration.
        env["XRAY_JSON_STRICT"] = "true";

        return env.Count == 0 ? null : env;
    }

    // ------------------------------------------------------------------ log

    private static XrayLogConfig BuildLog(XrayConfigRequest request) => new()
    {
        LogLevel = request.Settings.Logging.Verbosity switch
        {
            LogVerbosity.Error => "error",
            LogVerbosity.Warning => "warning",
            LogVerbosity.Info => "info",
            LogVerbosity.Debug => "debug",
            LogVerbosity.Trace => "debug",
            _ => "warning",
        },

        // Never write an access log by default: it records every destination the user visits.
        Access = "none",

        // Errors go to stderr unless the user asked for a file; MyVpn captures stderr anyway
        // and that is what feeds the diagnostics bundle.
        Error = request.ErrorLogPath,

        // DNS query logging is off: it is the most privacy-sensitive log the core can produce.
        DnsLog = request.Settings.Logging.Verbosity == LogVerbosity.Trace,
    };

    // ------------------------------------------------------------------ inbounds

    private static Result<IReadOnlyList<XrayInbound>> BuildInbounds(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var inbounds = new List<XrayInbound>();
        var sniffing = BuildSniffing(request.Settings);

        if (request.Settings.TunnelMode == TunnelMode.Tun)
        {
            var tun = BuildTunInbound(request, warnings);
            if (tun.IsFailure)
            {
                return Result<IReadOnlyList<XrayInbound>>.Fail(tun.Error!);
            }

            inbounds.Add(tun.Value);
        }

        // The local proxy inbounds are used in system-proxy mode, and are also useful in TUN
        // mode for applications that only speak SOCKS.
        if (request.Settings.TunnelMode == TunnelMode.SystemProxy || NeedsLocalInbound(request))
        {
            if (request.Settings.Proxy.EnableSocks)
            {
                inbounds.Add(new XrayInbound
                {
                    Tag = SocksInboundTag,
                    Protocol = "socks",
                    Listen = "127.0.0.1",
                    Port = request.SocksPort,
                    Settings = new XraySocksInboundSettings { Udp = true },
                    Sniffing = sniffing,
                });
            }

            if (request.Settings.Proxy.EnableHttp)
            {
                inbounds.Add(new XrayInbound
                {
                    Tag = HttpInboundTag,
                    Protocol = "http",
                    Listen = "127.0.0.1",
                    Port = request.HttpPort,
                    Settings = new XrayHttpInboundSettings(),
                    Sniffing = sniffing,
                });
            }
        }

        if (inbounds.Count == 0)
        {
            return Result<IReadOnlyList<XrayInbound>>.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.config.no_inbound",
                ErrorSeverity.Error,
                "Tunnel mode is Disabled and no local proxy inbounds are enabled, so there is "
                + "nothing for the core to accept."));
        }

        return Result<IReadOnlyList<XrayInbound>>.Ok(inbounds);
    }

    private static XraySniffingConfig? BuildSniffing(AppSettings settings) =>
        settings.Routing.EnableSniffing
            ? new XraySniffingConfig
            {
                Enabled = true,
                DestOverride = new[] { "http", "tls", "quic" },

                // `routeOnly` lives inside `sniffing`, not at the TUN level — the TUN inbound
                // has no routeOnly field. Setting it here uses the domain sniffed from the
                // connection purely for routing decisions.
                RouteOnly = settings.Tun.RouteOnly,
            }
            : new XraySniffingConfig { Enabled = false };

    private static Result<XrayInbound> BuildTunInbound(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var tun = request.Settings.Tun;
        var name = string.IsNullOrWhiteSpace(tun.InterfaceName)
            ? request.TunnelInterfaceName
            : tun.InterfaceName!;

        // macOS only accepts utunN, and silently accepts a name that does not exist yet, so a
        // wrong name here produces a fail-closed-but-broken tunnel rather than an error.
        if (request.Platform == PlatformTarget.MacOS
            && !name.StartsWith("utun", StringComparison.Ordinal))
        {
            warnings.Add(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.tun.macos_name_invalid",
                ErrorSeverity.Warning,
                $"macOS requires a 'utunN' interface name; '{name}' was requested and has been "
                + "replaced with 'utun0'."));

            name = "utun0";
        }

        var gateways = BuildGateways(request, warnings);
        if (gateways.IsFailure)
        {
            return Result<XrayInbound>.Fail(gateways.Error!);
        }

        // autoSystemRoutingTable installs routes into the MAIN table. With process routing
        // enabled the two mechanisms can contend, so the user is warned; see
        // docs/research/07-linux-networking.md and ADR-0007.
        IReadOnlyList<string>? autoRoutes = null;
        if (tun.AutoRoute)
        {
            autoRoutes = new[] { "0.0.0.0/0", "::/0" };

            if (request.Settings.ProcessRouting != ProcessRoutingMode.Off)
            {
                warnings.Add(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.tun.autoroute_with_process_routing",
                    ErrorSeverity.Warning,
                    "Per-process routing is enabled together with automatic system routes. "
                    + "Automatic routes are installed into the main table and may conflict with "
                    + "policy routing; verify on this platform."));
            }
        }

        var settings = new XrayTunInboundSettings
        {
            Name = name,
            Desc = "MyVpn tunnel",
            Mtu = tun.Mtu > 0 ? tun.Mtu : null,
            Gateway = gateways.Value,

            // The `dns` field performs DNS *assignment* on Windows only. Emitting it elsewhere
            // would be inert at best, misleading at worst.
            Dns = request.Platform == PlatformTarget.Windows && request.Settings.Dns.Mode != DnsMode.System
                ? request.Settings.Dns.Servers
                : null,

            UserLevel = 0,
            AutoSystemRoutingTable = autoRoutes,

            // Required whenever auto routes are requested, otherwise Xray installs routes but
            // cannot keep its own traffic off them.
            AutoOutboundsInterface = autoRoutes is null ? null : "auto",
        };

        return Result<XrayInbound>.Ok(new XrayInbound
        {
            Tag = TunInboundTag,
            Protocol = "tun",
            Settings = settings,
            Sniffing = BuildSniffing(request.Settings),
        });
    }

    /// <summary>
    /// Chooses the point-to-point addresses for the tunnel interface.
    /// </summary>
    /// <remarks>
    /// macOS is the awkward case: Xray uses only the first IPv4 prefix, treating it as the peer
    /// address and assigning the next address locally, and it rejects a /32. The default
    /// 169.254.10.1/30 follows that rule. Windows and Linux take both families.
    /// </remarks>
    private static Result<IReadOnlyList<string>> BuildGateways(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var gateways = request.Platform == PlatformTarget.MacOS
            ? new List<string> { "169.254.10.1/30" }
            : new List<string> { "172.19.0.1/30", "fdfe:dcba:9876::1/126" };

        foreach (var gateway in gateways)
        {
            // Client-side validation matters: a malformed gateway makes the Windows TUN path
            // panic inside Xray, which presents as a crash rather than a config error.
            if (!CidrBlock.TryParse(gateway, out var block))
            {
                return Result<IReadOnlyList<string>>.Fail(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.tun.gateway_invalid",
                    ErrorSeverity.Error,
                    $"Generated gateway '{gateway}' is not a valid CIDR block."));
            }

            if (request.Platform == PlatformTarget.MacOS && block.IsIPv4 && block.PrefixLength == 32)
            {
                return Result<IReadOnlyList<string>>.Fail(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.tun.macos_gateway_32",
                    ErrorSeverity.Error,
                    "macOS rejects a /32 tunnel gateway; it needs a point-to-point prefix."));
            }
        }

        // An IPv6 gateway on a network with no IPv6 at all is a common source of "connects but
        // nothing loads"; flag it rather than silently dropping it.
        if (request.Platform != PlatformTarget.MacOS
            && request.Settings.Ipv6 == Ipv6Mode.DisableWhileConnected)
        {
            warnings.Add(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.tun.ipv6_gateway_while_disabled",
                ErrorSeverity.Warning,
                "IPv6 is set to be disabled while connected, but an IPv6 tunnel gateway is "
                + "still configured. The Kill Switch blocks IPv6, so the address is harmless but unused."));
        }

        return Result<IReadOnlyList<string>>.Ok(gateways);
    }

    // ------------------------------------------------------------------ outbounds

    private static Result<IReadOnlyList<XrayOutbound>> BuildOutbounds(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var profile = request.Profile;
        var settings = request.Settings;

        // Freedom must resolve names itself, otherwise direct connections fail for hosts the
        // core only knows by name.
        //
        // The strategy goes on sockopt, not on the freedom settings: Xray 26.9.9 warns that
        // "freedom.domainStrategy" is deprecated and auto-migrates it to "sockopt.domainStrategy".
        // Emitting the deprecated form still works but produces a warning on every start, which
        // would train users to ignore core warnings — exactly the wrong habit for a VPN client.
        var direct = new XrayOutbound
        {
            Tag = DirectTag,
            Protocol = "freedom",
            StreamSettings = new XrayStreamSettings
            {
                Network = "tcp",
                Security = "none",
                Sockopt = BuildSockopt(request, applyMark: false),
            },
        };

        var block = new XrayOutbound
        {
            Tag = BlockTag,
            Protocol = "blackhole",
            Settings = new XrayBlackholeSettings
            {
                Response = new XrayBlackholeResponse { Type = "http" },
            },
        };

        var proxyResult = BuildProxyOutbound(request, warnings);
        if (proxyResult.IsFailure)
        {
            return Result<IReadOnlyList<XrayOutbound>>.Fail(proxyResult.Error!);
        }

        var outbounds = new List<XrayOutbound> { proxyResult.Value, direct, block };

        // DNS hijack requires a *dns outbound*. There is no "dns" inbound protocol: DNS is
        // intercepted by routing port 53 to this outbound. No settings are emitted, because
        // the documented settings surface for this protocol is narrow and version-dependent.
        if (settings.Dns.Mode is DnsMode.ThroughTunnel or DnsMode.Doh or DnsMode.Dot or DnsMode.Custom)
        {
            outbounds.Add(new XrayOutbound
            {
                Tag = DnsOutTag,
                Protocol = "dns",
            });
        }

        return Result<IReadOnlyList<XrayOutbound>>.Ok(outbounds);
    }

    private static Result<XrayOutbound> BuildProxyOutbound(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var profile = request.Profile;

        object settings = profile.Protocol switch
        {
            ProxyProtocol.Vless or ProxyProtocol.Vmess => new XrayVnextSettings
            {
                Vnext = new[]
                {
                    new XrayVnextServer
                    {
                        Address = profile.Address,
                        Port = profile.Port,
                        Users = new[]
                        {
                            new XrayOutboundUser
                            {
                                Id = profile.UserId ?? string.Empty,

                                // VLESS carries its encryption method here. Modern profiles put a
                                // post-quantum key in this field; defaulting to "none" produces a
                                // config the core accepts but that cannot connect, which is far
                                // harder to diagnose than a rejected config.
                                Encryption = profile.Protocol == ProxyProtocol.Vless
                                    ? (string.IsNullOrWhiteSpace(profile.Encryption) ? "none" : profile.Encryption)
                                    : null,

                                Flow = profile.Protocol == ProxyProtocol.Vless && profile.Flow == VlessFlow.XtlsRprxVision
                                    ? "xtls-rprx-vision"
                                    : null,

                                AlterId = profile.Protocol == ProxyProtocol.Vmess ? profile.AlterId : null,
                                Security = profile.Protocol == ProxyProtocol.Vmess
                                    ? profile.Encryption ?? "auto"
                                    : null,
                                Level = 0,
                            },
                        },
                    },
                },
            },

            ProxyProtocol.Trojan => new XrayServerSettings
            {
                Servers = new[]
                {
                    new XrayServerEntry
                    {
                        Address = profile.Address,
                        Port = profile.Port,
                        Password = profile.Password ?? string.Empty,
                        Level = 0,
                    },
                },
            },

            ProxyProtocol.Shadowsocks => new XrayServerSettings
            {
                Servers = new[]
                {
                    new XrayServerEntry
                    {
                        Address = profile.Address,
                        Port = profile.Port,
                        Password = profile.Password ?? string.Empty,
                        Method = profile.Encryption ?? "aes-256-gcm",
                        Level = 0,
                    },
                },
            },

            _ => null!,
        };

        if (settings is null)
        {
            return Result<XrayOutbound>.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.config.protocol_not_supported_for_outbound",
                ErrorSeverity.Error,
                $"Protocol {profile.Protocol} cannot be used as a proxy outbound."));
        }

        var stream = BuildStreamSettings(request, warnings);
        if (stream.IsFailure)
        {
            return Result<XrayOutbound>.Fail(stream.Error!);
        }

        return Result<XrayOutbound>.Ok(new XrayOutbound
        {
            Tag = ProxyTag,
            Protocol = profile.Protocol switch
            {
                ProxyProtocol.Vless => "vless",
                ProxyProtocol.Vmess => "vmess",
                ProxyProtocol.Trojan => "trojan",
                ProxyProtocol.Shadowsocks => "shadowsocks",
                _ => "vless",
            },
            Settings = settings,
            StreamSettings = stream.Value,
            Mux = BuildMux(request.Settings),
        });
    }

    private static Result<XrayStreamSettings> BuildStreamSettings(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var profile = request.Profile;

        var network = profile.Transport switch
        {
            TransportKind.Tcp => "tcp",
            TransportKind.WebSocket => "ws",
            TransportKind.Grpc => "grpc",
            TransportKind.HttpUpgrade => "httpupgrade",
            TransportKind.XHttp => "xhttp",
            TransportKind.Kcp => "kcp",
            TransportKind.Quic => "quic",
            TransportKind.Http => "http",
            _ => "tcp",
        };

        var security = profile.Security switch
        {
            SecurityKind.None => "none",
            SecurityKind.Tls => "tls",
            SecurityKind.Reality => "reality",
            _ => "none",
        };

        var settings = new XrayStreamSettings
        {
            Network = network,
            Security = security,
            Sockopt = BuildSockopt(request, applyMark: true),
        };

        switch (profile.Security)
        {
            case SecurityKind.Tls:
                settings = settings with
                {
                    TlsSettings = new XrayTlsSettings
                    {
                        ServerName = profile.EffectiveServerName,
                        AllowInsecure = profile.AllowInsecure,
                        Alpn = ParseAlpn(profile.Alpn),
                        Fingerprint = MapFingerprint(profile.Fingerprint),
                    },
                };

                break;

            case SecurityKind.Reality:
                if (string.IsNullOrWhiteSpace(profile.RealityPublicKey))
                {
                    return Result<XrayStreamSettings>.Fail(new MyVpnError(
                        ErrorCodes.ConfigInvalid,
                        "error.server.reality_public_key_missing"));
                }

                settings = settings with
                {
                    RealitySettings = new XrayRealitySettings
                    {
                        ServerName = profile.EffectiveServerName,

                        // REALITY always presents a uTLS fingerprint; "chrome" is the safe default
                        // when the profile does not pin one.
                        Fingerprint = MapFingerprint(profile.Fingerprint) ?? "chrome",
                        PublicKey = profile.RealityPublicKey!,
                        ShortId = profile.RealityShortId,
                        SpiderX = profile.RealitySpiderX,
                    },
                };

                break;
        }

        settings = profile.Transport switch
        {
            TransportKind.WebSocket => settings with
            {
                WsSettings = new XrayWebSocketSettings
                {
                    Path = profile.Path ?? "/",
                    Host = profile.Host,
                    Headers = profile.TransportHeaders,
                },
            },

            TransportKind.Grpc => settings with
            {
                GrpcSettings = new XrayGrpcSettings
                {
                    ServiceName = profile.ServiceName ?? profile.Path,
                    MultiMode = string.Equals(profile.TransportMode, "multi", StringComparison.OrdinalIgnoreCase),
                },
            },

            TransportKind.HttpUpgrade => settings with
            {
                HttpUpgradeSettings = new XrayHttpUpgradeSettings
                {
                    Path = profile.Path ?? "/",
                    Host = profile.Host,
                },
            },

            TransportKind.XHttp => settings with
            {
                XhttpSettings = new XrayXhttpSettings
                {
                    Path = profile.Path ?? "/",
                    Host = profile.Host,
                    Mode = NormalizeXhttpMode(profile.TransportMode, warnings),
                    Extra = ParseTransportExtra(profile.TransportExtra, warnings),
                },
            },

            TransportKind.Tcp when profile.TransportHeaders is { Count: > 0 } => settings with
            {
                TcpSettings = new XrayTcpSettings { Header = new XrayTcpHeader { Type = "http" } },
            },

            _ => settings,
        };

        return Result<XrayStreamSettings>.Ok(settings);
    }

    /// <summary>
    /// Builds socket options.
    /// </summary>
    /// <remarks>
    /// Two rules come straight from the verified upstream schema: there is no
    /// <c>bindAddress</c> field, and <c>sendThrough</c> does not work for UDP, so
    /// <c>interface</c> is the only portable binding knob. The firewall mark is applied to the
    /// proxy outbound only: marking the direct outbound would send ordinary traffic into the
    /// tunnel's policy-routing table and create a loop.
    /// </remarks>
    private static XraySockoptSettings? BuildSockopt(XrayConfigRequest request, bool applyMark)
    {
        var connectivity = request.Settings.Connectivity;
        var sockopt = new XraySockoptSettings
        {
            Interface = connectivity.BindToPhysicalInterface ? connectivity.PhysicalInterface : null,
            TcpKeepAliveInterval = connectivity.TcpKeepAliveSeconds > 0 ? connectivity.TcpKeepAliveSeconds : null,
            DomainStrategy = "UseIP",
        };

        if (applyMark && request.Platform == PlatformTarget.Linux)
        {
            // The mark is what Linux policy routing uses to keep tunnel traffic out of the tunnel.
            sockopt = sockopt with { Mark = 0x0CA6C };
        }

        return sockopt;
    }

    private static XrayMuxConfig? BuildMux(AppSettings settings)
    {
        if (!settings.Mux.Enabled)
        {
            // Emitting `{ "enabled": false }` is equivalent to omitting the block, but omitting
            // is smaller and cannot be misread.
            return null;
        }

        return new XrayMuxConfig
        {
            Enabled = true,
            Concurrency = settings.Mux.Concurrency,
            XudpConcurrency = settings.Mux.XudpConcurrency,
            XudpProxyUdp443 = settings.Mux.XudpProxyUdp443 switch
            {
                XudpUdp443Handling.Allow => "allow",
                XudpUdp443Handling.Skip => "skip",
                _ => "reject",
            },
        };
    }

    // ------------------------------------------------------------------ routing

    private static XrayRoutingConfig BuildRouting(
        XrayConfigRequest request,
        ICollection<MyVpnError> warnings)
    {
        var settings = request.Settings;
        var routing = settings.Routing;
        var rules = new List<XrayRoutingRule>();

        // 1. DNS hijack. Port 53 to the dns outbound; this is how DNS is steered over the
        //    tunnel, since Xray has no DNS inbound.
        if (settings.Dns.Mode is DnsMode.ThroughTunnel or DnsMode.Doh or DnsMode.Dot or DnsMode.Custom)
        {
            rules.Add(new XrayRoutingRule
            {
                RuleTag = "myvpn-dns-hijack",

                // A single string, not an array: Xray's PortList accepts only a number or a
                // comma-separated string. See XrayRoutingRule.Port for the verification.
                Port = "53",
                Network = "tcp,udp",
                OutboundTag = DnsOutTag,
            });
        }

        // 2. Block QUIC when UDP is not being tunnelled, so browsers fall back to TCP.
        if (settings.Connectivity.Transport == TransportStrategy.TcpOnly)
        {
            rules.Add(new XrayRoutingRule
            {
                RuleTag = "myvpn-block-quic",
                Port = "443",
                Network = "udp",
                OutboundTag = BlockTag,
            });
        }

        // 3. Local network stays direct, so printers, NAS and mDNS keep working.
        //
        // This rule is the one place where the geo-data gate was originally missed, and the
        // consequence was severe: `geoip:private` needs geoip.dat, so a missing or corrupt asset
        // made Xray reject the ENTIRE configuration rather than just dropping a rule. Found by
        // running the real core with an empty geo directory.
        //
        // The fix keeps the feature working without geo data instead of merely omitting the rule:
        // explicit RFC1918/ULA/link-local ranges cover the same ground and depend on nothing.
        if (routing.BypassLan)
        {
            if (request.GeoAvailability.GeoIpAvailable)
            {
                rules.Add(new XrayRoutingRule
                {
                    RuleTag = "myvpn-lan-direct",
                    Ip = new[] { "geoip:private" },
                    OutboundTag = DirectTag,
                });
            }
            else
            {
                rules.Add(new XrayRoutingRule
                {
                    RuleTag = "myvpn-lan-direct",
                    Ip = new[]
                    {
                        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                        "169.254.0.0/16", "100.64.0.0/10",
                        "::1/128", "fc00::/7", "fe80::/10",
                    },
                    OutboundTag = DirectTag,
                });

                warnings.Add(new MyVpnError(
                    ErrorCodes.GeoAssetMissing,
                    "error.config.geo_rule_omitted",
                    ErrorSeverity.Warning,
                    "geoip.dat is unavailable, so the LAN bypass rule uses explicit private ranges "
                    + "instead of geoip:private. Behaviour is equivalent.",
                    "geodata.repair")
                    .WithArg("pattern", "geoip:private"));
            }
        }

        // 4. Ad/tracker blocking by geosite. Only emitted when geosite is actually usable.
        if (routing.BlockAds)
        {
            if (request.GeoAvailability.GeoSiteAvailable)
            {
                rules.Add(new XrayRoutingRule
                {
                    RuleTag = "myvpn-block-ads",
                    Domain = new[] { "geosite:category-ads-all" },
                    OutboundTag = BlockTag,
                });
            }
            else
            {
                warnings.Add(GeoRuleOmitted("geosite:category-ads-all", GeoAssetKind.GeoSite));
            }
        }

        // 5. Site-level direct routing.
        if (routing.DirectGeoSites.Count > 0)
        {
            if (request.GeoAvailability.GeoSiteAvailable)
            {
                rules.Add(new XrayRoutingRule
                {
                    RuleTag = "myvpn-geosite-direct",
                    Domain = routing.DirectGeoSites.Select(s => $"geosite:{s}").ToArray(),
                    OutboundTag = DirectTag,
                });
            }
            else
            {
                warnings.Add(GeoRuleOmitted("geosite:*", GeoAssetKind.GeoSite));
            }
        }

        // 6. Country-level routing.
        if (routing.DirectGeoIpCountries.Count > 0)
        {
            if (request.GeoAvailability.GeoIpAvailable)
            {
                rules.Add(new XrayRoutingRule
                {
                    RuleTag = "myvpn-geoip-direct",
                    Ip = routing.DirectGeoIpCountries.Select(c => $"geoip:{c}").ToArray(),
                    OutboundTag = DirectTag,
                });
            }
            else
            {
                warnings.Add(GeoRuleOmitted("geoip:*", GeoAssetKind.GeoIp));
            }
        }

        // 7. Explicit user lists never depend on geo data.
        if (routing.DirectDomains.Count > 0)
        {
            rules.Add(new XrayRoutingRule
            {
                RuleTag = "myvpn-domains-direct",
                Domain = routing.DirectDomains,
                OutboundTag = DirectTag,
            });
        }

        if (routing.DirectIpCidrs.Count > 0)
        {
            rules.Add(new XrayRoutingRule
            {
                RuleTag = "myvpn-ips-direct",
                Ip = routing.DirectIpCidrs,
                OutboundTag = DirectTag,
            });
        }

        // 8. Custom rules, in user-defined order.
        foreach (var custom in routing.CustomRules.Where(r => r.Enabled))
        {
            rules.Add(new XrayRoutingRule
            {
                RuleTag = $"myvpn-custom-{custom.Id}",
                Domain = custom.Domains.Count > 0 ? custom.Domains : null,
                Ip = custom.IpCidrs.Count > 0 ? custom.IpCidrs : null,
                // Comma-separated string, matching Xray's PortList grammar (ranges use "a-b").
                Port = custom.Ports.Count > 0
                    ? string.Join(",", custom.Ports.Select(p => p.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                    : null,
                Network = string.IsNullOrWhiteSpace(custom.Network) ? null : custom.Network,
                Process = custom.Processes.Count > 0 ? custom.Processes : null,
                OutboundTag = custom.OutboundTag,
            });
        }

        // 9. Proxy-only mode: everything not matched above goes through the tunnel, which is
        //    the default outbound. An explicit catch-all is still emitted so the intent is
        //    visible in the config rather than implied by outbound order.
        rules.Add(new XrayRoutingRule
        {
            RuleTag = "myvpn-default-proxy",
            Network = "tcp,udp",
            OutboundTag = ProxyTag,
        });

        return new XrayRoutingConfig
        {
            DomainStrategy = routing.DomainStrategy,
            Rules = rules,
        };
    }

    private static MyVpnError GeoRuleOmitted(string pattern, GeoAssetKind kind) =>
        new MyVpnError(
            ErrorCodes.GeoAssetMissing,
            "error.config.geo_rule_omitted",
            ErrorSeverity.Warning,
            $"Routing rule '{pattern}' was omitted because {kind.FileName()} is not usable. The "
            + "connection still works; the geo-dependent part of the policy does not.",
            "geodata.repair")
        .WithArg("pattern", pattern);

    // ------------------------------------------------------------------ dns

    private static XrayDnsConfig? BuildDns(XrayConfigRequest request, ICollection<MyVpnError> warnings)
    {
        var dns = request.Settings.Dns;

        if (dns.Mode == DnsMode.System)
        {
            return null;
        }

        var servers = new List<object>();

        switch (dns.Mode)
        {
            case DnsMode.ThroughTunnel:
            case DnsMode.Custom:
                foreach (var server in dns.Servers)
                {
                    // Boundary assertion, not a policy decision.
                    //
                    // DnsSettings.Validate() already rejects a non-IP resolver, and Build() runs
                    // Settings.Validate() before reaching here, so this branch is unreachable
                    // through the public entry point. It is kept at the exact place the value
                    // would enter the generated configuration: if that validator is ever relaxed,
                    // failing loudly here is far better than handing Xray a hostname. A hostname
                    // resolver is not cosmetic — the core would fall back to the system resolver
                    // and leak DNS outside the tunnel.
                    if (!NetworkText.IsIpAddress(server))
                    {
                        warnings.Add(new MyVpnError(
                            ErrorCodes.ConfigInvalid,
                            "error.dns.server_not_ip",
                            ErrorSeverity.Error,
                            $"Resolver '{server}' is not an IP literal. Settings validation should "
                            + "have rejected it, so this is an internal inconsistency rather than bad "
                            + "user input.")
                            .WithArg("server", server));

                        continue;
                    }

                    servers.Add(server);
                }

                break;

            case DnsMode.Doh:
                if (!string.IsNullOrWhiteSpace(dns.DohUrl))
                {
                    servers.Add(dns.DohUrl!);
                    servers.Add("1.1.1.1");
                }

                break;

            case DnsMode.Dot:
                if (!string.IsNullOrWhiteSpace(dns.DotHost))
                {
                    servers.Add($"tls://{dns.DotHost}:{dns.DotPort}");
                    servers.Add("1.1.1.1");
                }

                break;
        }

        if (servers.Count == 0)
        {
            warnings.Add(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.dns.no_usable_resolver",
                ErrorSeverity.Warning,
                "No usable DNS resolver remained after validation; the DNS section was omitted so "
                + "the core falls back to the system resolver."));

            return null;
        }

        // Split DNS: a second, system-scoped resolver for the listed domains.
        if (dns.SplitDnsDomains.Count > 0)
        {
            servers.Add(new XrayNameServer
            {
                Address = "localhost",
                Domains = dns.SplitDnsDomains,
                SkipFallback = true,
            });
        }

        return new XrayDnsConfig
        {
            Servers = servers,
            QueryStrategy = "UseIP",
            DisableCache = false,

            // Honour the OS hosts file so local development names keep working.
            UseSystemHosts = dns.RespectSystemHosts,
        };
    }

    // ------------------------------------------------------------------ policy

    private static XrayPolicyConfig BuildPolicy() => new()
    {
        Levels = new Dictionary<string, XrayPolicyLevel>(StringComparer.Ordinal)
        {
            ["0"] = new()
            {
                HandshakeSeconds = 4,
                ConnectionIdleSeconds = 300,
                UplinkOnlySeconds = 2,
                DownlinkOnlySeconds = 5,

                // A zero buffer leaves the core's default; -1 would be unlimited memory.
                BufferSize = 0,
            },
        },
        System = new XraySystemPolicy
        {
            StatsInboundUplink = true,
            StatsInboundDownlink = true,
            StatsOutboundUplink = false,
            StatsOutboundDownlink = false,
        },
    };

    // ------------------------------------------------------------------ helpers

    private static IReadOnlyList<string>? ParseAlpn(string? alpn)
    {
        if (string.IsNullOrWhiteSpace(alpn))
        {
            return null;
        }

        var values = alpn
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

        return values.Length == 0 ? null : values;
    }

    private static string? MapFingerprint(TlsFingerprint fingerprint) => fingerprint switch
    {
        TlsFingerprint.None => null,
        TlsFingerprint.Chrome => "chrome",
        TlsFingerprint.Firefox => "firefox",
        TlsFingerprint.Safari => "safari",
        TlsFingerprint.Ios => "ios",
        TlsFingerprint.Android => "android",
        TlsFingerprint.Edge => "edge",
        TlsFingerprint.Randomized => "randomized",
        _ => null,
    };

    /// <summary>
    /// Validates an XHTTP mode against the set the core accepts.
    /// </summary>
    /// <remarks>
    /// <c>SplitHTTPConfig.Build()</c> rejects anything outside
    /// <c>auto</c>/<c>packet-up</c>/<c>stream-up</c>/<c>stream-one</c>, and normalises an empty
    /// value to <c>auto</c>. An unrecognised mode is reported and downgraded to <c>auto</c> rather
    /// than failing the whole build: an unusual subscription should still connect if it can.
    /// </remarks>
    private static string NormalizeXhttpMode(string? mode, ICollection<MyVpnError> warnings)
    {
        if (string.IsNullOrWhiteSpace(mode))
        {
            return "auto";
        }

        var normalized = mode.Trim().ToLowerInvariant();

        if (normalized is "auto" or "packet-up" or "stream-up" or "stream-one")
        {
            return normalized;
        }

        warnings.Add(new MyVpnError(
            ErrorCodes.ConfigInvalid,
            "error.config.xhttp_mode_unknown",
            ErrorSeverity.Warning,
            $"XHTTP mode '{mode}' is not one of auto/packet-up/stream-up/stream-one; using 'auto'.")
            .WithArg("mode", mode));

        return "auto";
    }

    /// <summary>
    /// Parses the share link's <c>extra=</c> JSON so it can be forwarded verbatim.
    /// </summary>
    /// <remarks>
    /// Forwarded rather than modelled because the key set grows between core releases. Invalid
    /// JSON is reported and dropped — the transport still works with its defaults, which is
    /// strictly better than failing to connect.
    /// </remarks>
    private static JsonNode? ParseTransportExtra(string? extra, ICollection<MyVpnError> warnings)
    {
        if (string.IsNullOrWhiteSpace(extra))
        {
            return null;
        }

        try
        {
            var node = JsonNode.Parse(extra, documentOptions: new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 16,
            });

            if (node is JsonObject)
            {
                return node;
            }

            warnings.Add(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.config.transport_extra_not_object",
                ErrorSeverity.Warning,
                "The transport 'extra' parameter is not a JSON object and was ignored."));
        }
        catch (JsonException ex)
        {
            warnings.Add(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.config.transport_extra_invalid",
                ErrorSeverity.Warning,
                $"The transport 'extra' parameter is not valid JSON ({ex.Message}) and was ignored."));
        }

        return null;
    }

    /// <summary>
    /// Whether a tunnel mode still needs the local SOCKS/HTTP listener.
    /// </summary>
    /// <remarks>
    /// In TUN mode the listener is not needed for routing, but advanced users rely on it for
    /// applications that only speak SOCKS or for feeding another tool.
    /// </remarks>
    private static bool NeedsLocalInbound(XrayConfigRequest request) =>
        request.Settings.AdvancedMode
        && request.Settings.TunnelMode == TunnelMode.Tun
        && (request.Settings.Proxy.EnableSocks || request.Settings.Proxy.EnableHttp);
}
