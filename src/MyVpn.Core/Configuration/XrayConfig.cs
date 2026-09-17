using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace MyVpn.Core.Configuration;

/// <summary>
/// Typed model of an Xray-core configuration document.
/// </summary>
/// <remarks>
/// <para>
/// Every property carries an explicit <see cref="JsonPropertyNameAttribute"/>. That is
/// deliberate: Xray's own loader accepts several near-miss spellings by accident (Go's
/// encoding/json is case-insensitive), so a config that "works" in testing can be silently
/// wrong. Pinning the names here means the emitted document is exactly the documented shape,
/// and a test can assert on the serialized text.
/// </para>
/// <para>
/// The field names and shapes were verified against the upstream repository rather than
/// inferred — see <c>docs/adr/ADR-0002-use-xray-core-only-native-tun.md</c> and
/// <c>docs/research/03-xray-tun-inbound.md</c>. In particular the TUN inbound has exactly the
/// fields <c>name</c>, <c>desc</c>, <c>mtu</c>, <c>gateway</c>, <c>dns</c>, <c>userLevel</c>,
/// <c>autoSystemRoutingTable</c> and <c>autoOutboundsInterface</c>: there is no
/// <c>address</c>, <c>autoRoute</c>, <c>strictRoute</c> or <c>sniffingOverride</c>, and
/// emitting them produces a config Xray rejects.
/// </para>
/// </remarks>
public sealed record XrayConfig
{
    /// <summary>
    /// Root environment map applied to the core. Requires Xray &gt;= v26.7.11.
    /// </summary>
    /// <remarks>
    /// This is the second, independent channel through which the asset directory reaches the
    /// core. The primary channel is the real process environment; this one survives a launcher
    /// that drops the environment, which is exactly the defect behind issue #9765. It must only
    /// be emitted for cores new enough to understand it.
    /// </remarks>
    [JsonPropertyName("env")]
    public IReadOnlyDictionary<string, string>? Env { get; init; }

    [JsonPropertyName("log")]
    public XrayLogConfig? Log { get; init; }

    [JsonPropertyName("dns")]
    public XrayDnsConfig? Dns { get; init; }

    [JsonPropertyName("inbounds")]
    public IReadOnlyList<XrayInbound> Inbounds { get; init; } = Array.Empty<XrayInbound>();

    [JsonPropertyName("outbounds")]
    public IReadOnlyList<XrayOutbound> Outbounds { get; init; } = Array.Empty<XrayOutbound>();

    [JsonPropertyName("routing")]
    public XrayRoutingConfig? Routing { get; init; }

    [JsonPropertyName("policy")]
    public XrayPolicyConfig? Policy { get; init; }

    [JsonPropertyName("stats")]
    public JsonObject? Stats { get; init; }
}

public sealed record XrayLogConfig
{
    [JsonPropertyName("loglevel")]
    public required string LogLevel { get; init; }

    /// <summary>Access log path, or <c>"none"</c> to disable. Privacy default: none.</summary>
    [JsonPropertyName("access")]
    public string Access { get; init; } = "none";

    /// <summary>Error log path. <c>null</c> sends errors to the process stderr, which MyVpn captures.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }

    [JsonPropertyName("dnsLog")]
    public bool DnsLog { get; init; }

    /// <summary>
    /// Redacts addresses in logs. Relevant because the default here is to capture stderr, and
    /// the diagnostics bundle is user-shareable.
    /// </summary>
    [JsonPropertyName("maskAddress")]
    public string? MaskAddress { get; init; }
}

public sealed record XrayDnsConfig
{
    /// <summary>
    /// Resolvers. Each entry is either a bare address string or a structured object; see
    /// <see cref="XrayNameServer"/> for the documented object form.
    /// </summary>
    [JsonPropertyName("servers")]
    public required IReadOnlyList<object> Servers { get; init; }

    [JsonPropertyName("hosts")]
    public IReadOnlyDictionary<string, object>? Hosts { get; init; }

    /// <summary><c>UseIP</c>, <c>UseIP4</c>, <c>UseIP6</c> or <c>UseSys</c>.</summary>
    [JsonPropertyName("queryStrategy")]
    public string? QueryStrategy { get; init; }

    [JsonPropertyName("disableCache")]
    public bool? DisableCache { get; init; }

    /// <summary>Marks this DNS config so routing can target it.</summary>
    [JsonPropertyName("tag")]
    public string? Tag { get; init; }

    [JsonPropertyName("useSystemHosts")]
    public bool? UseSystemHosts { get; init; }

    [JsonPropertyName("disableFallback")]
    public bool? DisableFallback { get; init; }

    [JsonPropertyName("enableParallelQuery")]
    public bool? EnableParallelQuery { get; init; }
}

/// <summary>
/// Structured resolver entry, matching Xray's <c>NameServerConfig</c> JSON.
/// </summary>
public sealed record XrayNameServer
{
    [JsonPropertyName("address")]
    public required string Address { get; init; }

    [JsonPropertyName("port")]
    public int? Port { get; init; }

    /// <summary>Only resolve these domains through this server (split DNS).</summary>
    [JsonPropertyName("domains")]
    public IReadOnlyList<string>? Domains { get; init; }

    [JsonPropertyName("expectIPs")]
    public IReadOnlyList<string>? ExpectIPs { get; init; }

    [JsonPropertyName("skipFallback")]
    public bool? SkipFallback { get; init; }

    [JsonPropertyName("tag")]
    public string? Tag { get; init; }
}

public sealed record XrayInbound
{
    [JsonPropertyName("tag")]
    public required string Tag { get; init; }

    /// <summary><c>tun</c>, <c>socks</c>, <c>http</c> or <c>dokodemo-door</c>.</summary>
    [JsonPropertyName("protocol")]
    public required string Protocol { get; init; }

    [JsonPropertyName("listen")]
    public string? Listen { get; init; }

    [JsonPropertyName("port")]
    public int? Port { get; init; }

    /// <summary>
    /// Protocol-specific settings. Typed at construction time; the runtime type drives
    /// serialization, so callers assign a concrete settings record.
    /// </summary>
    [JsonPropertyName("settings")]
    public object? Settings { get; init; }

    [JsonPropertyName("sniffing")]
    public XraySniffingConfig? Sniffing { get; init; }
}

/// <summary>
/// Native TUN inbound settings.
/// </summary>
/// <remarks>
/// Exactly the upstream field set. Note that <c>dns</c> here performs DNS <i>assignment</i> on
/// Windows only; it is not DNS interception. On Linux and macOS, interception has to be done by
/// MyVpn itself, which is why the DNS plan exists separately.
/// </remarks>
public sealed record XrayTunInboundSettings
{
    /// <summary>Interface name. On macOS this must match <c>utunN</c>.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("desc")]
    public string? Desc { get; init; }

    [JsonPropertyName("mtu")]
    public int? Mtu { get; init; }

    /// <summary>
    /// Point-to-point addresses for the interface. On macOS only the first IPv4 prefix is
    /// used, as the peer address, and a /32 is rejected.
    /// </summary>
    [JsonPropertyName("gateway")]
    public IReadOnlyList<string>? Gateway { get; init; }

    /// <summary>DNS servers to assign (Windows only).</summary>
    [JsonPropertyName("dns")]
    public IReadOnlyList<string>? Dns { get; init; }

    [JsonPropertyName("userLevel")]
    public int? UserLevel { get; init; }

    /// <summary>Prefixes Xray installs into the main routing table.</summary>
    [JsonPropertyName("autoSystemRoutingTable")]
    public IReadOnlyList<string>? AutoSystemRoutingTable { get; init; }

    /// <summary>Interface outbound sockets bind to, normally <c>auto</c>.</summary>
    [JsonPropertyName("autoOutboundsInterface")]
    public string? AutoOutboundsInterface { get; init; }
}

public sealed record XraySocksInboundSettings
{
    [JsonPropertyName("auth")]
    public string Auth { get; init; } = "noauth";

    [JsonPropertyName("udp")]
    public bool Udp { get; init; } = true;

    [JsonPropertyName("address")]
    public string Address { get; init; } = "127.0.0.1";
}

public sealed record XrayHttpInboundSettings
{
    [JsonPropertyName("timeout")]
    public int Timeout { get; init; } = 300;
}

public sealed record XraySniffingConfig
{
    [JsonPropertyName("enabled")]
    public required bool Enabled { get; init; }

    [JsonPropertyName("destOverride")]
    public IReadOnlyList<string> DestOverride { get; init; } = new[] { "http", "tls", "quic" };

    /// <summary>Sniff for routing only, without rewriting the destination.</summary>
    [JsonPropertyName("routeOnly")]
    public bool RouteOnly { get; init; }

    [JsonPropertyName("metadataOnly")]
    public bool? MetadataOnly { get; init; }
}

public sealed record XrayOutbound
{
    [JsonPropertyName("tag")]
    public required string Tag { get; init; }

    /// <summary><c>vless</c>, <c>vmess</c>, <c>trojan</c>, <c>shadowsocks</c>, <c>freedom</c>, <c>blackhole</c>, <c>dns</c>.</summary>
    [JsonPropertyName("protocol")]
    public required string Protocol { get; init; }

    [JsonPropertyName("settings")]
    public object? Settings { get; init; }

    [JsonPropertyName("streamSettings")]
    public XrayStreamSettings? StreamSettings { get; init; }

    [JsonPropertyName("mux")]
    public XrayMuxConfig? Mux { get; init; }
}

public sealed record XrayVnextSettings
{
    [JsonPropertyName("vnext")]
    public required IReadOnlyList<XrayVnextServer> Vnext { get; init; }
}

public sealed record XrayVnextServer
{
    [JsonPropertyName("address")]
    public required string Address { get; init; }

    [JsonPropertyName("port")]
    public required int Port { get; init; }

    [JsonPropertyName("users")]
    public required IReadOnlyList<XrayOutboundUser> Users { get; init; }
}

/// <summary>
/// A user entry. The same shape serves VLESS and VMess; unused members are omitted.
/// </summary>
public sealed record XrayOutboundUser
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>VLESS encryption. Modern Xray requires the literal <c>none</c>.</summary>
    [JsonPropertyName("encryption")]
    public string? Encryption { get; init; }

    /// <summary>VLESS flow control, e.g. <c>xtls-rprx-vision</c>.</summary>
    [JsonPropertyName("flow")]
    public string? Flow { get; init; }

    /// <summary>VMess alterId. Zero on current servers.</summary>
    [JsonPropertyName("alterId")]
    public int? AlterId { get; init; }

    /// <summary>VMess security: <c>auto</c>, <c>none</c>, <c>aes-128-gcm</c>, <c>chacha20-poly1305</c>.</summary>
    [JsonPropertyName("security")]
    public string? Security { get; init; }

    [JsonPropertyName("level")]
    public int Level { get; init; }
}

public sealed record XrayServerSettings
{
    [JsonPropertyName("servers")]
    public required IReadOnlyList<XrayServerEntry> Servers { get; init; }
}

public sealed record XrayServerEntry
{
    [JsonPropertyName("address")]
    public required string Address { get; init; }

    [JsonPropertyName("port")]
    public required int Port { get; init; }

    [JsonPropertyName("password")]
    public required string Password { get; init; }

    /// <summary>Shadowsocks cipher. Absent for Trojan.</summary>
    [JsonPropertyName("method")]
    public string? Method { get; init; }

    [JsonPropertyName("level")]
    public int Level { get; init; }
}

/// <summary>Freedom (direct) outbound settings.</summary>
/// <remarks>
/// <b>Do not set <see cref="DomainStrategy"/> here.</b> Xray 26.9.9 reports
/// <c>The "freedom.domainStrategy" setting is deprecated and will be removed</c> and silently
/// migrates the value to <c>sockopt.domainStrategy</c>. Put it on the outbound's
/// <see cref="XraySockoptSettings.DomainStrategy"/> instead. The property is kept so the
/// deprecation is discoverable rather than looking like an oversight.
/// </remarks>
public sealed record XrayFreedomSettings
{
    /// <summary><c>AsIs</c>, <c>UseIP</c>, <c>UseIPv4</c>, <c>UseIPv6</c>, <c>UseIPIfNonMatch</c>.</summary>
    [Obsolete("Deprecated by Xray; use XraySockoptSettings.DomainStrategy instead.")]
    [JsonPropertyName("domainStrategy")]
    public string? DomainStrategy { get; init; }
}

/// <summary>Blackhole (block) outbound settings.</summary>
public sealed record XrayBlackholeSettings
{
    [JsonPropertyName("response")]
    public XrayBlackholeResponse? Response { get; init; }
}

public sealed record XrayBlackholeResponse
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "http";
}

public sealed record XrayStreamSettings
{
    /// <summary><c>tcp</c>, <c>ws</c>, <c>grpc</c>, <c>httpupgrade</c>, <c>xhttp</c>, <c>kcp</c>, <c>quic</c>, <c>http</c>.</summary>
    [JsonPropertyName("network")]
    public required string Network { get; init; }

    /// <summary><c>none</c>, <c>tls</c> or <c>reality</c>.</summary>
    [JsonPropertyName("security")]
    public required string Security { get; init; }

    [JsonPropertyName("tlsSettings")]
    public XrayTlsSettings? TlsSettings { get; init; }

    [JsonPropertyName("realitySettings")]
    public XrayRealitySettings? RealitySettings { get; init; }

    [JsonPropertyName("wsSettings")]
    public XrayWebSocketSettings? WsSettings { get; init; }

    [JsonPropertyName("grpcSettings")]
    public XrayGrpcSettings? GrpcSettings { get; init; }

    [JsonPropertyName("httpupgradeSettings")]
    public XrayHttpUpgradeSettings? HttpUpgradeSettings { get; init; }

    [JsonPropertyName("xhttpSettings")]
    public XrayXhttpSettings? XhttpSettings { get; init; }

    [JsonPropertyName("tcpSettings")]
    public XrayTcpSettings? TcpSettings { get; init; }

    [JsonPropertyName("sockopt")]
    public XraySockoptSettings? Sockopt { get; init; }
}

public sealed record XrayTlsSettings
{
    [JsonPropertyName("serverName")]
    public string? ServerName { get; init; }

    [JsonPropertyName("allowInsecure")]
    public bool AllowInsecure { get; init; }

    [JsonPropertyName("alpn")]
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>uTLS fingerprint. Omitted when not requested.</summary>
    [JsonPropertyName("fingerprint")]
    public string? Fingerprint { get; init; }

    [JsonPropertyName("show")]
    public bool Show { get; init; }
}

public sealed record XrayRealitySettings
{
    [JsonPropertyName("serverName")]
    public required string ServerName { get; init; }

    [JsonPropertyName("fingerprint")]
    public required string Fingerprint { get; init; }

    [JsonPropertyName("publicKey")]
    public required string PublicKey { get; init; }

    [JsonPropertyName("shortId")]
    public string? ShortId { get; init; }

    [JsonPropertyName("spiderX")]
    public string? SpiderX { get; init; }

    [JsonPropertyName("show")]
    public bool Show { get; init; }
}

public sealed record XrayWebSocketSettings
{
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("host")]
    public string? Host { get; init; }

    [JsonPropertyName("headers")]
    public IReadOnlyDictionary<string, string>? Headers { get; init; }
}

public sealed record XrayGrpcSettings
{
    [JsonPropertyName("serviceName")]
    public string? ServiceName { get; init; }

    /// <summary><c>gun</c> or <c>multi</c>.</summary>
    [JsonPropertyName("multiMode")]
    public bool MultiMode { get; init; }

    [JsonPropertyName("idle_timeout")]
    public int? IdleTimeout { get; init; }

    [JsonPropertyName("health_check_timeout")]
    public int? HealthCheckTimeout { get; init; }

    [JsonPropertyName("permit_without_stream")]
    public bool PermitWithoutStream { get; init; }
}

public sealed record XrayHttpUpgradeSettings
{
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("host")]
    public string? Host { get; init; }
}

public sealed record XrayXhttpSettings
{
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("host")]
    public string? Host { get; init; }

    /// <summary><c>auto</c>, <c>packet-up</c> or <c>stream-up</c>.</summary>
    [JsonPropertyName("mode")]
    public string? Mode { get; init; }
}

public sealed record XrayTcpSettings
{
    /// <summary>Header type: <c>none</c> or <c>http</c>.</summary>
    [JsonPropertyName("header")]
    public XrayTcpHeader? Header { get; init; }
}

public sealed record XrayTcpHeader
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "none";
}

/// <summary>
/// Socket options. Field names verified against <c>transport/internet/config.proto</c>.
/// </summary>
/// <remarks>
/// There is no <c>bindAddress</c> field, and <c>sendThrough</c> explicitly does not work for
/// UDP — the only portable way to bind is <c>interface</c>. <c>mark</c> is Linux-only. See
/// <c>docs/research/04-nat-udp-matrix.md</c>.
/// </remarks>
public sealed record XraySockoptSettings
{
    /// <summary>SO_MARK value. Linux only.</summary>
    [JsonPropertyName("mark")]
    public int? Mark { get; init; }

    /// <summary>TCP fast open queue length; 0 disables.</summary>
    [JsonPropertyName("tcpFastOpen")]
    public int? TcpFastOpen { get; init; }

    /// <summary>Bind outbound sockets to a named interface, preventing routing loops.</summary>
    [JsonPropertyName("interface")]
    public string? Interface { get; init; }

    /// <summary><c>AsIs</c>, <c>UseIP</c>, <c>UseIPv4</c>, <c>UseIPv6</c>.</summary>
    [JsonPropertyName("domainStrategy")]
    public string? DomainStrategy { get; init; }

    /// <summary><c>off</c>, <c>tproxy</c> or <c>redirect</c>.</summary>
    [JsonPropertyName("tproxy")]
    public string? Tproxy { get; init; }

    [JsonPropertyName("tcpKeepAliveInterval")]
    public int? TcpKeepAliveInterval { get; init; }

    [JsonPropertyName("tcpKeepAliveIdle")]
    public int? TcpKeepAliveIdle { get; init; }

    /// <summary>Restrict to IPv6 only; mainly for diagnosing dual-stack behaviour.</summary>
    [JsonPropertyName("v6only")]
    public bool? V6Only { get; init; }

    [JsonPropertyName("tcpCongestion")]
    public string? TcpCongestion { get; init; }

    [JsonPropertyName("tcpWindowClamp")]
    public int? TcpWindowClamp { get; init; }

    [JsonPropertyName("tcpUserTimeout")]
    public int? TcpUserTimeout { get; init; }

    [JsonPropertyName("tcpMaxSeg")]
    public int? TcpMaxSeg { get; init; }

    [JsonPropertyName("tcpMptcp")]
    public bool? TcpMptcp { get; init; }
}

/// <summary>
/// Outbound multiplexing.
/// </summary>
/// <remarks>
/// The trap worth stating: <c>xudpConcurrency</c> is inert unless <c>enabled</c> is true — the
/// whole block sits inside an <c>if config.Enabled</c> guard upstream. To get XUDP without TCP
/// multiplexing, emit <c>enabled: true, concurrency: -1</c>.
/// </remarks>
public sealed record XrayMuxConfig
{
    [JsonPropertyName("enabled")]
    public required bool Enabled { get; init; }

    /// <summary>TCP mux concurrency; <c>-1</c> disables TCP multiplexing while keeping XUDP active.</summary>
    [JsonPropertyName("concurrency")]
    public int Concurrency { get; init; } = 8;

    /// <summary>XUDP concurrency; <c>-1</c> disables XUDP.</summary>
    [JsonPropertyName("xudpConcurrency")]
    public int XudpConcurrency { get; init; } = 16;

    /// <summary><c>reject</c>, <c>allow</c> or <c>skip</c> for UDP/443 (QUIC).</summary>
    [JsonPropertyName("xudpProxyUDP443")]
    public string XudpProxyUdp443 { get; init; } = "reject";
}

public sealed record XrayRoutingConfig
{
    /// <summary><c>AsIs</c>, <c>IPIfNonMatch</c> or <c>IPOnDemand</c>.</summary>
    [JsonPropertyName("domainStrategy")]
    public string DomainStrategy { get; init; } = "IPIfNonMatch";

    [JsonPropertyName("rules")]
    public IReadOnlyList<XrayRoutingRule> Rules { get; init; } = Array.Empty<XrayRoutingRule>();
}

/// <summary>
/// A routing rule. Field names verified against <c>infra/conf/router.go</c>.
/// </summary>
public sealed record XrayRoutingRule
{
    /// <summary>Always <c>field</c> for the rule form used here.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "field";

    /// <summary>Stable identifier, surfaced in MyVpn's diagnostics.</summary>
    [JsonPropertyName("ruleTag")]
    public string? RuleTag { get; init; }

    [JsonPropertyName("domain")]
    public IReadOnlyList<string>? Domain { get; init; }

    [JsonPropertyName("ip")]
    public IReadOnlyList<string>? Ip { get; init; }

    /// <summary>
    /// Ports to match. Serializes to a JSON <b>string</b> (or number), never an array.
    /// </summary>
    /// <remarks>
    /// Verified against Xray 26.9.9, which was run against a generated config. Xray's
    /// <c>PortList.UnmarshalJSON</c> in <c>infra/conf/common.go</c> accepts exactly two forms: a
    /// single JSON number, or a JSON string of comma-separated ports and ranges. An array — the
    /// obvious shape, and the one the protobuf field name <c>repeated PortRange range = 1</c>
    /// suggests — is <b>rejected</b> with
    /// <c>invalid port: [...] &gt; cannot unmarshal array into Go value of type uint32</c>, and
    /// that failure rejects the whole configuration.
    /// <para>
    /// Express multiple entries as a comma-separated string: <c>"80,443,8000-8100"</c>. Note that
    /// <c>network</c> behaves differently — <c>NetworkList.UnmarshalJSON</c> accepts both an array
    /// and a comma-separated string — so the two fields are not interchangeable in form.
    /// </para>
    /// </remarks>
    [JsonPropertyName("port")]
    public string? Port { get; init; }

    /// <summary><c>tcp</c>, <c>udp</c> or <c>tcp,udp</c>.</summary>
    [JsonPropertyName("network")]
    public string? Network { get; init; }

    [JsonPropertyName("inboundTag")]
    public IReadOnlyList<string>? InboundTag { get; init; }

    [JsonPropertyName("protocol")]
    public IReadOnlyList<string>? Protocol { get; init; }

    /// <summary>Per-process routing. Support varies by platform; see ADR-0007.</summary>
    [JsonPropertyName("process")]
    public IReadOnlyList<string>? Process { get; init; }

    [JsonPropertyName("user")]
    public IReadOnlyList<string>? User { get; init; }

    [JsonPropertyName("outboundTag")]
    public string? OutboundTag { get; init; }

    [JsonPropertyName("balancerTag")]
    public string? BalancerTag { get; init; }
}

public sealed record XrayPolicyConfig
{
    [JsonPropertyName("levels")]
    public IReadOnlyDictionary<string, XrayPolicyLevel>? Levels { get; init; }

    [JsonPropertyName("system")]
    public XraySystemPolicy? System { get; init; }
}

public sealed record XrayPolicyLevel
{
    [JsonPropertyName("handshake")]
    public int? HandshakeSeconds { get; init; }

    [JsonPropertyName("connIdle")]
    public int? ConnectionIdleSeconds { get; init; }

    [JsonPropertyName("uplinkOnly")]
    public int? UplinkOnlySeconds { get; init; }

    [JsonPropertyName("downlinkOnly")]
    public int? DownlinkOnlySeconds { get; init; }

    /// <summary>Per-connection buffer size in bytes; <c>-1</c> is unlimited.</summary>
    [JsonPropertyName("bufferSize")]
    public int? BufferSize { get; init; }
}

public sealed record XraySystemPolicy
{
    [JsonPropertyName("statsInboundUplink")]
    public bool StatsInboundUplink { get; init; }

    [JsonPropertyName("statsInboundDownlink")]
    public bool StatsInboundDownlink { get; init; }

    [JsonPropertyName("statsOutboundUplink")]
    public bool StatsOutboundUplink { get; init; }

    [JsonPropertyName("statsOutboundDownlink")]
    public bool StatsOutboundDownlink { get; init; }
}
