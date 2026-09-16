namespace MyVpn.Core.Domain;

/// <summary>Outbound proxy protocol spoken to the server.</summary>
public enum ProxyProtocol
{
    Vless = 0,
    Vmess = 1,
    Trojan = 2,
    Shadowsocks = 3,
    Socks = 4,
    Http = 5,
}

/// <summary>Stream transport carrying the proxy protocol.</summary>
public enum TransportKind
{
    Tcp = 0,
    WebSocket = 1,
    Grpc = 2,
    HttpUpgrade = 3,
    XHttp = 4,
    Kcp = 5,
    Quic = 6,
    Http = 7,
}

/// <summary>Transport security layer.</summary>
public enum SecurityKind
{
    None = 0,
    Tls = 1,

    /// <summary>XTLS REALITY — TLS-shaped handshake borrowing a real site's certificate.</summary>
    Reality = 2,
}

/// <summary>uTLS fingerprint presented during the TLS handshake.</summary>
public enum TlsFingerprint
{
    None = 0,
    Chrome = 1,
    Firefox = 2,
    Safari = 3,
    Ios = 4,
    Android = 5,
    Edge = 6,
    Randomized = 7,
}

/// <summary>VLESS flow control mode.</summary>
public enum VlessFlow
{
    None = 0,

    /// <summary><c>xtls-rprx-vision</c> — the only flow value still supported by current Xray.</summary>
    XtlsRprxVision = 1,
}

/// <summary>How the client presents itself to the local system.</summary>
public enum TunnelMode
{
    /// <summary>Native Xray TUN inbound captures all traffic. Requires elevation.</summary>
    Tun = 0,

    /// <summary>Xray exposes a SOCKS/HTTP inbound and we configure the OS proxy. No elevation.</summary>
    SystemProxy = 1,

    /// <summary>Xray runs but nothing is redirected; used for testing a profile.</summary>
    Disabled = 2,
}

/// <summary>Kill Switch operating mode.</summary>
public enum KillSwitchMode
{
    /// <summary>No firewall rules are installed.</summary>
    Disabled = 0,

    /// <summary>Rules exist only for the duration of a VPN session.</summary>
    OnDemand = 1,

    /// <summary>Rules survive reboot via a boot-time re-install.</summary>
    AlwaysOn = 2,
}

/// <summary>How IPv6 is handled while the VPN is active.</summary>
public enum Ipv6Mode
{
    /// <summary>IPv6 is routed through the tunnel.</summary>
    FullTunnel = 0,

    /// <summary>
    /// IPv6 is blocked for the duration of the session. This is the DEFAULT because
    /// it is the only mode that can be guaranteed leak-free on every platform,
    /// including when the server has no IPv6 egress at all.
    /// </summary>
    DisableWhileConnected = 1,

    /// <summary>IPv6 bypasses the tunnel and goes out directly.</summary>
    DirectBypass = 2,

    /// <summary>User-supplied rules decide per prefix.</summary>
    Custom = 3,
}

/// <summary>Per-process routing strategy.</summary>
public enum ProcessRoutingMode
{
    /// <summary>Every process uses the tunnel (subject to normal routing rules).</summary>
    Off = 0,

    /// <summary>Selected processes bypass the tunnel and use the real interface.</summary>
    BypassVpn = 1,

    /// <summary>Only selected processes use the tunnel; everything else is direct.</summary>
    VpnOnly = 2,

    /// <summary>Per-application rules may route either way.</summary>
    Rules = 3,
}

/// <summary>Where DNS queries are answered.</summary>
public enum DnsMode
{
    /// <summary>Leave the OS resolver untouched.</summary>
    System = 0,

    /// <summary>Use DNS servers pushed through the tunnel.</summary>
    ThroughTunnel = 1,

    /// <summary>DNS-over-HTTPS.</summary>
    Doh = 2,

    /// <summary>DNS-over-TLS.</summary>
    Dot = 3,

    /// <summary>Explicit user-provided servers.</summary>
    Custom = 4,
}

/// <summary>UI appearance theme.</summary>
public enum AppTheme
{
    System = 0,
    Light = 1,
    Dark = 2,
}

/// <summary>Information density of the UI.</summary>
public enum UiDensity
{
    Comfortable = 0,
    Compact = 1,
}

/// <summary>Supported UI languages.</summary>
public enum AppLanguage
{
    /// <summary>Follow the OS UI culture.</summary>
    System = 0,
    English = 1,
    Russian = 2,
    SimplifiedChinese = 3,
}
