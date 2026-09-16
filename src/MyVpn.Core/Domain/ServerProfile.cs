using MyVpn.Core.Results;

namespace MyVpn.Core.Domain;

/// <summary>
/// A single connection profile: everything needed to build one Xray outbound.
/// </summary>
/// <remarks>
/// This is a plain data record with no behaviour beyond validation, so that it can
/// be serialized to disk, sent across IPC and compared in tests. Credentials live
/// here, which is why the settings store treats instances of this type as
/// sensitive and the diagnostics exporter redacts them (see
/// <c>MyVpn.Infrastructure.Diagnostics.SecretRedactor</c>).
/// </remarks>
public sealed record ServerProfile
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Human-facing name, usually derived from the subscription remark.</summary>
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>Hostname or IP literal of the server.</summary>
    public string Address { get; init; } = string.Empty;

    public int Port { get; init; }

    public ProxyProtocol Protocol { get; init; } = ProxyProtocol.Vless;

    // ---- credentials ---------------------------------------------------

    /// <summary>UUID for VLESS/VMess.</summary>
    public string? UserId { get; init; }

    /// <summary>Password for Trojan/Shadowsocks/SOCKS/HTTP.</summary>
    public string? Password { get; init; }

    /// <summary>Encryption method: Shadowsocks cipher, or VMess <c>security</c>.</summary>
    public string? Encryption { get; init; }

    /// <summary>VMess <c>alterId</c>.</summary>
    public int AlterId { get; init; }

    // ---- transport -----------------------------------------------------

    public TransportKind Transport { get; init; } = TransportKind.Tcp;

    /// <summary>SNI/Host header for the transport (ws/http/grpc authority).</summary>
    public string? Host { get; init; }

    /// <summary>HTTP path for ws/httpupgrade/xhttp, or the service name carrier for grpc.</summary>
    public string? Path { get; init; }

    /// <summary>gRPC service name.</summary>
    public string? ServiceName { get; init; }

    /// <summary>Transport-specific mode: gRPC <c>multi</c>, xhttp <c>stream-up</c>, etc.</summary>
    public string? TransportMode { get; init; }

    /// <summary>HTTP header map for transports that need extra headers.</summary>
    public IReadOnlyDictionary<string, string>? TransportHeaders { get; init; }

    // ---- security ------------------------------------------------------

    public SecurityKind Security { get; init; } = SecurityKind.None;

    /// <summary>TLS SNI. Falls back to <see cref="Host"/> then <see cref="Address"/>.</summary>
    public string? ServerName { get; init; }

    /// <summary>ALPN list, comma separated as it appears in share links.</summary>
    public string? Alpn { get; init; }

    public TlsFingerprint Fingerprint { get; init; } = TlsFingerprint.None;

    /// <summary>REALITY public key (<c>pbk</c>).</summary>
    public string? RealityPublicKey { get; init; }

    /// <summary>REALITY short id (<c>sid</c>).</summary>
    public string? RealityShortId { get; init; }

    /// <summary>REALITY spider path (<c>spx</c>).</summary>
    public string? RealitySpiderX { get; init; }

    /// <summary>Allow insecure TLS (certificate validation disabled). Off by default.</summary>
    public bool AllowInsecure { get; init; }

    // ---- protocol tuning ------------------------------------------------

    public VlessFlow Flow { get; init; } = VlessFlow.None;

    /// <summary>VMess/VLESS packet encoding (<c>none</c>, <c>packet</c>, <c>xudp</c>).</summary>
    public string? PacketEncoding { get; init; }

    // ---- metadata --------------------------------------------------------

    /// <summary>Owning subscription, or <c>null</c> for a manually added profile.</summary>
    public Guid? SubscriptionId { get; init; }

    /// <summary>ISO-3166 alpha-2 country code when it can be derived from the name.</summary>
    public string? CountryCode { get; init; }

    public bool IsFavorite { get; init; }

    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    public DateTimeOffset AddedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary><c>host:port</c> as used for logging and Kill Switch allowlisting.</summary>
    public string Endpoint => $"{Address}:{Port}";

    /// <summary>
    /// Effective TLS SNI: explicit SNI, else the transport Host, else the address.
    /// </summary>
    public string EffectiveServerName =>
        !string.IsNullOrWhiteSpace(ServerName) ? ServerName!
        : !string.IsNullOrWhiteSpace(Host) ? Host!
        : Address;

    public ServerEndpoint ToEndpoint() => new(Address, Port);

    /// <summary>
    /// Structural validation. Called before a profile is allowed into the config
    /// builder so that a malformed subscription entry produces a clear per-server
    /// error instead of an Xray crash later.
    /// </summary>
    public Result Validate()
    {
        if (string.IsNullOrWhiteSpace(Address))
        {
            return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.address_missing");
        }

        if (Port is < 1 or > 65535)
        {
            return Result.Fail(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.server.port_out_of_range")
                .WithArg("port", Port.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        switch (Protocol)
        {
            case ProxyProtocol.Vless:
            case ProxyProtocol.Vmess:
                if (string.IsNullOrWhiteSpace(UserId))
                {
                    return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.user_id_missing");
                }

                break;
            case ProxyProtocol.Trojan:
            case ProxyProtocol.Shadowsocks:
                if (string.IsNullOrWhiteSpace(Password))
                {
                    return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.password_missing");
                }

                break;
            case ProxyProtocol.Socks:
            case ProxyProtocol.Http:
                break;
            default:
                return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.protocol_unsupported");
        }

        if (Security == SecurityKind.Reality && string.IsNullOrWhiteSpace(RealityPublicKey))
        {
            return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.reality_public_key_missing");
        }

        if (Transport == TransportKind.Grpc && string.IsNullOrWhiteSpace(ServiceName)
            && string.IsNullOrWhiteSpace(Path))
        {
            return Result.Fail(ErrorCodes.ConfigInvalid, "error.server.grpc_service_missing");
        }

        return Result.Ok();
    }
}

/// <summary>An <c>address:port</c> pair used for routing and firewall decisions.</summary>
public readonly record struct ServerEndpoint(string Address, int Port)
{
    /// <summary>
    /// True when <see cref="Address"/> is an IP literal rather than a hostname.
    /// A hostname must be resolved before it can be written into a firewall rule,
    /// which is a real failure mode for the Kill Switch: if the server is a domain
    /// and DNS is not yet available, we cannot pin the allowed destination.
    /// </summary>
    public bool IsIpLiteral =>
        System.Net.IPAddress.TryParse(Address, out _);

    public override string ToString() =>
        IsIpLiteral && Address.Contains(':', StringComparison.Ordinal)
            ? $"[{Address}]:{Port}"
            : $"{Address}:{Port}";
}
