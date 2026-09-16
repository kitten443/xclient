using System.Globalization;
using System.Text.Json;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;

namespace MyVpn.Core.Parsing;

/// <summary>A share-link line that could not be parsed, kept for user-facing reporting.</summary>
public sealed record ShareLinkFailure(string Line, MyVpnError Error);

/// <summary>Result of parsing a multi-line or Base64 subscription payload.</summary>
public sealed record ShareLinkBatch(
    IReadOnlyList<ServerProfile> Profiles,
    IReadOnlyList<ShareLinkFailure> Failures)
{
    public static ShareLinkBatch Empty { get; } = new(Array.Empty<ServerProfile>(), Array.Empty<ShareLinkFailure>());

    public bool HasProfiles => Profiles.Count > 0;
}

/// <summary>
/// Parses <c>vless://</c>, <c>vmess://</c>, <c>trojan://</c> and <c>ss://</c> share links.
/// </summary>
/// <remarks>
/// <para>
/// These URI shapes are a de-facto convention rather than a published standard, so the
/// parser is deliberately permissive about optional parameters and strict about the
/// fields that affect security: a link whose transport, security or credentials cannot
/// be understood is rejected with a specific error instead of being coerced into a
/// plausible-looking profile. Silently downgrading an unknown <c>security=</c> value to
/// <c>none</c>, for example, would turn a TLS server into a plaintext one.
/// </para>
/// <para>
/// A malformed line never aborts the whole payload: <see cref="ParseMany"/> returns
/// successfully parsed profiles plus per-line failures, so one bad entry in a 200-server
/// subscription does not hide the other 199.
/// </para>
/// </remarks>
public static class ShareLinkParser
{
    private static readonly string[] Schemes = { "vless", "vmess", "trojan", "ss", "socks", "http" };

    /// <summary>True when the line begins with a scheme this parser understands.</summary>
    public static bool IsShareLink(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var trimmed = line.TrimStart();
        foreach (var scheme in Schemes)
        {
            if (trimmed.StartsWith(scheme + "://", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses a single share link.</summary>
    public static Result<ServerProfile> Parse(string link)
    {
        if (string.IsNullOrWhiteSpace(link))
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.empty"));
        }

        var trimmed = link.Trim();
        var schemeEnd = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.missing_scheme"));
        }

        var scheme = trimmed[..schemeEnd].ToLowerInvariant();

        return scheme switch
        {
            "vless" => ParseUrlStyle(trimmed, ProxyProtocol.Vless),
            "trojan" => ParseUrlStyle(trimmed, ProxyProtocol.Trojan),
            "vmess" => ParseVmess(trimmed),
            "ss" => ParseShadowsocks(trimmed),
            "socks" => ParseUrlStyle(trimmed, ProxyProtocol.Socks),
            "http" => ParseUrlStyle(trimmed, ProxyProtocol.Http),
            _ => Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkUnsupportedScheme, "error.sharelink.unsupported_scheme")
                .WithArg("scheme", scheme)),
        };
    }

    /// <summary>
    /// Parses a subscription payload: either plain text with one link per line, or a
    /// single Base64 blob containing that text.
    /// </summary>
    public static ShareLinkBatch ParseMany(string? payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return ShareLinkBatch.Empty;
        }

        var text = payload;
        if (Base64Tolerant.LooksLikeBase64(payload))
        {
            // Some panels leave a plain-text prefix before the Base64 body; fall back to
            // the raw payload if decoding fails rather than losing everything.
            if (Base64Tolerant.TryDecodeToString(payload, out var decoded))
            {
                text = decoded;
            }
        }

        var profiles = new List<ServerProfile>();
        var failures = new List<ShareLinkFailure>();

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            // A leading '#' is a comment. Share links also use '#', but only after the
            // authority section, so a line starting with '#' is never a link.
            if (line[0] == '#')
            {
                continue;
            }

            if (!IsShareLink(line))
            {
                // Junk lines are reported only when they look like a broken link; a
                // trailing "generated by ..." banner is not worth alarming the user about.
                if (line.Contains("://", StringComparison.Ordinal))
                {
                    failures.Add(new ShareLinkFailure(
                        Truncate(line),
                        new MyVpnError(ErrorCodes.ShareLinkUnsupportedScheme, "error.sharelink.unsupported_scheme")
                            .WithArg("scheme", SchemeOf(line))));
                }

                continue;
            }

            var result = Parse(line);
            if (result.TryGetValue(out var profile))
            {
                profiles.Add(profile);
            }
            else
            {
                failures.Add(new ShareLinkFailure(Truncate(line), result.Error!));
            }
        }

        return new ShareLinkBatch(profiles, failures);
    }

    // ---------------------------------------------------------------- vless / trojan

    private static Result<ServerProfile> ParseUrlStyle(string link, ProxyProtocol protocol)
    {
        if (!Uri.TryCreate(link, UriKind.Absolute, out var uri))
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.malformed")
                .WithArg("scheme", protocol.ToString().ToLowerInvariant()));
        }

        if (uri.Port <= 0)
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMissingField, "error.sharelink.missing_port"));
        }

        if (string.IsNullOrWhiteSpace(uri.Host))
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMissingField, "error.sharelink.missing_host"));
        }

        var query = ParseQuery(uri.Query);
        var credential = Unescape(uri.UserInfo);

        var transportResult = MapTransport(GetValue(query, "type"));
        if (transportResult.IsFailure)
        {
            return Result<ServerProfile>.Fail(transportResult.Error!);
        }

        var securityResult = MapSecurity(GetValue(query, "security"));
        if (securityResult.IsFailure)
        {
            return Result<ServerProfile>.Fail(securityResult.Error!);
        }

        var security = securityResult.Value;
        var displayName = BuildDisplayName(uri.Fragment, uri.Host, uri.Port);

        var profile = new ServerProfile
        {
            DisplayName = displayName,
            Address = uri.Host,
            Port = uri.Port,
            Protocol = protocol,
            Transport = transportResult.Value,
            Security = security,
            UserId = protocol is ProxyProtocol.Vless ? credential : null,
            Password = protocol is ProxyProtocol.Trojan ? credential : null,
            Host = EmptyToNull(GetValue(query, "host")),
            Path = EmptyToNull(GetValue(query, "path")),
            ServiceName = EmptyToNull(GetValue(query, "serviceName")),
            TransportMode = EmptyToNull(GetValue(query, "mode")),
            ServerName = EmptyToNull(GetValue(query, "sni")),
            Alpn = EmptyToNull(GetValue(query, "alpn")),
            Fingerprint = MapFingerprint(GetValue(query, "fp")),
            Flow = MapFlow(GetValue(query, "flow")),
            RealityPublicKey = EmptyToNull(GetValue(query, "pbk")),
            RealityShortId = EmptyToNull(GetValue(query, "sid")),
            RealitySpiderX = EmptyToNull(GetValue(query, "spx")),
            AllowInsecure = IsTruthy(GetValue(query, "allowInsecure")),
            CountryCode = CountryInference.FromDisplayName(displayName),
        };

        var validation = profile.Validate();
        return validation.IsSuccess
            ? Result<ServerProfile>.Ok(profile)
            : Result<ServerProfile>.Fail(validation.Error!);
    }

    // ------------------------------------------------------------------------ vmess

    private static Result<ServerProfile> ParseVmess(string link)
    {
        var payload = link["vmess://".Length..];
        var hash = payload.IndexOf('#');
        if (hash >= 0)
        {
            payload = payload[..hash];
        }

        if (!Base64Tolerant.TryDecodeToString(payload, out var json))
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkDecodeFailed, "error.sharelink.vmess_base64_invalid"));
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                MaxDepth = 8,
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });
        }
        catch (JsonException ex)
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkDecodeFailed, "error.sharelink.vmess_json_invalid", ErrorSeverity.Error, ex.Message));
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkDecodeFailed, "error.sharelink.vmess_json_invalid"));
            }

            var address = GetJsonString(root, "add");
            var portText = GetJsonString(root, "port");
            var uuid = GetJsonString(root, "id");
            var displayName = GetJsonString(root, "ps");

            if (string.IsNullOrWhiteSpace(address))
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkMissingField, "error.sharelink.missing_host"));
            }

            if (!int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkMissingField, "error.sharelink.missing_port"));
            }

            if (string.IsNullOrWhiteSpace(uuid))
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkMissingField, "error.server.user_id_missing"));
            }

            var transportResult = MapTransport(GetJsonString(root, "net"));
            if (transportResult.IsFailure)
            {
                return Result<ServerProfile>.Fail(transportResult.Error!);
            }

            var tls = GetJsonString(root, "tls");
            var security = tls?.ToLowerInvariant() switch
            {
                "tls" => SecurityKind.Tls,
                "reality" => SecurityKind.Reality,
                "" or null or "none" => SecurityKind.None,
                _ => SecurityKind.Tls,
            };

            var name = string.IsNullOrWhiteSpace(displayName) ? $"{address}:{port}" : displayName!;

            var profile = new ServerProfile
            {
                DisplayName = name,
                Address = address!,
                Port = port,
                Protocol = ProxyProtocol.Vmess,
                Transport = transportResult.Value,
                Security = security,
                UserId = uuid,
                AlterId = ParseIntOrZero(GetJsonString(root, "aid")),
                Encryption = EmptyToNull(GetJsonString(root, "scy")) ?? "auto",
                Host = EmptyToNull(GetJsonString(root, "host")),
                Path = EmptyToNull(GetJsonString(root, "path")),
                ServerName = EmptyToNull(GetJsonString(root, "sni")),
                Alpn = EmptyToNull(GetJsonString(root, "alpn")),
                Fingerprint = MapFingerprint(GetJsonString(root, "fp")),
                CountryCode = CountryInference.FromDisplayName(name),
            };

            var validation = profile.Validate();
            return validation.IsSuccess
                ? Result<ServerProfile>.Ok(profile)
                : Result<ServerProfile>.Fail(validation.Error!);
        }
    }

    // ------------------------------------------------------------------ shadowsocks

    private static Result<ServerProfile> ParseShadowsocks(string link)
    {
        // Shadowsocks links are parsed by hand rather than with System.Uri: the legacy
        // SIP002 form puts a Base64 blob where a URI host belongs, and Base64 routinely
        // contains '/' and '+', which makes Uri mis-parse the authority.
        var body = link["ss://".Length..];

        string? tag = null;
        var hash = body.IndexOf('#');
        if (hash >= 0)
        {
            tag = Unescape(body[(hash + 1)..]);
            body = body[..hash];
        }

        var queryStart = body.IndexOf('?');
        var query = queryStart >= 0 ? ParseQuery(body[queryStart..]) : EmptyQuery;
        if (queryStart >= 0)
        {
            body = body[..queryStart];
        }

        body = body.TrimEnd('/');
        if (body.Length == 0)
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.malformed").WithArg("scheme", "ss"));
        }

        string methodPassword;
        string hostPort;

        var at = body.LastIndexOf('@');
        if (at >= 0)
        {
            var left = body[..at];
            hostPort = body[(at + 1)..];
            methodPassword = Base64Tolerant.TryDecodeToString(left, out var decodedLeft) ? decodedLeft : Unescape(left);
        }
        else
        {
            if (!Base64Tolerant.TryDecodeToString(body, out var decoded))
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkDecodeFailed, "error.sharelink.ss_base64_invalid"));
            }

            var innerAt = decoded.LastIndexOf('@');
            if (innerAt < 0)
            {
                return Result<ServerProfile>.Fail(new MyVpnError(
                    ErrorCodes.ShareLinkMalformed, "error.sharelink.malformed").WithArg("scheme", "ss"));
            }

            methodPassword = decoded[..innerAt];
            hostPort = decoded[(innerAt + 1)..];
        }

        var separator = methodPassword.IndexOf(':');
        if (separator <= 0)
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.ss_missing_method"));
        }

        var method = methodPassword[..separator];
        var password = methodPassword[(separator + 1)..];

        if (!TrySplitHostPort(hostPort, out var host, out var port))
        {
            return Result<ServerProfile>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkMalformed, "error.sharelink.missing_port"));
        }

        var name = string.IsNullOrWhiteSpace(tag) ? $"{host}:{port}" : tag!;

        var profile = new ServerProfile
        {
            DisplayName = name,
            Address = host,
            Port = port,
            Protocol = ProxyProtocol.Shadowsocks,
            Password = password,
            Encryption = method,
            Transport = TransportKind.Tcp,
            Security = SecurityKind.None,
            CountryCode = CountryInference.FromDisplayName(name),
        };

        var validation = profile.Validate();
        return validation.IsSuccess
            ? Result<ServerProfile>.Ok(profile)
            : Result<ServerProfile>.Fail(validation.Error!);
    }

    // ---------------------------------------------------------------------- helpers

    private static readonly IReadOnlyDictionary<string, string> EmptyQuery =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Splits <c>host:port</c>, <c>[v6]:port</c> or a bare IPv6 literal with a trailing
    /// port. Returns false when no usable port is present.
    /// </summary>
    internal static bool TrySplitHostPort(string input, out string host, out int port)
    {
        host = string.Empty;
        port = 0;

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var value = input.Trim();

        // Bracketed IPv6: [2001:db8::1]:443
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            host = value[1..close];
            var rest = value[(close + 1)..];
            if (!rest.StartsWith(':'))
            {
                return false;
            }

            return int.TryParse(rest[1..], NumberStyles.None, CultureInfo.InvariantCulture, out port)
                   && port is > 0 and <= 65535;
        }

        // Exactly one colon means host:port. More than one means a bare IPv6 literal
        // (which needs a bracket form to carry a port) or malformed input.
        var firstColon = value.IndexOf(':');
        var lastColon = value.LastIndexOf(':');
        if (firstColon < 0 || firstColon != lastColon)
        {
            return false;
        }

        host = value[..firstColon];
        if (host.Length == 0)
        {
            return false;
        }

        return int.TryParse(value[(firstColon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port)
               && port is > 0 and <= 65535;
    }

    internal static IReadOnlyDictionary<string, string> ParseQuery(string? query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(query))
        {
            return result;
        }

        var value = query.TrimStart('?');
        foreach (var pair in value.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0)
            {
                result[Unescape(pair)] = string.Empty;
                continue;
            }

            var key = Unescape(pair[..eq]);
            var val = Unescape(pair[(eq + 1)..]);

            // First occurrence wins: later duplicates must not silently override an
            // earlier security-relevant parameter such as `security` or `sni`.
            if (!result.ContainsKey(key))
            {
                result[key] = val;
            }
        }

        return result;
    }

    private static string? GetValue(IReadOnlyDictionary<string, string> query, string key) =>
        query.TryGetValue(key, out var value) ? value : null;

    private static string? GetJsonString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number => property.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => null,
                _ => null,
            };
        }

        return null;
    }

    private static Result<TransportKind> MapTransport(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant();

        return normalized switch
        {
            null or "" or "tcp" or "raw" or "none" => Result<TransportKind>.Ok(TransportKind.Tcp),
            "ws" or "websocket" => Result<TransportKind>.Ok(TransportKind.WebSocket),
            "grpc" or "gun" => Result<TransportKind>.Ok(TransportKind.Grpc),
            "httpupgrade" => Result<TransportKind>.Ok(TransportKind.HttpUpgrade),
            "xhttp" or "splithttp" => Result<TransportKind>.Ok(TransportKind.XHttp),
            "kcp" or "mkcp" => Result<TransportKind>.Ok(TransportKind.Kcp),
            "quic" => Result<TransportKind>.Ok(TransportKind.Quic),
            "http" or "h2" or "h2c" => Result<TransportKind>.Ok(TransportKind.Http),
            _ => Result<TransportKind>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkUnsupportedScheme, "error.sharelink.unknown_transport")
                .WithArg("transport", normalized)),
        };
    }

    private static Result<SecurityKind> MapSecurity(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant();

        return normalized switch
        {
            null or "" or "none" => Result<SecurityKind>.Ok(SecurityKind.None),
            "tls" or "xtls" or "https" => Result<SecurityKind>.Ok(SecurityKind.Tls),
            "reality" => Result<SecurityKind>.Ok(SecurityKind.Reality),
            _ => Result<SecurityKind>.Fail(new MyVpnError(
                ErrorCodes.ShareLinkUnsupportedScheme, "error.sharelink.unknown_security")
                .WithArg("security", normalized)),
        };
    }

    private static TlsFingerprint MapFingerprint(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "chrome" => TlsFingerprint.Chrome,
        "firefox" => TlsFingerprint.Firefox,
        "safari" => TlsFingerprint.Safari,
        "ios" => TlsFingerprint.Ios,
        "android" => TlsFingerprint.Android,
        "edge" => TlsFingerprint.Edge,
        "random" or "randomized" => TlsFingerprint.Randomized,
        _ => TlsFingerprint.None,
    };

    private static VlessFlow MapFlow(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "xtls-rprx-vision" or "xtls-rprx-vision-udp443" => VlessFlow.XtlsRprxVision,
        _ => VlessFlow.None,
    };

    private static bool IsTruthy(string? value) =>
        value is not null
        && (value.Equals("1", StringComparison.Ordinal)
            || value.Equals("true", StringComparison.OrdinalIgnoreCase));

    private static int ParseIntOrZero(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;

    private static string? EmptyToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    private static string BuildDisplayName(string? fragment, string host, int port)
    {
        var name = Unescape(fragment ?? string.Empty).TrimStart('#').Trim();
        return string.IsNullOrWhiteSpace(name) ? $"{host}:{port}" : name;
    }

    /// <summary>
    /// Percent-decodes a URI component, tolerating malformed escapes rather than throwing.
    /// </summary>
    internal static string Unescape(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    private static string SchemeOf(string line)
    {
        var index = line.IndexOf("://", StringComparison.Ordinal);
        return index > 0 ? line[..index].ToLowerInvariant() : "unknown";
    }

    /// <summary>
    /// Truncates a reported line so that a paste of thousands of characters cannot flood
    /// the UI or a log file. Credentials are masked by the caller when displayed.
    /// </summary>
    private static string Truncate(string line) =>
        line.Length <= 120 ? line : line[..120] + "...";
}
