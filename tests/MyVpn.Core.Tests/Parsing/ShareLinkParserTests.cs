using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class ShareLinkParserTests
{
    private const string Uuid = "11111111-1111-1111-1111-111111111111";

    private static ServerProfile ParseOk(string link)
    {
        var result = ShareLinkParser.Parse(link);

        result.IsSuccess.ShouldBeTrue(result.Error?.ToString());
        return result.Value;
    }

    private static string Vmess(string json) => "vmess://" + Base64Tolerant.EncodeString(json);

    // ------------------------------------------------------------ vless / trojan

    [Fact]
    public void Parses_a_vless_websocket_tls_link()
    {
        var link = $"vless://{Uuid}@example.com:443" +
                   "?security=tls&type=ws&sni=sni.example.com&path=%2Fws" +
                   "&host=host.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1#My%20Server";

        var profile = ParseOk(link);

        profile.Protocol.ShouldBe(ProxyProtocol.Vless);
        profile.Address.ShouldBe("example.com");
        profile.Port.ShouldBe(443);
        profile.UserId.ShouldBe(Uuid);
        profile.Security.ShouldBe(SecurityKind.Tls);
        profile.Transport.ShouldBe(TransportKind.WebSocket);
        profile.Host.ShouldBe("host.example.com");
        profile.Path.ShouldBe("/ws");
        profile.ServerName.ShouldBe("sni.example.com");
        profile.Fingerprint.ShouldBe(TlsFingerprint.Chrome);
        profile.Alpn.ShouldBe("h2,http/1.1");
        profile.DisplayName.ShouldBe("My Server");
    }

    [Fact]
    public void Parses_a_vless_reality_link()
    {
        var link = $"vless://{Uuid}@example.com:443" +
                   "?security=reality&type=tcp&pbk=PUBLICKEY&sid=abcd&spx=%2F&flow=xtls-rprx-vision#DE%20Node";

        var profile = ParseOk(link);

        profile.Security.ShouldBe(SecurityKind.Reality);
        profile.RealityPublicKey.ShouldBe("PUBLICKEY");
        profile.RealityShortId.ShouldBe("abcd");
        profile.RealitySpiderX.ShouldBe("/");
        profile.Flow.ShouldBe(VlessFlow.XtlsRprxVision);
        profile.CountryCode.ShouldBe("DE");
    }

    [Fact]
    public void Reality_without_a_public_key_is_rejected()
    {
        var result = ShareLinkParser.Parse($"vless://{Uuid}@example.com:443?security=reality");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.reality_public_key_missing");
    }

    [Fact]
    public void Xtls_and_https_are_treated_as_tls()
    {
        ParseOk($"vless://{Uuid}@example.com:443?security=xtls").Security.ShouldBe(SecurityKind.Tls);
        ParseOk($"vless://{Uuid}@example.com:443?security=https").Security.ShouldBe(SecurityKind.Tls);
    }

    [Fact]
    public void A_vless_link_without_security_stays_plain()
    {
        ParseOk($"vless://{Uuid}@example.com:443").Security.ShouldBe(SecurityKind.None);
    }

    [Fact]
    public void Parses_a_trojan_link()
    {
        var profile = ParseOk("trojan://secret@example.com:443?security=tls&type=tcp&sni=x.example#TR");

        profile.Protocol.ShouldBe(ProxyProtocol.Trojan);
        profile.Password.ShouldBe("secret");
        profile.UserId.ShouldBeNull();
        profile.Security.ShouldBe(SecurityKind.Tls);
        profile.DisplayName.ShouldBe("TR");
    }

    [Fact]
    public void Parses_a_socks_link()
    {
        var profile = ParseOk("socks://example.com:1080#Socks");

        profile.Protocol.ShouldBe(ProxyProtocol.Socks);
    }

    [Fact]
    public void Parses_an_http_link()
    {
        var profile = ParseOk("http://example.com:8080#Http");

        profile.Protocol.ShouldBe(ProxyProtocol.Http);
    }

    [Fact]
    public void Parses_an_ipv6_host_in_brackets()
    {
        var profile = ParseOk($"vless://{Uuid}@[2001:db8::1]:443?security=tls#V6");

        profile.Port.ShouldBe(443);
        profile.Address.Trim('[', ']').ShouldBe("2001:db8::1");
    }

    [Fact]
    public void A_missing_port_is_rejected()
    {
        var result = ShareLinkParser.Parse($"vless://{Uuid}@example.com?type=tcp");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.missing_port");
    }

    [Fact]
    public void A_port_of_zero_is_rejected()
    {
        ShareLinkParser.Parse($"vless://{Uuid}@example.com:0?sni=x").IsFailure.ShouldBeTrue();
    }

    [Fact]
    public void An_unknown_transport_is_rejected()
    {
        var result = ShareLinkParser.Parse($"vless://{Uuid}@example.com:443?type=carrier-pigeon");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.unknown_transport");
        result.Error.Arguments["transport"].ShouldBe("carrier-pigeon");
    }

    [Fact]
    public void An_unknown_security_is_rejected_and_not_downgraded()
    {
        var result = ShareLinkParser.Parse($"vless://{Uuid}@example.com:443?security=quantum");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.unknown_security");
        result.Error.Arguments["security"].ShouldBe("quantum");
    }

    [Fact]
    public void The_first_duplicate_query_parameter_wins()
    {
        var profile = ParseOk($"vless://{Uuid}@example.com:443?security=tls&security=none&sni=first&sni=second");

        profile.Security.ShouldBe(SecurityKind.Tls);
        profile.ServerName.ShouldBe("first");
    }

    [Theory]
    [InlineData("ws", TransportKind.WebSocket)]
    [InlineData("websocket", TransportKind.WebSocket)]
    [InlineData("grpc", TransportKind.Grpc)]
    [InlineData("gun", TransportKind.Grpc)]
    [InlineData("httpupgrade", TransportKind.HttpUpgrade)]
    [InlineData("xhttp", TransportKind.XHttp)]
    [InlineData("splithttp", TransportKind.XHttp)]
    [InlineData("kcp", TransportKind.Kcp)]
    [InlineData("quic", TransportKind.Quic)]
    [InlineData("http", TransportKind.Http)]
    [InlineData("h2", TransportKind.Http)]
    [InlineData("tcp", TransportKind.Tcp)]
    [InlineData("raw", TransportKind.Tcp)]
    [InlineData(null, TransportKind.Tcp)]
    public void Transport_names_map_as_documented(string? type, TransportKind expected)
    {
        var suffix = type is null ? string.Empty : "&type=" + type;
        var profile = ParseOk($"vless://{Uuid}@example.com:443?security=tls&serviceName=s&path=%2Fp{suffix}");

        profile.Transport.ShouldBe(expected);
    }

    [Fact]
    public void A_vless_without_a_user_id_is_rejected()
    {
        var result = ShareLinkParser.Parse("vless://@example.com:443");

        result.IsFailure.ShouldBeTrue();
    }

    // ---------------------------------------------------------------------- vmess

    [Fact]
    public void Parses_a_vmess_link_with_string_port_and_aid()
    {
        var link = Vmess(
            "{\"v\":\"2\",\"ps\":\"VM Node\",\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"" + Uuid + "\"," +
            "\"aid\":\"64\",\"net\":\"ws\",\"host\":\"h.example\",\"path\":\"/p\",\"tls\":\"tls\",\"scy\":\"auto\"}");

        var profile = ParseOk(link);

        profile.Protocol.ShouldBe(ProxyProtocol.Vmess);
        profile.Address.ShouldBe("1.2.3.4");
        profile.Port.ShouldBe(443);
        profile.UserId.ShouldBe(Uuid);
        profile.AlterId.ShouldBe(64);
        profile.Transport.ShouldBe(TransportKind.WebSocket);
        profile.Host.ShouldBe("h.example");
        profile.Path.ShouldBe("/p");
        profile.Security.ShouldBe(SecurityKind.Tls);
        profile.Encryption.ShouldBe("auto");
        profile.DisplayName.ShouldBe("VM Node");
    }

    [Fact]
    public void Parses_a_vmess_link_with_numeric_port_and_aid()
    {
        var link = Vmess(
            "{\"ps\":\"VM Numeric\",\"add\":\"1.2.3.4\",\"port\":8443,\"id\":\"" + Uuid + "\"," +
            "\"aid\":0,\"net\":\"tcp\"}");

        var profile = ParseOk(link);

        profile.Port.ShouldBe(8443);
        profile.AlterId.ShouldBe(0);
        profile.Security.ShouldBe(SecurityKind.None);
        profile.Encryption.ShouldBe("auto");
    }

    [Fact]
    public void A_vmess_link_without_a_remark_falls_back_to_host_and_port()
    {
        var link = Vmess("{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"" + Uuid + "\"}");

        ParseOk(link).DisplayName.ShouldBe("1.2.3.4:443");
    }

    [Fact]
    public void A_vmess_link_with_invalid_base64_is_rejected()
    {
        var result = ShareLinkParser.Parse("vmess://!!!!not-base64!!!!");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.vmess_base64_invalid");
    }

    [Fact]
    public void A_vmess_link_with_invalid_json_is_rejected()
    {
        var result = ShareLinkParser.Parse(Vmess("this is not json"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.vmess_json_invalid");
    }

    [Fact]
    public void A_vmess_link_whose_json_is_not_an_object_is_rejected()
    {
        var result = ShareLinkParser.Parse(Vmess("[1,2,3]"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.vmess_json_invalid");
    }

    [Fact]
    public void A_vmess_link_without_a_host_is_rejected()
    {
        var result = ShareLinkParser.Parse(Vmess("{\"port\":\"443\",\"id\":\"" + Uuid + "\"}"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.missing_host");
    }

    [Fact]
    public void A_vmess_link_without_a_port_is_rejected()
    {
        var result = ShareLinkParser.Parse(Vmess("{\"add\":\"1.2.3.4\",\"id\":\"" + Uuid + "\"}"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.missing_port");
    }

    [Fact]
    public void A_vmess_link_without_an_id_is_rejected()
    {
        var result = ShareLinkParser.Parse(Vmess("{\"add\":\"1.2.3.4\",\"port\":\"443\"}"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.user_id_missing");
    }

    [Fact]
    public void A_vmess_fragment_is_not_part_of_the_base64_payload()
    {
        var link = Vmess("{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"" + Uuid + "\"}") + "#ignored";

        ParseOk(link).Address.ShouldBe("1.2.3.4");
    }

    // ---------------------------------------------------------------- shadowsocks

    [Fact]
    public void Parses_the_sip002_shadowsocks_form()
    {
        var userInfo = Base64Tolerant.EncodeString("aes-256-gcm:secret");
        var profile = ParseOk($"ss://{userInfo}@example.com:8388#SS%20Node");

        profile.Protocol.ShouldBe(ProxyProtocol.Shadowsocks);
        profile.Encryption.ShouldBe("aes-256-gcm");
        profile.Password.ShouldBe("secret");
        profile.Address.ShouldBe("example.com");
        profile.Port.ShouldBe(8388);
        profile.DisplayName.ShouldBe("SS Node");
    }

    [Fact]
    public void Parses_the_legacy_shadowsocks_form()
    {
        var blob = Base64Tolerant.EncodeString("chacha20-ietf-poly1305:pw@1.2.3.4:8388");
        var profile = ParseOk($"ss://{blob}#Legacy");

        profile.Protocol.ShouldBe(ProxyProtocol.Shadowsocks);
        profile.Encryption.ShouldBe("chacha20-ietf-poly1305");
        profile.Password.ShouldBe("pw");
        profile.Address.ShouldBe("1.2.3.4");
        profile.Port.ShouldBe(8388);
        profile.DisplayName.ShouldBe("Legacy");
    }

    [Fact]
    public void Parses_a_shadowsocks_link_with_a_bracketed_ipv6_host()
    {
        var blob = Base64Tolerant.EncodeString("aes-128-gcm:pw@[2001:db8::2]:8388");
        var profile = ParseOk($"ss://{blob}#V6");

        profile.Address.ShouldBe("2001:db8::2");
        profile.Port.ShouldBe(8388);
    }

    [Fact]
    public void A_shadowsocks_link_without_a_method_is_rejected()
    {
        var blob = Base64Tolerant.EncodeString("no-colon@1.2.3.4:8388");
        var result = ShareLinkParser.Parse($"ss://{blob}");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.ss_missing_method");
    }

    [Fact]
    public void A_shadowsocks_link_with_unreadable_base64_is_rejected()
    {
        var result = ShareLinkParser.Parse("ss://!!!!not-base64!!!!");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.ss_base64_invalid");
    }

    [Fact]
    public void A_shadowsocks_link_without_a_port_is_rejected()
    {
        var blob = Base64Tolerant.EncodeString("aes-128-gcm:pw@1.2.3.4");
        var result = ShareLinkParser.Parse($"ss://{blob}");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.missing_port");
    }

    [Fact]
    public void A_shadowsocks_link_without_a_tag_uses_host_and_port()
    {
        var userInfo = Base64Tolerant.EncodeString("aes-128-gcm:pw");
        ParseOk($"ss://{userInfo}@example.com:8388").DisplayName.ShouldBe("example.com:8388");
    }

    // ------------------------------------------------------------------ ParseMany

    [Fact]
    public void IsShareLink_recognises_the_supported_schemes()
    {
        foreach (var scheme in new[] { "vless", "vmess", "trojan", "ss", "socks", "http" })
        {
            ShareLinkParser.IsShareLink($"{scheme}://x").ShouldBeTrue(scheme);
        }

        ShareLinkParser.IsShareLink("hysteria2://x").ShouldBeFalse();
        ShareLinkParser.IsShareLink("# comment").ShouldBeFalse();
        ShareLinkParser.IsShareLink(null).ShouldBeFalse();
        ShareLinkParser.IsShareLink("").ShouldBeFalse();
    }

    [Fact]
    public void ParseMany_parses_a_plain_newline_separated_list()
    {
        var payload = $"{Link1()}\n{Link2()}\n";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(2);
        batch.Failures.ShouldBeEmpty();
        batch.HasProfiles.ShouldBeTrue();
    }

    [Fact]
    public void ParseMany_parses_a_base64_blob()
    {
        var blob = Base64Tolerant.EncodeString($"{Link1()}\n{Link2()}");

        var batch = ShareLinkParser.ParseMany(blob);

        batch.Profiles.Count.ShouldBe(2);
        batch.Failures.ShouldBeEmpty();
    }

    [Fact]
    public void ParseMany_skips_blank_lines_and_comments()
    {
        var payload = $"\n   \n# this is a comment\n{Link1()}\n\n#another\n";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(1);
        batch.Failures.ShouldBeEmpty();
    }

    [Fact]
    public void ParseMany_handles_crlf_line_endings()
    {
        var payload = $"{Link1()}\r\n{Link2()}\r\n";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(2);
    }

    [Fact]
    public void One_bad_line_does_not_prevent_the_others_from_parsing()
    {
        var payload = $"{Link1()}\nvless://{Uuid}@missing-port.example\n{Link2()}";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(2);
        batch.Failures.Count.ShouldBe(1);
        batch.Failures[0].Error.MessageKey.ShouldBe("error.sharelink.missing_port");
        batch.Failures[0].Line.ShouldContain("missing-port.example");
    }

    [Fact]
    public void An_unsupported_scheme_is_recorded_as_a_failure()
    {
        var payload = $"{Link1()}\nhysteria2://example.com:443#H";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(1);
        batch.Failures.Count.ShouldBe(1);
        batch.Failures[0].Error.Code.ShouldBe(ErrorCodes.ShareLinkUnsupportedScheme);
        batch.Failures[0].Error.Arguments["scheme"].ShouldBe("hysteria2");
    }

    [Fact]
    public void Junk_lines_without_a_scheme_are_silently_skipped()
    {
        var payload = $"{Link1()}\ngenerated by some panel\n";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(1);
        batch.Failures.ShouldBeEmpty();
    }

    [Fact]
    public void ParseMany_returns_empty_for_null_or_whitespace()
    {
        ShareLinkParser.ParseMany(null).Profiles.ShouldBeEmpty();
        ShareLinkParser.ParseMany("").Profiles.ShouldBeEmpty();
        ShareLinkParser.ParseMany("   ").Profiles.ShouldBeEmpty();
        ShareLinkParser.ParseMany(null).Failures.ShouldBeEmpty();
    }

    [Fact]
    public void A_long_failing_line_is_truncated_in_the_failure_report()
    {
        var payload = "vless://" + new string('a', 500);

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Failures.Count.ShouldBe(1);
        batch.Failures[0].Line.Length.ShouldBeLessThanOrEqualTo(123);
    }

    [Fact]
    public void ParseMany_infers_a_country_from_a_flag_emoji_remark()
    {
        var payload = $"vless://{Uuid}@example.com:443?security=tls#\U0001F1E9\U0001F1EA%20Frankfurt";

        var batch = ShareLinkParser.ParseMany(payload);

        batch.Profiles.Count.ShouldBe(1);
        batch.Profiles[0].CountryCode.ShouldBe("DE");
        batch.Profiles[0].DisplayName.ShouldBe("\U0001F1E9\U0001F1EA Frankfurt");
    }

    // ------------------------------------------------------------------- failures

    [Fact]
    public void Parse_rejects_an_empty_link()
    {
        var result = ShareLinkParser.Parse("");

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ShareLinkMalformed);
        result.Error.MessageKey.ShouldBe("error.sharelink.empty");
    }

    [Fact]
    public void Parse_rejects_a_link_without_a_scheme()
    {
        var result = ShareLinkParser.Parse("example.com:443");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.sharelink.missing_scheme");
    }

    [Fact]
    public void Parse_rejects_an_unsupported_scheme()
    {
        var result = ShareLinkParser.Parse("hysteria2://example.com:443");

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ShareLinkUnsupportedScheme);
        result.Error.Arguments["scheme"].ShouldBe("hysteria2");
    }

    [Fact]
    public void Schemes_are_matched_case_insensitively()
    {
        ParseOk($"VLESS://{Uuid}@example.com:443").Protocol.ShouldBe(ProxyProtocol.Vless);
    }

    [Fact]
    public void A_percent_encoded_fragment_is_decoded()
    {
        var profile = ParseOk($"vless://{Uuid}@example.com:443?security=tls#Tokyo%20%231");

        profile.DisplayName.ShouldBe("Tokyo #1");
    }

    private static string Link1() => $"vless://{Uuid}@one.example.com:443?security=tls&type=tcp#One";

    private static string Link2() => $"trojan://pw@two.example.com:8443?security=tls&type=tcp#Two";
}
