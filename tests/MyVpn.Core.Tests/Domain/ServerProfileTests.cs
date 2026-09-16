using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class ServerProfileTests
{
    private static ServerProfile ValidVless() => new()
    {
        Address = "example.com",
        Port = 443,
        Protocol = ProxyProtocol.Vless,
        UserId = "11111111-1111-1111-1111-111111111111",
    };

    [Fact]
    public void A_minimal_vless_profile_is_valid()
    {
        ValidVless().Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Missing_address_is_rejected()
    {
        var result = (ValidVless() with { Address = "" }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.address_missing");
    }

    [Fact]
    public void Whitespace_address_is_rejected()
    {
        (ValidVless() with { Address = "   " }).Validate().IsFailure.ShouldBeTrue();
    }

    [Fact]
    public void Port_zero_is_rejected()
    {
        var result = (ValidVless() with { Port = 0 }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.port_out_of_range");
        result.Error.Arguments["port"].ShouldBe("0");
    }

    [Fact]
    public void Port_65536_is_rejected()
    {
        var result = (ValidVless() with { Port = 65536 }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.port_out_of_range");
    }

    [Fact]
    public void Negative_port_is_rejected()
    {
        (ValidVless() with { Port = -1 }).Validate().IsFailure.ShouldBeTrue();
    }

    [Fact]
    public void Boundary_ports_are_accepted()
    {
        (ValidVless() with { Port = 1 }).Validate().IsSuccess.ShouldBeTrue();
        (ValidVless() with { Port = 65535 }).Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Vless_without_user_id_is_rejected()
    {
        var result = (ValidVless() with { UserId = null }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.user_id_missing");
    }

    [Fact]
    public void Vmess_without_user_id_is_rejected()
    {
        var result = (ValidVless() with { Protocol = ProxyProtocol.Vmess, UserId = "" }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.user_id_missing");
    }

    [Fact]
    public void Vmess_with_user_id_is_valid()
    {
        (ValidVless() with { Protocol = ProxyProtocol.Vmess }).Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Trojan_without_password_is_rejected()
    {
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Trojan,
        };

        var result = profile.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.password_missing");
    }

    [Fact]
    public void Trojan_with_password_is_valid()
    {
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Trojan,
            Password = "secret",
        };

        profile.Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Shadowsocks_without_password_is_rejected()
    {
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 8388,
            Protocol = ProxyProtocol.Shadowsocks,
        };

        profile.Validate().IsFailure.ShouldBeTrue();
    }

    [Fact]
    public void Socks_and_http_need_no_credentials()
    {
        foreach (var protocol in new[] { ProxyProtocol.Socks, ProxyProtocol.Http })
        {
            var profile = new ServerProfile { Address = "example.com", Port = 1080, Protocol = protocol };
            profile.Validate().IsSuccess.ShouldBeTrue($"{protocol}");
        }
    }

    [Fact]
    public void Reality_without_public_key_is_rejected()
    {
        var result = (ValidVless() with { Security = SecurityKind.Reality }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.reality_public_key_missing");
    }

    [Fact]
    public void Reality_with_a_public_key_is_valid()
    {
        (ValidVless() with { Security = SecurityKind.Reality, RealityPublicKey = "pbk" })
            .Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Tls_does_not_require_a_reality_key()
    {
        (ValidVless() with { Security = SecurityKind.Tls }).Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Grpc_without_service_or_path_is_rejected()
    {
        var result = (ValidVless() with { Transport = TransportKind.Grpc }).Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.server.grpc_service_missing");
    }

    [Fact]
    public void Grpc_with_a_service_name_is_valid()
    {
        (ValidVless() with { Transport = TransportKind.Grpc, ServiceName = "svc" })
            .Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Grpc_with_only_a_path_is_valid()
    {
        (ValidVless() with { Transport = TransportKind.Grpc, Path = "/svc" })
            .Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Web_socket_does_not_require_a_service_name()
    {
        (ValidVless() with { Transport = TransportKind.WebSocket, Path = "/ws" })
            .Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void EffectiveServerName_prefers_explicit_sni()
    {
        var profile = ValidVless() with { Address = "1.2.3.4", Host = "host.example", ServerName = "sni.example" };

        profile.EffectiveServerName.ShouldBe("sni.example");
    }

    [Fact]
    public void EffectiveServerName_falls_back_to_host()
    {
        var profile = ValidVless() with { Address = "1.2.3.4", Host = "host.example", ServerName = null };

        profile.EffectiveServerName.ShouldBe("host.example");
    }

    [Fact]
    public void EffectiveServerName_falls_back_to_address()
    {
        var profile = ValidVless() with { Address = "1.2.3.4", Host = null, ServerName = null };

        profile.EffectiveServerName.ShouldBe("1.2.3.4");
    }

    [Fact]
    public void EffectiveServerName_ignores_whitespace_values()
    {
        var profile = ValidVless() with { Address = "1.2.3.4", Host = "  ", ServerName = "  " };

        profile.EffectiveServerName.ShouldBe("1.2.3.4");
    }

    [Fact]
    public void Endpoint_formats_address_and_port()
    {
        (ValidVless() with { Address = "example.com", Port = 8443 })
            .Endpoint.ShouldBe("example.com:8443");
    }

    [Fact]
    public void ToEndpoint_produces_the_same_pair()
    {
        var endpoint = (ValidVless() with { Address = "example.com", Port = 8443 }).ToEndpoint();

        endpoint.Address.ShouldBe("example.com");
        endpoint.Port.ShouldBe(8443);
        endpoint.IsIpLiteral.ShouldBeFalse();
        endpoint.ToString().ShouldBe("example.com:8443");
    }

    [Fact]
    public void ServerEndpoint_recognises_an_ipv4_literal()
    {
        var endpoint = new ServerEndpoint("1.2.3.4", 443);

        endpoint.IsIpLiteral.ShouldBeTrue();
        endpoint.ToString().ShouldBe("1.2.3.4:443");
    }

    [Fact]
    public void ServerEndpoint_brackets_an_ipv6_literal()
    {
        var endpoint = new ServerEndpoint("2001:db8::1", 443);

        endpoint.IsIpLiteral.ShouldBeTrue();
        endpoint.ToString().ShouldBe("[2001:db8::1]:443");
    }

    [Fact]
    public void Defaults_are_sane()
    {
        var profile = new ServerProfile();

        profile.Protocol.ShouldBe(ProxyProtocol.Vless);
        profile.Transport.ShouldBe(TransportKind.Tcp);
        profile.Security.ShouldBe(SecurityKind.None);
        profile.Fingerprint.ShouldBe(TlsFingerprint.None);
        profile.Flow.ShouldBe(VlessFlow.None);
        profile.AllowInsecure.ShouldBeFalse();
        profile.IsFavorite.ShouldBeFalse();
        profile.Tags.ShouldBeEmpty();
        profile.Id.ShouldNotBe(Guid.Empty);
    }
}
