using System.Text.Json.Nodes;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Xray;
using Shouldly;

namespace MyVpn.Core.Tests;

/// <summary>
/// Behavioural tests for <see cref="XrayConfigBuilder"/>: protocol mapping, transports,
/// inbound selection, DNS and validation propagation.
/// </summary>
public sealed class XrayConfigBuilderTests
{
    // ---------------------------------------------------------------- protocols

    [Fact]
    public void Vless_maps_encryption_flow_and_tls()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Vless,
            security: SecurityKind.Tls) with
        {
            Flow = VlessFlow.XtlsRprxVision,
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        outbound["protocol"]!.GetValue<string>().ShouldBe("vless");

        var server = outbound["settings"]!["vnext"]!.AsArray()[0]!.AsObject();
        server["address"]!.GetValue<string>().ShouldBe(XrayConfigTestFactory.HostName);
        server["port"]!.GetValue<int>().ShouldBe(XrayConfigTestFactory.DefaultPort);

        var user = server["users"]!.AsArray()[0]!.AsObject();
        user["id"]!.GetValue<string>().ShouldBe(XrayConfigTestFactory.Uuid);
        user["encryption"]!.GetValue<string>().ShouldBe("none");
        user["flow"]!.GetValue<string>().ShouldBe("xtls-rprx-vision");

        var stream = XrayConfigTestFactory.StreamSettings(outbound);
        stream["security"]!.GetValue<string>().ShouldBe("tls");
        stream["tlsSettings"]!["serverName"]!.GetValue<string>().ShouldBe(XrayConfigTestFactory.DefaultSni);
    }

    [Fact]
    public void Vless_without_flow_omits_the_flow_field()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);
        var user = outbound["settings"]!["vnext"]!.AsArray()[0]!["users"]!.AsArray()[0]!.AsObject();

        user.ContainsKey("flow").ShouldBeFalse();
        user.ContainsKey("security").ShouldBeFalse();
        user.ContainsKey("alterId").ShouldBeFalse();
    }

    [Fact]
    public void Vmess_maps_alterId_and_security()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Vmess,
            security: SecurityKind.Tls) with
        {
            AlterId = 4,
            Encryption = "auto",
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        outbound["protocol"]!.GetValue<string>().ShouldBe("vmess");

        var user = outbound["settings"]!["vnext"]!.AsArray()[0]!["users"]!.AsArray()[0]!.AsObject();
        user["id"]!.GetValue<string>().ShouldBe(XrayConfigTestFactory.Uuid);
        user["alterId"]!.GetValue<int>().ShouldBe(4);
        user["security"]!.GetValue<string>().ShouldBe("auto");

        // VMess uses `security`, not VLESS's `encryption`.
        user.ContainsKey("encryption").ShouldBeFalse();
        user.ContainsKey("flow").ShouldBeFalse();
    }

    [Fact]
    public void Vmess_without_an_explicit_cipher_uses_auto()
    {
        var profile = XrayConfigTestFactory.Profile(protocol: ProxyProtocol.Vmess) with { Encryption = null };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);
        var user = outbound["settings"]!["vnext"]!.AsArray()[0]!["users"]!.AsArray()[0]!.AsObject();

        user["security"]!.GetValue<string>().ShouldBe("auto");
    }

    [Fact]
    public void Trojan_uses_server_settings_with_a_password()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Trojan,
            userId: null,
            password: "trojan-secret",
            security: SecurityKind.Tls);

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        outbound["protocol"]!.GetValue<string>().ShouldBe("trojan");

        var server = outbound["settings"]!["servers"]!.AsArray()[0]!.AsObject();
        server["address"]!.GetValue<string>().ShouldBe(XrayConfigTestFactory.HostName);
        server["port"]!.GetValue<int>().ShouldBe(XrayConfigTestFactory.DefaultPort);
        server["password"]!.GetValue<string>().ShouldBe("trojan-secret");

        // Trojan has no cipher.
        server.ContainsKey("method").ShouldBeFalse();
    }

    [Fact]
    public void Shadowsocks_uses_the_server_settings_with_a_cipher()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Shadowsocks,
            userId: null,
            password: "ss-secret",
            security: SecurityKind.None) with
        {
            Encryption = "chacha20-poly1305",
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        outbound["protocol"]!.GetValue<string>().ShouldBe("shadowsocks");

        var server = outbound["settings"]!["servers"]!.AsArray()[0]!.AsObject();
        server["password"]!.GetValue<string>().ShouldBe("ss-secret");
        server["method"]!.GetValue<string>().ShouldBe("chacha20-poly1305");
    }

    [Fact]
    public void Shadowsocks_without_an_explicit_cipher_defaults_to_aes_256_gcm()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Shadowsocks,
            userId: null,
            password: "ss-secret",
            security: SecurityKind.None) with
        {
            Encryption = null,
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);
        var server = outbound["settings"]!["servers"]!.AsArray()[0]!.AsObject();

        server["method"]!.GetValue<string>().ShouldBe("aes-256-gcm");
    }

    [Fact]
    public void A_protocol_that_cannot_be_an_outbound_is_rejected()
    {
        var profile = XrayConfigTestFactory.Profile(
            protocol: ProxyProtocol.Socks,
            userId: null,
            password: null,
            security: SecurityKind.None);

        var result = XrayConfigBuilder.Build(XrayConfigTestFactory.Request(profile: profile));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.config.protocol_not_supported_for_outbound");
    }

    // ---------------------------------------------------------------- mux

    [Fact]
    public void Mux_is_omitted_when_disabled()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        outbound.ContainsKey("mux").ShouldBeFalse();
        XrayConfigTestFactory.Serialize(result).ShouldNotContain("\"mux\"");
    }

    [Theory]
    [InlineData(XudpUdp443Handling.Reject, "reject")]
    [InlineData(XudpUdp443Handling.Allow, "allow")]
    [InlineData(XudpUdp443Handling.Skip, "skip")]
    public void Mux_maps_the_xudp_udp443_tri_state(XudpUdp443Handling handling, string expected)
    {
        var settings = new AppSettings
        {
            Mux = new MuxSettings
            {
                Enabled = true,
                Concurrency = 8,
                XudpConcurrency = 16,
                XudpProxyUdp443 = handling,
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));
        var mux = XrayConfigTestFactory
            .Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag)["mux"]!.AsObject();

        mux["enabled"]!.GetValue<bool>().ShouldBeTrue();
        mux["concurrency"]!.GetValue<int>().ShouldBe(8);
        mux["xudpConcurrency"]!.GetValue<int>().ShouldBe(16);
        mux["xudpProxyUDP443"]!.GetValue<string>().ShouldBe(expected);
    }

    // ---------------------------------------------------------------- transports

    [Fact]
    public void WebSocket_transport_maps_path_and_host()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.Tls) with
        {
            Transport = TransportKind.WebSocket,
            Path = "/ws",
            Host = "host.example.com",
        };

        var stream = BuildStream(profile);

        stream["network"]!.GetValue<string>().ShouldBe("ws");
        stream["wsSettings"]!["path"]!.GetValue<string>().ShouldBe("/ws");
        stream["wsSettings"]!["host"]!.GetValue<string>().ShouldBe("host.example.com");
    }

    [Fact]
    public void WebSocket_transport_defaults_the_path_to_slash()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.WebSocket,
            Path = null,
            Host = null,
        };

        BuildStream(profile)["wsSettings"]!["path"]!.GetValue<string>().ShouldBe("/");
    }

    [Fact]
    public void Grpc_transport_maps_the_service_name_and_multi_mode()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.Grpc,
            ServiceName = "gsvc",
            Path = null,
            TransportMode = "multi",
        };

        var stream = BuildStream(profile);

        stream["network"]!.GetValue<string>().ShouldBe("grpc");
        stream["grpcSettings"]!["serviceName"]!.GetValue<string>().ShouldBe("gsvc");
        stream["grpcSettings"]!["multiMode"]!.GetValue<bool>().ShouldBeTrue();
    }

    [Fact]
    public void Grpc_transport_defaults_multi_mode_to_false_and_falls_back_to_the_path()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.Grpc,
            ServiceName = null,
            Path = "/fallback",
            TransportMode = null,
        };

        var stream = BuildStream(profile);

        stream["grpcSettings"]!["serviceName"]!.GetValue<string>().ShouldBe("/fallback");
        stream["grpcSettings"]!["multiMode"]!.GetValue<bool>().ShouldBeFalse();
    }

    [Fact]
    public void HttpUpgrade_transport_maps_path_and_host()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.HttpUpgrade,
            Path = "/hu",
            Host = "hu.example.com",
        };

        var stream = BuildStream(profile);

        stream["network"]!.GetValue<string>().ShouldBe("httpupgrade");
        stream["httpupgradeSettings"]!["path"]!.GetValue<string>().ShouldBe("/hu");
        stream["httpupgradeSettings"]!["host"]!.GetValue<string>().ShouldBe("hu.example.com");
    }

    [Fact]
    public void Xhttp_transport_maps_path_host_and_mode()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.XHttp,
            Path = "/xh",
            Host = "xh.example.com",
            TransportMode = "stream-up",
        };

        var stream = BuildStream(profile);

        stream["network"]!.GetValue<string>().ShouldBe("xhttp");
        stream["xhttpSettings"]!["path"]!.GetValue<string>().ShouldBe("/xh");
        stream["xhttpSettings"]!["host"]!.GetValue<string>().ShouldBe("xh.example.com");
        stream["xhttpSettings"]!["mode"]!.GetValue<string>().ShouldBe("stream-up");
    }

    [Fact]
    public void Tcp_transport_with_headers_emits_an_http_header()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.Tcp,
            TransportHeaders = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Host"] = "camouflage.example.com",
            },
        };

        var stream = BuildStream(profile);

        stream["network"]!.GetValue<string>().ShouldBe("tcp");
        stream["tcpSettings"]!["header"]!["type"]!.GetValue<string>().ShouldBe("http");
    }

    [Fact]
    public void Plain_tcp_transport_emits_no_tcp_settings()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.None) with
        {
            Transport = TransportKind.Tcp,
            TransportHeaders = null,
        };

        BuildStream(profile).ContainsKey("tcpSettings").ShouldBeFalse();
    }

    // ---------------------------------------------------------------- tls / reality

    [Fact]
    public void Tls_server_name_prefers_sni_then_host_then_address()
    {
        var withSni = XrayConfigTestFactory.Profile(security: SecurityKind.Tls) with
        {
            ServerName = "sni.example.com",
            Host = "host.example.com",
        };

        var withHost = XrayConfigTestFactory.Profile(security: SecurityKind.Tls) with
        {
            ServerName = null,
            Host = "host.example.com",
        };

        var withAddress = XrayConfigTestFactory.Profile(security: SecurityKind.Tls) with
        {
            ServerName = null,
            Host = null,
        };

        BuildStream(withSni)["tlsSettings"]!["serverName"]!.GetValue<string>()
            .ShouldBe("sni.example.com");
        BuildStream(withHost)["tlsSettings"]!["serverName"]!.GetValue<string>()
            .ShouldBe("host.example.com");
        BuildStream(withAddress)["tlsSettings"]!["serverName"]!.GetValue<string>()
            .ShouldBe(XrayConfigTestFactory.HostName);
    }

    [Fact]
    public void Tls_allow_insecure_and_alpn_are_carried_through()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.Tls) with
        {
            AllowInsecure = true,
            Alpn = "h2,http/1.1",
        };

        var tls = BuildStream(profile)["tlsSettings"]!.AsObject();

        tls["allowInsecure"]!.GetValue<bool>().ShouldBeTrue();
        tls["alpn"]!.AsArray().Select(node => node!.GetValue<string>())
            .ShouldBe(new[] { "h2", "http/1.1" });
    }

    [Fact]
    public void Reality_maps_public_key_short_id_and_spider_path()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.Reality) with
        {
            ServerName = "reality.example.com",
            RealityPublicKey = "PUBLIC-KEY",
            RealityShortId = "abcd",
            RealitySpiderX = "/",
            Fingerprint = TlsFingerprint.None,
        };

        var stream = BuildStream(profile);
        var reality = stream["realitySettings"]!.AsObject();

        stream["security"]!.GetValue<string>().ShouldBe("reality");
        reality["serverName"]!.GetValue<string>().ShouldBe("reality.example.com");
        reality["publicKey"]!.GetValue<string>().ShouldBe("PUBLIC-KEY");
        reality["shortId"]!.GetValue<string>().ShouldBe("abcd");
        reality["spiderX"]!.GetValue<string>().ShouldBe("/");

        // A REALITY handshake always presents a uTLS fingerprint; chrome is the safe default.
        reality["fingerprint"]!.GetValue<string>().ShouldBe("chrome");
    }

    [Fact]
    public void Reality_uses_the_pinned_fingerprint_when_one_is_set()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.Reality) with
        {
            RealityPublicKey = "PUBLIC-KEY",
            Fingerprint = TlsFingerprint.Firefox,
        };

        BuildStream(profile)["realitySettings"]!["fingerprint"]!.GetValue<string>()
            .ShouldBe("firefox");
    }

    [Fact]
    public void Reality_without_a_public_key_fails_validation()
    {
        var profile = XrayConfigTestFactory.Profile(security: SecurityKind.Reality) with
        {
            RealityPublicKey = null,
        };

        var result = XrayConfigBuilder.Build(XrayConfigTestFactory.Request(profile: profile));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.server.reality_public_key_missing");
    }

    // ---------------------------------------------------------------- inbounds

    [Fact]
    public void Tun_mode_emits_a_single_tun_inbound()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());
        var inbounds = XrayConfigTestFactory.Inbounds(XrayConfigTestFactory.Root(result));

        inbounds.Count.ShouldBe(1);
        inbounds[0]!["protocol"]!.GetValue<string>().ShouldBe("tun");
        inbounds[0]!["tag"]!.GetValue<string>().ShouldBe(XrayConfigBuilder.TunInboundTag);
    }

    [Fact]
    public void SystemProxy_mode_emits_socks_and_http_inbounds_on_the_configured_ports()
    {
        var settings = new AppSettings { TunnelMode = TunnelMode.SystemProxy };
        var request = XrayConfigTestFactory.Request(settings: settings) with
        {
            SocksPort = 12345,
            HttpPort = 12346,
        };

        var result = XrayConfigTestFactory.BuildOk(request);
        var inbounds = XrayConfigTestFactory.Inbounds(XrayConfigTestFactory.Root(result));

        inbounds.Count.ShouldBe(2);

        var socks = inbounds[0]!.AsObject();
        socks["protocol"]!.GetValue<string>().ShouldBe("socks");
        socks["listen"]!.GetValue<string>().ShouldBe("127.0.0.1");
        socks["port"]!.GetValue<int>().ShouldBe(12345);
        socks["settings"]!["auth"]!.GetValue<string>().ShouldBe("noauth");
        socks["settings"]!["udp"]!.GetValue<bool>().ShouldBeTrue();

        var http = inbounds[1]!.AsObject();
        http["protocol"]!.GetValue<string>().ShouldBe("http");
        http["listen"]!.GetValue<string>().ShouldBe("127.0.0.1");
        http["port"]!.GetValue<int>().ShouldBe(12346);
    }

    [Fact]
    public void Disabled_mode_with_no_local_inbounds_fails_without_an_inbound()
    {
        var settings = new AppSettings { TunnelMode = TunnelMode.Disabled };

        var result = XrayConfigBuilder.Build(XrayConfigTestFactory.Request(settings: settings));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.config.no_inbound");
    }

    // ---------------------------------------------------------------- dns

    [Fact]
    public void DnsMode_System_emits_no_dns_section()
    {
        var settings = new AppSettings { Dns = new DnsSettings { Mode = DnsMode.System } };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));
        var root = XrayConfigTestFactory.Root(result);

        root["dns"].ShouldBeNull();
        XrayConfigTestFactory.Outbounds(root)
            .Any(outbound => outbound!["protocol"]?.GetValue<string>() == "dns").ShouldBeFalse();
    }

    [Fact]
    public void DnsMode_ThroughTunnel_emits_a_dns_outbound_and_a_port_53_hijack()
    {
        var settings = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.ThroughTunnel,
                Servers = new[] { "1.1.1.1", "8.8.8.8" },
                RespectSystemHosts = true,
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));
        var root = XrayConfigTestFactory.Root(result);

        var dns = root["dns"]!.AsObject();
        dns["servers"]!.AsArray().Select(node => node!.GetValue<string>())
            .ShouldBe(new[] { "1.1.1.1", "8.8.8.8" });
        dns["queryStrategy"]!.GetValue<string>().ShouldBe("UseIP");
        dns["useSystemHosts"]!.GetValue<bool>().ShouldBeTrue();

        var dnsOutbound = XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.DnsOutTag);
        dnsOutbound["protocol"]!.GetValue<string>().ShouldBe("dns");

        var hijack = XrayConfigTestFactory.RoutingRule(root, "myvpn-dns-hijack");
        hijack["port"]!.AsArray().Select(node => node!.GetValue<string>()).ShouldBe(new[] { "53" });
        hijack["network"]!.GetValue<string>().ShouldBe("tcp,udp");
        hijack["outboundTag"]!.GetValue<string>().ShouldBe(XrayConfigBuilder.DnsOutTag);
    }

    [Fact]
    public void No_dns_inbound_protocol_is_ever_emitted()
    {
        var modes = new[]
        {
            DnsMode.System, DnsMode.ThroughTunnel, DnsMode.Doh, DnsMode.Dot, DnsMode.Custom,
        };

        foreach (var mode in modes)
        {
            var settings = new AppSettings
            {
                Dns = new DnsSettings
                {
                    Mode = mode,
                    DohUrl = "https://dns.example/dns-query",
                    DotHost = "dns.example",
                },
            };

            var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));

            var protocols = XrayConfigTestFactory.Inbounds(XrayConfigTestFactory.Root(result))
                .Select(node => node!["protocol"]!.GetValue<string>())
                .ToArray();

            // Xray has no DNS inbound: DNS is steered by routing port 53 to a `dns` outbound.
            protocols.ShouldNotContain("dns", $"DNS mode {mode}");
        }
    }

    [Fact]
    public void Doh_and_dot_still_emit_the_dns_outbound_and_hijack()
    {
        var doh = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.Doh,
                DohUrl = "https://dns.example/dns-query",
            },
        };

        var dot = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.Dot,
                DotHost = "dns.example",
                DotPort = 853,
            },
        };

        foreach (var settings in new[] { doh, dot })
        {
            var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));
            var root = XrayConfigTestFactory.Root(result);

            root["dns"].ShouldNotBeNull();
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.DnsOutTag)["protocol"]!
                .GetValue<string>().ShouldBe("dns");
            XrayConfigTestFactory.RoutingRule(root, "myvpn-dns-hijack")["outboundTag"]!
                .GetValue<string>().ShouldBe(XrayConfigBuilder.DnsOutTag);
        }
    }

    [Fact]
    public void ThroughTunnel_with_no_resolvers_warns_and_omits_the_dns_section()
    {
        var settings = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.ThroughTunnel,
                Servers = Array.Empty<string>(),
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));

        XrayConfigTestFactory.Root(result)["dns"].ShouldBeNull();

        result.Warnings.ShouldContain(w => w.MessageKey == "error.dns.no_usable_resolver");
    }

    [Fact]
    public void A_non_ip_resolver_is_rejected_before_the_builder_can_skip_it()
    {
        // The builder's resolver loop skips non-literals with a warning, but AppSettings
        // validation rejects them first, so the observable outcome is a hard failure. This
        // asserts the effective contract; see the coverage notes for the dead branch.
        var settings = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.Custom,
                Servers = new[] { "1.1.1.1", "not-an-ip" },
            },
        };

        var result = XrayConfigBuilder.Build(XrayConfigTestFactory.Request(settings: settings));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.settings.invalid");
        result.Error.TechnicalDetail!.ShouldContain("error.dns.server_not_ip");
    }

    // ---------------------------------------------------------------- determinism

    [Fact]
    public void Serializing_the_same_request_twice_is_byte_identical()
    {
        var request = XrayConfigTestFactory.Request(
            settings: new AppSettings
            {
                Mux = new MuxSettings { Enabled = true, XudpProxyUdp443 = XudpUdp443Handling.Skip },
                Routing = new RoutingSettings
                {
                    BlockAds = true,
                    DirectGeoSites = new[] { "cn" },
                    DirectGeoIpCountries = new[] { "ru" },
                },
            },
            geo: new GeoRuleAvailability(GeoIpAvailable: true, GeoSiteAvailable: true),
            assetDirectory: Path.Combine(Path.GetTempPath(), "myvpn-determinism"));

        var first = XrayConfigTestFactory.Serialize(XrayConfigTestFactory.BuildOk(request));
        var second = XrayConfigTestFactory.Serialize(XrayConfigTestFactory.BuildOk(request));

        second.ShouldBe(first);
        first.ShouldContain("geoip:ru");
        first.ShouldContain("geosite:cn");
    }

    // ---------------------------------------------------------------- validation propagation

    [Fact]
    public void An_invalid_profile_fails_the_build_with_the_profiles_error()
    {
        var profile = XrayConfigTestFactory.Profile(userId: null);
        var request = XrayConfigTestFactory.Request(profile: profile);

        var result = XrayConfigBuilder.Build(request);

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.server.user_id_missing");

        // The profile's own error is propagated unchanged, not wrapped or reworded.
        result.Error.ShouldBe(profile.Validate().Error);
    }

    [Fact]
    public void Invalid_settings_fail_the_build_before_a_config_is_produced()
    {
        var settings = new AppSettings { UiScale = 5.0 };

        var result = XrayConfigBuilder.Build(XrayConfigTestFactory.Request(settings: settings));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.settings.invalid");
    }

    private static JsonObject BuildStream(ServerProfile profile)
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var outbound = XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag);

        return XrayConfigTestFactory.StreamSettings(outbound);
    }
}
