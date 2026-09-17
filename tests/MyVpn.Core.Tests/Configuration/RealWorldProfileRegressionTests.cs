using System.Text.Json;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using Shouldly;
using Xunit;

namespace MyVpn.Core.Tests.Configuration;

/// <summary>
/// Regression tests for defects found by connecting to a real server.
/// </summary>
/// <remarks>
/// <para>
/// Every case here produced a configuration that the core <i>accepted</i> and that therefore
/// passed a full unit-test suite, but that could not connect. That is the important property:
/// schema validation proves a config is well-formed, not that it is complete. Only running real
/// traffic exposed these.
/// </para>
/// <para>Verified against a live subscription using XHttp, gRPC, TLS and REALITY transports.</para>
/// </remarks>
public sealed class RealWorldProfileRegressionTests
{
    private const string VlessEncryption =
        "mlkem768x25519plus.native.0rtt.AAfakekeystringforunittestingonly0000000000";

    private const string XhttpExtra =
        """{"noSSEHeader":true,"xPaddingBytes":"100-1000","uplinkHTTPMethod":"POST","scMaxEachPostBytes":1000000}""";

    private static string VlessLink(string extraQuery = "") =>
        "vless://11111111-2222-3333-4444-555555555555@example.com:443"
        + "?type=xhttp&security=tls&sni=example.com&host=example.com&path=/api/v1/sync/"
        + "&mode=packet-up&fp=random&alpn=h2,http%2F1.1"
        + "&encryption=" + Uri.EscapeDataString(VlessEncryption)
        + extraQuery
        + "#Test";

    // ------------------------------------------------------------ share-link parsing

    [Fact]
    public void Vless_encryption_parameter_is_preserved_verbatim()
    {
        // The `encryption` parameter carries the VLESS encryption method. For modern profiles it
        // holds a post-quantum key. Discarding it and defaulting to "none" yields a config the
        // core accepts but that cannot connect.
        var profile = ShareLinkParser.Parse(VlessLink()).Value;

        profile.Encryption.ShouldBe(VlessEncryption);
    }

    [Fact]
    public void Xhttp_extra_parameter_is_preserved_verbatim()
    {
        var link = VlessLink("&extra=" + Uri.EscapeDataString(XhttpExtra));

        var profile = ShareLinkParser.Parse(link).Value;

        profile.TransportExtra.ShouldBe(XhttpExtra);
    }

    [Fact]
    public void Vless_link_without_an_encryption_parameter_leaves_it_null()
    {
        var link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#X";

        ShareLinkParser.Parse(link).Value.Encryption.ShouldBeNull();
    }

    // ------------------------------------------------------------ config generation

    [Fact]
    public void Vless_outbound_carries_the_profiles_encryption_instead_of_none()
    {
        var profile = ShareLinkParser.Parse(VlessLink()).Value;

        var root = XrayConfigTestFactory.Root(
            XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile)));

        var user = XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag)["settings"]!["vnext"]![0]!["users"]![0]!;

        user["encryption"]!.GetValue<string>().ShouldBe(VlessEncryption);
    }

    [Fact]
    public void Vless_outbound_falls_back_to_none_when_the_profile_specifies_nothing()
    {
        // "none" is still the correct value for a classic VLESS link, so the fallback matters.
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            UserId = "11111111-2222-3333-4444-555555555555",
            Security = SecurityKind.Tls,
        };

        var root = XrayConfigTestFactory.Root(
            XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile)));

        var user = XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag)["settings"]!["vnext"]![0]!["users"]![0]!;
        user["encryption"]!.GetValue<string>().ShouldBe("none");
    }

    [Fact]
    public void Xhttp_settings_forward_the_extra_block_as_json()
    {
        var profile = ShareLinkParser.Parse(VlessLink("&extra=" + Uri.EscapeDataString(XhttpExtra))).Value;

        var root = XrayConfigTestFactory.Root(
            XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile)));

        var xhttp = XrayConfigTestFactory.StreamSettings(
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))["xhttpSettings"]!;

        xhttp["path"]!.GetValue<string>().ShouldBe("/api/v1/sync/");
        xhttp["host"]!.GetValue<string>().ShouldBe("example.com");
        xhttp["mode"]!.GetValue<string>().ShouldBe("packet-up");

        var extra = xhttp["extra"]!;
        extra["uplinkHTTPMethod"]!.GetValue<string>().ShouldBe("POST");
        extra["xPaddingBytes"]!.GetValue<string>().ShouldBe("100-1000");
        extra["noSSEHeader"]!.GetValue<bool>().ShouldBeTrue();
    }

    [Fact]
    public void Malformed_extra_json_is_reported_and_dropped_rather_than_failing_the_build()
    {
        // A broken extra block must not cost the user their connection: the transport still
        // works with its defaults.
        var profile = ShareLinkParser.Parse(VlessLink("&extra=" + Uri.EscapeDataString("{not json"))).Value;

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));

        result.Warnings.ShouldContain(w => w.MessageKey == "error.config.transport_extra_invalid");

        var root = XrayConfigTestFactory.Root(result);
        var xhttp = XrayConfigTestFactory.StreamSettings(
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))["xhttpSettings"]!;

        xhttp["extra"].ShouldBeNull();
        xhttp["path"]!.GetValue<string>().ShouldBe("/api/v1/sync/");
    }

    [Fact]
    public void Non_object_extra_json_is_rejected()
    {
        var profile = ShareLinkParser.Parse(VlessLink("&extra=" + Uri.EscapeDataString("[1,2,3]"))).Value;

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));

        result.Warnings.ShouldContain(w => w.MessageKey == "error.config.transport_extra_not_object");
    }

    [Theory]
    [InlineData("packet-up")]
    [InlineData("stream-up")]
    [InlineData("stream-one")]
    [InlineData("auto")]
    [InlineData("AUTO")]
    public void Accepted_xhttp_modes_are_emitted(string mode)
    {
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            UserId = "11111111-2222-3333-4444-555555555555",
            Security = SecurityKind.Tls,
            Transport = TransportKind.XHttp,
            Path = "/x",
            TransportMode = mode,
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));
        var root = XrayConfigTestFactory.Root(result);
        var xhttp = XrayConfigTestFactory.StreamSettings(
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))["xhttpSettings"]!;

        xhttp["mode"]!.GetValue<string>().ShouldBe(mode.ToLowerInvariant());

        // Scoped to the mode: the default settings legitimately also warn about the IPv6 gateway
        // being configured while IPv6 is disabled, so asserting "no warnings at all" would be
        // asserting the wrong thing.
        result.Warnings.ShouldNotContain(w => w.MessageKey == "error.config.xhttp_mode_unknown");
    }

    [Fact]
    public void Unsupported_xhttp_mode_is_downgraded_with_a_warning()
    {
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            UserId = "11111111-2222-3333-4444-555555555555",
            Security = SecurityKind.Tls,
            Transport = TransportKind.XHttp,
            Path = "/x",
            TransportMode = "made-up-mode",
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile));

        result.Warnings.ShouldContain(w => w.MessageKey == "error.config.xhttp_mode_unknown");

        var root = XrayConfigTestFactory.Root(result);
        var xhttp = XrayConfigTestFactory.StreamSettings(
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))["xhttpSettings"]!;

        xhttp["mode"]!.GetValue<string>().ShouldBe("auto");
    }

    [Fact]
    public void Vmess_still_carries_its_cipher_and_is_not_affected_by_the_vless_fix()
    {
        // The VLESS fix must not leak a VLESS encryption string into a VMess user, where the
        // same JSON field means the cipher.
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Vmess,
            UserId = "11111111-2222-3333-4444-555555555555",
            Encryption = "auto",
            Security = SecurityKind.Tls,
        };

        var root = XrayConfigTestFactory.Root(
            XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile)));

        var user = XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag)["settings"]!["vnext"]![0]!["users"]![0]!;
        user["security"]!.GetValue<string>().ShouldBe("auto");
        user["encryption"].ShouldBeNull();
    }

    [Fact]
    public void Reality_fingerprint_defaults_to_chrome_when_the_profile_pins_none()
    {
        // REALITY always presents a uTLS fingerprint; the link in the live test used fp=random,
        // but a profile with no fingerprint at all must still produce a usable handshake.
        var profile = new ServerProfile
        {
            Address = "example.com",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            UserId = "11111111-2222-3333-4444-555555555555",
            Security = SecurityKind.Reality,
            RealityPublicKey = "fake-public-key",
            ServerName = "www.example.com",
        };

        var root = XrayConfigTestFactory.Root(
            XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(profile: profile)));

        var reality = XrayConfigTestFactory.StreamSettings(
            XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))["realitySettings"]!;

        reality["fingerprint"]!.GetValue<string>().ShouldBe("chrome");
    }
}
