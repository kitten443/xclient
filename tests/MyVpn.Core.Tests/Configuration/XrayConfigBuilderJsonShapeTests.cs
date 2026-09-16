using System.Text.Json.Nodes;
using MyVpn.Core.Configuration;
using MyVpn.Core.Geo;
using MyVpn.Core.Settings;
using MyVpn.Core.Xray;
using Shouldly;

namespace MyVpn.Core.Tests;

/// <summary>
/// Serialized-shape tests for <see cref="XrayConfigBuilder"/>.
/// </summary>
/// <remarks>
/// Xray's own loader accepts several near-miss spellings, so these tests assert on the exact
/// emitted document rather than on the typed model: a config that round-trips through MyVpn's
/// records can still be rejected (or silently misread) by the core. The TUN inbound in
/// particular has a fixed field set, and emitting a field it does not have makes Xray refuse
/// to start — see docs/research/03-xray-tun-inbound.md.
/// </remarks>
public sealed class XrayConfigBuilderJsonShapeTests
{
    // ---------------------------------------------------------------- TUN field set

    [Fact]
    public void Tun_inbound_emits_exactly_the_documented_settings_keys()
    {
        var request = XrayConfigTestFactory.Request();
        var result = XrayConfigTestFactory.BuildOk(request);
        var json = XrayConfigTestFactory.Serialize(result);

        // Positive: the documented TUN keys are all present in the serialized text.
        json.ShouldContain("\"protocol\": \"tun\"");
        json.ShouldContain("\"name\"");
        json.ShouldContain("\"gateway\"");
        json.ShouldContain("\"autoSystemRoutingTable\"");
        json.ShouldContain("\"autoOutboundsInterface\"");

        var tun = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun");
        var settings = tun["settings"]!.AsObject();

        // The default Linux TUN request has no MTU and system (not Windows) DNS, so the
        // exact key set is fixed. Anything else is a field Xray does not have.
        string[] expected =
        {
            "name", "desc", "gateway", "userLevel", "autoSystemRoutingTable", "autoOutboundsInterface",
        };

        settings.Select(pair => pair.Key).OrderBy(key => key, StringComparer.Ordinal)
            .ShouldBe(expected.OrderBy(key => key, StringComparer.Ordinal).ToArray());

        // Negative: these do not exist on the TUN inbound. `address` in particular is checked
        // on the settings object, because the VLESS/VMess `vnext` array legitimately has one.
        settings.ContainsKey("address").ShouldBeFalse();
        settings.ContainsKey("autoRoute").ShouldBeFalse();
        settings.ContainsKey("strictRoute").ShouldBeFalse();
        settings.ContainsKey("sniffingOverride").ShouldBeFalse();
        settings.ContainsKey("routeOnly").ShouldBeFalse();

        json.ShouldNotContain("autoRoute");
        json.ShouldNotContain("strictRoute");
        json.ShouldNotContain("sniffingOverride");
    }

    [Fact]
    public void Tun_inbound_emits_mtu_only_when_it_is_configured()
    {
        var withoutMtu = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());
        var withoutMtuSettings = XrayConfigTestFactory
            .Inbound(XrayConfigTestFactory.Root(withoutMtu), "tun")["settings"]!.AsObject();

        withoutMtuSettings.ContainsKey("mtu").ShouldBeFalse();

        var withMtu = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: new AppSettings { Tun = new TunSettings { Mtu = 1500 } }));
        var withMtuSettings = XrayConfigTestFactory
            .Inbound(XrayConfigTestFactory.Root(withMtu), "tun")["settings"]!.AsObject();

        withMtuSettings["mtu"]!.GetValue<int>().ShouldBe(1500);
    }

    [Fact]
    public void Tun_inbound_uses_the_requested_interface_name_on_non_macos_platforms()
    {
        var request = XrayConfigTestFactory.Request(platform: PlatformTarget.Linux);

        var result = XrayConfigTestFactory.BuildOk(request);
        var tun = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun");

        tun["settings"]!["name"]!.GetValue<string>().ShouldBe("myvpn0");
    }

    // ---------------------------------------------------------------- routing shape

    [Fact]
    public void Routing_rules_use_outboundTag_and_the_field_type()
    {
        // BypassLan is on by default, so at least one concrete rule is emitted.
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());
        var rules = XrayConfigTestFactory.RoutingRules(XrayConfigTestFactory.Root(result));

        rules.ShouldNotBeEmpty();

        foreach (var rule in rules)
        {
            rule["type"]!.GetValue<string>().ShouldBe("field");

            // The outbound is named `outboundTag`; there is no `tag` on a routing rule.
            rule.ContainsKey("outboundTag").ShouldBeTrue();
            rule.ContainsKey("tag").ShouldBeFalse();
            rule["outboundTag"]!.GetValue<string>()
                .ShouldBeOneOf(
                    XrayConfigBuilder.ProxyTag,
                    XrayConfigBuilder.DirectTag,
                    XrayConfigBuilder.BlockTag,
                    XrayConfigBuilder.DnsOutTag);
        }
    }

    [Fact]
    public void The_default_route_targets_the_proxy_outbound()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request());

        var rule = XrayConfigTestFactory.RoutingRule(
            XrayConfigTestFactory.Root(result), "myvpn-default-proxy");

        rule["outboundTag"]!.GetValue<string>().ShouldBe(XrayConfigBuilder.ProxyTag);
        rule["network"]!.GetValue<string>().ShouldBe("tcp,udp");
    }

    // ---------------------------------------------------------------- env gating

    [Fact]
    public void The_asset_environment_is_absent_for_a_core_too_old_for_the_root_env_object()
    {
        var directory = Path.Combine(Path.GetTempPath(), "myvpn-assets-old-core");

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            assetDirectory: directory,
            coreVersion: new XrayVersion(26, 6, 1)));

        var json = XrayConfigTestFactory.Serialize(result);
        var root = XrayConfigTestFactory.Root(result);

        json.ShouldNotContain(GeoDataConstants.AssetLocationEnvironmentVariable);

        // The whole root `env` object was introduced in v26.7.11. Xray older than that rejects
        // the key outright, so nothing at all (not even XRAY_JSON_STRICT) may be emitted.
        root["env"].ShouldBeNull();
    }

    [Theory]
    [InlineData(26, 7, 11)]
    [InlineData(26, 9, 9)]
    public void The_asset_environment_is_present_and_exact_from_the_introducing_version_on(
        int major, int minor, int patch)
    {
        var directory = Path.Combine(Path.GetTempPath(), "myvpn-assets-new-core");

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            assetDirectory: directory,
            coreVersion: new XrayVersion(major, minor, patch)));

        var json = XrayConfigTestFactory.Serialize(result);
        var root = XrayConfigTestFactory.Root(result);

        json.ShouldContain(GeoDataConstants.AssetLocationEnvironmentVariable);

        var env = root["env"]!.AsObject();
        env[GeoDataConstants.AssetLocationEnvironmentVariable]!.GetValue<string>().ShouldBe(directory);
        env["XRAY_JSON_STRICT"]!.GetValue<string>().ShouldBe("true");
    }

    [Fact]
    public void The_asset_environment_is_absent_when_no_directory_is_known()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            assetDirectory: null,
            coreVersion: XrayVersionPolicy.Recommended));

        var root = XrayConfigTestFactory.Root(result);

        root["env"]!.AsObject().ContainsKey(GeoDataConstants.AssetLocationEnvironmentVariable)
            .ShouldBeFalse();

        // The strict-JSON flag still rides the env object on a new enough core.
        root["env"]!["XRAY_JSON_STRICT"]!.GetValue<string>().ShouldBe("true");
    }

    [Fact]
    public void An_empty_asset_directory_is_treated_as_absent()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            assetDirectory: "   ",
            coreVersion: XrayVersionPolicy.Recommended));

        XrayConfigTestFactory.Root(result)["env"]!.AsObject()
            .ContainsKey(GeoDataConstants.AssetLocationEnvironmentVariable).ShouldBeFalse();
    }
}
