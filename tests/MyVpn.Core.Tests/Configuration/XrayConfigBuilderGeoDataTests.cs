using MyVpn.Core.Configuration;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using Shouldly;

namespace MyVpn.Core.Tests;

/// <summary>
/// The headline safety property: corrupt or missing geo data must not break the connection.
/// </summary>
/// <remarks>
/// A routing rule naming <c>geoip:cn</c> or <c>geosite:cn</c> while the corresponding
/// <c>.dat</c> file is missing or corrupt makes Xray refuse to start at all. The builder must
/// therefore consult <see cref="GeoRuleAvailability"/> and omit exactly the rules whose asset
/// is unusable, warn about each omission, and still produce a working config.
/// </remarks>
public sealed class XrayConfigBuilderGeoDataTests
{
    private static AppSettings GeoRouting(
        bool blockAds = true,
        bool directGeoIp = true,
        bool directGeoSites = true,
        bool bypassLan = false) => new()
    {
        Routing = new RoutingSettings
        {
            BypassLan = bypassLan,
            BlockAds = blockAds,
            DirectGeoIpCountries = directGeoIp ? new[] { "ru" } : Array.Empty<string>(),
            DirectGeoSites = directGeoSites ? new[] { "cn" } : Array.Empty<string>(),
        },
    };

    [Fact]
    public void No_usable_geo_data_omits_every_geo_reference_and_warns()
    {
        var request = XrayConfigTestFactory.Request(
            settings: GeoRouting(),
            geo: GeoRuleAvailability.None);

        var result = XrayConfigTestFactory.BuildOk(request);
        var json = XrayConfigTestFactory.Serialize(result);

        json.ShouldNotContain("geosite:");
        json.ShouldNotContain("geoip:");

        result.UsesGeoData.ShouldBeFalse();

        // BlockAds, DirectGeoSites and DirectGeoIpCountries each omit one rule.
        var omissions = result.Warnings.Where(w => w.Code == ErrorCodes.GeoAssetMissing).ToArray();
        omissions.Length.ShouldBe(3);
        omissions.ShouldAllBe(w => w.Severity == ErrorSeverity.Warning);
        omissions.ShouldAllBe(w => w.MessageKey == "error.config.geo_rule_omitted");
        omissions.ShouldAllBe(w => w.RemediationKey == "geodata.repair");

        // ...and the connection still comes up: a proxy outbound and a catch-all route exist.
        var root = XrayConfigTestFactory.Root(result);
        XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag)["protocol"]!
            .GetValue<string>().ShouldBe("vless");
        XrayConfigTestFactory.RoutingRule(root, "myvpn-default-proxy")["outboundTag"]!
            .GetValue<string>().ShouldBe(XrayConfigBuilder.ProxyTag);
    }

    [Fact]
    public void Full_geo_availability_emits_the_rules_and_does_not_warn()
    {
        var request = XrayConfigTestFactory.Request(
            settings: GeoRouting(),
            geo: new GeoRuleAvailability(GeoIpAvailable: true, GeoSiteAvailable: true));

        var result = XrayConfigTestFactory.BuildOk(request);
        var json = XrayConfigTestFactory.Serialize(result);

        json.ShouldContain("geoip:ru");
        json.ShouldContain("geosite:cn");
        json.ShouldContain("geosite:category-ads-all");

        result.UsesGeoData.ShouldBeTrue();
        result.Warnings.ShouldNotContain(w => w.Code == ErrorCodes.GeoAssetMissing);
    }

    [Fact]
    public void Geosite_availability_alone_keeps_geosite_rules_and_drops_geoip_rules()
    {
        var request = XrayConfigTestFactory.Request(
            settings: GeoRouting(),
            geo: new GeoRuleAvailability(GeoIpAvailable: false, GeoSiteAvailable: true));

        var result = XrayConfigTestFactory.BuildOk(request);
        var json = XrayConfigTestFactory.Serialize(result);

        json.ShouldContain("geosite:cn");
        json.ShouldContain("geosite:category-ads-all");
        json.ShouldNotContain("geoip:ru");

        result.UsesGeoData.ShouldBeTrue();

        var omissions = result.Warnings.Where(w => w.Code == ErrorCodes.GeoAssetMissing).ToArray();
        omissions.Length.ShouldBe(1);
        omissions[0].Arguments["pattern"].ShouldBe("geoip:*");
    }

    [Fact]
    public void Geoip_availability_alone_keeps_geoip_rules_and_drops_geosite_rules()
    {
        var request = XrayConfigTestFactory.Request(
            settings: GeoRouting(),
            geo: new GeoRuleAvailability(GeoIpAvailable: true, GeoSiteAvailable: false));

        var result = XrayConfigTestFactory.BuildOk(request);
        var json = XrayConfigTestFactory.Serialize(result);

        json.ShouldContain("geoip:ru");
        json.ShouldNotContain("geosite:");

        result.UsesGeoData.ShouldBeTrue();

        // The ad list and the direct site list each omit one rule.
        result.Warnings.Count(w => w.Code == ErrorCodes.GeoAssetMissing).ShouldBe(2);
    }

    [Fact]
    public void UsesGeoData_is_false_when_the_only_requested_geo_kind_is_unavailable()
    {
        var settings = GeoRouting(blockAds: false, directGeoIp: true, directGeoSites: false);
        var request = XrayConfigTestFactory.Request(
            settings: settings,
            geo: new GeoRuleAvailability(GeoIpAvailable: false, GeoSiteAvailable: true));

        var result = XrayConfigTestFactory.BuildOk(request);

        XrayConfigTestFactory.Serialize(result).ShouldNotContain("geoip:");
        result.UsesGeoData.ShouldBeFalse();
        result.Warnings.ShouldContain(w => w.Code == ErrorCodes.GeoAssetMissing);
    }

    [Fact]
    public void Lan_bypass_routes_geoip_private_directly()
    {
        var settings = new AppSettings
        {
            Routing = new RoutingSettings { BypassLan = true },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));

        var rule = XrayConfigTestFactory.RoutingRule(
            XrayConfigTestFactory.Root(result), "myvpn-lan-direct");

        rule["ip"]!.AsArray().Select(node => node!.GetValue<string>())
            .ShouldBe(new[] { "geoip:private" });
        rule["outboundTag"]!.GetValue<string>().ShouldBe(XrayConfigBuilder.DirectTag);
    }

    [Fact]
    public void Lan_bypass_does_not_require_the_geoip_asset_because_private_is_built_in()
    {
        var settings = new AppSettings
        {
            Routing = new RoutingSettings { BypassLan = true },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            geo: GeoRuleAvailability.None));

        XrayConfigTestFactory.RoutingRule(XrayConfigTestFactory.Root(result), "myvpn-lan-direct")
            .ShouldNotBeNull();

        // geoip:private is served from Xray's built-in table, so the missing asset is not warned about.
        result.Warnings.ShouldNotContain(w => w.Code == ErrorCodes.GeoAssetMissing);
    }

    [Fact]
    public void Block_ads_emits_the_ad_geosite_rule_to_block()
    {
        var settings = GeoRouting(blockAds: true, directGeoIp: false, directGeoSites: false);
        var request = XrayConfigTestFactory.Request(
            settings: settings,
            geo: new GeoRuleAvailability(GeoIpAvailable: true, GeoSiteAvailable: true));

        var result = XrayConfigTestFactory.BuildOk(request);

        var rule = XrayConfigTestFactory.RoutingRule(
            XrayConfigTestFactory.Root(result), "myvpn-block-ads");

        rule["domain"]!.AsArray().Select(node => node!.GetValue<string>())
            .ShouldBe(new[] { "geosite:category-ads-all" });
        rule["outboundTag"]!.GetValue<string>().ShouldBe(XrayConfigBuilder.BlockTag);
    }

    [Fact]
    public void Block_ads_is_omitted_with_a_geosite_warning_when_the_ad_asset_is_unusable()
    {
        var settings = GeoRouting(blockAds: true, directGeoIp: false, directGeoSites: false);
        var request = XrayConfigTestFactory.Request(
            settings: settings,
            geo: new GeoRuleAvailability(GeoIpAvailable: true, GeoSiteAvailable: false));

        var result = XrayConfigTestFactory.BuildOk(request);

        XrayConfigTestFactory.Serialize(result).ShouldNotContain("geosite:");

        var warning = result.Warnings.Single(w => w.Code == ErrorCodes.GeoAssetMissing);
        warning.Arguments["pattern"].ShouldBe("geosite:category-ads-all");
    }
}
