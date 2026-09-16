using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.Geo;
using Shouldly;
using Xunit;

namespace MyVpn.Integration.Tests;

/// <summary>
/// End-to-end pipeline from real geo data on disk, through <see cref="GeoDataManager"/>,
/// into an <see cref="XrayConfig"/> produced by <see cref="XrayConfigBuilder"/>.
/// </summary>
/// <remarks>
/// These tests exercise both components together on purpose. The manager's health verdict is
/// what the builder turns into routing rules, and the two only agree if the status is threaded
/// through correctly — which is exactly the "corrupt geo data must not break the connection"
/// requirement. No network and no elevation are involved.
/// </remarks>
public sealed class GeoToConfigPipelineTests : IDisposable
{
    private const string Uuid = "33333333-3333-3333-3333-333333333333";

    private readonly string _root;

    public GeoToConfigPipelineTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "myvpn-geo-pipeline", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // Temp cleanup is best effort.
        }
    }

    [Fact]
    public async Task Inspected_geo_status_drives_geo_rules_and_the_asset_environment()
    {
        var assets = Path.Combine(_root, "geodata");
        IntegrationGeoFixture.WriteAsset(assets, GeoAssetKind.GeoIp, IntegrationGeoFixture.BuildValidGeoAsset(200));
        IntegrationGeoFixture.WriteAsset(assets, GeoAssetKind.GeoSite, IntegrationGeoFixture.BuildValidGeoAsset(200));

        var manager = CreateManager(assets);
        var status = await manager.InspectAsync(CancellationToken.None);

        status.AllUsable.ShouldBeTrue();
        status.AssetDirectory.ShouldBe(Path.GetFullPath(assets));

        var result = BuildFor(status, directGeoIp: true, directGeoSites: true);

        result.IsSuccess.ShouldBeTrue(result.Error?.ToString());

        var json = XrayConfigBuilder.Serialize(result.Value.Config);
        json.ShouldContain("geoip:ru");
        json.ShouldContain("geosite:cn");

        // The second channel for issue #9765: the asset directory rides in the config's env object.
        var env = JsonNode.Parse(json)!["env"]!.AsObject();
        env[GeoDataConstants.AssetLocationEnvironmentVariable]!.GetValue<string>()
            .ShouldBe(Path.GetFullPath(assets));
    }

    [Fact]
    public async Task Corrupt_geoip_drops_the_rule_without_breaking_the_config_and_repair_restores_it()
    {
        var assets = Path.Combine(_root, "geodata");
        var seed = Path.Combine(_root, "seed");

        var healthyGeoIp = IntegrationGeoFixture.BuildValidGeoAsset(180);
        IntegrationGeoFixture.WriteAsset(seed, GeoAssetKind.GeoIp, healthyGeoIp);
        IntegrationGeoFixture.WriteAsset(seed, GeoAssetKind.GeoSite, IntegrationGeoFixture.BuildValidGeoAsset(120));
        IntegrationGeoFixture.WriteAsset(assets, GeoAssetKind.GeoIp, healthyGeoIp);
        IntegrationGeoFixture.WriteAsset(assets, GeoAssetKind.GeoSite, IntegrationGeoFixture.BuildValidGeoAsset(120));

        var manager = CreateManager(assets, seedDirectory: seed);

        var healthy = await manager.InspectAsync(CancellationToken.None);
        healthy.GeoIp.IsUsable.ShouldBeTrue();

        var baseline = BuildFor(healthy, directGeoIp: true, directGeoSites: false);
        baseline.IsSuccess.ShouldBeTrue(baseline.Error?.ToString());
        XrayConfigBuilder.Serialize(baseline.Value.Config).ShouldContain("geoip:ru");

        // Corrupt the working copy the way a bad mirror or a captive portal would.
        IntegrationGeoFixture.WriteAsset(assets, GeoAssetKind.GeoIp, IntegrationGeoFixture.BuildCorruptGeoAsset());

        var corrupted = await manager.InspectAsync(CancellationToken.None);
        corrupted.GeoIp.IsUsable.ShouldBeFalse();

        var degraded = BuildFor(corrupted, directGeoIp: true, directGeoSites: false);

        // The connection still builds: the unusable rule is omitted and warned about.
        degraded.IsSuccess.ShouldBeTrue(degraded.Error?.ToString());
        var degradedJson = XrayConfigBuilder.Serialize(degraded.Value.Config);
        degradedJson.ShouldNotContain("geoip:ru");
        degraded.Value.Warnings.ShouldContain(w => w.Code == ErrorCodes.GeoAssetMissing);

        // ...and the proxy path is intact, so there is somewhere for traffic to go.
        var degradedRoot = JsonNode.Parse(degradedJson)!.AsObject();
        degradedRoot["outbounds"]!.AsArray()
            .Any(outbound => outbound!["tag"]!.GetValue<string>() == XrayConfigBuilder.ProxyTag)
            .ShouldBeTrue();

        // Repair reseeds the working copy from the bundled seed directory.
        var repaired = await manager.RepairAsync(CancellationToken.None);
        repaired.GeoIp.IsUsable.ShouldBeTrue();
        repaired.GeoIp.EntryCount.ShouldBe(180);

        var restored = BuildFor(repaired, directGeoIp: true, directGeoSites: false);
        restored.IsSuccess.ShouldBeTrue(restored.Error?.ToString());
        XrayConfigBuilder.Serialize(restored.Value.Config).ShouldContain("geoip:ru");
    }

    private GeoDataManager CreateManager(string assetDirectory, string? seedDirectory = null) =>
        new(
            new GeoDataOptions
            {
                AssetDirectory = assetDirectory,
                SeedDirectory = seedDirectory,
                BackupDirectory = Path.Combine(_root, "backup"),
                ManifestPath = Path.Combine(_root, "geodata-manifest.json"),
            },
            NullLogger<GeoDataManager>.Instance);

    private static Result<XrayConfigBuildResult> BuildFor(
        GeoDataStatus status,
        bool directGeoIp,
        bool directGeoSites)
    {
        var request = new XrayConfigRequest
        {
            Profile = new ServerProfile
            {
                Address = "server.example.com",
                Port = 443,
                Protocol = ProxyProtocol.Vless,
                UserId = Uuid,
                Security = SecurityKind.Tls,
                ServerName = "sni.example.com",
            },
            Settings = new AppSettings
            {
                Routing = new RoutingSettings
                {
                    BypassLan = false,
                    DirectGeoIpCountries = directGeoIp ? new[] { "ru" } : Array.Empty<string>(),
                    DirectGeoSites = directGeoSites ? new[] { "cn" } : Array.Empty<string>(),
                },
            },
            GeoAvailability = status.Availability,
            AssetDirectory = status.AssetDirectory,
        };

        return XrayConfigBuilder.Build(request);
    }
}
