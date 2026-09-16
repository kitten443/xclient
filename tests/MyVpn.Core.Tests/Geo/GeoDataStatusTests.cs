using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class GeoDataStatusTests
{
    private static GeoAssetInfo Asset(GeoAssetKind kind, GeoAssetHealth health) =>
        new() { Kind = kind, AbsolutePath = "/data/" + kind.FileName(), Health = health };

    private static GeoDataStatus Status(
        GeoAssetHealth geoIp,
        GeoAssetHealth geoSite,
        bool absolute = true) => new()
    {
        AssetDirectory = absolute ? "/data/geodata" : "geodata",
        IsAssetDirectoryAbsolute = absolute,
        IsAssetDirectoryWritable = true,
        GeoIp = Asset(GeoAssetKind.GeoIp, geoIp),
        GeoSite = Asset(GeoAssetKind.GeoSite, geoSite),
    };

    [Fact]
    public void AllUsable_requires_both_assets()
    {
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid).AllUsable.ShouldBeTrue();
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Missing).AllUsable.ShouldBeFalse();
        Status(GeoAssetHealth.Missing, GeoAssetHealth.Valid).AllUsable.ShouldBeFalse();
        Status(GeoAssetHealth.Missing, GeoAssetHealth.Corrupt).AllUsable.ShouldBeFalse();
    }

    [Fact]
    public void AnyUsable_requires_at_least_one_asset()
    {
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid).AnyUsable.ShouldBeTrue();
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Missing).AnyUsable.ShouldBeTrue();
        Status(GeoAssetHealth.Missing, GeoAssetHealth.Valid).AnyUsable.ShouldBeTrue();
        Status(GeoAssetHealth.Missing, GeoAssetHealth.Corrupt).AnyUsable.ShouldBeFalse();
    }

    [Fact]
    public void RequiresRepair_covers_both_unusable_assets_and_a_relative_directory()
    {
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid, absolute: true).RequiresRepair.ShouldBeFalse();
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid, absolute: false).RequiresRepair.ShouldBeTrue();
        Status(GeoAssetHealth.Missing, GeoAssetHealth.Valid, absolute: true).RequiresRepair.ShouldBeTrue();
    }

    [Fact]
    public void Availability_reflects_the_asset_health()
    {
        var availability = Status(GeoAssetHealth.Valid, GeoAssetHealth.Missing).Availability;

        availability.GeoIpAvailable.ShouldBeTrue();
        availability.GeoSiteAvailable.ShouldBeFalse();
        availability.Any.ShouldBeTrue();
        availability.All.ShouldBeFalse();
        availability.CanUse(GeoAssetKind.GeoIp).ShouldBeTrue();
        availability.CanUse(GeoAssetKind.GeoSite).ShouldBeFalse();
    }

    [Fact]
    public void Availability_none_and_all()
    {
        GeoRuleAvailability.None.Any.ShouldBeFalse();
        GeoRuleAvailability.None.All.ShouldBeFalse();
        GeoRuleAvailability.None.CanUse(GeoAssetKind.GeoIp).ShouldBeFalse();

        var full = new GeoRuleAvailability(true, true);
        full.All.ShouldBeTrue();
        full.Any.ShouldBeTrue();
    }

    [Fact]
    public void Availability_CanUse_is_false_for_an_unknown_kind()
    {
        new GeoRuleAvailability(true, true).CanUse((GeoAssetKind)99).ShouldBeFalse();
    }

    [Fact]
    public void Assets_enumerates_both_assets_and_ProblemAssets_filters()
    {
        var status = Status(GeoAssetHealth.Valid, GeoAssetHealth.Corrupt);

        status.Assets.Count().ShouldBe(2);
        status.ProblemAssets.Count.ShouldBe(1);
        status.ProblemAssets[0].Kind.ShouldBe(GeoAssetKind.GeoSite);
    }

    [Fact]
    public void ToWorstError_is_null_when_everything_is_healthy()
    {
        Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid).ToWorstError().ShouldBeNull();
    }

    [Fact]
    public void ToWorstError_reports_a_critical_error_for_a_relative_directory()
    {
        var error = Status(GeoAssetHealth.Valid, GeoAssetHealth.Valid, absolute: false).ToWorstError();

        error.ShouldNotBeNull();
        error!.Code.ShouldBe(ErrorCodes.GeoAssetPathNotAbsolute);
        error.Severity.ShouldBe(ErrorSeverity.Critical);
        error.MessageKey.ShouldBe("error.geodata.path_not_absolute");
        error.RemediationKey.ShouldBe("geodata.repair");
        error.TechnicalDetail!.ShouldContain("geodata");
    }

    [Fact]
    public void ToWorstError_prefers_the_most_severe_problem()
    {
        var status = Status(GeoAssetHealth.ChecksumMismatch, GeoAssetHealth.Missing) with
        {
            GeoSite = Asset(GeoAssetKind.GeoSite, GeoAssetHealth.Missing) with
            {
                ErrorCode = ErrorCodes.GeoAssetMissing,
            },
        };

        var error = status.ToWorstError();

        error.ShouldNotBeNull();
        // Missing is an Error; ChecksumMismatch is only a Warning.
        error!.Severity.ShouldBe(ErrorSeverity.Error);
        error.Code.ShouldBe(ErrorCodes.GeoAssetMissing);
    }

    [Fact]
    public void Empty_factory_produces_an_unusable_status()
    {
        var status = GeoDataStatus.Empty("/tmp/geodata");
        status.IsAssetDirectoryAbsolute.ShouldBeTrue();
        status.IsAssetDirectoryWritable.ShouldBeFalse();
        status.RequiresRepair.ShouldBeTrue();

        var relative = GeoDataStatus.Empty("geodata", isAbsolute: false);
        relative.IsAssetDirectoryAbsolute.ShouldBeFalse();
        relative.ToWorstError()!.Severity.ShouldBe(ErrorSeverity.Critical);
    }

    [Fact]
    public void GeoRuleAvailability_From_rejects_null()
    {
        Should.Throw<ArgumentNullException>(() => GeoRuleAvailability.From(null!));
    }

    [Theory]
    [InlineData(GeoAssetHealth.Valid, true)]
    [InlineData(GeoAssetHealth.Unknown, false)]
    [InlineData(GeoAssetHealth.Missing, false)]
    [InlineData(GeoAssetHealth.Empty, false)]
    [InlineData(GeoAssetHealth.TooSmall, false)]
    [InlineData(GeoAssetHealth.Corrupt, false)]
    [InlineData(GeoAssetHealth.ChecksumMismatch, false)]
    [InlineData(GeoAssetHealth.Unreadable, false)]
    [InlineData(GeoAssetHealth.PathNotAbsolute, false)]
    public void IsUsable_is_only_true_for_valid(GeoAssetHealth health, bool expected)
    {
        Asset(GeoAssetKind.GeoIp, health).IsUsable.ShouldBe(expected);
    }

    [Fact]
    public void ToError_is_null_only_for_a_valid_asset()
    {
        Asset(GeoAssetKind.GeoIp, GeoAssetHealth.Valid).ToError().ShouldBeNull();

        var error = Asset(GeoAssetKind.GeoIp, GeoAssetHealth.Corrupt).ToError();
        error.ShouldNotBeNull();
        error!.Code.ShouldBe(ErrorCodes.GeoAssetCorrupt);
        error.MessageKey.ShouldBe("error.geodata.unusable");
        error.RemediationKey.ShouldBe("geodata.repair");
        error.Severity.ShouldBe(ErrorSeverity.Error);
    }

    [Fact]
    public void ToError_honours_explicit_codes_and_messages()
    {
        var asset = Asset(GeoAssetKind.GeoIp, GeoAssetHealth.Missing) with
        {
            ErrorCode = "custom.code",
            MessageKey = "custom.key",
            RemediationKey = "custom.fix",
            FailureDetail = "detail",
        };

        var error = asset.ToError();

        error.ShouldNotBeNull();
        error!.Code.ShouldBe("custom.code");
        error.MessageKey.ShouldBe("custom.key");
        error.RemediationKey.ShouldBe("custom.fix");
        error.TechnicalDetail.ShouldBe("detail");
    }

    [Theory]
    [InlineData(GeoAssetHealth.Valid, ErrorSeverity.Warning)]
    [InlineData(GeoAssetHealth.Unknown, ErrorSeverity.Warning)]
    [InlineData(GeoAssetHealth.ChecksumMismatch, ErrorSeverity.Warning)]
    [InlineData(GeoAssetHealth.Missing, ErrorSeverity.Error)]
    [InlineData(GeoAssetHealth.Empty, ErrorSeverity.Error)]
    [InlineData(GeoAssetHealth.TooSmall, ErrorSeverity.Error)]
    [InlineData(GeoAssetHealth.Corrupt, ErrorSeverity.Error)]
    [InlineData(GeoAssetHealth.Unreadable, ErrorSeverity.Error)]
    [InlineData(GeoAssetHealth.PathNotAbsolute, ErrorSeverity.Critical)]
    public void SeverityFor_maps_every_health_value(GeoAssetHealth health, ErrorSeverity expected)
    {
        GeoAssetInfo.SeverityFor(health).ShouldBe(expected);
    }

    [Theory]
    [InlineData("empty", GeoAssetHealth.Empty, ErrorCodes.GeoAssetEmpty)]
    [InlineData("too_small", GeoAssetHealth.TooSmall, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("no_entries", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("entry_without_code", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("truncated_tag", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("truncated_entry", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("malformed_entry", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("malformed_field", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("wrong_wire_type", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    [InlineData("something_else", GeoAssetHealth.Corrupt, ErrorCodes.GeoAssetCorrupt)]
    public void MapValidationFailure_maps_each_failure_code(
        string failureCode,
        GeoAssetHealth expectedHealth,
        string expectedErrorCode)
    {
        var (health, errorCode, messageKey) =
            GeoAssetInfo.MapValidationFailure(GeoAssetKind.GeoIp, failureCode);

        health.ShouldBe(expectedHealth);
        errorCode.ShouldBe(expectedErrorCode);
        messageKey.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Geo_asset_kind_extensions_are_consistent()
    {
        GeoAssetKind.GeoIp.FileName().ShouldBe("geoip.dat");
        GeoAssetKind.GeoSite.FileName().ShouldBe("geosite.dat");
        GeoAssetKind.GeoIp.RulePrefix().ShouldBe("geoip");
        GeoAssetKind.GeoSite.RulePrefix().ShouldBe("geosite");
        GeoAssetKind.GeoIp.DisplayNameKey().ShouldBe("geodata.geoip.name");
        GeoAssetKind.GeoSite.DisplayNameKey().ShouldBe("geodata.geosite.name");
    }

    [Fact]
    public void ParseFileName_recognises_both_assets()
    {
        GeoAssetKindExtensions.ParseFileName("geoip.dat").ShouldBe(GeoAssetKind.GeoIp);
        GeoAssetKindExtensions.ParseFileName("GEOSITE.DAT").ShouldBe(GeoAssetKind.GeoSite);
        GeoAssetKindExtensions.ParseFileName("/some/dir/geoip.dat").ShouldBe(GeoAssetKind.GeoIp);
    }

    [Fact]
    public void ParseFileName_rejects_other_names()
    {
        Should.Throw<ArgumentException>(() => GeoAssetKindExtensions.ParseFileName("other.dat"));
        Should.Throw<ArgumentNullException>(() => GeoAssetKindExtensions.ParseFileName(null!));
    }

    [Fact]
    public void Unknown_geo_asset_kinds_throw()
    {
        var unknown = (GeoAssetKind)99;

        Should.Throw<ArgumentOutOfRangeException>(() => unknown.FileName());
        Should.Throw<ArgumentOutOfRangeException>(() => unknown.RulePrefix());
        Should.Throw<ArgumentOutOfRangeException>(() => unknown.DisplayNameKey());
    }

    [Fact]
    public void Geo_data_constants_match_xray_contract()
    {
        GeoDataConstants.AssetLocationEnvironmentVariable.ShouldBe("XRAY_LOCATION_ASSET");
        GeoDataConstants.DefaultAssetDirectoryName.ShouldBe("geodata");
        GeoDataConstants.BackupDirectoryName.ShouldBe("geodata-backup");
        GeoDataConstants.TemporaryFileSuffix.ShouldBe(".download");
    }
}
