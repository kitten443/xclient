using MyVpn.Core.Results;
using MyVpn.Core.Xray;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class XrayVersionTests
{
    [Fact]
    public void Parses_the_current_version_banner()
    {
        XrayVersion.TryParse("Xray 26.9.9 (go1.24.0 linux/amd64)", out var version).ShouldBeTrue();

        version.ShouldBe(new XrayVersion(26, 9, 9));
        version.ToString().ShouldBe("26.9.9");
        version.IsKnown.ShouldBeTrue();
    }

    [Fact]
    public void Parses_a_legacy_version_banner()
    {
        XrayVersion.TryParse("Xray 1.8.24 (go1.22.5 linux/amd64)", out var version).ShouldBeTrue();

        version.ShouldBe(new XrayVersion(1, 8, 24));
    }

    [Fact]
    public void Parses_a_bare_version_string()
    {
        XrayVersion.TryParse("26.4.15", out var version).ShouldBeTrue();

        version.ShouldBe(new XrayVersion(26, 4, 15));
    }

    [Fact]
    public void Parses_a_two_component_version()
    {
        XrayVersion.TryParse("Xray 26.9 (go1.24.0)", out var version).ShouldBeTrue();

        version.ShouldBe(new XrayVersion(26, 9, 0));
    }

    [Fact]
    public void Ignores_versions_after_the_first_line()
    {
        XrayVersion.TryParse("Xray 26.9.9 (go1.24.0 linux/amd64)\nXray 1.2.3", out var version).ShouldBeTrue();

        version.ShouldBe(new XrayVersion(26, 9, 9));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no version here")]
    [InlineData("Xray")]
    [InlineData("Xray v26")]
    public void Unparseable_text_fails(string? text)
    {
        XrayVersion.TryParse(text, out var version).ShouldBeFalse();
        version.ShouldBe(XrayVersion.Unknown);
    }

    [Fact]
    public void Parse_throws_for_unparseable_text()
    {
        Should.Throw<FormatException>(() => XrayVersion.Parse("no version here"));
    }

    [Fact]
    public void Unknown_is_not_known_and_is_zero()
    {
        XrayVersion.Unknown.IsKnown.ShouldBeFalse();
        XrayVersion.Unknown.Major.ShouldBe(0);
        XrayVersion.Unknown.ToString().ShouldBe("0.0.0");
    }

    [Fact]
    public void Versions_are_ordered_by_major_then_minor_then_patch()
    {
        var current = new XrayVersion(26, 9, 9);
        var floor = new XrayVersion(26, 4, 15);
        var legacy = new XrayVersion(1, 8, 24);

        current.ShouldBeGreaterThan(floor);
        floor.ShouldBeGreaterThan(legacy);
        (current > floor).ShouldBeTrue();
        (legacy < floor).ShouldBeTrue();
        (current >= floor).ShouldBeTrue();
        (legacy <= floor).ShouldBeTrue();
    }

    [Fact]
    public void CompareTo_orders_correctly()
    {
        new XrayVersion(26, 4, 15).CompareTo(new XrayVersion(26, 4, 13)).ShouldBeGreaterThan(0);
        new XrayVersion(26, 4, 13).CompareTo(new XrayVersion(26, 4, 15)).ShouldBeLessThan(0);
        new XrayVersion(26, 4, 15).CompareTo(new XrayVersion(26, 4, 15)).ShouldBe(0);
    }

    [Fact]
    public void Policy_constants_match_the_documented_releases()
    {
        XrayVersionPolicy.FirstWithTun.ShouldBe(new XrayVersion(26, 1, 13));
        XrayVersionPolicy.MinimumForTun.ShouldBe(new XrayVersion(26, 4, 15));
        XrayVersionPolicy.Recommended.ShouldBe(new XrayVersion(26, 9, 9));
        XrayVersionPolicy.KnownBroken.ShouldContain(new XrayVersion(26, 4, 13));
    }

    [Fact]
    public void A_known_broken_release_is_rejected()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(26, 4, 13));

        support.IsKnownBroken.ShouldBeTrue();
        support.IsUsable.ShouldBeFalse();
        support.TunSupported.ShouldBeFalse();
        support.ErrorCode.ShouldBe(ErrorCodes.XrayVersionUnsupported);
        support.MessageKey.ShouldBe("error.xray.version_known_broken");
    }

    [Fact]
    public void The_minimum_for_tun_release_is_usable_but_not_recommended()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(26, 4, 15));

        support.IsUsable.ShouldBeTrue();
        support.TunSupported.ShouldBeTrue();
        support.IsRecommended.ShouldBeFalse();
        support.IsKnownBroken.ShouldBeFalse();
        support.ErrorCode.ShouldBeNull();
    }

    [Fact]
    public void A_release_below_the_floor_but_with_tun_is_not_usable()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(26, 1, 13));

        support.IsUsable.ShouldBeFalse();
        support.ErrorCode.ShouldBe(ErrorCodes.XrayVersionUnsupported);
        support.MessageKey.ShouldBe("error.xray.version_tun_schema_too_old");
    }

    [Fact]
    public void A_release_without_tun_support_at_all_is_not_usable()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(25, 12, 8));

        support.IsUsable.ShouldBeFalse();
        support.MessageKey.ShouldBe("error.xray.version_no_tun_support");
        support.ErrorCode.ShouldBe(ErrorCodes.XrayVersionUnsupported);
    }

    [Fact]
    public void The_recommended_release_is_usable_and_recommended()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(26, 9, 9));

        support.IsUsable.ShouldBeTrue();
        support.IsRecommended.ShouldBeTrue();
        support.IsKnownBroken.ShouldBeFalse();
    }

    [Fact]
    public void A_newer_release_is_also_recommended()
    {
        XrayVersionPolicy.Evaluate(new XrayVersion(27, 0, 0)).IsRecommended.ShouldBeTrue();
        XrayVersionPolicy.Evaluate(new XrayVersion(27, 0, 0)).IsUsable.ShouldBeTrue();
    }

    [Fact]
    public void An_unknown_version_reports_a_probe_failure()
    {
        var support = XrayVersionPolicy.Evaluate(XrayVersion.Unknown);

        support.IsUsable.ShouldBeFalse();
        support.ErrorCode.ShouldBe(ErrorCodes.XrayVersionProbeFailed);
        support.MessageKey.ShouldBe("error.xray.version_unknown");
        support.RemediationKey.ShouldBe("xray.select_binary");
    }

    [Fact]
    public void When_tun_is_not_required_an_old_version_is_usable()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(1, 8, 24), tunRequired: false);

        support.IsUsable.ShouldBeTrue();
        support.TunSupported.ShouldBeTrue();
        support.IsRecommended.ShouldBeFalse();
    }

    [Fact]
    public void When_tun_is_not_required_a_known_broken_release_is_still_rejected()
    {
        var support = XrayVersionPolicy.Evaluate(new XrayVersion(26, 4, 13), tunRequired: false);

        support.IsUsable.ShouldBeFalse();
        support.IsKnownBroken.ShouldBeTrue();
    }

    [Fact]
    public void ToResult_is_success_for_a_usable_version()
    {
        var result = XrayVersionPolicy.Evaluate(new XrayVersion(26, 9, 9)).ToResult();

        result.IsSuccess.ShouldBeTrue();
        result.Error.ShouldBeNull();
    }

    [Fact]
    public void ToResult_is_failure_for_an_unsupported_version()
    {
        var result = XrayVersionPolicy.Evaluate(new XrayVersion(25, 12, 8)).ToResult();

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.XrayVersionUnsupported);
        result.Error.MessageKey.ShouldBe("error.xray.version_no_tun_support");
        result.Error.RemediationKey.ShouldBe("xray.update");
    }

    [Fact]
    public void ToResult_is_failure_for_an_unknown_version_with_the_probe_code()
    {
        var result = XrayVersionPolicy.Evaluate(XrayVersion.Unknown).ToResult();

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.XrayVersionProbeFailed);
    }
}
