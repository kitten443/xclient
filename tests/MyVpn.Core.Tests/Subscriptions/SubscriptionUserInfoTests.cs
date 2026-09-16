using MyVpn.Core.Subscriptions;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class SubscriptionUserInfoTests
{
    private static SubscriptionUserInfo ParseOk(string value)
    {
        SubscriptionUserInfo.TryParse(value, out var info, out var failure).ShouldBeTrue(failure);
        return info;
    }

    [Fact]
    public void Parses_the_documented_four_field_form()
    {
        var info = ParseOk("upload=0; download=0; total=0; expire=0");

        info.Upload.ShouldBe(0);
        info.Download.ShouldBe(0);
        info.Total.ShouldBe(0);
        info.ExpiresAt.ShouldBeNull();
        info.IsUnlimited.ShouldBeTrue();
        info.HasNoExpiry.ShouldBeTrue();
        info.Used.ShouldBe(0);
    }

    [Fact]
    public void Parses_a_realistic_payload()
    {
        var info = ParseOk("upload=1024; download=2048; total=10737418240; expire=1893456000");

        info.Upload.ShouldBe(1024);
        info.Download.ShouldBe(2048);
        info.Total.ShouldBe(10737418240);
        info.Used.ShouldBe(3072);
        info.ExpiresAt.ShouldBe(DateTimeOffset.FromUnixTimeSeconds(1893456000));
        info.IsUnlimited.ShouldBeFalse();
        info.HasNoExpiry.ShouldBeFalse();
    }

    [Fact]
    public void Total_zero_means_unlimited()
    {
        var info = ParseOk("upload=1; download=1; total=0; expire=0");

        info.IsUnlimited.ShouldBeTrue();
        info.UsedFraction.ShouldBeNull();
    }

    [Fact]
    public void A_missing_total_means_unlimited()
    {
        var info = ParseOk("upload=1; download=1");

        info.Total.ShouldBeNull();
        info.IsUnlimited.ShouldBeTrue();
        info.UsedFraction.ShouldBeNull();
    }

    [Fact]
    public void Expire_zero_means_no_expiry()
    {
        var info = ParseOk("total=100; expire=0");

        info.ExpiresAt.ShouldBeNull();
        info.HasNoExpiry.ShouldBeTrue();
    }

    [Fact]
    public void Comma_separators_are_accepted()
    {
        var info = ParseOk("upload=1,download=2,total=100,expire=0");

        info.Upload.ShouldBe(1);
        info.Download.ShouldBe(2);
        info.Total.ShouldBe(100);
    }

    [Fact]
    public void Surrounding_whitespace_and_quotes_are_tolerated()
    {
        var info = ParseOk("  \"upload=5\" ;  \"download=6\" ; total=10 ");

        info.Upload.ShouldBe(5);
        info.Download.ShouldBe(6);
        info.Total.ShouldBe(10);
    }

    [Fact]
    public void Float_byte_values_are_rounded()
    {
        var info = ParseOk("total=1.5e9");

        info.Total.ShouldBe(1_500_000_000);
    }

    [Fact]
    public void A_fractional_value_is_rounded_to_the_nearest_byte()
    {
        var info = ParseOk("download=1024.6");

        info.Download.ShouldBe(1025);
    }

    [Fact]
    public void Unknown_keys_are_ignored()
    {
        var info = ParseOk("upload=5; future-counter=99; total=10");

        info.Upload.ShouldBe(5);
        info.Total.ShouldBe(10);
    }

    [Fact]
    public void A_negative_value_is_rejected()
    {
        SubscriptionUserInfo.TryParse("upload=-5", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("not_a_number:upload");
    }

    [Fact]
    public void Garbage_without_an_equals_sign_is_rejected()
    {
        SubscriptionUserInfo.TryParse("garbage", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("missing_equals");
    }

    [Fact]
    public void A_header_with_no_recognised_key_is_rejected()
    {
        SubscriptionUserInfo.TryParse("foo=1; bar=2", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("no_recognized_keys");
    }

    [Fact]
    public void An_empty_value_is_rejected()
    {
        SubscriptionUserInfo.TryParse("total=", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("empty_value");
    }

    [Fact]
    public void An_empty_header_is_rejected()
    {
        SubscriptionUserInfo.TryParse("", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("empty");
        SubscriptionUserInfo.TryParse(null, out _, out _).ShouldBeFalse();
        SubscriptionUserInfo.TryParse("   ", out _, out _).ShouldBeFalse();
    }

    [Fact]
    public void A_non_numeric_value_is_rejected()
    {
        SubscriptionUserInfo.TryParse("total=abc", out _, out var failure).ShouldBeFalse();

        failure.ShouldBe("not_a_number:total");
    }

    [Fact]
    public void Used_is_null_when_no_traffic_counter_was_reported()
    {
        var info = ParseOk("total=100; expire=0");

        info.Used.ShouldBeNull();
        info.UsedFraction.ShouldBeNull();
    }

    [Fact]
    public void Used_accounts_for_a_missing_counter()
    {
        ParseOk("upload=5").Used.ShouldBe(5);
        ParseOk("download=7").Used.ShouldBe(7);
    }

    [Fact]
    public void UsedFraction_is_computed_and_clamped()
    {
        ParseOk("upload=25; download=25; total=100; expire=0").UsedFraction!.Value.ShouldBe(0.5, 1e-9);
        ParseOk("upload=200; download=0; total=100; expire=0").UsedFraction!.Value.ShouldBe(1.0, 1e-9);
    }

    [Fact]
    public void IsExpired_compares_against_the_supplied_clock()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var expired = ParseOk("total=1; expire=" + (now.ToUnixTimeSeconds() - 60));
        var active = ParseOk("total=1; expire=" + (now.ToUnixTimeSeconds() + 60));

        expired.IsExpired(now).ShouldBeTrue();
        active.IsExpired(now).ShouldBeFalse();
    }

    [Fact]
    public void DaysRemaining_floors_and_handles_expiry()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        ParseOk("total=1; expire=" + (now.ToUnixTimeSeconds() + (long)TimeSpan.FromDays(2.5).TotalSeconds))
            .DaysRemaining(now).ShouldBe(2);
        ParseOk("total=1; expire=" + (now.ToUnixTimeSeconds() - 10))
            .DaysRemaining(now).ShouldBe(0);
        ParseOk("total=1; expire=0").DaysRemaining(now).ShouldBeNull();
    }

    [Fact]
    public void Millisecond_expiry_values_are_detected_by_magnitude()
    {
        var info = ParseOk("total=1; expire=1700000000000");

        info.ExpiresAt.ShouldBe(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
    }

    [Fact]
    public void An_out_of_range_expiry_is_treated_as_no_expiry()
    {
        var info = ParseOk("total=1; expire=9223372036854775807");

        info.ExpiresAt.ShouldBeNull();
        info.HasNoExpiry.ShouldBeTrue();
    }

    [Fact]
    public void Keys_are_case_insensitive()
    {
        var info = ParseOk("UPLOAD=1; Download=2; TOTAL=3; Expire=0");

        info.Upload.ShouldBe(1);
        info.Download.ShouldBe(2);
        info.Total.ShouldBe(3);
    }

    [Fact]
    public void Empty_segments_between_separators_are_skipped()
    {
        var info = ParseOk(";;upload=1;;,download=2;;");

        info.Upload.ShouldBe(1);
        info.Download.ShouldBe(2);
    }
}
