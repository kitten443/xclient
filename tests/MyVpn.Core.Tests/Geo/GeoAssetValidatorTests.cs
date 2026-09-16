using System.Text;
using MyVpn.Core.Geo;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class GeoAssetValidatorTests
{
    private static byte[] ValidAsset(params string[] codes) =>
        ProtoFixtures.GeoAsset(codes, paddingFieldBytes: 6000);

    [Fact]
    public void A_valid_geo_asset_is_accepted_with_the_right_entry_count()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, ValidAsset("cn", "us", "private"));

        result.IsValid.ShouldBeTrue();
        result.EntryCount.ShouldBe(3);
        result.HasEntries.ShouldBeTrue();
        result.FailureCode.ShouldBeNull();
        result.FailureDetail.ShouldBeNull();
        result.SampleCodes.ShouldContain("cn");
        result.SampleCodes.ShouldContain("us");
        result.SampleCodes.ShouldContain("private");
    }

    [Fact]
    public void A_valid_geosite_asset_is_accepted()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoSite, ValidAsset("category-ads-all", "google"));

        result.IsValid.ShouldBeTrue();
        result.EntryCount.ShouldBe(2);
    }

    [Fact]
    public void An_empty_file_is_invalid()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, ReadOnlySpan<byte>.Empty);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("empty");
        result.EntryCount.ShouldBe(0);
        result.HasEntries.ShouldBeFalse();
        result.FailureDetail!.ShouldContain("geoip.dat");
    }

    [Fact]
    public void A_file_below_the_minimum_size_is_invalid()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, ProtoFixtures.GeoAsset(new[] { "cn" }));

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("too_small");
        result.FailureDetail!.ShouldContain("4096");
    }

    [Fact]
    public void A_truncated_entry_is_reported_as_truncated_entry()
    {
        var content = ProtoFixtures.Concat(
            ValidAsset("cn"),
            ProtoFixtures.Tag(1, 2),
            ProtoFixtures.Varint(255));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("truncated_entry");
    }

    [Fact]
    public void An_html_error_page_saved_as_a_dat_file_is_invalid()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoSite, ProtoFixtures.HtmlErrorPage());

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldNotBeNull();
        result.EntryCount.ShouldBe(0);
    }

    [Fact]
    public void A_zero_filled_buffer_is_invalid()
    {
        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, new byte[5000]);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("truncated_tag");
    }

    [Fact]
    public void An_entry_without_a_code_field_is_invalid()
    {
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(1, ProtoFixtures.EntryWithoutCode()),
            ProtoFixtures.LengthDelimited(2, new byte[6000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("entry_without_code");
    }

    [Fact]
    public void A_code_that_is_not_printable_ascii_makes_the_entry_unusable()
    {
        var entry = ProtoFixtures.LengthDelimited(1, new byte[] { 0x00, 0x01, 0x02 });
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(1, entry),
            ProtoFixtures.LengthDelimited(2, new byte[6000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("entry_without_code");
    }

    [Fact]
    public void A_code_longer_than_the_limit_makes_the_entry_unusable()
    {
        var entry = ProtoFixtures.LengthDelimited(1, Encoding.ASCII.GetBytes(new string('a', 65)));
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(1, entry),
            ProtoFixtures.LengthDelimited(2, new byte[6000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("entry_without_code");
    }

    [Fact]
    public void Unknown_top_level_fields_are_skipped_for_forward_compatibility()
    {
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(1, ProtoFixtures.Entry("cn")),
            ProtoFixtures.Tag(3, 0),
            ProtoFixtures.Varint(12345),
            ProtoFixtures.LengthDelimited(4, new byte[] { 1, 2, 3 }),
            ProtoFixtures.LengthDelimited(1, ProtoFixtures.Entry("us")),
            ProtoFixtures.LengthDelimited(2, new byte[6000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeTrue();
        result.EntryCount.ShouldBe(2);
    }

    [Fact]
    public void Field_one_with_the_wrong_wire_type_is_invalid()
    {
        var content = ProtoFixtures.Concat(
            ProtoFixtures.Tag(1, 0),
            ProtoFixtures.Varint(7),
            ProtoFixtures.LengthDelimited(2, new byte[6000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("wrong_wire_type");
    }

    [Fact]
    public void A_malformed_unknown_field_is_invalid()
    {
        // Unknown field 5 with wire type 1 (64-bit) at the very end, with fewer than
        // eight bytes left: the skip must fail rather than read past the buffer.
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(1, ProtoFixtures.Entry("cn")),
            ProtoFixtures.LengthDelimited(2, new byte[6000]),
            ProtoFixtures.Tag(5, 1),
            new byte[] { 1, 2, 3 });

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoIp, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("malformed_field");
    }

    [Fact]
    public void A_wrong_kind_of_protobuf_message_with_no_entries_is_invalid()
    {
        // A well-formed top-level message that only carries unknown fields.
        var content = ProtoFixtures.Concat(
            ProtoFixtures.LengthDelimited(3, new byte[5000]));

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoSite, content);

        result.IsValid.ShouldBeFalse();
        result.FailureCode.ShouldBe("no_entries");
        result.FailureDetail!.ShouldContain("geosite.dat");
    }

    [Fact]
    public void Sample_codes_are_distinct_and_capped()
    {
        var codes = Enumerable.Range(0, 40).Select(i => "code" + i).ToArray();
        codes = codes.Concat(codes).ToArray();

        var result = GeoAssetValidator.Validate(GeoAssetKind.GeoSite, ValidAsset(codes));

        result.IsValid.ShouldBeTrue();
        result.EntryCount.ShouldBe(80);
        result.SampleCodes.Count.ShouldBe(16);
        result.SampleCodes.Distinct(StringComparer.Ordinal).Count().ShouldBe(16);
    }

    [Fact]
    public void HasPlausibleSize_matches_the_documented_minimum()
    {
        GeoAssetValidator.MinimumPlausibleSizeBytes.ShouldBe(4096);
        GeoAssetValidator.HasPlausibleSize(0).ShouldBeFalse();
        GeoAssetValidator.HasPlausibleSize(4095).ShouldBeFalse();
        GeoAssetValidator.HasPlausibleSize(4096).ShouldBeTrue();
        GeoAssetValidator.HasPlausibleSize(long.MaxValue).ShouldBeTrue();
    }

    [Fact]
    public void Validation_result_factories_are_consistent()
    {
        var valid = GeoAssetValidationResult.Valid(5, new[] { "cn" });

        valid.IsValid.ShouldBeTrue();
        valid.EntryCount.ShouldBe(5);
        valid.HasEntries.ShouldBeTrue();
        valid.FailureCode.ShouldBeNull();

        var invalid = GeoAssetValidationResult.Invalid("empty", "detail");

        invalid.IsValid.ShouldBeFalse();
        invalid.EntryCount.ShouldBe(0);
        invalid.HasEntries.ShouldBeFalse();
        invalid.FailureCode.ShouldBe("empty");
        invalid.FailureDetail.ShouldBe("detail");
        invalid.SampleCodes.ShouldBeEmpty();
    }
}
