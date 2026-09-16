using System.Text;
using MyVpn.Core.Parsing;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class Base64TolerantTests
{
    [Fact]
    public void Decodes_standard_padded_base64()
    {
        Base64Tolerant.TryDecodeToString("aGVsbG8=", out var text).ShouldBeTrue();

        text.ShouldBe("hello");
    }

    [Fact]
    public void Decodes_url_safe_unpadded_base64()
    {
        // 0xFB 0xFF encodes to "+/8=" in standard and "-_8" URL-safe/unpadded.
        var bytes = new byte[] { 0xFB, 0xFF, 0x01 };

        Base64Tolerant.TryDecode(Convert.ToBase64String(bytes).TrimEnd('='), out var standard).ShouldBeTrue();
        Base64Tolerant.TryDecode(Base64Tolerant.Encode(bytes), out var urlSafe).ShouldBeTrue();

        standard.ShouldBe(bytes);
        urlSafe.ShouldBe(bytes);
    }

    [Fact]
    public void Removes_whitespace_and_newlines_inside_the_payload()
    {
        Base64Tolerant.TryDecodeToString("aGVs\nbG8=", out var text).ShouldBeTrue();

        text.ShouldBe("hello");
    }

    [Fact]
    public void Removes_tabs_and_spaces_inside_the_payload()
    {
        Base64Tolerant.TryDecodeToString("aG Vs\tbG8 =", out var text).ShouldBeTrue();

        text.ShouldBe("hello");
    }

    [Fact]
    public void A_remainder_of_one_is_rejected()
    {
        // "AAAAA" has length % 4 == 1 and can never be valid Base64.
        Base64Tolerant.TryDecode("AAAAA", out var bytes).ShouldBeFalse();
        bytes.ShouldBeEmpty();
    }

    [Fact]
    public void Empty_or_whitespace_input_is_rejected()
    {
        Base64Tolerant.TryDecode(null, out _).ShouldBeFalse();
        Base64Tolerant.TryDecode("", out _).ShouldBeFalse();
        Base64Tolerant.TryDecode("   ", out _).ShouldBeFalse();
    }

    [Fact]
    public void Non_base64_characters_are_rejected()
    {
        Base64Tolerant.TryDecode("not base64!!", out _).ShouldBeFalse();
    }

    [Fact]
    public void Strips_a_utf8_bom_from_the_decoded_text()
    {
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF, (byte)'h', (byte)'i' };

        Base64Tolerant.TryDecodeToString(Convert.ToBase64String(bytes), out var text).ShouldBeTrue();

        text.ShouldBe("hi");
    }

    [Fact]
    public void Invalid_utf8_bytes_fail_to_decode_to_string()
    {
        var bytes = new byte[] { 0xFF, 0xFE };

        Base64Tolerant.TryDecode(Convert.ToBase64String(bytes), out var decodedBytes).ShouldBeTrue();
        decodedBytes.ShouldBe(bytes);
        Base64Tolerant.TryDecodeToString(Convert.ToBase64String(bytes), out _).ShouldBeFalse();
    }

    [Fact]
    public void Encode_produces_unpadded_url_safe_base64()
    {
        var encoded = Base64Tolerant.Encode(new byte[] { 0xFB, 0xFF, 0x01 });

        encoded.ShouldNotContain("=");
        encoded.ShouldNotContain("+");
        encoded.ShouldNotContain("/");
        encoded.ShouldBe("-_8B");
    }

    [Fact]
    public void Encode_string_round_trips()
    {
        const string original = "héllo + / world";

        var encoded = Base64Tolerant.EncodeString(original);
        Base64Tolerant.TryDecodeToString(encoded, out var decoded).ShouldBeTrue();

        decoded.ShouldBe(original);
    }

    [Theory]
    [InlineData("YWJjZGVmZ2hpamtsbW5vcA")]
    [InlineData("YWJjZGVmZ2hpamtsbW5vcA==")]
    [InlineData("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=")]
    public void LooksLikeBase64_accepts_base64_bodies(string input)
    {
        Base64Tolerant.LooksLikeBase64(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("short")]
    [InlineData("vless://abcdefghijklmnop")]
    [InlineData("aGVs bG8gd29ybGQ=")]
    [InlineData("aGVs\nbG8gd29ybGQ=")]
    [InlineData("not*base64*payload!")]
    [InlineData("YWJjZGVmZ2hpamtsbW5vc")]
    public void LooksLikeBase64_rejects_non_base64_bodies(string? input)
    {
        Base64Tolerant.LooksLikeBase64(input).ShouldBeFalse();
    }

    [Fact]
    public void LooksLikeBase64_rejects_a_remainder_of_one_even_when_long()
    {
        // 17 valid Base64 characters: long enough, but length % 4 == 1.
        var input = new string('A', 17);

        Base64Tolerant.LooksLikeBase64(input).ShouldBeFalse();
    }

    [Fact]
    public void LooksLikeBase64_accepts_url_safe_alphabet()
    {
        Base64Tolerant.LooksLikeBase64("ABCDEFGHIJKLMNOPQRSTUV-_").ShouldBeTrue();
    }
}
