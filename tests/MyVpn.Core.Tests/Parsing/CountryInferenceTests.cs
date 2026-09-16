using MyVpn.Core.Parsing;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class CountryInferenceTests
{
    [Fact]
    public void A_flag_emoji_is_decoded_to_its_country_code()
    {
        CountryInference.FromDisplayName("\U0001F1E9\U0001F1EA").ShouldBe("DE");
        CountryInference.FromDisplayName("\U0001F1EF\U0001F1F5").ShouldBe("JP");
        CountryInference.FromDisplayName("\U0001F1FA\U0001F1F8").ShouldBe("US");
    }

    [Fact]
    public void A_flag_emoji_works_at_the_very_start_of_the_name()
    {
        CountryInference.FromDisplayName("\U0001F1E9\U0001F1EA Frankfurt").ShouldBe("DE");
    }

    [Fact]
    public void A_flag_emoji_works_after_other_text()
    {
        CountryInference.FromDisplayName("Fast Node \U0001F1EB\U0001F1F7").ShouldBe("FR");
    }

    [Fact]
    public void Bracketed_and_parenthesised_codes_are_recognised()
    {
        CountryInference.FromDisplayName("[JP] Tokyo").ShouldBe("JP");
        CountryInference.FromDisplayName("(US) New York").ShouldBe("US");
        CountryInference.FromDisplayName("<DE> Frankfurt").ShouldBe("DE");
        CountryInference.FromDisplayName("[de] frankfurt").ShouldBe("DE");
    }

    [Fact]
    public void A_leading_two_letter_code_with_a_separator_is_recognised()
    {
        CountryInference.FromDisplayName("US - New York").ShouldBe("US");
        CountryInference.FromDisplayName("FR | Paris").ShouldBe("FR");
    }

    [Fact]
    public void A_leading_two_letter_word_is_not_treated_as_a_code()
    {
        // "Italy" starts with the letters "It", which is a valid ISO shape, but is
        // followed by another letter and must not be read as a code.
        CountryInference.FromDisplayName("Italy").ShouldBeNull();
        CountryInference.FromDisplayName("Node").ShouldBeNull();
    }

    [Theory]
    [InlineData("United States", "US")]
    [InlineData("United Kingdom", "GB")]
    [InlineData("Netherlands", "NL")]
    [InlineData("Singapore", "SG")]
    [InlineData("Switzerland", "CH")]
    [InlineData("Australia", "AU")]
    [InlineData("Hong Kong", "HK")]
    public void English_country_names_are_recognised(string name, string expected)
    {
        CountryInference.FromDisplayName(name).ShouldBe(expected);
    }

    [Theory]
    [InlineData("Германия", "DE")]
    [InlineData("Франция", "FR")]
    [InlineData("Россия", "RU")]
    [InlineData("Япония", "JP")]
    [InlineData("Соединённые Штаты", "US")]
    public void Russian_country_names_are_recognised(string name, string expected)
    {
        CountryInference.FromDisplayName(name).ShouldBe(expected);
    }

    [Theory]
    [InlineData("德国", "DE")]
    [InlineData("法国", "FR")]
    [InlineData("日本", "JP")]
    [InlineData("美国", "US")]
    [InlineData("新加坡", "SG")]
    public void Chinese_country_names_are_recognised(string name, string expected)
    {
        CountryInference.FromDisplayName(name).ShouldBe(expected);
    }

    [Fact]
    public void United_states_is_not_shadowed_by_a_shorter_alias()
    {
        CountryInference.FromDisplayName("United States Server 1").ShouldBe("US");
    }

    [Fact]
    public void Unknown_names_return_null()
    {
        CountryInference.FromDisplayName("Node 42").ShouldBeNull();
        CountryInference.FromDisplayName("fast-1.example.net").ShouldBeNull();
        CountryInference.FromDisplayName("").ShouldBeNull();
        CountryInference.FromDisplayName("   ").ShouldBeNull();
        CountryInference.FromDisplayName(null).ShouldBeNull();
    }

    [Fact]
    public void A_non_letter_pair_is_not_a_country_code()
    {
        CountryInference.FromDisplayName("[1A] nowhere").ShouldBeNull();
        CountryInference.FromDisplayName("[ABC] nowhere").ShouldBeNull();
    }

    [Fact]
    public void Unmatched_open_bracket_does_not_throw()
    {
        CountryInference.FromDisplayName("[DE Frankfurt").ShouldBeNull();
    }

    [Fact]
    public void A_lone_high_surrogate_does_not_throw()
    {
        Should.NotThrow(() => CountryInference.FromDisplayName("\uD83C"));
    }

    [Fact]
    public void A_lone_low_surrogate_does_not_throw()
    {
        Should.NotThrow(() => CountryInference.FromDisplayName("\uDDE9"));
    }

    [Fact]
    public void A_high_surrogate_pair_that_is_not_a_flag_is_ignored()
    {
        // U+1F600 (grinning face) shares nothing with the regional indicators.
        CountryInference.FromDisplayName("\U0001F600").ShouldBeNull();
        CountryInference.FromDisplayName("\uD83C\uD83C").ShouldBeNull();
    }

    [Fact]
    public void A_truncated_flag_does_not_throw()
    {
        // A high surrogate at the very end cannot possibly form a flag.
        Should.NotThrow(() => CountryInference.FromDisplayName("Node \uD83C"));
        CountryInference.FromDisplayName("Node \uD83C").ShouldBeNull();
    }

    [Fact]
    public void ToFlagEmoji_round_trips_through_the_inference()
    {
        var flag = CountryInference.ToFlagEmoji("DE");

        flag.ShouldBe("\U0001F1E9\U0001F1EA");
        CountryInference.FromDisplayName(flag!).ShouldBe("DE");
    }

    [Fact]
    public void ToFlagEmoji_handles_lowercase_and_mixed_case()
    {
        CountryInference.ToFlagEmoji("de").ShouldBe("\U0001F1E9\U0001F1EA");
        CountryInference.ToFlagEmoji("De").ShouldBe("\U0001F1E9\U0001F1EA");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("D")]
    [InlineData("DEU")]
    [InlineData("D1")]
    [InlineData("12")]
    public void ToFlagEmoji_returns_null_for_invalid_codes(string? code)
    {
        CountryInference.ToFlagEmoji(code).ShouldBeNull();
    }

    [Fact]
    public void Every_letter_pair_maps_to_a_distinct_flag()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var first in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        {
            foreach (var second in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            {
                var code = string.Concat(first, second);
                var flag = CountryInference.ToFlagEmoji(code);

                flag.ShouldNotBeNull();
                seen.Add(flag!).ShouldBeTrue($"duplicate flag for {code}");
                CountryInference.FromDisplayName(flag!).ShouldBe(code);
            }
        }

        seen.Count.ShouldBe(26 * 26);
    }
}
