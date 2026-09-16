using MyVpn.Core.Subscriptions;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class RawHeaderBagTests
{
    private static RawHeaderBag Bag(
        IEnumerable<KeyValuePair<string, string>> pairs,
        ISet<string>? known = null,
        HeaderLimits? limits = null) => RawHeaderBag.FromPairs(pairs, known, limits);

    private static KeyValuePair<string, string> Pair(string name, string value) => new(name, value);

    private static readonly ISet<string> Known =
        new HashSet<string>(new[] { "profile-title", "subscription-userinfo" }, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void Null_pairs_produce_the_shared_empty_bag()
    {
        var bag = RawHeaderBag.FromPairs(null);

        bag.ShouldBeSameAs(RawHeaderBag.Empty);
        bag.Count.ShouldBe(0);
        bag.TotalBytes.ShouldBe(0);
        bag.All.ShouldBeEmpty();
        bag.Rejected.ShouldBeEmpty();
    }

    [Fact]
    public void Accepted_headers_are_preserved_in_order()
    {
        var bag = Bag(new[] { Pair("A", "1"), Pair("B", "2"), Pair("C", "3") });

        bag.Count.ShouldBe(3);
        bag.All.Select(h => h.Name).ShouldBe(new[] { "A", "B", "C" });
        bag.All.Select(h => h.Value).ShouldBe(new[] { "1", "2", "3" });
    }

    [Fact]
    public void Lookups_are_case_insensitive()
    {
        var bag = Bag(new[] { Pair("Profile-Title", "Hello") });

        bag.Contains("profile-title").ShouldBeTrue();
        bag.Contains("PROFILE-TITLE").ShouldBeTrue();
        bag.GetSingle("pRoFiLe-TiTlE").ShouldBe("Hello");
        bag.GetValues("profile-title").ShouldBe(new[] { "Hello" });
        bag.GetEntries("PROFILE-TITLE").Count.ShouldBe(1);
    }

    [Fact]
    public void GetSingle_returns_null_when_the_header_is_duplicated()
    {
        var bag = Bag(new[] { Pair("X-Test", "one"), Pair("x-test", "two") });

        bag.GetSingle("x-test").ShouldBeNull();
        bag.GetValues("x-test").ShouldBe(new[] { "one", "two" });
        bag.GetEntries("x-test").Count.ShouldBe(2);
    }

    [Fact]
    public void GetSingle_returns_the_only_value()
    {
        Bag(new[] { Pair("X-Test", "one") }).GetSingle("x-test").ShouldBe("one");
        Bag(Array.Empty<KeyValuePair<string, string>>()).GetSingle("x-test").ShouldBeNull();
    }

    [Fact]
    public void Unknown_headers_are_preserved_and_marked_unknown()
    {
        var bag = Bag(new[] { Pair("profile-title", "Hello"), Pair("x-custom", "opaque") }, Known);

        bag.All.Count.ShouldBe(2);
        bag.Unknown.Select(h => h.Name).ShouldBe(new[] { "x-custom" });
        bag.All.Single(h => h.Name == "profile-title").IsKnown.ShouldBeTrue();
        bag.All.Single(h => h.Name == "x-custom").IsKnown.ShouldBeFalse();
    }

    [Fact]
    public void Known_names_are_matched_case_insensitively()
    {
        var bag = Bag(new[] { Pair("PROFILE-TITLE", "Hello") }, Known);

        bag.All[0].IsKnown.ShouldBeTrue();
    }

    [Fact]
    public void Names_are_distinct_but_case_preserving()
    {
        var bag = Bag(new[] { Pair("X-Test", "1"), Pair("x-test", "2") });

        bag.Names.ShouldBe(new[] { "X-Test" });
    }

    [Fact]
    public void Total_bytes_sums_accepted_values()
    {
        var bag = Bag(new[] { Pair("A", "12345"), Pair("B", "123") });

        bag.TotalBytes.ShouldBe(8);
    }

    [Theory]
    [InlineData("a\rb")]
    [InlineData("a\nb")]
    [InlineData("a\0b")]
    [InlineData("a\tb")]
    [InlineData("a\u0001b")]
    [InlineData("a\u001Fb")]
    [InlineData("a\u007Fb")]
    public void Values_with_control_characters_are_rejected_not_accepted(string value)
    {
        var bag = Bag(new[] { Pair("x-evil", value) });

        bag.All.ShouldBeEmpty();
        bag.Count.ShouldBe(0);
        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("control_characters");
        bag.Rejected[0].ReasonKey.ShouldBe("error.header.control_characters");
    }

    [Fact]
    public void A_crlf_injection_attempt_lands_in_rejected()
    {
        var bag = Bag(new[] { Pair("x-evil", "value\r\nX-Injected: 1") });

        bag.All.ShouldBeEmpty();
        bag.Rejected.Count.ShouldBe(1);
        bag.Contains("X-Injected").ShouldBeFalse();
    }

    [Theory]
    [InlineData("bad name")]
    [InlineData("bad:name")]
    [InlineData("bad(name)")]
    [InlineData("bad,name")]
    [InlineData("bad@name")]
    public void Invalid_header_names_are_rejected(string name)
    {
        var bag = Bag(new[] { Pair(name, "value") });

        bag.All.ShouldBeEmpty();
        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("invalid_name");
    }

    [Fact]
    public void An_empty_header_name_is_rejected()
    {
        var bag = Bag(new[] { Pair(string.Empty, "value") });

        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("empty_name");
    }

    [Fact]
    public void A_name_longer_than_the_limit_is_rejected()
    {
        var limits = new HeaderLimits { MaxNameLength = 8 };
        var bag = Bag(new[] { Pair("x-way-too-long", "value") }, limits: limits);

        bag.All.ShouldBeEmpty();
        bag.Rejected[0].ReasonCode.ShouldBe("name_too_long");
    }

    [Fact]
    public void A_value_longer_than_the_limit_is_rejected()
    {
        var limits = new HeaderLimits { MaxValueLength = 4 };
        var bag = Bag(new[] { Pair("x-long", "12345") }, limits: limits);

        bag.All.ShouldBeEmpty();
        bag.Rejected[0].ReasonCode.ShouldBe("value_too_long");
        bag.Rejected[0].Length.ShouldBe(5);
    }

    [Fact]
    public void A_value_at_the_default_limit_is_accepted()
    {
        var value = new string('a', HeaderLimits.Default.MaxValueLength);
        var bag = Bag(new[] { Pair("x-long", value) });

        bag.All.Count.ShouldBe(1);
    }

    [Fact]
    public void The_header_count_limit_is_enforced()
    {
        var limits = new HeaderLimits { MaxHeaderCount = 2 };
        var bag = Bag(
            new[] { Pair("a", "1"), Pair("b", "2"), Pair("c", "3") },
            limits: limits);

        bag.All.Count.ShouldBe(2);
        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("too_many_headers");
    }

    [Fact]
    public void The_total_bytes_limit_is_enforced()
    {
        var limits = new HeaderLimits { MaxTotalBytes = 10 };
        var bag = Bag(
            new[] { Pair("a", "123456"), Pair("b", "123456"), Pair("c", "1") },
            limits: limits);

        bag.All.Count.ShouldBe(2);
        bag.TotalBytes.ShouldBe(7);
        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("total_size_exceeded");
    }

    [Fact]
    public void Rejected_headers_record_the_reason_and_length()
    {
        var bag = Bag(new[] { Pair("bad name", "abc") });

        var rejected = bag.Rejected[0];
        rejected.Name.ShouldBe("bad name");
        rejected.Length.ShouldBe(8);
        rejected.ReasonCode.ShouldNotBeNullOrWhiteSpace();
        rejected.ReasonKey.ShouldStartWith("error.header.");
    }

    [Fact]
    public void A_rejected_name_is_truncated_to_a_safe_length()
    {
        var limits = new HeaderLimits { MaxNameLength = 4 };
        var bag = Bag(new[] { Pair(new string('n', 100), "v") }, limits: limits);

        bag.Rejected[0].Name.Length.ShouldBe(64);
    }

    [Fact]
    public void Null_pair_members_are_treated_as_empty()
    {
        var bag = Bag(new[] { new KeyValuePair<string, string>(null!, null!) });

        bag.All.ShouldBeEmpty();
        bag.Rejected.Count.ShouldBe(1);
        bag.Rejected[0].ReasonCode.ShouldBe("empty_name");
    }

    [Fact]
    public void Fingerprints_are_stable_lowercase_hex()
    {
        var bag = Bag(new[] { Pair("a", "value"), Pair("b", "value"), Pair("c", "other") });

        var first = bag.All[0].ValueFingerprint;

        first.Length.ShouldBe(64);
        first.ShouldBe(first.ToLowerInvariant());
        first.All(Uri.IsHexDigit).ShouldBeTrue();

        bag.All[1].ValueFingerprint.ShouldBe(first);
        bag.All[2].ValueFingerprint.ShouldNotBe(first);
    }

    [Fact]
    public void Fingerprints_are_sha256_of_the_value()
    {
        var bag = Bag(new[] { Pair("a", "value") });
        var expected = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("value"))).ToLowerInvariant();

        bag.All[0].ValueFingerprint.ShouldBe(expected);
    }

    [Fact]
    public void An_empty_value_is_accepted_with_a_fingerprint()
    {
        var bag = Bag(new[] { Pair("x-empty", string.Empty) });

        bag.All.Count.ShouldBe(1);
        bag.All[0].Value.ShouldBeEmpty();
        bag.All[0].ValueFingerprint.Length.ShouldBe(64);
    }

    [Fact]
    public void Lookup_members_reject_null_names()
    {
        var bag = Bag(new[] { Pair("a", "1") });

        Should.Throw<ArgumentNullException>(() => bag.GetValues(null!));
        Should.Throw<ArgumentNullException>(() => bag.GetEntries(null!));
        Should.Throw<ArgumentNullException>(() => bag.Contains(null!));
    }

    [Fact]
    public void Non_ascii_values_are_accepted()
    {
        var bag = Bag(new[] { Pair("x-unicode", "Привет 🇩🇪") });

        bag.All.Count.ShouldBe(1);
        bag.GetSingle("x-unicode").ShouldBe("Привет 🇩🇪");
    }
}
