using System.Net;
using MyVpn.Core.Net;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class CidrBlockTests
{
    [Fact]
    public void Parses_an_ipv4_block()
    {
        CidrBlock.TryParse("10.0.0.0/8", out var block).ShouldBeTrue();

        block.IsIPv4.ShouldBeTrue();
        block.IsIPv6.ShouldBeFalse();
        block.PrefixLength.ShouldBe(8);
        block.Network.ShouldBe(IPAddress.Parse("10.0.0.0"));
        block.AddressFamily.ShouldBe(System.Net.Sockets.AddressFamily.InterNetwork);
        block.ToString().ShouldBe("10.0.0.0/8");
    }

    [Fact]
    public void Parses_a_bare_ipv4_as_a_host_route()
    {
        CidrBlock.TryParse("192.168.1.5", out var block).ShouldBeTrue();

        block.PrefixLength.ShouldBe(32);
        block.Contains(IPAddress.Parse("192.168.1.5")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("192.168.1.6")).ShouldBeFalse();
    }

    [Fact]
    public void Parses_an_ipv6_block()
    {
        CidrBlock.TryParse("2001:db8::/32", out var block).ShouldBeTrue();

        block.IsIPv6.ShouldBeTrue();
        block.PrefixLength.ShouldBe(32);
        block.Contains(IPAddress.Parse("2001:db8:1234::1")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("2001:db9::1")).ShouldBeFalse();
    }

    [Fact]
    public void Parses_a_bare_ipv6_as_a_host_route()
    {
        CidrBlock.TryParse("::1", out var block).ShouldBeTrue();

        block.IsIPv6.ShouldBeTrue();
        block.PrefixLength.ShouldBe(128);
        block.Contains(IPAddress.Parse("::1")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("::2")).ShouldBeFalse();
    }

    [Fact]
    public void Parses_a_bracketed_ipv6_literal()
    {
        CidrBlock.TryParse("[2001:db8::1]/64", out var block).ShouldBeTrue();

        block.IsIPv6.ShouldBeTrue();
        block.PrefixLength.ShouldBe(64);
        block.Network.ShouldBe(IPAddress.Parse("2001:db8::"));
    }

    [Fact]
    public void Parses_a_bracketed_bare_ipv6_literal()
    {
        CidrBlock.TryParse("[2001:db8::1]", out var block).ShouldBeTrue();

        block.PrefixLength.ShouldBe(128);
    }

    [Fact]
    public void Tolerates_surrounding_whitespace()
    {
        CidrBlock.TryParse("  10.0.0.0/8  ", out var block).ShouldBeTrue();

        block.PrefixLength.ShouldBe(8);
    }

    [Fact]
    public void Prefix_zero_contains_every_address_of_its_family()
    {
        CidrBlock.TryParse("0.0.0.0/0", out var v4).ShouldBeTrue();
        CidrBlock.TryParse("::/0", out var v6).ShouldBeTrue();

        v4.Contains(IPAddress.Parse("8.8.8.8")).ShouldBeTrue();
        v4.Contains(IPAddress.Parse("255.255.255.255")).ShouldBeTrue();
        v4.Contains(IPAddress.Parse("0.0.0.0")).ShouldBeTrue();
        v6.Contains(IPAddress.Parse("2001:4860::8888")).ShouldBeTrue();
        v6.Contains(IPAddress.Parse("::")).ShouldBeTrue();
    }

    [Fact]
    public void Prefix_zero_does_not_cross_address_families()
    {
        CidrBlock.TryParse("0.0.0.0/0", out var v4).ShouldBeTrue();
        CidrBlock.TryParse("::/0", out var v6).ShouldBeTrue();

        v4.Contains(IPAddress.Parse("2001:db8::1")).ShouldBeFalse();
        v6.Contains(IPAddress.Parse("10.0.0.1")).ShouldBeFalse();
    }

    [Fact]
    public void A_slash_32_is_a_host_route()
    {
        CidrBlock.TryParse("192.168.1.10/32", out var block).ShouldBeTrue();

        block.Contains(IPAddress.Parse("192.168.1.10")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("192.168.1.11")).ShouldBeFalse();
    }

    [Fact]
    public void A_slash_128_is_an_ipv6_host_route()
    {
        CidrBlock.TryParse("2001:db8::5/128", out var block).ShouldBeTrue();

        block.Contains(IPAddress.Parse("2001:db8::5")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("2001:db8::6")).ShouldBeFalse();
    }

    [Fact]
    public void Contains_respects_the_boundary_of_a_class_a_block()
    {
        var block = CidrBlock.Parse("10.0.0.0/8");

        block.Contains(IPAddress.Parse("10.0.0.0")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("10.255.255.255")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("11.0.0.1")).ShouldBeFalse();
        block.Contains(IPAddress.Parse("9.255.255.255")).ShouldBeFalse();
    }

    [Fact]
    public void Contains_respects_a_partial_byte_prefix()
    {
        var block = CidrBlock.Parse("192.168.1.0/25");

        block.Contains(IPAddress.Parse("192.168.1.0")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("192.168.1.127")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("192.168.1.128")).ShouldBeFalse();
        block.Contains(IPAddress.Parse("192.168.1.255")).ShouldBeFalse();
    }

    [Fact]
    public void Contains_is_false_for_the_other_address_family()
    {
        var v4 = CidrBlock.Parse("10.0.0.0/8");
        var v6 = CidrBlock.Parse("2001:db8::/32");

        v4.Contains(IPAddress.IPv6Loopback).ShouldBeFalse();
        v6.Contains(IPAddress.Loopback).ShouldBeFalse();
    }

    [Fact]
    public void Ipv4_mapped_ipv6_behaves_as_ipv4()
    {
        CidrBlock.TryParse("::ffff:192.168.1.1", out var block).ShouldBeTrue();

        block.IsIPv4.ShouldBeTrue();
        block.PrefixLength.ShouldBe(32);
        block.Contains(IPAddress.Parse("192.168.1.1")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("::ffff:192.168.1.1")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("192.168.1.2")).ShouldBeFalse();
    }

    [Fact]
    public void An_ipv4_block_contains_a_mapped_ipv6_candidate()
    {
        var block = CidrBlock.Parse("10.0.0.0/8");

        block.Contains(IPAddress.Parse("::ffff:10.1.2.3")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("::ffff:11.1.2.3")).ShouldBeFalse();
    }

    [Fact]
    public void Big_endian_masking_is_correct()
    {
        var block = CidrBlock.Parse("10.0.0.0/8");

        block.Contains(IPAddress.Parse("10.255.255.255")).ShouldBeTrue();
        block.Contains(IPAddress.Parse("11.0.0.1")).ShouldBeFalse();
    }

    [Fact]
    public void Contains_block_implements_subset_semantics()
    {
        var parent = CidrBlock.Parse("10.0.0.0/8");
        var child = CidrBlock.Parse("10.1.0.0/16");

        parent.Contains(child).ShouldBeTrue();
        child.Contains(parent).ShouldBeFalse();
        parent.Contains(CidrBlock.Parse("11.0.0.0/16")).ShouldBeFalse();
        parent.Contains(CidrBlock.Parse("2001:db8::/32")).ShouldBeFalse();
    }

    [Fact]
    public void Contains_block_is_reflexive()
    {
        var block = CidrBlock.Parse("172.16.0.0/12");

        block.Contains(block).ShouldBeTrue();
    }

    [Fact]
    public void Equality_and_hashcode_use_the_masked_network()
    {
        var a = CidrBlock.Parse("10.0.0.1/8");
        var b = CidrBlock.Parse("10.0.0.0/8");
        var c = CidrBlock.Parse("10.0.0.0/9");

        a.Equals(b).ShouldBeTrue();
        (a == b).ShouldBeTrue();
        a.GetHashCode().ShouldBe(b.GetHashCode());

        a.Equals(c).ShouldBeFalse();
        (a != c).ShouldBeTrue();
        a.Equals((object)c).ShouldBeFalse();
        a.Equals("not a block").ShouldBeFalse();
    }

    [Fact]
    public void Different_families_with_the_same_prefix_are_not_equal()
    {
        var v4 = CidrBlock.Parse("0.0.0.0/0");
        var v6 = CidrBlock.Parse("::/0");

        v4.Equals(v6).ShouldBeFalse();
    }

    [Fact]
    public void Default_value_is_safe_to_compare()
    {
        var left = default(CidrBlock);
        var right = default(CidrBlock);

        left.Equals(right).ShouldBeTrue();
        left.GetHashCode().ShouldBe(right.GetHashCode());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-cidr")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/abc")]
    [InlineData("2001:db8::/129")]
    [InlineData("1.2.3.4/")]
    [InlineData("1.2.3.4/ 8")]
    [InlineData("10.0.0.0/8/8")]
    [InlineData("300.1.2.3/24")]
    public void Invalid_input_is_rejected(string? text)
    {
        CidrBlock.TryParse(text, out var block).ShouldBeFalse();
        block.ShouldBe(default);
    }

    [Fact]
    public void Parse_throws_a_format_exception_for_invalid_input()
    {
        Should.Throw<FormatException>(() => CidrBlock.Parse("nonsense"));
    }

    [Fact]
    public void Constructor_validates_its_arguments()
    {
        Should.Throw<ArgumentNullException>(() => new CidrBlock(null!, 24));
        Should.Throw<ArgumentOutOfRangeException>(() => new CidrBlock(IPAddress.Parse("10.0.0.0"), 33));
        Should.Throw<ArgumentOutOfRangeException>(() => new CidrBlock(IPAddress.Parse("10.0.0.0"), -1));
        Should.Throw<ArgumentOutOfRangeException>(() => new CidrBlock(IPAddress.Parse("2001:db8::"), 129));
    }

    [Fact]
    public void Constructor_accepts_maximum_prefixes()
    {
        new CidrBlock(IPAddress.Parse("10.0.0.0"), 32).PrefixLength.ShouldBe(32);
        new CidrBlock(IPAddress.Parse("2001:db8::"), 128).PrefixLength.ShouldBe(128);
        new CidrBlock(IPAddress.Parse("10.0.0.0"), 0).PrefixLength.ShouldBe(0);
    }

    [Fact]
    public void Contains_rejects_a_null_address()
    {
        Should.Throw<ArgumentNullException>(() => CidrBlock.Parse("10.0.0.0/8").Contains(null!));
    }
}
