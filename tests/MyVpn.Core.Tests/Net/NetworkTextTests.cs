using MyVpn.Core.Net;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class NetworkTextTests
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("sub.example.co.uk")]
    [InlineData("localhost")]
    [InlineData("a")]
    [InlineData("my_host")]
    [InlineData("host-name")]
    [InlineData("*.example.com")]
    [InlineData("example.com.")]
    public void Valid_host_names_are_accepted(string host)
    {
        NetworkText.IsValidHostName(host).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bad host")]
    [InlineData("bad..com")]
    [InlineData(".example.com")]
    [InlineData("host!name")]
    [InlineData("host:80")]
    [InlineData("host/path")]
    [InlineData("host\\path")]
    public void Invalid_host_names_are_rejected(string? host)
    {
        NetworkText.IsValidHostName(host).ShouldBeFalse();
    }

    [Fact]
    public void A_label_longer_than_63_characters_is_rejected()
    {
        var label = new string('a', 64);

        NetworkText.IsValidHostName(label + ".com").ShouldBeFalse();
        NetworkText.IsValidHostName(new string('a', 63) + ".com").ShouldBeTrue();
    }

    [Fact]
    public void A_name_longer_than_253_characters_is_rejected()
    {
        var host = string.Join('.', Enumerable.Repeat(new string('a', 60), 5));

        host.Length.ShouldBeGreaterThan(253);
        NetworkText.IsValidHostName(host).ShouldBeFalse();
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("full:example.com")]
    [InlineData("domain:example.com")]
    [InlineData("keyword:ads")]
    [InlineData("regexp:^.*\\.example\\.com$")]
    [InlineData("geosite:cn")]
    [InlineData("geosite:category-ads-all")]
    [InlineData("ext:geoip.dat:cn")]
    public void Valid_domain_patterns_are_accepted(string pattern)
    {
        NetworkText.IsValidDomainPattern(pattern).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("full:")]
    [InlineData("full:bad host")]
    [InlineData("domain:bad host")]
    [InlineData("keyword:")]
    [InlineData("regexp:[unclosed")]
    [InlineData("geosite:")]
    [InlineData("geosite:a b")]
    [InlineData("ext:")]
    [InlineData("ext:../../etc/passwd")]
    [InlineData("ext:sub/dir")]
    [InlineData("ext:sub\\dir")]
    [InlineData("ext:..")]
    [InlineData("unknown:value")]
    public void Invalid_domain_patterns_are_rejected(string? pattern)
    {
        NetworkText.IsValidDomainPattern(pattern).ShouldBeFalse();
    }

    [Fact]
    public void A_domain_pattern_longer_than_255_characters_is_rejected()
    {
        var pattern = "domain:" + new string('a', 250) + ".com";

        pattern.Length.ShouldBeGreaterThan(255);
        NetworkText.IsValidDomainPattern(pattern).ShouldBeFalse();
    }

    [Fact]
    public void Regexp_patterns_are_validated_as_regular_expressions()
    {
        NetworkText.IsValidRegex("^abc$").ShouldBeTrue();
        NetworkText.IsValidRegex("(").ShouldBeFalse();
        NetworkText.IsValidRegex("").ShouldBeFalse();
        NetworkText.IsValidRegex(new string('a', 513)).ShouldBeFalse();
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("10.0.0.1")]
    [InlineData("::1")]
    [InlineData("2001:db8::/32")]
    [InlineData("[2001:db8::1]/64")]
    public void Ip_or_cidr_accepts_addresses_and_prefixes(string text)
    {
        NetworkText.IsIpOrCidr(text).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("999.1.1.1")]
    [InlineData("10.0.0.0/33")]
    [InlineData("example.com")]
    [InlineData("::1/129")]
    public void Ip_or_cidr_rejects_nonsense(string? text)
    {
        NetworkText.IsIpOrCidr(text).ShouldBeFalse();
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    public void Is_ip_address_accepts_bare_addresses(string text)
    {
        NetworkText.IsIpAddress(text).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("10.0.0.0/8")]
    [InlineData("example.com")]
    public void Is_ip_address_rejects_prefixes_and_names(string? text)
    {
        NetworkText.IsIpAddress(text).ShouldBeFalse();
    }

    [Fact]
    public void Is_ip_address_trims_whitespace()
    {
        NetworkText.IsIpAddress("  1.1.1.1  ").ShouldBeTrue();
    }
}
