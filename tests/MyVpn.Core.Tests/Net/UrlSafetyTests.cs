using System.Net;
using MyVpn.Core.Net;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class UrlSafetyTests
{
    [Fact]
    public void A_public_https_url_is_accepted()
    {
        UrlSafety.IsSafeHttpUrl("https://example.com/sub", allowInsecureHttp: false, out var reason)
            .ShouldBeTrue();
        reason.ShouldBe(UrlRejectionReason.None);
    }

    [Fact]
    public void Http_is_rejected_when_insecure_is_not_allowed()
    {
        UrlSafety.IsSafeHttpUrl("http://example.com/sub", allowInsecureHttp: false, out var reason)
            .ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.InsecureScheme);
    }

    [Fact]
    public void Http_is_accepted_when_insecure_is_allowed()
    {
        UrlSafety.IsSafeHttpUrl("http://example.com/sub", allowInsecureHttp: true, out var reason)
            .ShouldBeTrue();
        reason.ShouldBe(UrlRejectionReason.None);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_input_is_rejected(string? url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.Empty);
    }

    [Fact]
    public void A_relative_url_is_rejected()
    {
        UrlSafety.IsSafeHttpUrl("relative", allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.NotAbsolute);

        // On Unix a leading slash parses as an absolute file URI, which is refused
        // because only http/https are allowed.
        UrlSafety.IsSafeHttpUrl("/relative/path", allowInsecureHttp: true, out var slashReason).ShouldBeFalse();
        slashReason.ShouldBeOneOf(UrlRejectionReason.NotAbsolute, UrlRejectionReason.SchemeNotAllowed);
    }

    [Theory]
    [InlineData("ftp://example.com/file")]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://example.com")]
    public void A_non_http_scheme_is_rejected(string url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.SchemeNotAllowed);
    }

    [Theory]
    [InlineData("https://user:pass@example.com/")]
    [InlineData("http://user@example.com/")]
    public void Embedded_credentials_are_rejected(string url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.HasCredentials);
    }

    [Theory]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.1.2.3/")]
    [InlineData("http://[::1]/")]
    public void Loopback_addresses_are_rejected(string url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.LoopbackAddress);
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("http://LOCALHOST/admin")]
    [InlineData("http://foo.localhost/")]
    [InlineData("http://metadata.google.internal/computeMetadata/v1/")]
    [InlineData("http://instance-data/")]
    public void Blocked_host_names_are_rejected(string url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.BlockedHostName);
    }

    [Theory]
    [InlineData("http://10.0.0.1/")]
    [InlineData("http://192.168.0.1/")]
    [InlineData("http://172.16.0.1/")]
    [InlineData("http://172.31.255.255/")]
    [InlineData("http://100.64.0.1/")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://0.0.0.0/")]
    public void Private_reserved_and_unspecified_addresses_are_rejected(string url)
    {
        UrlSafety.IsSafeHttpUrl(url, allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldNotBe(UrlRejectionReason.None);
    }

    [Fact]
    public void Zero_address_is_reported_as_unspecified()
    {
        UrlSafety.IsSafeHttpUrl("http://0.0.0.0/", allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.UnspecifiedAddress);
    }

    [Fact]
    public void Link_local_ipv4_is_reported_as_private()
    {
        UrlSafety.IsSafeHttpUrl("http://169.254.169.254/", allowInsecureHttp: true, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.PrivateAddress);
    }

    [Fact]
    public void Ipv6_loopback_is_rejected_even_when_the_host_has_no_brackets_alternative()
    {
        UrlSafety.IsSafeHttpUrl("https://[::1]/", allowInsecureHttp: false, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.LoopbackAddress);
    }

    [Fact]
    public void Missing_host_is_rejected()
    {
        // "https://" parses as absolute but carries no host.
        UrlSafety.IsSafeHttpUrl("https://", allowInsecureHttp: false, out var reason).ShouldBeFalse();
        reason.ShouldBeOneOf(UrlRejectionReason.HostMissing, UrlRejectionReason.NotAbsolute);
    }

    [Fact]
    public void IsAddressAllowed_rejects_loopback()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Loopback, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.LoopbackAddress);
        UrlSafety.IsAddressAllowed(IPAddress.IPv6Loopback, out var v6Reason).ShouldBeFalse();
        v6Reason.ShouldBe(UrlRejectionReason.LoopbackAddress);
    }

    [Fact]
    public void IsAddressAllowed_rejects_unspecified_addresses()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Any, out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.UnspecifiedAddress);
        UrlSafety.IsAddressAllowed(IPAddress.IPv6Any, out var v6Reason).ShouldBeFalse();
        v6Reason.ShouldBe(UrlRejectionReason.UnspecifiedAddress);
    }

    [Fact]
    public void IsAddressAllowed_rejects_ipv6_link_local()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Parse("fe80::1"), out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.LinkLocalAddress);
    }

    [Fact]
    public void IsAddressAllowed_rejects_ipv6_multicast()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Parse("ff02::1"), out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.MulticastAddress);
    }

    [Fact]
    public void IsAddressAllowed_rejects_a_mapped_private_ipv4()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Parse("::ffff:192.168.1.1"), out var reason).ShouldBeFalse();
        reason.ShouldBe(UrlRejectionReason.PrivateAddress);
    }

    [Fact]
    public void IsAddressAllowed_accepts_a_public_address()
    {
        UrlSafety.IsAddressAllowed(IPAddress.Parse("1.1.1.1"), out var reason).ShouldBeTrue();
        reason.ShouldBe(UrlRejectionReason.None);
        UrlSafety.IsAddressAllowed(IPAddress.Parse("2606:4700:4700::1111"), out _).ShouldBeTrue();
    }

    [Fact]
    public void IsAddressAllowed_rejects_null()
    {
        Should.Throw<ArgumentNullException>(() => UrlSafety.IsAddressAllowed(null!, out _));
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.0.1", true)]
    [InlineData("100.64.0.0", true)]
    [InlineData("100.127.255.255", true)]
    [InlineData("100.128.0.0", false)]
    [InlineData("127.0.0.1", true)]
    [InlineData("198.18.0.1", true)]
    [InlineData("198.51.100.1", true)]
    [InlineData("203.0.113.1", true)]
    [InlineData("192.0.2.1", true)]
    [InlineData("255.255.255.255", true)]
    [InlineData("0.1.2.3", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("93.184.216.34", false)]
    public void IsPrivateOrReserved_classifies_ipv4_space(string address, bool expected)
    {
        UrlSafety.IsPrivateOrReserved(IPAddress.Parse(address)).ShouldBe(expected);
    }

    [Theory]
    [InlineData("fc00::1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("2606:4700::1111", false)]
    [InlineData("2001:4860::8888", false)]
    public void IsPrivateOrReserved_classifies_ipv6_space(string address, bool expected)
    {
        UrlSafety.IsPrivateOrReserved(IPAddress.Parse(address)).ShouldBe(expected);
    }

    [Fact]
    public void IsPrivateOrReserved_treats_mapped_ipv4_as_ipv4()
    {
        UrlSafety.IsPrivateOrReserved(IPAddress.Parse("::ffff:10.0.0.1")).ShouldBeTrue();
        UrlSafety.IsPrivateOrReserved(IPAddress.Parse("::ffff:8.8.8.8")).ShouldBeFalse();
    }

    [Fact]
    public void IsPrivateOrReserved_rejects_null()
    {
        Should.Throw<ArgumentNullException>(() => UrlSafety.IsPrivateOrReserved(null!));
    }
}
