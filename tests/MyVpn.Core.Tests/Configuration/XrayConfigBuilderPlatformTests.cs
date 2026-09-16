using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using Shouldly;

namespace MyVpn.Core.Tests;

/// <summary>
/// Platform-specific behaviour of the generated config.
/// </summary>
/// <remarks>
/// The three platforms differ in ways that are easy to get wrong and expensive to debug:
/// macOS insists on a <c>utunN</c> name and rejects a /32 point-to-point prefix, the TUN
/// <c>dns</c> field only means anything on Windows, and the Linux firewall mark must be
/// applied to the proxy outbound only — putting it on the direct outbound would send
/// ordinary traffic back into the tunnel's policy-routing table.
/// </remarks>
public sealed class XrayConfigBuilderPlatformTests
{
    [Fact]
    public void MacOS_replaces_a_non_utun_name_and_warns()
    {
        var settings = new AppSettings
        {
            Tun = new TunSettings { InterfaceName = "myvpn0" },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            platform: PlatformTarget.MacOS));

        var tun = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun");
        tun["settings"]!["name"]!.GetValue<string>().ShouldBe("utun0");

        var warning = result.Warnings.ShouldHaveSingleItem();
        warning.MessageKey.ShouldBe("error.tun.macos_name_invalid");
        warning.Severity.ShouldBe(MyVpn.Core.Results.ErrorSeverity.Warning);
    }

    [Fact]
    public void MacOS_keeps_an_existing_utun_name_without_a_warning()
    {
        var settings = new AppSettings
        {
            Tun = new TunSettings { InterfaceName = "utun7" },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            platform: PlatformTarget.MacOS));

        XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!["name"]!
            .GetValue<string>().ShouldBe("utun7");

        result.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public void MacOS_uses_exactly_one_ipv4_gateway_that_is_not_a_host_prefix()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            platform: PlatformTarget.MacOS));

        var gateways = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!
            ["gateway"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray();

        gateways.Length.ShouldBe(1);

        var gateway = gateways[0];
        gateway.ShouldBe("169.254.10.1/30");

        // Exactly one IPv4 prefix, and macOS rejects /32 because it needs a peer address.
        gateway.ShouldNotContain(":");
        gateway.ShouldNotEndWith("/32");
    }

    [Theory]
    [InlineData(PlatformTarget.Linux)]
    [InlineData(PlatformTarget.Windows)]
    public void Other_platforms_use_both_address_families_for_the_gateway(PlatformTarget platform)
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(platform: platform));

        var gateways = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!
            ["gateway"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray();

        gateways.ShouldContain("172.19.0.1/30");
        gateways.ShouldContain("fdfe:dcba:9876::1/126");
    }

    [Fact]
    public void Windows_assigns_dns_on_the_tun_inbound_when_dns_is_not_system()
    {
        var settings = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.ThroughTunnel,
                Servers = new[] { "9.9.9.9", "149.112.112.112" },
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            platform: PlatformTarget.Windows));

        var dns = XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!
            ["dns"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray();

        dns.ShouldBe(new[] { "9.9.9.9", "149.112.112.112" });
    }

    [Fact]
    public void Windows_does_not_assign_dns_when_dns_is_system()
    {
        var settings = new AppSettings
        {
            Dns = new DnsSettings { Mode = DnsMode.System },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            platform: PlatformTarget.Windows));

        XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!
            .AsObject().ContainsKey("dns").ShouldBeFalse();
    }

    [Theory]
    [InlineData(PlatformTarget.Linux)]
    [InlineData(PlatformTarget.MacOS)]
    public void Non_windows_platforms_never_assign_tun_dns(PlatformTarget platform)
    {
        var settings = new AppSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.ThroughTunnel,
                Servers = new[] { "9.9.9.9" },
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            settings: settings,
            platform: platform));

        XrayConfigTestFactory.Inbound(XrayConfigTestFactory.Root(result), "tun")["settings"]!
            .AsObject().ContainsKey("dns").ShouldBeFalse();
    }

    [Fact]
    public void Linux_marks_the_proxy_outbound_but_not_the_direct_outbound()
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(
            platform: PlatformTarget.Linux));

        var root = XrayConfigTestFactory.Root(result);

        XrayConfigTestFactory.Sockopt(XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.ProxyTag))
            ["mark"]!.GetValue<int>().ShouldBe(0x0CA6C);

        XrayConfigTestFactory.Sockopt(XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.DirectTag))
            .ContainsKey("mark").ShouldBeFalse();
    }

    [Theory]
    [InlineData(PlatformTarget.Windows)]
    [InlineData(PlatformTarget.MacOS)]
    public void The_firewall_mark_is_linux_only(PlatformTarget platform)
    {
        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(platform: platform));

        XrayConfigTestFactory.Sockopt(
                XrayConfigTestFactory.Outbound(XrayConfigTestFactory.Root(result), XrayConfigBuilder.ProxyTag))
            .ContainsKey("mark").ShouldBeFalse();
    }

    [Fact]
    public void The_direct_outbound_binds_to_the_physical_interface_when_asked()
    {
        var settings = new AppSettings
        {
            Connectivity = new ConnectivitySettings
            {
                BindToPhysicalInterface = true,
                PhysicalInterface = "eth0",
            },
        };

        var result = XrayConfigTestFactory.BuildOk(XrayConfigTestFactory.Request(settings: settings));
        var root = XrayConfigTestFactory.Root(result);

        XrayConfigTestFactory.Sockopt(XrayConfigTestFactory.Outbound(root, XrayConfigBuilder.DirectTag))
            ["interface"]!.GetValue<string>().ShouldBe("eth0");
    }
}
