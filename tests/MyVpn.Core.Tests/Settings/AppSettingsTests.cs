using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class AppSettingsTests
{
    private static string[] Keys(IEnumerable<MyVpn.Core.Results.MyVpnError> errors) =>
        errors.Select(e => e.MessageKey).ToArray();

    // ------------------------------------------------------------------ defaults

    [Fact]
    public void Defaults_match_the_documented_security_posture()
    {
        var settings = new AppSettings();

        settings.Ipv6.ShouldBe(Ipv6Mode.DisableWhileConnected);
        settings.KillSwitch.ShouldBe(KillSwitchMode.OnDemand);
        settings.Privacy.TelemetryEnabled.ShouldBeFalse();
        settings.Privacy.CrashReportsEnabled.ShouldBeFalse();
        settings.Privacy.IncludeSecretsInDiagnostics.ShouldBeFalse();
        settings.Mux.Enabled.ShouldBeFalse();
        settings.Tun.Mtu.ShouldBe(0);
        settings.TunnelMode.ShouldBe(TunnelMode.Tun);
        settings.Dns.BlockPlainDnsLeaks.ShouldBeTrue();
        settings.Dns.EnableFakeDns.ShouldBeFalse();
        settings.Tun.AutoRoute.ShouldBeTrue();
        settings.Tun.StrictRoute.ShouldBeTrue();
        settings.Subscriptions.AllowInsecureHttp.ShouldBeFalse();
        settings.Updates.RequireSignature.ShouldBeTrue();
        settings.AutoReconnect.ShouldBeTrue();
        settings.AdvancedMode.ShouldBeFalse();
    }

    [Fact]
    public void The_default_settings_validate()
    {
        var result = new AppSettings().Validate();

        result.IsSuccess.ShouldBeTrue(result.Error?.ToString());
    }

    // ------------------------------------------------------------ aggregate error

    [Fact]
    public void Validate_reports_multiple_problems_at_once()
    {
        var settings = new AppSettings
        {
            UiScale = 5.0,
            AccentColor = "red",
        };

        var result = settings.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(MyVpn.Core.Results.ErrorCodes.ConfigInvalid);
        result.Error.MessageKey.ShouldBe("error.settings.invalid");
        result.Error.Arguments["count"].ShouldBe("2");
        result.Error!.TechnicalDetail!.ShouldContain("error.settings.ui_scale_range");
        result.Error!.TechnicalDetail!.ShouldContain("error.settings.accent_color_format");
    }

    [Fact]
    public void Unsupported_schema_version_is_rejected()
    {
        new AppSettings { SchemaVersion = 0 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { SchemaVersion = 2 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { SchemaVersion = 1 }.Validate().IsSuccess.ShouldBeTrue();
    }

    // ---------------------------------------------------------------- appearance

    [Theory]
    [InlineData(0.5)]
    [InlineData(0.74)]
    [InlineData(2.01)]
    [InlineData(5.0)]
    public void UiScale_outside_the_range_is_rejected(double scale)
    {
        var result = new AppSettings { UiScale = scale }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.settings.ui_scale_range");
    }

    [Theory]
    [InlineData(0.75)]
    [InlineData(1.0)]
    [InlineData(2.0)]
    public void UiScale_inside_the_range_is_accepted(double scale)
    {
        new AppSettings { UiScale = scale }.Validate().IsSuccess.ShouldBeTrue();
    }

    [Theory]
    [InlineData("red")]
    [InlineData("#ABC")]
    [InlineData("#GGGGGG")]
    [InlineData("112233")]
    [InlineData("#1122334")]
    public void A_malformed_accent_colour_is_rejected(string colour)
    {
        new AppSettings { AccentColor = colour }.Validate().IsFailure.ShouldBeTrue();
    }

    [Theory]
    [InlineData("#AABBCC")]
    [InlineData("#000000")]
    [InlineData("#abcdef")]
    public void A_well_formed_accent_colour_is_accepted(string colour)
    {
        new AppSettings { AccentColor = colour }.Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Reconnect_delay_and_restart_attempts_are_bounded()
    {
        new AppSettings { ReconnectDelaySeconds = -1 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { ReconnectDelaySeconds = 301 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { ReconnectDelaySeconds = 300 }.Validate().IsSuccess.ShouldBeTrue();
        new AppSettings { MaxRestartAttempts = -1 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { MaxRestartAttempts = 101 }.Validate().IsFailure.ShouldBeTrue();
        new AppSettings { MaxRestartAttempts = 100 }.Validate().IsSuccess.ShouldBeTrue();
    }

    // ----------------------------------------------------------------------- tun

    [Fact]
    public void Tun_mtu_zero_means_auto_and_is_valid()
    {
        new AppSettings { Tun = new TunSettings { Mtu = 0 } }.Validate().IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Tun_mtu_of_100_is_rejected()
    {
        Keys(new TunSettings { Mtu = 100 }.Validate()).ShouldContain("error.tun.mtu_range");
    }

    [Fact]
    public void Tun_mtu_of_10000_is_rejected()
    {
        Keys(new TunSettings { Mtu = 10000 }.Validate()).ShouldContain("error.tun.mtu_range");
    }

    [Fact]
    public void Tun_mtu_of_1300_is_allowed()
    {
        new AppSettings { Tun = new TunSettings { Mtu = 1300 } }.Validate().IsSuccess.ShouldBeTrue();
        new TunSettings { Mtu = 1300 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Tun_mtu_below_the_ipv6_minimum_is_rejected()
    {
        Keys(new TunSettings { Mtu = 1279 }.Validate()).ShouldContain("error.tun.mtu_ipv6_minimum");
        new TunSettings { Mtu = 1280 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Tun_boundary_mtus_are_checked()
    {
        Keys(new TunSettings { Mtu = 575 }.Validate()).ShouldContain("error.tun.mtu_range");
        Keys(new TunSettings { Mtu = 9001 }.Validate()).ShouldContain("error.tun.mtu_range");
        new TunSettings { Mtu = 9000 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Tun_interface_name_and_excluded_routes_are_validated()
    {
        Keys(new TunSettings { InterfaceName = "bad name" }.Validate())
            .ShouldContain("error.tun.interface_name_invalid");
        Keys(new TunSettings { ExcludedRoutes = new[] { "not-a-cidr" } }.Validate())
            .ShouldContain("error.tun.excluded_route_invalid");
        new TunSettings { InterfaceName = "tun0", ExcludedRoutes = new[] { "10.0.0.0/8" } }
            .Validate().ShouldBeEmpty();
    }

    // ----------------------------------------------------------------------- dns

    [Fact]
    public void Doh_requires_an_https_endpoint()
    {
        Keys(new DnsSettings { Mode = DnsMode.Doh, DohUrl = "http://dns.example/dns-query" }.Validate())
            .ShouldContain("error.dns.doh_requires_https");
        Keys(new DnsSettings { Mode = DnsMode.Doh, DohUrl = null }.Validate())
            .ShouldContain("error.dns.doh_requires_https");
        Keys(new DnsSettings { Mode = DnsMode.Doh, DohUrl = "not a url" }.Validate())
            .ShouldContain("error.dns.doh_requires_https");

        new DnsSettings { Mode = DnsMode.Doh, DohUrl = "https://dns.example/dns-query" }
            .Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Dot_requires_a_valid_host()
    {
        Keys(new DnsSettings { Mode = DnsMode.Dot, DotHost = null }.Validate())
            .ShouldContain("error.dns.dot_requires_host");
        Keys(new DnsSettings { Mode = DnsMode.Dot, DotHost = "bad host" }.Validate())
            .ShouldContain("error.dns.dot_requires_host");

        new DnsSettings { Mode = DnsMode.Dot, DotHost = "dns.example" }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Dot_port_must_be_in_range()
    {
        Keys(new DnsSettings { DotPort = 0 }.Validate()).ShouldContain("error.dns.dot_port_range");
        Keys(new DnsSettings { DotPort = 65536 }.Validate()).ShouldContain("error.dns.dot_port_range");
        new DnsSettings { DotPort = 853 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Custom_dns_requires_servers_and_servers_must_be_ips()
    {
        Keys(new DnsSettings { Mode = DnsMode.Custom, Servers = Array.Empty<string>() }.Validate())
            .ShouldContain("error.dns.custom_requires_servers");
        Keys(new DnsSettings { Servers = new[] { "not-an-ip" } }.Validate())
            .ShouldContain("error.dns.server_not_ip");
        new DnsSettings { Mode = DnsMode.Custom, Servers = new[] { "9.9.9.9" } }
            .Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Split_dns_domains_are_validated()
    {
        Keys(new DnsSettings { SplitDnsDomains = new[] { "bad host" } }.Validate())
            .ShouldContain("error.dns.split_domain_invalid");
        new DnsSettings { SplitDnsDomains = new[] { "corp.example" } }.Validate().ShouldBeEmpty();
    }

    // ------------------------------------------------------------------- routing

    [Fact]
    public void Routing_rejects_a_bad_cidr()
    {
        var result = new AppSettings
        {
            Routing = new RoutingSettings { DirectIpCidrs = new[] { "999.1.1.1" } },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.routing.cidr_invalid");
    }

    [Fact]
    public void Routing_rejects_a_bad_domain()
    {
        var result = new AppSettings
        {
            Routing = new RoutingSettings { DirectDomains = new[] { "bad host" } },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.routing.domain_invalid");
    }

    [Fact]
    public void Routing_rejects_a_bad_regex_pattern()
    {
        var result = new AppSettings
        {
            Routing = new RoutingSettings { ProxyDomains = new[] { "regexp:[unclosed" } },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.routing.domain_invalid");
    }

    [Fact]
    public void Routing_validates_the_domain_strategy()
    {
        Keys(new RoutingSettings { DomainStrategy = "Nope" }.Validate())
            .ShouldContain("error.routing.domain_strategy_invalid");

        foreach (var strategy in new[] { "AsIs", "IPIfNonMatch", "IPOnDemand" })
        {
            new RoutingSettings { DomainStrategy = strategy }.Validate().ShouldBeEmpty();
        }
    }

    [Fact]
    public void Routing_validates_geo_codes()
    {
        Keys(new RoutingSettings { DirectGeoIpCountries = new[] { "r u" } }.Validate())
            .ShouldContain("error.routing.geo_code_invalid");
        Keys(new RoutingSettings { DirectGeoSites = new[] { "a b" } }.Validate())
            .ShouldContain("error.routing.geo_code_invalid");

        new RoutingSettings
        {
            DirectGeoIpCountries = new[] { "ru", "cn" },
            DirectGeoSites = new[] { "category-ads-all" },
        }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void An_empty_custom_rule_is_rejected()
    {
        var rule = new CustomRoutingRule();

        Keys(rule.Validate()).ShouldContain("error.routing.rule_empty");
    }

    [Fact]
    public void A_custom_rule_with_domains_is_valid_and_targets_an_outbound()
    {
        var rule = new CustomRoutingRule { Domains = new[] { "example.com" }, Proxy = true };

        rule.Validate().ShouldBeEmpty();
        rule.OutboundTag.ShouldBe("proxy");
        (rule with { Proxy = false }).OutboundTag.ShouldBe("direct");
    }

    [Fact]
    public void A_custom_rule_validates_ports_and_network()
    {
        var baseRule = new CustomRoutingRule { Domains = new[] { "example.com" } };

        Keys((baseRule with { Ports = new[] { 0 } }).Validate()).ShouldContain("error.routing.port_range");
        Keys((baseRule with { Network = "udp2" }).Validate()).ShouldContain("error.routing.network_invalid");
        Keys((baseRule with { IpCidrs = new[] { "bad" } }).Validate()).ShouldContain("error.routing.cidr_invalid");

        (baseRule with { Ports = new[] { 443 }, Network = "tcp,udp" }).Validate().ShouldBeEmpty();
    }

    // -------------------------------------------------------------------- proxy

    [Fact]
    public void Proxy_with_no_listener_is_rejected()
    {
        var result = new AppSettings
        {
            Proxy = new ProxySettings { EnableSocks = false, EnableHttp = false },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.proxy.no_listener");
    }

    [Fact]
    public void Proxy_listen_port_is_bounded()
    {
        Keys(new ProxySettings { ListenPort = 80 }.Validate()).ShouldContain("error.proxy.port_range");
        Keys(new ProxySettings { ListenPort = 70000 }.Validate()).ShouldContain("error.proxy.port_range");
        new ProxySettings { ListenPort = 10808 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Proxy_pac_url_is_validated()
    {
        Keys(new ProxySettings { UsePac = true, CustomPacUrl = "ftp://example/pac" }.Validate())
            .ShouldContain("error.proxy.pac_url_invalid");
        new ProxySettings { UsePac = true, CustomPacUrl = "https://example/pac" }.Validate().ShouldBeEmpty();
        new ProxySettings { UsePac = true, CustomPacUrl = "file:///tmp/pac" }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Proxy_bypass_domains_and_cidrs_are_validated()
    {
        Keys(new ProxySettings { BypassDomains = new[] { "bad host" } }.Validate())
            .ShouldContain("error.proxy.bypass_domain_invalid");
        Keys(new ProxySettings { BypassIpCidrs = new[] { "bad" } }.Validate())
            .ShouldContain("error.proxy.bypass_cidr_invalid");
    }

    // ----------------------------------------------------------------------- mux

    [Fact]
    public void Mux_concurrency_is_only_bounded_when_enabled()
    {
        new MuxSettings { Enabled = false, Concurrency = 0 }.Validate().ShouldBeEmpty();
        Keys(new MuxSettings { Enabled = true, Concurrency = 0 }.Validate())
            .ShouldContain("error.mux.concurrency_range");
        Keys(new MuxSettings { Enabled = true, Concurrency = 1025 }.Validate())
            .ShouldContain("error.mux.concurrency_range");
        new MuxSettings { Enabled = true, Concurrency = 1024 }.Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Mux_xudp_concurrency_is_validated()
    {
        Keys(new MuxSettings { XudpConcurrency = 0 }.Validate())
            .ShouldContain("error.mux.xudp_concurrency_range");
        Keys(new MuxSettings { XudpConcurrency = -2 }.Validate())
            .ShouldContain("error.mux.xudp_concurrency_range");
        new MuxSettings { XudpConcurrency = -1 }.Validate().ShouldBeEmpty();
    }

    // --------------------------------------------------------- process routing

    [Fact]
    public void Process_routing_mode_without_any_selection_warns()
    {
        var errors = new ProcessRoutingSettings { Mode = ProcessRoutingMode.BypassVpn }.Validate().ToArray();

        errors.Length.ShouldBe(1);
        errors[0].MessageKey.ShouldBe("error.process.mode_without_selection");
        errors[0].Severity.ShouldBe(MyVpn.Core.Results.ErrorSeverity.Warning);
    }

    [Fact]
    public void Process_selector_by_name_is_validated()
    {
        Keys(new ProcessSelector { Kind = ProcessSelectorKind.ExecutableName, ExecutableName = null }.Validate())
            .ShouldContain("error.process.name_invalid");
        Keys(new ProcessSelector { Kind = ProcessSelectorKind.ExecutableName, ExecutableName = "a/b" }.Validate())
            .ShouldContain("error.process.name_invalid");
        new ProcessSelector { Kind = ProcessSelectorKind.ExecutableName, ExecutableName = "game.exe" }
            .Validate().ShouldBeEmpty();
    }

    [Fact]
    public void Process_selector_by_path_requires_an_absolute_path()
    {
        Keys(new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "rel/game.exe" }.Validate())
            .ShouldContain("error.process.path_not_absolute");
        new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = Path.Combine(Path.GetTempPath(), "game.exe") }
            .Validate().ShouldBeEmpty();
    }

    [Fact]
    public void An_unknown_process_selector_kind_is_rejected()
    {
        Keys(new ProcessSelector { Kind = (ProcessSelectorKind)99 }.Validate())
            .ShouldContain("error.process.selector_unsupported");
    }

    // -------------------------------------------------------------- connectivity

    [Fact]
    public void Connectivity_ranges_are_bounded()
    {
        Keys(new ConnectivitySettings { TcpKeepAliveSeconds = -1 }.Validate())
            .ShouldContain("error.connectivity.keepalive_range");
        Keys(new ConnectivitySettings { TcpKeepAliveSeconds = 3601 }.Validate())
            .ShouldContain("error.connectivity.keepalive_range");
        Keys(new ConnectivitySettings { ConnectTimeoutSeconds = 4 }.Validate())
            .ShouldContain("error.connectivity.timeout_range");
        Keys(new ConnectivitySettings { ConnectTimeoutSeconds = 301 }.Validate())
            .ShouldContain("error.connectivity.timeout_range");
        Keys(new ConnectivitySettings { PhysicalInterface = "bad host" }.Validate())
            .ShouldContain("error.connectivity.interface_invalid");
        new ConnectivitySettings().Validate().ShouldBeEmpty();
    }

    // ------------------------------------------------------------------- updates

    [Fact]
    public void The_update_feed_must_use_https()
    {
        var result = new AppSettings
        {
            Updates = new UpdateSettings { FeedUrl = "http://example.com/feed" },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.updates.feed_requires_https");
    }

    [Fact]
    public void Update_feed_over_https_is_accepted()
    {
        new UpdateSettings { FeedUrl = "https://example.com/feed" }.Validate().ShouldBeEmpty();
        new UpdateSettings { FeedUrl = null }.Validate().ShouldBeEmpty();
        Keys(new UpdateSettings { FeedUrl = "not a url" }.Validate())
            .ShouldContain("error.updates.feed_requires_https");
    }

    [Fact]
    public void Update_check_interval_is_bounded()
    {
        Keys(new UpdateSettings { CheckIntervalHours = -1 }.Validate())
            .ShouldContain("error.updates.interval_range");
        Keys(new UpdateSettings { CheckIntervalHours = 24 * 30 + 1 }.Validate())
            .ShouldContain("error.updates.interval_range");
        new UpdateSettings { CheckIntervalHours = 24 * 30 }.Validate().ShouldBeEmpty();
    }

    // ---------------------------------------------------------------- logging

    [Fact]
    public void Logging_ranges_are_bounded()
    {
        Keys(new LoggingSettings { MaxFileSizeMb = 0 }.Validate()).ShouldContain("error.logging.file_size_range");
        Keys(new LoggingSettings { MaxFileSizeMb = 1025 }.Validate()).ShouldContain("error.logging.file_size_range");
        Keys(new LoggingSettings { MaxFiles = 0 }.Validate()).ShouldContain("error.logging.files_range");
        Keys(new LoggingSettings { MaxFiles = 101 }.Validate()).ShouldContain("error.logging.files_range");
        Keys(new LoggingSettings { RetentionDays = 0 }.Validate()).ShouldContain("error.logging.retention_range");
        Keys(new LoggingSettings { RetentionDays = 366 }.Validate()).ShouldContain("error.logging.retention_range");
        new LoggingSettings().Validate().ShouldBeEmpty();
    }

    // ------------------------------------------------------------ subscriptions

    [Fact]
    public void A_subscription_interval_that_is_too_big_is_rejected()
    {
        var result = new AppSettings
        {
            Subscriptions = new SubscriptionSettings { UpdateIntervalHours = 24 * 30 + 1 },
        }.Validate();

        result.IsFailure.ShouldBeTrue();
        result.Error!.TechnicalDetail!.ShouldContain("error.subscriptions.interval_range");
    }

    [Fact]
    public void Subscription_ranges_are_bounded()
    {
        Keys(new SubscriptionSettings { UpdateIntervalHours = -1 }.Validate())
            .ShouldContain("error.subscriptions.interval_range");
        Keys(new SubscriptionSettings { TimeoutSeconds = 4 }.Validate())
            .ShouldContain("error.subscriptions.timeout_range");
        Keys(new SubscriptionSettings { MaxBodySizeMb = 0 }.Validate())
            .ShouldContain("error.subscriptions.body_size_range");
        Keys(new SubscriptionSettings { MaxHeaderValueBytes = 100 }.Validate())
            .ShouldContain("error.subscriptions.header_size_range");
        Keys(new SubscriptionSettings { UserAgent = "   " }.Validate())
            .ShouldContain("error.subscriptions.user_agent_required");
        new SubscriptionSettings().Validate().ShouldBeEmpty();
    }

    // ----------------------------------------------------------------- normalize

    [Fact]
    public void Normalize_clamps_numeric_ranges()
    {
        var normalized = new AppSettings
        {
            UiScale = 5.0,
            ReconnectDelaySeconds = 10_000,
            MaxRestartAttempts = -5,
            SchemaVersion = 99,
        }.Normalize();

        normalized.UiScale.ShouldBe(2.0);
        normalized.ReconnectDelaySeconds.ShouldBe(300);
        normalized.MaxRestartAttempts.ShouldBe(0);
        normalized.SchemaVersion.ShouldBe(AppSettings.CurrentSchemaVersion);

        var low = new AppSettings { UiScale = 0.1 }.Normalize();
        low.UiScale.ShouldBe(0.75);
    }

    [Fact]
    public void Normalize_clears_a_bad_accent_colour_and_keeps_a_good_one()
    {
        new AppSettings { AccentColor = "red" }.Normalize().AccentColor.ShouldBeNull();
        new AppSettings { AccentColor = "#AABBCC" }.Normalize().AccentColor.ShouldBe("#AABBCC");
        new AppSettings { AccentColor = null }.Normalize().AccentColor.ShouldBeNull();
    }

    [Fact]
    public void Normalize_fixes_nested_sections()
    {
        var normalized = new AppSettings
        {
            Tun = new TunSettings { Mtu = 100 },
            Mux = new MuxSettings { Concurrency = 0, XudpConcurrency = 0 },
            Logging = new LoggingSettings { MaxFileSizeMb = 0, MaxFiles = 1000, RetentionDays = 0 },
            Subscriptions = new SubscriptionSettings
            {
                UpdateIntervalHours = 100_000,
                TimeoutSeconds = 1,
                MaxBodySizeMb = 0,
                MaxHeaderValueBytes = 1,
                UserAgent = "",
            },
        }.Normalize();

        normalized.Tun.Mtu.ShouldBe(0);
        normalized.Mux.Concurrency.ShouldBe(1);
        normalized.Mux.XudpConcurrency.ShouldBe(8);
        normalized.Logging.MaxFileSizeMb.ShouldBe(1);
        normalized.Logging.MaxFiles.ShouldBe(100);
        normalized.Logging.RetentionDays.ShouldBe(1);
        normalized.Subscriptions.UpdateIntervalHours.ShouldBe(24 * 30);
        normalized.Subscriptions.TimeoutSeconds.ShouldBe(5);
        normalized.Subscriptions.MaxBodySizeMb.ShouldBe(1);
        normalized.Subscriptions.MaxHeaderValueBytes.ShouldBe(256);
        normalized.Subscriptions.UserAgent.ShouldBe("MyVpn/0.1");
    }

    [Fact]
    public void Normalize_preserves_a_legal_mtu()
    {
        new AppSettings { Tun = new TunSettings { Mtu = 1500 } }.Normalize().Tun.Mtu.ShouldBe(1500);
    }

    [Fact]
    public void Normalize_leaves_valid_settings_valid()
    {
        var normalized = new AppSettings { UiScale = 5.0, AccentColor = "red" }.Normalize();

        normalized.Validate().IsSuccess.ShouldBeTrue(normalized.Validate().Error?.ToString());
    }
}
