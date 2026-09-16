using MyVpn.Core.Parsing;
using MyVpn.Core.Subscriptions;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class SubscriptionHeaderRegistryTests
{
    private static readonly SubscriptionHeaderRegistry Registry = SubscriptionHeaderRegistry.CreateDefault();

    private static HeaderParseContext Context(params (string Name, string Value)[] headers) =>
        ContextFor(Registry, "sub-1", headers);

    private static HeaderParseContext ContextFor(
        SubscriptionHeaderRegistry registry,
        string subscriptionId,
        params (string Name, string Value)[] headers)
    {
        var bag = registry.CreateBag(
            headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value)));

        return new HeaderParseContext
        {
            Headers = bag,
            SubscriptionId = subscriptionId,
        };
    }

    private static ParseResult Run(params (string Name, string Value)[] headers) => Registry.Parse(Context(headers));

    private static PendingChange SingleChange(params (string Name, string Value)[] headers)
    {
        var result = Run(headers);

        result.PendingChanges.Count.ShouldBe(
            1,
            string.Join(" | ", result.Errors.Select(e => e.MessageKey)));

        return result.PendingChanges[0];
    }

    // --------------------------------------------------------------------- schema

    [Fact]
    public void CreateDefault_builds_a_registry_with_the_documented_catalog()
    {
        var registry = SubscriptionHeaderRegistry.CreateDefault();

        registry.Parsers.Count.ShouldBe(7);
        registry.Catalog.ShouldNotBeEmpty();
        registry.KnownHeaderNames.ShouldContain("profile-title");
        registry.KnownHeaderNames.ShouldContain("subscription-userinfo");
        registry.KnownHeaderNames.ShouldContain("custom-tunnel-config");

        var bag = registry.CreateBag(new[] { new KeyValuePair<string, string>("profile-title", "x") });
        bag.All.Count.ShouldBe(1);
    }

    [Fact]
    public void Parsers_are_ordered_by_priority()
    {
        var priorities = Registry.Parsers.Select(p => p.Priority).ToArray();

        priorities.ShouldBe(priorities.OrderBy(p => p).ToArray());
    }

    [Fact]
    public void Every_catalog_descriptor_is_well_formed()
    {
        foreach (var descriptor in HeaderCatalog.All.Values)
        {
            descriptor.Name.ShouldNotBeNullOrWhiteSpace();
            descriptor.LabelKey.ShouldNotBeNullOrWhiteSpace();
            descriptor.MaxLength.ShouldBeGreaterThan(0);
            descriptor.Name.ShouldBe(descriptor.Name.ToLowerInvariant());
        }
    }

    [Fact]
    public void Catalog_lookup_is_case_insensitive()
    {
        HeaderCatalog.Find("PROFILE-TITLE").ShouldNotBeNull();
        HeaderCatalog.Find("Profile-Title").ShouldNotBeNull();
        HeaderCatalog.Find("nope-not-a-header").ShouldBeNull();
        HeaderCatalog.Find(null!).ShouldBeNull();
    }

    [Fact]
    public void An_empty_bag_produces_an_empty_result()
    {
        var result = Run();

        result.Metadata.IsEmpty.ShouldBeTrue();
        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldBeEmpty();
        result.RefusedHeaders.ShouldBeEmpty();
    }

    [Fact]
    public void Parse_rejects_a_null_context()
    {
        Should.Throw<ArgumentNullException>(() => Registry.Parse(null!));
    }

    [Fact]
    public void The_registry_rejects_null_parsers()
    {
        Should.Throw<ArgumentNullException>(() => new SubscriptionHeaderRegistry(null!));
    }

    [Fact]
    public void Parser_metadata_is_consistent()
    {
        foreach (var parser in Registry.Parsers)
        {
            parser.Id.ShouldNotBeNullOrWhiteSpace();
            parser.Version.ShouldBeGreaterThan(0);
            parser.HeaderNames.ShouldNotBeEmpty();
            parser.MaxValueLength.ShouldBeGreaterThan(0);
            parser.CanParse(parser.HeaderNames.First().ToUpperInvariant()).ShouldBeTrue();
        }
    }

    // ---------------------------------------------------------------- title/files

    [Fact]
    public void A_plain_profile_title_is_used_as_is()
    {
        Run(("profile-title", "My Provider")).Metadata.Title.ShouldBe("My Provider");
    }

    [Fact]
    public void A_base64_profile_title_is_decoded()
    {
        var encoded = "base64:" + Base64Tolerant.EncodeString("Decoded Title");

        Run(("profile-title", encoded)).Metadata.Title.ShouldBe("Decoded Title");
    }

    [Fact]
    public void A_profile_title_longer_than_the_schema_limit_is_truncated()
    {
        var title = new string('A', 40);

        var result = Run(("profile-title", title));

        result.Metadata.Title.ShouldNotBeNull();
        result.Metadata.Title!.Length.ShouldBe(25);
        result.Metadata.Title.ShouldBe(new string('A', 25));
    }

    [Fact]
    public void A_base64_profile_title_longer_than_the_limit_is_truncated()
    {
        var encoded = "base64:" + Base64Tolerant.EncodeString(new string('B', 60));

        var result = Run(("profile-title", encoded));

        result.Metadata.Title.ShouldNotBeNull();
        result.Metadata.Title!.Length.ShouldBe(25);
    }

    [Fact]
    public void An_invalid_base64_profile_title_warns_and_is_dropped()
    {
        var result = Run(("profile-title", "base64:!!!!"));

        result.Metadata.Title.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.base64_invalid");
    }

    [Fact]
    public void Content_disposition_extracts_a_file_name()
    {
        var result = Run(("content-disposition", "attachment; filename=\"my-servers.txt\""));

        result.Metadata.SuggestedFileName.ShouldBe("my-servers.txt");
    }

    [Fact]
    public void Content_disposition_reduces_a_traversal_path_to_a_leaf()
    {
        var result = Run(("content-disposition", "attachment; filename=\"../../etc/passwd\""));

        var name = result.Metadata.SuggestedFileName ?? string.Empty;

        name.ShouldBe("passwd");
        name.ShouldNotContain("/");
        name.ShouldNotContain("\\");
        name.ShouldNotContain("..");
    }

    [Fact]
    public void Content_disposition_handles_a_windows_style_path()
    {
        var result = Run(("content-disposition", "attachment; filename=\"..\\..\\windows\\system32\\evil.txt\""));

        result.Metadata.SuggestedFileName.ShouldBe("evil.txt");
    }

    [Fact]
    public void Content_disposition_handles_the_rfc5987_form()
    {
        var result = Run(("content-disposition", "attachment; filename*=UTF-8''%E2%82%AC-sub.txt"));

        result.Metadata.SuggestedFileName.ShouldBe("€-sub.txt");
    }

    [Fact]
    public void Content_disposition_without_a_file_name_yields_null()
    {
        Run(("content-disposition", "attachment")).Metadata.SuggestedFileName.ShouldBeNull();
    }

    // ------------------------------------------------------------------ user info

    [Fact]
    public void Subscription_userinfo_is_parsed_into_metadata()
    {
        var result = Run(("subscription-userinfo", "upload=10; download=20; total=1000; expire=0"));

        result.Metadata.UserInfo.ShouldNotBeNull();
        result.Metadata.UserInfo!.Used.ShouldBe(30);
        result.Metadata.UserInfo.Total.ShouldBe(1000);
        result.Metadata.UserInfo.IsUnlimited.ShouldBeFalse();
    }

    [Fact]
    public void A_malformed_subscription_userinfo_warns()
    {
        var result = Run(("subscription-userinfo", "not a userinfo header"));

        result.Metadata.UserInfo.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.userinfo_malformed");
    }

    // ---------------------------------------------------------------------- links

    [Fact]
    public void A_safe_support_url_is_kept()
    {
        Run(("support-url", "https://support.example/help")).Metadata.SupportUrl
            .ShouldBe("https://support.example/help");
    }

    [Fact]
    public void A_safe_web_page_url_is_kept()
    {
        Run(("profile-web-page-url", "https://provider.example/")).Metadata.WebPageUrl
            .ShouldBe("https://provider.example/");
    }

    [Fact]
    public void A_loopback_support_url_is_rejected_with_a_warning()
    {
        var result = Run(("support-url", "http://127.0.0.1/"));

        result.Metadata.SupportUrl.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.url_rejected");
    }

    [Fact]
    public void A_loopback_support_url_is_rejected_even_when_insecure_http_is_allowed()
    {
        var context = Context(("support-url", "http://127.0.0.1/")) with { AllowInsecureHttp = true };

        var result = Registry.Parse(context);

        result.Metadata.SupportUrl.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.url_rejected");
    }

    [Fact]
    public void A_private_support_url_is_rejected()
    {
        var result = Run(("support-url", "https://169.254.169.254/latest/meta-data/"));

        result.Metadata.SupportUrl.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.url_rejected");
    }

    // ------------------------------------------------------------------ toggles

    [Fact]
    public void Toggle_true_produces_a_pending_true()
    {
        SingleChange(("xray-tun-enable", "true")).Value.ShouldBe("true");
    }

    [Fact]
    public void Toggle_one_produces_a_pending_true()
    {
        SingleChange(("xray-tun-enable", "1")).Value.ShouldBe("true");
    }

    [Fact]
    public void Toggle_true_is_case_insensitive()
    {
        SingleChange(("xray-tun-enable", "TRUE")).Value.ShouldBe("true");
    }

    [Fact]
    public void Toggle_any_other_value_produces_a_pending_false()
    {
        SingleChange(("xray-tun-enable", "maybe")).Value.ShouldBe("false");
        SingleChange(("xray-tun-enable", "0")).Value.ShouldBe("false");
        SingleChange(("xray-tun-enable", "off")).Value.ShouldBe("false");
    }

    [Fact]
    public void Toggle_with_an_empty_value_produces_no_change_at_all()
    {
        var result = Run(("xray-tun-enable", ""));

        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldBeEmpty();
    }

    [Fact]
    public void A_toggle_is_never_applied_automatically()
    {
        var result = Run(("xray-tun-enable", "true"));

        result.Metadata.IsEmpty.ShouldBeTrue();
        result.PendingChanges.Count.ShouldBe(1);
    }

    [Fact]
    public void A_valid_integer_header_produces_a_canonical_pending_value()
    {
        SingleChange(("xray-tun-mtu", "1300")).Value.ShouldBe("1300");
        SingleChange(("xray-tun-mtu", " 1500 ")).Value.ShouldBe("1500");
    }

    [Fact]
    public void An_out_of_range_mtu_produces_an_error_and_no_change()
    {
        foreach (var value in new[] { "100", "575", "9001", "10000", "0", "-1" })
        {
            var result = Run(("xray-tun-mtu", value));

            result.PendingChanges.ShouldBeEmpty($"mtu {value}");
            result.Errors.ShouldContain(
                e => e.MessageKey == "error.header.value_out_of_range",
                $"mtu {value}");
        }
    }

    [Fact]
    public void An_enum_header_rejects_a_value_outside_the_allowed_set()
    {
        var bad = Run(("mux-quic", "sometimes"));

        bad.PendingChanges.ShouldBeEmpty();
        bad.Errors.ShouldContain(e => e.MessageKey == "error.header.value_not_allowed");

        SingleChange(("mux-quic", "allow")).Value.ShouldBe("allow");
    }

    [Fact]
    public void A_cidr_list_header_rejects_a_bad_entry()
    {
        var bad = Run(("exclude-routes", "10.0.0.0/8,not-a-cidr"));

        bad.PendingChanges.ShouldBeEmpty();
        bad.Errors.ShouldContain(e => e.MessageKey == "error.header.cidr_invalid");

        SingleChange(("exclude-routes", "10.0.0.0/8,192.168.0.0/16")).Value
            .ShouldBe("10.0.0.0/8,192.168.0.0/16");
    }

    [Fact]
    public void A_url_header_requires_https()
    {
        var bad = Run(("check-url-via-proxy", "http://example.com/ping"));

        bad.PendingChanges.ShouldBeEmpty();
        bad.Errors.ShouldContain(e => e.MessageKey == "error.header.url_rejected");

        SingleChange(("check-url-via-proxy", "https://example.com/ping")).Value
            .ShouldBe("https://example.com/ping");
    }

    // ---------------------------------------------------------------- consent token

    [Fact]
    public void A_pending_change_carries_a_lowercase_sha256_consent_token()
    {
        var change = SingleChange(("xray-tun-enable", "true"));

        change.ConsentToken.Length.ShouldBe(64);
        change.ConsentToken.ShouldBe(change.ConsentToken.ToLowerInvariant());
        change.ConsentToken.All(Uri.IsHexDigit).ShouldBeTrue();
    }

    [Fact]
    public void The_consent_token_changes_when_the_value_changes()
    {
        var on = SingleChange(("xray-tun-enable", "true")).ConsentToken;
        var off = SingleChange(("xray-tun-enable", "false")).ConsentToken;

        off.ShouldNotBe(on);
    }

    [Fact]
    public void The_consent_token_is_stable_for_the_same_value()
    {
        var first = SingleChange(("xray-tun-enable", "true")).ConsentToken;
        var second = SingleChange(("xray-tun-enable", "true")).ConsentToken;

        second.ShouldBe(first);
    }

    [Fact]
    public void The_consent_token_is_bound_to_the_subscription()
    {
        var one = Registry.Parse(ContextFor(Registry, "sub-1", ("xray-tun-enable", "true")))
            .PendingChanges[0].ConsentToken;
        var two = Registry.Parse(ContextFor(Registry, "sub-2", ("xray-tun-enable", "true")))
            .PendingChanges[0].ConsentToken;

        two.ShouldNotBe(one);
    }

    [Fact]
    public void The_consent_token_is_bound_to_the_raw_header_value()
    {
        var canonical = SingleChange(("xray-tun-enable", "true")).ConsentToken;
        var alias = SingleChange(("xray-tun-enable", "1")).ConsentToken;

        // Both normalize to "true", but the raw values differ, so consent must differ.
        alias.ShouldNotBe(canonical);
    }

    [Fact]
    public void The_pending_change_carries_the_descriptor_metadata()
    {
        var change = SingleChange(("xray-tun-enable", "true"));

        change.HeaderName.ShouldBe("xray-tun-enable");
        change.Id.ShouldBe("xray-tun-enable");
        change.LabelKey.ShouldBe("header.xray_tun_enable");
        change.Risk.ShouldBe(ChangeRisk.High);
        change.MobileOnly.ShouldBeFalse();
        change.ValueFingerprint.Length.ShouldBe(64);
    }

    // ------------------------------------------------------------------- refusal

    [Fact]
    public void Refused_headers_are_reported_without_any_pending_change()
    {
        var result = Run(
            ("custom-tunnel-config", "{\"inbounds\":[]}"),
            ("routing", "{\"rules\":[]}"),
            ("providerid", "abc-123"));

        result.PendingChanges.ShouldBeEmpty();
        result.RefusedHeaders.ShouldContain("custom-tunnel-config");
        result.RefusedHeaders.ShouldContain("routing");
        result.RefusedHeaders.ShouldContain("providerid");
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.refused_for_security");
    }

    [Fact]
    public void Hardware_identifier_headers_are_refused()
    {
        var result = Run(
            ("subscription-always-hwid-enable", "true"),
            ("subscription-alternative-hwid-enabled", "true"));

        result.PendingChanges.ShouldBeEmpty();
        result.RefusedHeaders.Count.ShouldBe(2);
    }

    [Fact]
    public void Refused_headers_are_distinct_in_the_result()
    {
        var result = Run(("routing", "a"), ("routing", "b"));

        result.RefusedHeaders.Count.ShouldBe(1);
    }

    // ------------------------------------------------------------------ duplicates

    [Fact]
    public void Duplicate_conflicting_values_under_unanimous_are_dropped_with_a_warning()
    {
        var result = Run(("xray-tun-enable", "true"), ("xray-tun-enable", "false"));

        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.duplicate_conflict");
    }

    [Fact]
    public void Duplicate_conflicting_values_under_reject_on_conflict_are_dropped()
    {
        var result = Run(
            ("subscription-userinfo", "upload=1; total=2"),
            ("subscription-userinfo", "upload=9; total=9"));

        result.Metadata.UserInfo.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.duplicate_conflict");
    }

    [Fact]
    public void Duplicate_identical_values_under_unanimous_are_accepted()
    {
        var result = Run(("xray-tun-enable", "true"), ("xray-tun-enable", "true"));

        result.PendingChanges.Count.ShouldBe(1);
        result.PendingChanges[0].Value.ShouldBe("true");
    }

    [Fact]
    public void The_case_insensitive_duplicate_check_covers_header_name_spelling()
    {
        var result = Run(("XRAY-TUN-ENABLE", "true"), ("xray-tun-enable", "false"));

        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.duplicate_conflict");
    }

    // --------------------------------------------------------------------- gates

    [Fact]
    public void A_parser_emitting_a_change_for_an_auto_header_is_overruled()
    {
        var registry = new SubscriptionHeaderRegistry(new ISubscriptionHeaderParser[]
        {
            new ProfileIdentityParser(),
            new GateViolatingHeaderParser(),
        });

        var result = registry.Parse(ContextFor(registry, "sub-1", ("x-fake-gate", "1")));

        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.gate_violation");
    }

    [Fact]
    public void A_parser_emitting_a_change_for_an_unknown_header_is_overruled()
    {
        var registry = new SubscriptionHeaderRegistry(new ISubscriptionHeaderParser[]
        {
            new UnknownHeaderChangeParser(),
        });

        var result = registry.Parse(ContextFor(registry, "sub-1", ("x-fake-unknown", "1")));

        result.PendingChanges.ShouldBeEmpty();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.change_for_unknown_header");
    }

    [Fact]
    public void A_throwing_parser_does_not_break_the_others()
    {
        var registry = new SubscriptionHeaderRegistry(new ISubscriptionHeaderParser[]
        {
            new ProfileIdentityParser(),
            new ThrowingHeaderParser(),
        });

        var result = registry.Parse(ContextFor(
            registry,
            "sub-1",
            ("profile-title", "Still Works"),
            ("x-fake-throw", "1")));

        result.Metadata.Title.ShouldBe("Still Works");
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.parser_failed");
    }

    [Fact]
    public void A_throwing_parser_does_not_prevent_a_change_from_another_parser()
    {
        var registry = new SubscriptionHeaderRegistry(new ISubscriptionHeaderParser[]
        {
            new ConfirmationGatedParser(),
            new ThrowingHeaderParser(),
        });

        var result = registry.Parse(ContextFor(
            registry,
            "sub-1",
            ("xray-tun-enable", "true"),
            ("x-fake-throw", "1")));

        result.PendingChanges.Count.ShouldBe(1);
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.parser_failed");
    }

    // ------------------------------------------------------------ unknown, merging

    [Fact]
    public void Unknown_headers_are_preserved_but_produce_nothing()
    {
        var context = Context(("x-totally-unknown", "value"), ("profile-title", "Known"));
        var result = Registry.Parse(context);

        context.Headers.Unknown.Select(h => h.Name).ShouldBe(new[] { "x-totally-unknown" });
        result.PendingChanges.ShouldBeEmpty();
        result.Metadata.Title.ShouldBe("Known");
    }

    [Fact]
    public void Results_from_multiple_parsers_are_merged()
    {
        var result = Run(
            ("profile-title", "Provider"),
            ("subscription-userinfo", "upload=1; download=2; total=100; expire=0"),
            ("support-url", "https://support.example/"),
            ("announce", "Scheduled maintenance"),
            ("sub-info-color", "#FF8800"),
            ("profile-update-interval", "12"),
            ("xray-tun-enable", "true"));

        result.Metadata.Title.ShouldBe("Provider");
        result.Metadata.UserInfo.ShouldNotBeNull();
        result.Metadata.SupportUrl.ShouldBe("https://support.example/");
        result.Metadata.Announce.ShouldBe("Scheduled maintenance");
        result.Metadata.AnnounceColor.ShouldBe("#FF8800");
        result.Metadata.UpdateInterval.ShouldBe(TimeSpan.FromHours(12));
        result.PendingChanges.Count.ShouldBe(1);
        result.Errors.ShouldBeEmpty();
    }

    // ------------------------------------------------------------- announcements

    [Fact]
    public void Announce_accepts_a_base64_payload()
    {
        var encoded = "base64:" + Base64Tolerant.EncodeString("Maintenance at 22:00");

        Run(("announce", encoded)).Metadata.Announce.ShouldBe("Maintenance at 22:00");
    }

    [Fact]
    public void An_invalid_announce_colour_is_dropped_silently()
    {
        var result = Run(("sub-info-color", "red"), ("announce", "Hello"));

        result.Metadata.AnnounceColor.ShouldBeNull();
        result.Metadata.Announce.ShouldBe("Hello");
    }

    [Fact]
    public void The_zero_sentinel_clears_the_announcement()
    {
        Run(("announce", "0")).Metadata.Announce.ShouldBeNull();
        Run(("sub-info-text", "0")).Metadata.Announce.ShouldBeNull();
    }

    [Fact]
    public void An_unsafe_announcement_button_link_is_not_kept()
    {
        var result = Run(("sub-info-button-link", "http://127.0.0.1/admin"));

        result.Metadata.Extra.ContainsKey("sub-info-button-link").ShouldBeFalse();
    }

    [Fact]
    public void A_safe_announcement_button_link_is_kept_as_extra()
    {
        var result = Run(("sub-info-button-link", "https://provider.example/news"));

        result.Metadata.Extra["sub-info-button-link"].ShouldBe("https://provider.example/news");
    }

    // ------------------------------------------------------------------- schedule

    [Fact]
    public void A_valid_update_interval_becomes_a_timespan()
    {
        Run(("profile-update-interval", "24")).Metadata.UpdateInterval.ShouldBe(TimeSpan.FromHours(24));
    }

    [Fact]
    public void An_out_of_range_update_interval_warns()
    {
        var result = Run(("profile-update-interval", "0"));

        result.Metadata.UpdateInterval.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.update_interval_range");
    }

    [Fact]
    public void A_valid_request_timeout_is_parsed()
    {
        Run(("subscription-request-timeout", "10")).Metadata.RequestTimeoutSeconds.ShouldBe(10);
    }

    [Fact]
    public void An_out_of_range_request_timeout_warns()
    {
        var result = Run(("subscription-request-timeout", "60"));

        result.Metadata.RequestTimeoutSeconds.ShouldBeNull();
        result.Errors.ShouldContain(e => e.MessageKey == "error.header.request_timeout_range");
    }
}
