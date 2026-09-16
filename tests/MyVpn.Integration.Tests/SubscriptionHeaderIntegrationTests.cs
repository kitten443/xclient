using MyVpn.Core.Parsing;
using MyVpn.Core.Subscriptions;
using Shouldly;
using Xunit;

namespace MyVpn.Integration.Tests;

/// <summary>
/// Runs a realistic bundled subscription-header set all the way through the registry and
/// checks the three different gate outcomes at once.
/// </summary>
/// <remarks>
/// The registry is the security boundary for provider-controlled headers: a response may set a
/// display title automatically, ask for a confirmation-gated change, or ask for something that
/// is recognised and always refused. This test crosses <see cref="RawHeaderBag"/> bounds
/// checking, the catalog, the parsers and gate enforcement in a single run.
/// </remarks>
public sealed class SubscriptionHeaderIntegrationTests
{
    [Fact]
    public void Metadata_changes_and_refusals_are_separated_correctly()
    {
        var registry = SubscriptionHeaderRegistry.CreateDefault();

        var headers = new[]
        {
            new KeyValuePair<string, string>(
                "subscription-userinfo",
                "upload=100; download=200; total=1000; expire=0"),
            new KeyValuePair<string, string>(
                "profile-title",
                "base64:" + Base64Tolerant.EncodeString("Integration Provider")),
            new KeyValuePair<string, string>("tun-enable", "true"),
            new KeyValuePair<string, string>("custom-tunnel-config", "{\"inbounds\":[]}"),
            new KeyValuePair<string, string>("support-url", "https://provider.example/help"),
        };

        var bag = registry.CreateBag(headers);

        var context = new HeaderParseContext
        {
            Headers = bag,
            SubscriptionId = "sub-integration-1",
        };

        var result = registry.Parse(context);

        // Gate A: display metadata is applied automatically.
        result.Metadata.Title.ShouldBe("Integration Provider");
        result.Metadata.SupportUrl.ShouldBe("https://provider.example/help");
        result.Metadata.UserInfo.ShouldNotBeNull();
        result.Metadata.UserInfo!.Used.ShouldBe(300);
        result.Metadata.UserInfo.Total.ShouldBe(1000);

        // Gate B: exactly one pending change, for the tun-enable header, and never auto-applied.
        var change = result.PendingChanges.ShouldHaveSingleItem();
        change.HeaderName.ShouldBe("tun-enable");
        change.Value.ShouldBe("true");
        change.Risk.ShouldBe(ChangeRisk.High);
        HeaderCatalog.Find("tun-enable")!.Gate.ShouldBe(HeaderApplyGate.RequiresConfirmation);

        // Gate C: recognised but refused, reported, and never offered as a change.
        result.RefusedHeaders.ShouldContain("custom-tunnel-config");
        HeaderCatalog.Find("custom-tunnel-config")!.Gate.ShouldBe(HeaderApplyGate.Refused);
        result.PendingChanges.ShouldNotContain(
            pending => pending.HeaderName == "custom-tunnel-config");

        // Every consent token binds the request to the exact subscription, header and value.
        result.PendingChanges.ShouldNotBeEmpty();

        foreach (var pending in result.PendingChanges)
        {
            pending.ConsentToken.Length.ShouldBe(64);
            pending.ConsentToken.ShouldBe(pending.ConsentToken.ToLowerInvariant());
            pending.ConsentToken.All(Uri.IsHexDigit).ShouldBeTrue();
        }
    }

    [Fact]
    public void The_bag_marks_the_recognised_headers_and_preserves_unknown_ones_inertly()
    {
        var registry = SubscriptionHeaderRegistry.CreateDefault();

        var bag = registry.CreateBag(new[]
        {
            new KeyValuePair<string, string>("profile-title", "Provider"),
            new KeyValuePair<string, string>("x-provider-private", "opaque"),
        });

        bag.GetEntries("profile-title").ShouldHaveSingleItem().IsKnown.ShouldBeTrue();
        bag.Unknown.Select(header => header.Name).ShouldBe(new[] { "x-provider-private" });
    }
}
