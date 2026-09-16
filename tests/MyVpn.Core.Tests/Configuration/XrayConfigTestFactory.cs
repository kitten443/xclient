using System.Text.Json.Nodes;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Settings;
using MyVpn.Core.Xray;
using Shouldly;

namespace MyVpn.Core.Tests;

/// <summary>
/// Request and assertion helpers shared by the <see cref="XrayConfigBuilder"/> tests.
/// </summary>
/// <remarks>
/// The builder is pure, so every test is a matter of constructing one immutable
/// <see cref="XrayConfigRequest"/> and reading the serialized document. Keeping the
/// request builders here means the tests assert on behaviour rather than on fixture setup.
/// </remarks>
internal static class XrayConfigTestFactory
{
    public const string Uuid = "11111111-1111-1111-1111-111111111111";
    public const string HostName = "server.example.com";
    public const int DefaultPort = 443;
    public const string DefaultSni = "sni.example.com";

    /// <summary>A valid profile; individual tests change only what they exercise.</summary>
    public static ServerProfile Profile(
        ProxyProtocol protocol = ProxyProtocol.Vless,
        SecurityKind security = SecurityKind.Tls,
        TransportKind transport = TransportKind.Tcp,
        string? userId = Uuid,
        string? password = "secret",
        string address = HostName,
        int port = DefaultPort) => new()
    {
        Address = address,
        Port = port,
        Protocol = protocol,
        UserId = userId,
        Password = password,
        Security = security,
        ServerName = DefaultSni,
    };

    public static XrayConfigRequest Request(
        ServerProfile? profile = null,
        AppSettings? settings = null,
        GeoRuleAvailability? geo = null,
        PlatformTarget platform = PlatformTarget.Linux,
        string? assetDirectory = null,
        XrayVersion? coreVersion = null) => new()
    {
        Profile = profile ?? Profile(),
        Settings = settings ?? new AppSettings(),
        GeoAvailability = geo ?? GeoRuleAvailability.None,
        Platform = platform,
        AssetDirectory = assetDirectory,
        CoreVersion = coreVersion ?? XrayVersionPolicy.Recommended,
    };

    /// <summary>Asserts the build succeeded and returns the result.</summary>
    public static XrayConfigBuildResult BuildOk(XrayConfigRequest request)
    {
        var result = XrayConfigBuilder.Build(request);

        result.IsSuccess.ShouldBeTrue(result.Error?.ToString());
        return result.Value;
    }

    public static string Serialize(XrayConfigBuildResult result) =>
        XrayConfigBuilder.Serialize(result.Config);

    /// <summary>Parses the serialized document so tests can assert on structure, not substrings.</summary>
    public static JsonObject Root(XrayConfigBuildResult result) =>
        JsonNode.Parse(Serialize(result))!.AsObject();

    public static JsonArray Inbounds(JsonObject root) => root["inbounds"]!.AsArray();

    public static JsonArray Outbounds(JsonObject root) => root["outbounds"]!.AsArray();

    public static JsonObject Inbound(JsonObject root, string protocol) =>
        Inbounds(root)
            .Select(node => node!.AsObject())
            .Single(inbound => inbound["protocol"]!.GetValue<string>() == protocol);

    public static JsonObject Outbound(JsonObject root, string tag) =>
        Outbounds(root)
            .Select(node => node!.AsObject())
            .Single(outbound => outbound["tag"]!.GetValue<string>() == tag);

    public static JsonObject RoutingRule(JsonObject root, string ruleTag) =>
        root["routing"]!["rules"]!.AsArray()
            .Select(node => node!.AsObject())
            .Single(rule => rule["ruleTag"]?.GetValue<string>() == ruleTag);

    public static IReadOnlyList<JsonObject> RoutingRules(JsonObject root) =>
        root["routing"]!["rules"]!.AsArray()
            .Select(node => node!.AsObject())
            .ToArray();

    public static JsonObject StreamSettings(JsonObject outbound) =>
        outbound["streamSettings"]!.AsObject();

    public static JsonObject Sockopt(JsonObject outbound) =>
        StreamSettings(outbound)["sockopt"]!.AsObject();
}
