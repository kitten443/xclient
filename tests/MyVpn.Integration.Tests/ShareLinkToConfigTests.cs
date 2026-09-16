using System.Text.Json.Nodes;
using MyVpn.Core.Configuration;
using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Parsing;
using MyVpn.Core.Settings;
using Shouldly;
using Xunit;

namespace MyVpn.Integration.Tests;

/// <summary>
/// Proves that a real subscription body, the share-link parser, the domain model and the
/// config builder all agree on the same server.
/// </summary>
/// <remarks>
/// Each of these components has its own unit tests. What is only observable here is that the
/// address and port a share link declares survive the trip: parse → <see cref="ServerProfile"/>
/// → <see cref="XrayConfigBuilder"/> → outbound JSON.
/// </remarks>
public sealed class ShareLinkToConfigTests
{
    private const string VlessId = "22222222-2222-2222-2222-222222222222";

    private const string Payload =
        "vless://" + VlessId + "@vless.example.com:8443" +
        "?security=tls&type=ws&sni=vless-sni.example.com&path=%2Fws&host=vless-host.example.com#Vless%20Node\n" +
        "trojan://trojan-secret@trojan.example.com:9443?security=tls&type=tcp&sni=trojan-sni.example.com#Trojan%20Node\n";

    [Fact]
    public void A_subscription_payload_parses_into_profiles_the_builder_agrees_with()
    {
        var batch = ShareLinkParser.ParseMany(Payload);

        batch.Failures.ShouldBeEmpty();
        batch.Profiles.Count.ShouldBe(2);

        var vless = batch.Profiles[0];
        vless.Protocol.ShouldBe(ProxyProtocol.Vless);
        vless.Address.ShouldBe("vless.example.com");
        vless.Port.ShouldBe(8443);
        vless.UserId.ShouldBe(VlessId);
        vless.Transport.ShouldBe(TransportKind.WebSocket);

        var trojan = batch.Profiles[1];
        trojan.Protocol.ShouldBe(ProxyProtocol.Trojan);
        trojan.Address.ShouldBe("trojan.example.com");
        trojan.Port.ShouldBe(9443);
        trojan.Password.ShouldBe("trojan-secret");

        // The first parsed profile builds the VLESS vnext outbound, address and port intact.
        var outbound = BuildProxyOutbound(vless);
        outbound["protocol"]!.GetValue<string>().ShouldBe("vless");

        var server = outbound["settings"]!["vnext"]!.AsArray()[0]!.AsObject();
        server["address"]!.GetValue<string>().ShouldBe("vless.example.com");
        server["port"]!.GetValue<int>().ShouldBe(8443);
        server["users"]!.AsArray()[0]!["id"]!.GetValue<string>().ShouldBe(VlessId);

        // The declared WebSocket transport is carried through as well.
        XrayConfigTestStream(outbound)["network"]!.GetValue<string>().ShouldBe("ws");
        XrayConfigTestStream(outbound)["wsSettings"]!["path"]!.GetValue<string>().ShouldBe("/ws");

        // The Trojan profile maps to the `servers` form with the same agreement.
        var trojanOutbound = BuildProxyOutbound(trojan);
        trojanOutbound["protocol"]!.GetValue<string>().ShouldBe("trojan");

        var trojanServer = trojanOutbound["settings"]!["servers"]!.AsArray()[0]!.AsObject();
        trojanServer["address"]!.GetValue<string>().ShouldBe("trojan.example.com");
        trojanServer["port"]!.GetValue<int>().ShouldBe(9443);
        trojanServer["password"]!.GetValue<string>().ShouldBe("trojan-secret");
    }

    private static JsonObject BuildProxyOutbound(ServerProfile profile)
    {
        var result = XrayConfigBuilder.Build(new XrayConfigRequest
        {
            Profile = profile,
            Settings = new AppSettings(),
            GeoAvailability = GeoRuleAvailability.None,
        });

        result.IsSuccess.ShouldBeTrue(result.Error?.ToString());

        var root = JsonNode.Parse(XrayConfigBuilder.Serialize(result.Value.Config))!.AsObject();

        return root["outbounds"]!.AsArray()
            .Select(node => node!.AsObject())
            .Single(outbound => outbound["tag"]!.GetValue<string>() == XrayConfigBuilder.ProxyTag);
    }

    private static JsonObject XrayConfigTestStream(JsonObject outbound) =>
        outbound["streamSettings"]!.AsObject();
}
