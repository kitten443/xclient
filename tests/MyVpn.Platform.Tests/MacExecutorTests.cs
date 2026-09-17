using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.MacOS.Dns;
using MyVpn.Platform.MacOS.KillSwitch;
using MyVpn.Platform.MacOS.Network;
using MyVpn.Platform.MacOS.Proxy;
using MyVpn.Platform.MacOS.Routing;
using MyVpn.Platform.MacOS.Tun;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>
/// Shared fixtures for the macOS executor tests.
/// </summary>
/// <remarks>
/// These tests run on Linux by design. Everything that executes a macOS process is guarded by
/// <c>OperatingSystem.IsMacOS()</c> in the implementation, so what is exercised here is:
/// the pure renderers, argument builders and parsers (which is where the fire-and-routing logic
/// actually lives); the guard itself, which proves no macOS path can run on this host; and the
/// emergency-cleanup resilience with scripted collaborators. The macOS invocation paths themselves
/// are runtime-unverified — see the platform report.
/// </remarks>
internal static class MacTestData
{
    /// <summary>A command runner with every macOS tool available and nothing else scripted.</summary>
    public static FakeCommandRunner MacRunner()
    {
        var runner = new FakeCommandRunner();

        foreach (var tool in new[]
                 {
                     "pfctl", "ifconfig", "networksetup", "route", "netstat", "scutil", "pgrep",
                 })
        {
            runner.Available.Add(tool);
        }

        return runner;
    }

    /// <summary>A Kill Switch plan that is valid for every platform's validation rules.</summary>
    public static KillSwitchPlan KillSwitchPlan(
        bool blockIpv6 = true,
        bool allowLan = false,
        bool allowDhcp = true,
        string tunnelInterface = "utun3",
        string identifier = "myvpn") => new()
    {
        Identifier = identifier,
        Mode = KillSwitchMode.OnDemand,
        TunnelInterface = tunnelInterface,
        AllowedEndpoints = new[]
        {
            AllowedEndpoint.FromEndpoint(
                new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
        },
        AllowedApplications = new[] { "/Applications/MyVpn.app/Contents/Resources/xray" },
        AllowedDestinations = Array.Empty<AllowedEndpoint>(),
        BlockIpv6 = blockIpv6,
        AllowLan = allowLan,
        AllowDhcp = allowDhcp,
        AllowLoopback = true,
    };

    /// <summary>A route plan whose tunnel routes capture the default prefix, as a full tunnel does.</summary>
    public static RoutePlan RoutePlan() => new()
    {
        TunnelInterface = "utun3",
        TunnelRoutes = new[]
        {
            new RouteEntry
            {
                Destination = CidrBlock.Parse("0.0.0.0/0"),
                Interface = "utun3",
                ReasonKey = "route.reason.tunnel",
                DisplacesDefaultRoute = true,
            },
        },
        BypassRoutes = new[]
        {
            new RouteEntry
            {
                Destination = CidrBlock.Parse("203.0.113.5/32"),
                Gateway = "192.0.2.1",
                Interface = "en0",
                ReasonKey = "route.reason.bypass",
            },
        },
        PhysicalInterface = "en0",
    };

    /// <summary>A DNS plan with a resolver and one split-DNS domain.</summary>
    public static DnsPlan DnsPlan() => new()
    {
        TunnelInterface = "utun3",
        Servers = new[] { new DnsServerEntry { Address = "10.8.0.1" } },
        SplitDnsDomains = new[] { "corp.example" },
    };

    /// <summary>An enabled manual system-proxy plan.</summary>
    public static SystemProxyPlan SystemProxyPlan() => new()
    {
        SocksPort = 10808,
        HttpPort = 10809,
        EnableSocks = true,
        EnableHttp = true,
    };
}

/// <summary>Tests for the pure PF ruleset renderer.</summary>
/// <remarks>
/// The renderer is the only part of the macOS Kill Switch that can be proved correct here, so it carries
/// the weight: determinism, rule ordering, Apple's anchors, the persistent server table, and the
/// injection surface. The executor's own macOS behaviour is runtime-unverified.
/// </remarks>
public sealed class PfAnchorRendererTests
{
    private readonly ITestOutputHelper _output;

    public PfAnchorRendererTests(ITestOutputHelper output) => _output = output;

    private static string Render(KillSwitchPlan plan)
    {
        var result = PfAnchorRenderer.RenderInstall(plan);
        result.IsSuccess.ShouldBeTrue(result.Error?.TechnicalDetail);
        return result.Value;
    }

    [FactOnNonMacOS]
    public void RendersDeterministicallyWithNoPlatformSpecificLineEndings()
    {
        var first = Render(MacTestData.KillSwitchPlan());
        var second = Render(MacTestData.KillSwitchPlan());

        first.ShouldBe(second);

        // The generated file is parsed by pfctl on macOS, but a deterministic byte-for-byte artefact is
        // what makes it diffable in a bug report, and Environment.NewLine would make it differ per host.
        first.ShouldNotContain("\r");
        first.ShouldEndWith("\n");
    }

    [FactOnNonMacOS]
    public void EndsWithATerminalQuickBlock()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        var ruleLines = ruleset
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToArray();

        ruleLines[^1].ShouldBe("block drop quick all label \"myvpn\"");

        // 'quick' is load-bearing: PF passes a packet that matches no rule, so a terminal block without
        // quick can be overridden by a later pass, and there is no later pass to override it with.
        ruleLines[^1].ShouldContain("quick");

        // Exactly one terminal block: an injected or duplicated rule would show up here.
        ruleLines.Count(l => l.StartsWith("block drop quick all", StringComparison.Ordinal)).ShouldBe(1);
    }

    [FactOnNonMacOS]
    public void PreservesApplesAnchorsBecauseLoadingReplacesTheMainRuleset()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        // pfctl -f flushes the rules the system added at startup, so the anchor point Apple's services
        // insert into has to be re-established or Internet Sharing and friends break.
        ruleset.ShouldContain("scrub-anchor \"com.apple/*\"");
        ruleset.ShouldContain("nat-anchor \"com.apple/*\"");
        ruleset.ShouldContain("rdr-anchor \"com.apple/*\"");
        ruleset.ShouldContain("dummynet-anchor \"com.apple/*\"");
        ruleset.ShouldContain("anchor \"com.apple/*\"");
        ruleset.ShouldContain("load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"");
    }

    [FactOnNonMacOS]
    public void RendersThePersistTableWithItsAddressesAndNeverAnEmptyLiteral()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        // Exact text of the persist-table line. An empty initialiser is the trap: pf.conf(5) says a table
        // "initialized with the empty list ... will be cleared on load", which would black-hole the
        // tunnel's own transport on the next reload.
        ruleset.ShouldContain("table <myvpn_server> persist { 203.0.113.5 }\n");

        ruleset.ShouldNotContain("{ }");
        ruleset.ShouldNotContain("persist { }");
        ruleset.ShouldNotContain("persist\n");
    }

    [FactOnNonMacOS]
    public void SortsAndDeduplicatesTableAddressesAndCollapsesPorts()
    {
        var plan = MacTestData.KillSwitchPlan() with
        {
            AllowedEndpoints = new[]
            {
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.9", 8443), "killswitch.reason.vpn_server"),
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("198.51.100.7", 443), "killswitch.reason.vpn_server"),
            },
        };

        var ruleset = Render(plan);

        ruleset.ShouldContain(
            "table <myvpn_server> persist { 198.51.100.7, 203.0.113.5, 203.0.113.9 }\n");

        // One rule per distinct port, deterministic order.
        ruleset.ShouldContain("pass out quick proto { tcp, udp } from any to <myvpn_server> port 443\n");
        ruleset.ShouldContain("pass out quick proto { tcp, udp } from any to <myvpn_server> port 8443\n");

        IndexOf(ruleset, "port 443").ShouldBeLessThan(IndexOf(ruleset, "port 8443"));
    }

    [FactOnNonMacOS]
    public void RendersSingleProtocolEndpointsWithoutABraceList()
    {
        var plan = MacTestData.KillSwitchPlan() with
        {
            AllowedEndpoints = new[]
            {
                new AllowedEndpoint
                {
                    Destination = CidrBlock.Parse("203.0.113.5/32"),
                    Port = 443,
                    Network = "udp",
                    ReasonKey = "killswitch.reason.vpn_server",
                },
            },
        };

        var ruleset = Render(plan);

        ruleset.ShouldContain("pass out quick proto udp from any to <myvpn_server> port 443\n");
        ruleset.ShouldNotContain("proto { udp }");
    }

    [FactOnNonMacOS]
    public void BlocksComeBeforePermitsAndTheTerminalBlockComesLast()
    {
        var plan = MacTestData.KillSwitchPlan(blockIpv6: true, allowLan: true) with
        {
            BlockedDestinations = new[] { CidrBlock.Parse("198.51.100.0/24") },
        };

        var ruleset = Render(plan);

        var loopback = IndexOf(ruleset, "pass quick on lo0 all");
        var explicitBlock = IndexOf(ruleset, "block drop quick inet from any to 198.51.100.0/24");
        var ipv6Block = IndexOf(ruleset, "block drop quick inet6 all");
        var serverPass = IndexOf(ruleset, "to <myvpn_server> port 443");
        var dnsPass = IndexOf(ruleset, "from any to any port 53");
        var tunnelPass = IndexOf(ruleset, "pass quick on utun3 all");
        var terminal = IndexOf(ruleset, "block drop quick all label");

        // Loopback first (it cannot leak, and the local inbound depends on it): that is the research's
        // order, and it is the one permit that legitimately precedes the blocks.
        loopback.ShouldBeGreaterThanOrEqualTo(0);
        loopback.ShouldBeLessThan(explicitBlock);
        explicitBlock.ShouldBeLessThan(ipv6Block);

        // Every rule is 'quick', so a block written after a permit would never be reached.
        ipv6Block.ShouldBeLessThan(serverPass);
        ipv6Block.ShouldBeLessThan(dnsPass);
        ipv6Block.ShouldBeLessThan(tunnelPass);

        serverPass.ShouldBeLessThan(terminal);
        dnsPass.ShouldBeLessThan(terminal);
        tunnelPass.ShouldBeLessThan(terminal);
    }

    [FactOnNonMacOS]
    public void DropsIpv6InsideTheTunnelTooWhenIpv6IsDisabled()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan(blockIpv6: true));

        var ipv6Block = IndexOf(ruleset, "block drop quick inet6 all");
        var tunnelPass = IndexOf(ruleset, "pass quick on utun3 all");

        // "Disable IPv6 while connected" means exactly that. A block placed after the tunnel pass would
        // silently permit IPv6 over the tunnel.
        ipv6Block.ShouldBeGreaterThanOrEqualTo(0);
        ipv6Block.ShouldBeLessThan(tunnelPass);

        // No DHCPv6/NDP passes in this mode: IPv6 is off.
        ruleset.ShouldNotContain("port 546");
        ruleset.ShouldNotContain("ipv6-icmp");
    }

    [FactOnNonMacOS]
    public void PassesDhcpv6AndIcmpv6WhenIpv6IsCarried()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan(blockIpv6: false));

        ruleset.ShouldNotContain("block drop quick inet6 all");

        // Carrying IPv6 brings obligations: DHCPv6 and NDP keep the physical link configured, and
        // ICMPv6 must not be blocked wholesale or Packet Too Big (type 2) breaks path-MTU discovery.
        ruleset.ShouldContain("pass out quick inet6 proto udp from any port 546 to any port 547");
        ruleset.ShouldContain("pass in quick inet6 proto udp from any port 547 to any port 546");
        ruleset.ShouldContain("pass quick inet6 proto ipv6-icmp from any to any");
    }

    [FactOnNonMacOS]
    public void RendersDnsOnlyOnTheTunnelAndNeverAsAnExemption()
    {
        var plan = MacTestData.KillSwitchPlan() with
        {
            AllowedDestinations = new[]
            {
                new AllowedEndpoint
                {
                    Destination = CidrBlock.Parse("1.1.1.1/32"),
                    Port = 53,
                    ReasonKey = "killswitch.reason.resolver",
                },
                new AllowedEndpoint
                {
                    Destination = CidrBlock.Parse("192.0.2.10/32"),
                    Port = 8443,
                    ReasonKey = "killswitch.reason.user_exemption",
                },
            },
        };

        var ruleset = Render(plan);

        // DNS resolves through the tunnel, full stop.
        ruleset.ShouldContain("pass out quick on utun3 proto { tcp, udp } from any to any port 53\n");

        // A resolver exemption must NOT become a direct pass: that is the plaintext leak the ruleset
        // exists to prevent, and it would not even help, because mDNSResponder binds its sockets to the
        // physical interface.
        ruleset.ShouldNotContain("to 1.1.1.1");
        ruleset.ShouldContain("#     (1 resolver exemption(s) were supplied by the plan.)");

        // A genuine user exemption is rendered.
        ruleset.ShouldContain("pass out quick proto { tcp, udp } from any to 192.0.2.10 port 8443\n");
    }

    [FactOnNonMacOS]
    public void RendersLoopbackAsBothASkipOptionAndAnExplicitPass()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        // Both forms: a 'set' option is global to the main ruleset and may be ignored in an anchor
        // context, so the explicit pass is kept as belt and braces.
        ruleset.ShouldContain("set skip on lo0\n");
        ruleset.ShouldContain("pass quick on lo0 all\n");
    }

    [FactOnNonMacOS]
    public void RendersDhcpOnlyWhenThePlanAsksForIt()
    {
        var withDhcp = Render(MacTestData.KillSwitchPlan(allowDhcp: true));
        withDhcp.ShouldContain("pass out quick proto udp from any port 68 to any port 67\n");
        withDhcp.ShouldContain("pass in quick proto udp from any port 67 to any port 68\n");

        var withoutDhcp = Render(MacTestData.KillSwitchPlan(allowDhcp: false));
        withoutDhcp.ShouldNotContain("port 68");
    }

    [FactOnNonMacOS]
    public void DoesNotRenderAnIcmpPassOutsideTheTunnel()
    {
        // AllowIcmp defaults to true on the plan, but the researched fail-closed ruleset does not pass
        // ICMPv4 outside the tunnel: that would reopen an exfiltration path. The plan value is reported
        // in a comment instead of being silently dropped.
        var ruleset = Render(MacTestData.KillSwitchPlan());

        ruleset.ShouldNotContain("proto icmp ");
        ruleset.ShouldContain("#   * AllowIcmp is true in this plan, but no ICMP pass is rendered outside the");
    }

    [FactOnNonMacOS]
    public void SetsBlockPolicyAndDisablesTheOptimizer()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        // Silent drops, and rules that stay 1:1 with the source so pfctl -s rules can be compared with
        // what was generated.
        ruleset.ShouldContain("set block-policy drop\n");
        ruleset.ShouldContain("set ruleset-optimization none\n");
    }

    [FactOnNonMacOS]
    public void RefusesAPlanWithoutAnAllowedEndpoint()
    {
        var plan = MacTestData.KillSwitchPlan() with { AllowedEndpoints = Array.Empty<AllowedEndpoint>() };

        var rendered = PfAnchorRenderer.RenderInstall(plan);

        rendered.IsFailure.ShouldBeTrue();
        rendered.Error!.Code.ShouldBe(ErrorCodes.KillSwitchApplyFailed);
        rendered.Error.MessageKey.ShouldBe("error.killswitch.no_server_endpoint");
        rendered.Error.TechnicalDetail.ShouldNotBeNullOrWhiteSpace();
    }

    [FactOnNonMacOS]
    public void RefusesAnEmptyTunnelInterface()
    {
        var rendered = PfAnchorRenderer.RenderInstall(
            MacTestData.KillSwitchPlan(tunnelInterface: "   "));

        rendered.IsFailure.ShouldBeTrue();
        rendered.Error!.MessageKey.ShouldBe("error.killswitch.tunnel_interface_invalid");
    }

    [TheoryOnNonMacOS]
    [InlineData("utun0 all\nblock drop quick all")]
    [InlineData("utun0\npass quick on lo0 all")]
    [InlineData("utun0; pass")]
    [InlineData("utun0\" }")]
    [InlineData("../utun0")]
    [InlineData("utun0/../en0")]
    [InlineData("utun 0")]
    [InlineData("utun+")]
    public void RefusesAnInterfaceNameThatCouldInjectRulesetSyntax(string hostileName)
    {
        var rendered = PfAnchorRenderer.RenderInstall(
            MacTestData.KillSwitchPlan(tunnelInterface: hostileName));

        rendered.IsFailure.ShouldBeTrue();
        rendered.Error!.MessageKey.ShouldBe("error.killswitch.tunnel_interface_invalid");

        // The raw value may appear in the error's technical detail, but flattened onto one line: it can
        // never become a second ruleset line.
        rendered.Error.TechnicalDetail!.ShouldNotContain("\n");
        PfAnchorRenderer.IsSafeInterfaceName(hostileName).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void RefusesAnIdentifierThatWouldAddARuleThroughAComment()
    {
        var plan = MacTestData.KillSwitchPlan(identifier: "myvpn\nblock drop quick all\npass quick all");

        var ruleset = Render(plan);

        // The identifier is plan data placed in a comment, so the newline is flattened rather than
        // allowed to terminate the comment and start a rule.
        var injected = ruleset
            .Split('\n')
            .Count(l => l.Trim().StartsWith("block drop quick all", StringComparison.Ordinal));

        injected.ShouldBe(1);
        ruleset.ShouldContain("# identifier: myvpn block drop quick all pass quick all");
    }

    [FactOnNonMacOS]
    public void AcceptsRealisticUtunNames()
    {
        foreach (var name in new[] { "utun0", "utun3", "utun12", "utun255" })
        {
            PfAnchorRenderer.IsSafeInterfaceName(name).ShouldBeTrue(name);
            Render(MacTestData.KillSwitchPlan(tunnelInterface: name)).ShouldContain($"pass quick on {name} all");
        }
    }

    [FactOnNonMacOS]
    public void DisabledModeRendersThePermissiveTeardownRuleset()
    {
        var rendered = PfAnchorRenderer.RenderInstall(MacTestData.KillSwitchPlan() with
        {
            Mode = KillSwitchMode.Disabled,
        });

        rendered.IsSuccess.ShouldBeTrue();
        rendered.Value.ShouldNotContain("block drop quick all");
        rendered.Value.ShouldNotContain("table <myvpn_server>");
        rendered.Value.ShouldContain("anchor \"com.apple/*\"");
    }

    [FactOnNonMacOS]
    public void DisarmRulesetFiltersNothingAndKeepsApplesAnchors()
    {
        var rendered = PfAnchorRenderer.RenderDisarm();

        rendered.IsSuccess.ShouldBeTrue();

        var ruleLines = rendered.Value
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToArray();

        // Only options and anchors: PF's default action is to pass, so the machine is online again.
        ruleLines.ShouldAllBe(l => l.StartsWith("set ", StringComparison.Ordinal)
                                   || l.Contains("anchor", StringComparison.Ordinal));
        rendered.Value.ShouldContain("load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"");
    }

    [FactOnNonMacOS]
    public void ReportsTheInterfacesItsRulesetReferences()
    {
        var names = PfAnchorRenderer.ReferencedInterfaces(MacTestData.KillSwitchPlan());

        names.ShouldContain("utun3");
        names.ShouldContain("lo0");
    }

    [FactOnNonMacOS]
    public void DocumentsTheBestEffortWarningAndTheForbiddenFlag()
    {
        var ruleset = Render(MacTestData.KillSwitchPlan());

        // The caveat has to travel with the artefact, not only with the source: TN3165 is explicit that
        // PF is not API.
        ruleset.ShouldContain("BEST EFFORT, NOT API");
        ruleset.ShouldContain("TN3165");
        ruleset.ShouldContain("pfctl -d is never used by MyVpn");
    }

    private static int IndexOf(string text, string value)
    {
        var index = text.IndexOf(value, StringComparison.Ordinal);
        index.ShouldBeGreaterThanOrEqualTo(0, $"'{value}' was not rendered");
        return index;
    }
}

/// <summary>Tests for the pure pfctl argv shapes and output parsers.</summary>
public sealed class PfctlCommandShapeTests
{
    private readonly ITestOutputHelper _output;

    public PfctlCommandShapeTests(ITestOutputHelper output) => _output = output;

    [FactOnNonMacOS]
    public void NeverEmitsTheDisableOrUntokenedEnableFlag()
    {
        var shapes = PfctlCommands.AllShapes();

        shapes.ShouldNotBeEmpty();

        foreach (var shape in shapes)
        {
            var rendered = string.Join(' ', shape);
            _output.WriteLine($"pfctl {rendered}");

            // 'pfctl -d' runs pf_stop() and invalidate_all_tokens(), which disables PF for every other
            // enabler including the Application Firewall. 'pfctl -e' takes a reference that can never be
            // released selectively. Neither may ever appear in this codebase.
            shape.ShouldNotContain("-d");
            shape.ShouldNotContain("-e");
            shape.ShouldNotContain("-D");
        }
    }

    [FactOnNonMacOS]
    public void EmitsExactlyTheResearchedSequence()
    {
        var shapes = PfctlCommands.AllShapes().Select(s => string.Join(' ', s)).ToArray();

        shapes.ShouldContain("-E");
        shapes.ShouldContain("-n -f /tmp/myvpn-pf-ruleset.conf");
        shapes.ShouldContain("-f /tmp/myvpn-pf-ruleset.conf");
        shapes.ShouldContain("-f /etc/pf.conf");
        shapes.ShouldContain("-F states");
        shapes.ShouldContain($"-X {PfctlCommands.TokenPlaceholder}");
        shapes.ShouldContain("-s rules");
        shapes.ShouldContain("-s Tables");
        shapes.ShouldContain("-s References");
        shapes.ShouldContain("-t myvpn_server -T replace 203.0.113.5");
        shapes.ShouldContain("utun0");
    }

    [FactOnNonMacOS]
    public void EveryReleaseShapeIsPairedWithAToken()
    {
        foreach (var shape in PfctlCommands.AllShapes())
        {
            if (!shape.Contains("-X", StringComparer.Ordinal))
            {
                continue;
            }

            shape.Count.ShouldBe(2);
            shape[1].ShouldBe(PfctlCommands.TokenPlaceholder);
            PfctlCommands.IsValidToken(shape[1]).ShouldBeTrue();
        }
    }

    [TheoryOnNonMacOS]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("123456789012345678901")]
    [InlineData("0")]
    [InlineData("00")]
    [InlineData("-1")]
    [InlineData("12 34")]
    public void ReleaseRefusesAnythingThatIsNotARealToken(string token)
    {
        // '-X 0' is not a global shutdown (it returns EINVAL), but shipping it would leak the reference
        // MyVpn took, leaving PF enabled for the rest of the boot.
        Should.Throw<ArgumentException>(() => PfctlCommands.Release(token));
    }

    [FactOnNonMacOS]
    public void ReleaseAcceptsATokenAndPassesItVerbatim()
    {
        PfctlCommands.Release("1234567890").ShouldBe(new[] { "-X", "1234567890" });
    }

    [FactOnNonMacOS]
    public void ReplaceServerTableRefusesToEmptyTheTable()
    {
        // An empty replacement would make the pass rules match nothing and black-hole the tunnel.
        Should.Throw<ArgumentException>(() => PfctlCommands.ReplaceServerTable(Array.Empty<string>()));
    }

    [FactOnNonMacOS]
    public void ProbeInterfaceRefusesAnUnsafeName()
    {
        Should.Throw<ArgumentException>(() => PfctlCommands.ProbeInterface("utun0; rm -rf /"));
        PfctlCommands.ProbeInterface("utun3").ShouldBe(new[] { "utun3" });
    }

    [FactOnNonMacOS]
    public void ParsesTheTokenFromPfctlEnableOutput()
    {
        PfctlOutput.TryParseEnableToken("pf enabled\nToken : 1234567890\n", out var token).ShouldBeTrue();
        token.ShouldBe("1234567890");

        // The token can also arrive on the merged stream.
        PfctlOutput.TryParseEnableToken("Token : 987654321", out var bare).ShouldBeTrue();
        bare.ShouldBe("987654321");
    }

    [TheoryOnNonMacOS]
    [InlineData("")]
    [InlineData("pf enabled")]
    [InlineData("pfctl: /dev/pf: Permission denied")]
    [InlineData("Token : ")]
    [InlineData("Token : 0")]
    public void RefusesToGuessATokenFromUnrecognisedOutput(string output)
    {
        // Guessing would release someone else's reference; reporting the failure is the only safe answer.
        PfctlOutput.TryParseEnableToken(output, out var token).ShouldBeFalse();
        token.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void FindsTokensInReferenceListingsWithoutPartialMatches()
    {
        const string references = "pf enabled ref count 2\npid 4711 token 1234567890 added Mon\n";

        PfctlOutput.ContainsToken(references, "1234567890").ShouldBeTrue();

        // The search is digit-delimited, so a prefix or suffix of a longer number never matches.
        PfctlOutput.ContainsToken(references, "123456789").ShouldBeFalse();
        PfctlOutput.ContainsToken(references, "234567890").ShouldBeFalse();
        PfctlOutput.ContainsToken(references, "999").ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void StoredTokenRoundTrips()
    {
        var contents = PfctlOutput.RenderStoredToken("1234567890");

        PfctlOutput.TryParseStoredToken(contents, out var token).ShouldBeTrue();
        token.ShouldBe("1234567890");

        // Comments and blank lines are tolerated so the file can carry its own instructions.
        PfctlOutput.TryParseStoredToken("# comment\n\n  42  \n", out var trimmed).ShouldBeTrue();
        trimmed.ShouldBe("42");

        PfctlOutput.TryParseStoredToken("not-a-token\n", out _).ShouldBeFalse();
        PfctlOutput.TryParseStoredToken(string.Empty, out _).ShouldBeFalse();
        Should.Throw<ArgumentException>(() => PfctlOutput.RenderStoredToken("0"));
    }
}

/// <summary>
/// The guard that proves no macOS path can execute on this host.
/// </summary>
/// <remarks>
/// This is the test the brief calls for explicitly: on Linux every executor must report
/// <c>IsSupported == false</c> and every mutating call must return a clear unsupported error
/// <i>without invoking the command runner at all</i>. If a guard is ever lost, these tests fail rather
/// than a Linux CI machine quietly starting to run <c>pfctl</c>, <c>networksetup</c> or <c>route</c>.
/// </remarks>
public sealed class MacOsExecutorGuardTests
{
    [FactOnNonMacOS]
    public async Task KillSwitchIsNotSupportedAndRefusesEveryCall()
    {
        var runner = MacTestData.MacRunner();
        var killSwitch = new MacPfKillSwitch(runner, isElevated: () => true);

        OperatingSystem.IsMacOS().ShouldBeFalse("this suite runs on Linux");
        killSwitch.IsSupported.ShouldBeFalse();
        killSwitch.MechanismName.ShouldBe("pf");

        // IsSupported must be a cheap property: it is read by capability reporting in the UI.
        runner.Calls.ShouldBeEmpty();

        var applied = await killSwitch.ApplyAsync(MacTestData.KillSwitchPlan(), CancellationToken.None);
        applied.Succeeded.ShouldBeFalse();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);
        applied.Error.MessageKey.ShouldBe("error.platform.macos_only");
        applied.Error.TechnicalDetail.ShouldNotBeNullOrWhiteSpace();

        var removed = await killSwitch.RemoveAsync("myvpn", CancellationToken.None);
        removed.Succeeded.ShouldBeFalse();
        removed.Error!.MessageKey.ShouldBe("error.platform.macos_only");

        var table = await killSwitch.UpdateServerTableAsync(MacTestData.KillSwitchPlan(), CancellationToken.None);
        table.Succeeded.ShouldBeFalse();
        table.Error!.MessageKey.ShouldBe("error.platform.macos_only");

        var state = await killSwitch.InspectAsync(MacTestData.KillSwitchPlan(), CancellationToken.None);
        state.IsArmed.ShouldBeFalse();
        state.MechanismName.ShouldBe("pf");

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task SystemProxyIsNotSupportedAndRefusesEveryCall()
    {
        var runner = MacTestData.MacRunner();
        var proxy = new MacSystemProxy(runner, isElevated: () => true);

        proxy.IsSupported.ShouldBeFalse();
        runner.Calls.ShouldBeEmpty();

        var captured = await proxy.CaptureAsync(CancellationToken.None);
        captured.IsFailure.ShouldBeTrue();
        captured.Error!.MessageKey.ShouldBe("error.platform.macos_only");

        var applied = await proxy.ApplyAsync(MacTestData.SystemProxyPlan(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.platform.macos_only");

        var restored = await proxy.RestoreAsync(
            new SystemProxySnapshot { Mode = "manual", Enabled = true }, CancellationToken.None);
        restored.IsFailure.ShouldBeTrue();

        var reset = await proxy.ResetAsync(CancellationToken.None);
        reset.IsFailure.ShouldBeTrue();

        (await proxy.InspectAsync(CancellationToken.None)).IsConfigured.ShouldBeFalse();

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task RouteManagerIsNotSupportedAndRefusesEveryCall()
    {
        var runner = MacTestData.MacRunner();
        var routes = new MacRouteManager(runner, isElevated: () => true);

        routes.IsSupported.ShouldBeFalse();
        runner.Calls.ShouldBeEmpty();

        (await routes.ApplyAsync(MacTestData.RoutePlan(), CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        (await routes.RemoveAsync(MacTestData.RoutePlan(), CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        (await routes.RemoveAllOwnedAsync(CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        (await routes.GetDefaultUplinkAsync(CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        (await routes.InspectAsync(MacTestData.RoutePlan(), CancellationToken.None))
            .TunnelRoutesPresent.ShouldBeFalse();

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task DnsConfiguratorIsNotSupportedAndRefusesEveryCall()
    {
        var runner = MacTestData.MacRunner();
        var dns = new MacDnsConfigurator(runner, isElevated: () => true);

        dns.IsSupported.ShouldBeFalse();
        runner.Calls.ShouldBeEmpty();

        var applied = await dns.ApplyAsync(MacTestData.DnsPlan(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.DnsConfigureFailed);
        applied.Error.MessageKey.ShouldBe("error.platform.macos_only");

        (await dns.RestoreAsync(MacTestData.DnsPlan(), CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        (await dns.RemoveAllOwnedAsync(CancellationToken.None))
            .Error!.MessageKey.ShouldBe("error.platform.macos_only");

        var state = await dns.InspectAsync(CancellationToken.None);
        state.ActiveServers.ShouldBeEmpty();
        state.PlainDnsReachableOutsideTunnel.ShouldBeFalse();

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task TunDeviceManagerIsNotSupportedAndNeverProbesIfconfig()
    {
        var runner = MacTestData.MacRunner();
        var tun = new MacTunDeviceManager(runner);

        tun.IsSupported.ShouldBeFalse();
        tun.DefaultInterfaceName.ShouldBe("utun0");
        runner.Calls.ShouldBeEmpty();

        // 'ifconfig' exists on many Unix systems, so the guard is not theoretical: without it this would
        // list Linux interfaces and report them as utun devices.
        (await tun.ExistsAsync("utun0", CancellationToken.None)).ShouldBeFalse();
        (await tun.GetAddressesAsync("utun0", CancellationToken.None)).ShouldBeEmpty();
        (await tun.ListTunnelInterfacesAsync(CancellationToken.None)).ShouldBeEmpty();
        (await tun.ResolveTunnelInterfaceAsync("utun0", CancellationToken.None)).ShouldBeNull();

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task ExecutorsRejectAnUnsafeInterfaceNameBeforeTheOperatingSystemGuard()
    {
        // Argument validation happens first: a hostile name must never reach a command runner even if a
        // future change moved the platform guard.
        var runner = MacTestData.MacRunner();
        var tun = new MacTunDeviceManager(runner);

        await Should.ThrowAsync<ArgumentException>(() => tun.ExistsAsync("utun0; rm -rf /", CancellationToken.None));
        await Should.ThrowAsync<ArgumentException>(() => tun.GetAddressesAsync("../utun0", CancellationToken.None));
        await Should.ThrowAsync<ArgumentNullException>(() => tun.ExistsAsync(null!, CancellationToken.None));

        runner.Calls.ShouldBeEmpty();
    }
}

/// <summary>Tests for the networksetup argv grammar.</summary>
public sealed class NetworksetupCommandTests
{
    private readonly ITestOutputHelper _output;

    public NetworksetupCommandTests(ITestOutputHelper output) => _output = output;

    [FactOnNonMacOS]
    public void SetProxyNeverCarriesTheAuthenticatedSwitch()
    {
        // The documented grammar is "-setwebproxy service domain port authenticated username password",
        // and the trailing on|off is the *authenticated-proxy* switch — not the enable switch. The
        // widely copied 'networksetup -setwebproxy "Wi-Fi" host port off' therefore leaves the proxy
        // ON. These builders must produce exactly four arguments.
        NetworksetupCommands.SetWebProxy("Wi-Fi", "127.0.0.1", 10809)
            .ShouldBe(new[] { "-setwebproxy", "Wi-Fi", "127.0.0.1", "10809" });

        NetworksetupCommands.SetSecureWebProxy("Wi-Fi", "127.0.0.1", 10809)
            .ShouldBe(new[] { "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "10809" });

        NetworksetupCommands.SetSocksProxy("Wi-Fi", "127.0.0.1", 10808)
            .ShouldBe(new[] { "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "10808" });

        foreach (var shape in NetworksetupCommands.AllShapes())
        {
            var rendered = string.Join(' ', shape);
            _output.WriteLine(rendered);

            if (!shape[0].StartsWith("-set", StringComparison.Ordinal)
                || shape[0].EndsWith("state", StringComparison.Ordinal)
                || shape[0] is "-setautoproxyurl" or "-setdnsservers" or "-setproxybypassdomains")
            {
                continue;
            }

            shape.ShouldNotContain("on");
            shape.ShouldNotContain("off");
        }
    }

    [FactOnNonMacOS]
    public void EnablingAndDisablingAreSeparateStateCommands()
    {
        var shapes = NetworksetupCommands.AllShapes().Select(s => string.Join(' ', s)).ToArray();

        foreach (var verb in new[]
                 {
                     "-setwebproxystate",
                     "-setsecurewebproxystate",
                     "-setsocksfirewallproxystate",
                     "-setautoproxystate",
                 })
        {
            shapes.ShouldContain($"{verb} Wi-Fi on");
            shapes.ShouldContain($"{verb} Wi-Fi off");
        }
    }

    [FactOnNonMacOS]
    public void ClearingLiteralsMatchTheManPageExactly()
    {
        // The man page documents lowercase 'empty' for -setdnsservers and capitalised 'Empty' for
        // -setproxybypassdomains. Mixed up, the command errors out instead of clearing.
        NetworksetupCommands.SetDnsServers("Wi-Fi", Array.Empty<string>())
            .ShouldBe(new[] { "-setdnsservers", "Wi-Fi", "empty" });

        NetworksetupCommands.SetBypassDomains("Wi-Fi", Array.Empty<string>())
            .ShouldBe(new[] { "-setproxybypassdomains", "Wi-Fi", "Empty" });
    }

    [FactOnNonMacOS]
    public void RefusesBadValuesBeforeTheyReachArgv()
    {
        Should.Throw<ArgumentException>(() => NetworksetupCommands.SetWebProxy("-evil", "127.0.0.1", 1080));
        Should.Throw<ArgumentException>(() => NetworksetupCommands.SetWebProxy("Wi-Fi", "-evil", 1080));
        Should.Throw<ArgumentOutOfRangeException>(() => NetworksetupCommands.SetWebProxy("Wi-Fi", "127.0.0.1", 0));
        Should.Throw<ArgumentException>(() => NetworksetupCommands.SetSocksProxy("Wi-Fi", "127.0.0.1", 70000));
        Should.Throw<ArgumentException>(() => NetworksetupCommands.SetDnsServers("Wi-Fi", new[] { "not-an-ip" }));
        Should.Throw<ArgumentException>(() => NetworksetupCommands.SetAutoProxyUrl("Wi-Fi", " "));
    }

    [FactOnNonMacOS]
    public void KeepsServiceNamesWithSpacesAsOneArgument()
    {
        var arguments = NetworksetupCommands.SetWebProxy("Thunderbolt Bridge", "127.0.0.1", 10809);

        arguments.Count.ShouldBe(4);
        arguments[1].ShouldBe("Thunderbolt Bridge");
    }
}

/// <summary>Tests for the pure system-proxy parsers and restore sequence.</summary>
public sealed class MacSystemProxyPureTests
{
    private const string ServiceList =
        "An asterisk (*) denotes that a network service is disabled.\n"
        + "Wi-Fi\n"
        + "*Thunderbolt Bridge\n"
        + "iPhone USB\n";

    private const string ServiceOrder =
        "An asterisk (*) denotes that a network service is disabled.\n"
        + "(1) Wi-Fi\n"
        + "(Hardware Port: Wi-Fi, Device: en0)\n"
        + "\n"
        + "(2) Thunderbolt Bridge\n"
        + "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";

    [FactOnNonMacOS]
    public void ParsesTheServiceListDroppingTheHeaderAndTheDisabledMarker()
    {
        MacSystemProxy.ParseServiceList(ServiceList).ShouldBe(new[] { "Wi-Fi", "Thunderbolt Bridge", "iPhone USB" });

        // The enabled/disabled distinction is kept separately, because a disabled service still carries
        // proxy preferences that apply the moment it is enabled again.
        MacSystemProxy.ParseServiceEntries(ServiceList)
            .ShouldBe(new[] { ("Wi-Fi", true), ("Thunderbolt Bridge", false), ("iPhone USB", true) });

        MacSystemProxy.ParseServiceList(null).ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void ParsesTheServiceOrderAndTreatsTheFirstEntryAsPrimary()
    {
        var order = MacSystemProxy.ParseServiceOrder(ServiceOrder);

        // The parenthesised detail lines must not be mistaken for service names.
        order.ShouldBe(new[] { "Wi-Fi", "Thunderbolt Bridge" });
        order[0].ShouldBe("Wi-Fi");
    }

    [FactOnNonMacOS]
    public void ParsesProxyGetterOutput()
    {
        var web = MacSystemProxy.ParseProxyEntry(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 10809\nAuthenticated Proxy Enabled: 0\n");

        web.Enabled.ShouldBeTrue();
        web.Server.ShouldBe("127.0.0.1");
        web.Port.ShouldBe(10809);
        web.Describe().ShouldBe("127.0.0.1:10809");

        var disabled = MacSystemProxy.ParseProxyEntry("Enabled: No\nServer: (null)\nPort: 0\n");
        disabled.Enabled.ShouldBeFalse();
        disabled.Describe().ShouldBeNull();

        var pac = MacSystemProxy.ParseProxyEntry("URL: (null)\nEnabled: No\n");
        pac.Url.ShouldBeNull();
        pac.Enabled.ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void ParsesBypassDomainsIncludingTheEmptySentence()
    {
        MacSystemProxy.ParseBypassDomains("There aren't any bypass domains set on Wi-Fi.\n")
            .ShouldBeEmpty();

        MacSystemProxy.ParseBypassDomains("*.corp.example\n192.168.0.0/16\n")
            .ShouldBe(new[] { "*.corp.example", "192.168.0.0/16" });
    }

    [FactOnNonMacOS]
    public void MergingBypassDomainsKeepsTheUsersOwnEntriesAndAlwaysAddsLoopback()
    {
        var plan = new SystemProxyPlan
        {
            BypassDomains = new[] { "corp.example", "localhost" },
            BypassNetworks = new[] { CidrBlock.Parse("10.0.0.0/8") },
            Previous = new SystemProxySnapshot { BypassList = "user.example, 172.16.0.0/12" },
        };

        var merged = MacSystemProxy.MergeBypassDomains(plan);

        // -setproxybypassdomains replaces the list, so dropping the user's entries would silently delete
        // their exceptions.
        merged.ShouldContain("user.example");
        merged.ShouldContain("172.16.0.0/12");
        merged.ShouldContain("corp.example");
        merged.ShouldContain("10.0.0.0/8");

        // Loopback is always bypassed: proxying MyVpn's own local inbound back through the proxy is a loop.
        merged.ShouldContain("localhost");
        merged.ShouldContain("127.0.0.1");
        merged.ShouldContain("::1");

        merged.Count(d => string.Equals(d, "localhost", StringComparison.OrdinalIgnoreCase)).ShouldBe(1);
    }

    [FactOnNonMacOS]
    public void RestoringAManualSnapshotWritesValuesThenStates()
    {
        var commands = MacSystemProxy.BuildRestoreCommands(
            "Wi-Fi",
            new SystemProxySnapshot
            {
                Mode = "manual",
                Enabled = true,
                HttpProxy = "proxy.corp:3128",
                HttpsProxy = "proxy.corp:3128",
                SocksProxy = "127.0.0.1:1080",
                BypassList = "user.example",
            });

        var rendered = commands.Select(c => string.Join(' ', c)).ToArray();

        rendered.ShouldContain("-setwebproxy Wi-Fi proxy.corp 3128");
        rendered.ShouldContain("-setwebproxystate Wi-Fi on");
        rendered.ShouldContain("-setsecurewebproxy Wi-Fi proxy.corp 3128");
        rendered.ShouldContain("-setsocksfirewallproxy Wi-Fi 127.0.0.1 1080");
        rendered.ShouldContain("-setproxybypassdomains Wi-Fi user.example");

        // The user's manual configuration is restored exactly, not flattened to "off".
        rendered.ShouldNotContain("-setwebproxystate Wi-Fi off");
    }

    [FactOnNonMacOS]
    public void RestoringAnAutomaticSnapshotKeepsPacAndTurnsManualProxiesOff()
    {
        var commands = MacSystemProxy.BuildRestoreCommands(
            "Wi-Fi",
            new SystemProxySnapshot
            {
                Mode = "auto",
                Enabled = true,
                PacUrl = "https://corp.example/proxy.pac",
                HttpProxy = "proxy.corp:3128",
            });

        var rendered = commands.Select(c => string.Join(' ', c)).ToArray();

        // Losing a corporate PAC configuration would leave the machine unable to reach anything after the
        // VPN exits, so the PAC URL is written back rather than the mode being flattened.
        rendered.ShouldContain("-setautoproxyurl Wi-Fi https://corp.example/proxy.pac");
        rendered.ShouldContain("-setwebproxystate Wi-Fi off");
        rendered.ShouldContain("-setsecurewebproxystate Wi-Fi off");
        rendered.ShouldContain("-setsocksfirewallproxystate Wi-Fi off");
    }

    [FactOnNonMacOS]
    public void RestoringADisabledSnapshotTurnsEverythingOff()
    {
        var commands = MacSystemProxy.BuildRestoreCommands(
            "Wi-Fi",
            new SystemProxySnapshot { Mode = "none", Enabled = false, HttpProxy = "proxy.corp:3128" });

        var rendered = commands.Select(c => string.Join(' ', c)).ToArray();

        rendered.ShouldContain("-setwebproxystate Wi-Fi off");
        rendered.ShouldContain("-setsecurewebproxystate Wi-Fi off");
        rendered.ShouldContain("-setsocksfirewallproxystate Wi-Fi off");
        rendered.ShouldContain("-setautoproxystate Wi-Fi off");
        rendered.ShouldNotContain("-setwebproxy Wi-Fi proxy.corp 3128");
    }

    [FactOnNonMacOS]
    public void ResetTurnsEveryProxyOffThroughTheDistinctStateCommands()
    {
        var rendered = MacSystemProxy.BuildResetCommands("Thunderbolt Bridge")
            .Select(c => string.Join(' ', c))
            .ToArray();

        // One state verb per proxy kind, each naming the service, and never a value-setting command:
        // reset has no plan to restore from, so writing a host or port would be a guess.
        rendered.ShouldBe(new[]
        {
            "-setwebproxystate Thunderbolt Bridge off",
            "-setsecurewebproxystate Thunderbolt Bridge off",
            "-setsocksfirewallproxystate Thunderbolt Bridge off",
            "-setautoproxystate Thunderbolt Bridge off",
        });
    }

    [FactOnNonMacOS]
    public void ParsesBracketedIpv6ProxyEndpoints()
    {
        var commands = MacSystemProxy.BuildRestoreCommands(
            "Wi-Fi",
            new SystemProxySnapshot { Mode = "manual", Enabled = true, HttpProxy = "[::1]:10809" });

        commands.Select(c => string.Join(' ', c)).ShouldContain("-setwebproxy Wi-Fi ::1 10809");
    }
}

/// <summary>Tests for the pure route argv, def1 expansion, journal and parsers.</summary>
public sealed class MacRouteManagerPureTests
{
    private const string NetstatInet =
        "Routing tables\n"
        + "\n"
        + "Internet:\n"
        + "Destination        Gateway            Flags        Netif Expire\n"
        + "default            192.0.2.1          UGScg          en0\n"
        + "10                 192.0.2.1          UGSc           en0\n"
        + "127.0.0.1          127.0.0.1          UH             lo0\n"
        + "192.0.2.0/24       link#4             UCS            en0\n"
        + "203.0.113.5/32     192.0.2.1          UGHS           en0\n"
        + "0.0.0.0/1          169.254.10.1       UGSc           utun3\n"
        + "128.0.0.0/1        169.254.10.1       UGSc           utun3\n";

    private const string DefaultRouteOutput =
        "   route to: default\n"
        + "destination: default\n"
        + "       mask: default\n"
        + "    gateway: 192.0.2.1\n"
        + "  interface: en0\n"
        + "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";

    [FactOnNonMacOS]
    public void AddsAPointToPointRouteThroughTheInterface()
    {
        var arguments = MacRouteCommands.Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("0.0.0.0/1"),
            Interface = "utun3",
            ReasonKey = "route.reason.tunnel",
        });

        // The form WireGuard's Darwin script uses, and the one route(8) documents for an interface with
        // no intermediary gateway.
        arguments.ShouldBe(new[] { "-n", "add", "-inet", "0.0.0.0/1", "-interface", "utun3" });
    }

    [FactOnNonMacOS]
    public void AddsAViaGatewayRouteAndAnIpv6Route()
    {
        MacRouteCommands.Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("203.0.113.5/32"),
            Gateway = "192.0.2.1",
            Interface = "en0",
            ReasonKey = "route.reason.bypass",
        }).ShouldBe(new[] { "-n", "add", "-inet", "203.0.113.5/32", "192.0.2.1" });

        MacRouteCommands.Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("8000::/1"),
            Interface = "utun3",
            ReasonKey = "route.reason.tunnel",
        }).ShouldBe(new[] { "-n", "add", "-inet6", "8000::/1", "-interface", "utun3" });
    }

    [FactOnNonMacOS]
    public void DeletesByDestinationAlone()
    {
        // After the tunnel disappears XNU removes its routes, and a destination-only delete is the form
        // route(8) documents: repeating a gateway that has since changed would fail.
        MacRouteCommands.Delete(new RouteEntry
        {
            Destination = CidrBlock.Parse("128.0.0.0/1"),
            Gateway = "192.0.2.1",
            Interface = "utun3",
            ReasonKey = "route.reason.tunnel",
        }).ShouldBe(new[] { "-n", "delete", "-inet", "128.0.0.0/1" });
    }

    [FactOnNonMacOS]
    public void RefusesAnUnsafeInterfaceNameBeforeArgv()
    {
        Should.Throw<ArgumentException>(() => MacRouteCommands.Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("0.0.0.0/1"),
            Interface = "utun3; rm -rf /",
            ReasonKey = "route.reason.tunnel",
        }));
    }

    [FactOnNonMacOS]
    public void ExpandsADefaultRouteIntoTheDef1Halves()
    {
        var route = new RouteEntry
        {
            Destination = CidrBlock.Parse("0.0.0.0/0"),
            Interface = "utun3",
            ReasonKey = "route.reason.tunnel",
            DisplacesDefaultRoute = true,
        };

        var halves = MacRouteManager.ExpandRoute(route);

        // OpenVPN's def1: two /1 routes are more specific than 0.0.0.0/0, so they win for every address
        // while the original default stays installed. Teardown is a two-route delete, and XNU's
        // if_rtdel() removes them when the utun goes away.
        halves.Select(h => h.Destination.ToString()).ShouldBe(new[] { "0.0.0.0/1", "128.0.0.0/1" });
        halves.ShouldAllBe(h => h.Interface == "utun3");

        // The system default is never displaced, so the flag must not survive the translation.
        halves.ShouldAllBe(h => !h.DisplacesDefaultRoute);

        var v6 = MacRouteManager.ExpandRoute(route with { Destination = CidrBlock.Parse("::/0") });
        v6.Select(h => h.Destination.ToString()).ShouldBe(new[] { "::/1", "8000::/1" });
    }

    [FactOnNonMacOS]
    public void LeavesANonDefaultRouteAloneAndDeduplicates()
    {
        var specific = new RouteEntry
        {
            Destination = CidrBlock.Parse("10.0.0.0/8"),
            Interface = "utun3",
            ReasonKey = "route.reason.tunnel",
        };

        MacRouteManager.ExpandRoute(specific).ShouldHaveSingleItem().ShouldBe(specific);

        var expanded = MacRouteManager.ExpandRoutes(new[]
        {
            specific with { Destination = CidrBlock.Parse("0.0.0.0/0") },
            specific with { Destination = CidrBlock.Parse("0.0.0.0/0") },
        });

        expanded.Count.ShouldBe(2);
    }

    [FactOnNonMacOS]
    public void InstallsBypassRoutesBeforeAnythingThatCapturesTheDefault()
    {
        var operations = MacRouteManager.BuildApplySequence(MacTestData.RoutePlan());

        var kinds = operations.Select(o => (o.Kind, o.Route.Destination.ToString())).ToArray();

        kinds.ShouldBe(new[]
        {
            (RouteOperationKind.Add, "203.0.113.5/32"),
            (RouteOperationKind.Add, "0.0.0.0/1"),
            (RouteOperationKind.Add, "128.0.0.0/1"),
        });

        // The bypass route is the fail-closed one: without the uplink host route to the server, capturing
        // the default prefix routes the core's own transport into the tunnel that cannot carry it.
        operations[0].FailClosed.ShouldBeTrue();
        operations[1].FailClosed.ShouldBeFalse();
        operations[2].FailClosed.ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void TearsDownInTheReverseOrder()
    {
        var operations = MacRouteManager.BuildRemoveSequence(MacTestData.RoutePlan());

        operations.Select(o => (o.Kind, o.Route.Destination.ToString())).ShouldBe(new[]
        {
            (RouteOperationKind.Delete, "128.0.0.0/1"),
            (RouteOperationKind.Delete, "0.0.0.0/1"),
            (RouteOperationKind.Delete, "203.0.113.5/32"),
        });
    }

    [FactOnNonMacOS]
    public void TreatsAduplicateAddAsIdempotentSuccess()
    {
        // route(4): "The routing code returns EEXIST if requested to duplicate an existing entry."
        MacRouteManager.IsAlreadyExists(new CommandResult(1, string.Empty, "route: writing to routing socket: File exists"))
            .ShouldBeTrue();
        MacRouteManager.IsAlreadyExists(new CommandResult(1, string.Empty, "EEXIST"))
            .ShouldBeTrue();
        MacRouteManager.IsAlreadyExists(new CommandResult(1, string.Empty, "Network is unreachable"))
            .ShouldBeFalse();

        MacRouteManager.IsAlreadyGone(new CommandResult(1, string.Empty, "route: delete net 0.0.0.0/1: not in table"))
            .ShouldBeTrue();
        MacRouteManager.IsAlreadyGone(new CommandResult(1, string.Empty, "some other failure")).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void JournalRoundTripsAndIgnoresNoise()
    {
        var plan = MacTestData.RoutePlan();
        var tunnel = MacRouteManager.ExpandRoutes(plan.TunnelRoutes);
        var journal = MacRouteManager.RenderJournal(tunnel, plan.BypassRoutes);

        journal.ShouldContain("tunnel inet 0.0.0.0/1 - utun3");
        journal.ShouldContain("tunnel inet 128.0.0.0/1 - utun3");
        journal.ShouldContain("bypass inet 203.0.113.5/32 192.0.2.1 en0");

        var parsed = MacRouteManager.ParseJournal(journal);

        parsed.Count.ShouldBe(3);
        parsed.Count(e => e.Kind == MacRouteManager.TunnelKind).ShouldBe(2);
        parsed.Count(e => e.Kind == MacRouteManager.BypassKind).ShouldBe(1);
        parsed.Single(e => e.Kind == MacRouteManager.BypassKind).Route.Gateway.ShouldBe("192.0.2.1");
        parsed.Single(e => e.Kind == MacRouteManager.BypassKind).Route.Destination.ToString()
            .ShouldBe("203.0.113.5/32");

        // The journal is read after a crash, so a damaged line must be skipped rather than abort the
        // recovery.
        MacRouteManager.ParseJournal("# comment\n\nnot a journal line\ntunnel inet 0.0.0.0/1 - utun3\n")
            .ShouldHaveSingleItem();
        MacRouteManager.ParseJournal(null).ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void ParsesNetstatOutputIncludingClassfulShorthand()
    {
        var routes = MacRouteManager.ParseRoutes(NetstatInet, isIpv6: false);

        routes.Select(r => r.Destination.ToString()).ShouldContain("0.0.0.0/0");
        routes.Select(r => r.Destination.ToString()).ShouldContain("10.0.0.0/8");
        routes.Select(r => r.Destination.ToString()).ShouldContain("192.0.2.0/24");
        routes.Select(r => r.Destination.ToString()).ShouldContain("203.0.113.5/32");
        routes.Select(r => r.Destination.ToString()).ShouldContain("0.0.0.0/1");

        // The header must not be mistaken for a route.
        routes.Count.ShouldBe(7);

        var halfRoute = routes.Single(r => r.Destination.ToString() == "0.0.0.0/1");
        halfRoute.Interface.ShouldBe("utun3");
        halfRoute.Gateway.ShouldBe("169.254.10.1");
        MacRouteManager.IsHalfRouteOnTunnel(halfRoute).ShouldBeTrue();

        var onLink = routes.Single(r => r.Destination.ToString() == "192.0.2.0/24");
        onLink.Gateway.ShouldBeNull();
        MacRouteManager.IsHalfRouteOnTunnel(onLink).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void ParsesTheDefaultRouteLookup()
    {
        var uplink = MacRouteManager.ParseDefaultRoute(DefaultRouteOutput);

        uplink.ShouldNotBeNull();
        uplink!.InterfaceName.ShouldBe("en0");
        uplink.GatewayAddress.ShouldBe("192.0.2.1");
        uplink.IsIpv6.ShouldBeFalse();

        MacRouteManager.ParseDefaultRoute("no interface line here").ShouldBeNull();
        MacRouteManager.ParseDefaultRoute(null).ShouldBeNull();
    }

    [FactOnNonMacOS]
    public void RecognisesTunnelInterfaceNames()
    {
        MacRouteManager.IsTunnelInterfaceName("utun0").ShouldBeTrue();
        MacRouteManager.IsTunnelInterfaceName("utun12").ShouldBeTrue();

        // 'utun' alone and 'utunx' are not device names, and en0 is not a tunnel.
        MacRouteManager.IsTunnelInterfaceName("utun").ShouldBeFalse();
        MacRouteManager.IsTunnelInterfaceName("utunx").ShouldBeFalse();
        MacRouteManager.IsTunnelInterfaceName("en0").ShouldBeFalse();
        MacRouteManager.IsTunnelInterfaceName(null).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void RefusesABypassRouteThatCapturesTheDefault()
    {
        var plan = MacTestData.RoutePlan();
        var bad = plan with
        {
            BypassRoutes = new[]
            {
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("0.0.0.0/0"),
                    Gateway = "192.0.2.1",
                    Interface = "en0",
                    ReasonKey = "route.reason.bypass",
                },
            },
        };

        // A bypass route exists to pin the server to the physical uplink; a default route there would
        // defeat the tunnel, so the meaning is inverted and the plan is refused.
        var route = bad.BypassRoutes[0];
        MacRouteManager.BypassCapturesDefault(route).MessageKey.ShouldBe("error.route.bypass_captures_default");
        MacRouteManager.BypassCapturesDefault(route).Code.ShouldBe(ErrorCodes.RouteAddFailed);
    }
}

/// <summary>Tests for the pure DNS parsers, resolver files and service round trip.</summary>
public sealed class MacDnsConfiguratorPureTests
{
    private const string ScutilOutput =
        "DNS configuration\n"
        + "\n"
        + "resolver #1\n"
        + "  search domain[0] : lan\n"
        + "  nameserver[0] : 192.0.2.1\n"
        + "  if_index : 14 (en0)\n"
        + "  flags    : Request A records, Request AAAA records\n"
        + "  reach    : 0x00000002 (Reachable)\n"
        + "\n"
        + "DNS configuration (for scoped queries)\n"
        + "\n"
        + "resolver #1\n"
        + "  nameserver[0] : 10.8.0.1\n"
        + "  if_index : 21 (utun3)\n"
        + "  flags    : Scoped, Request A records\n"
        + "\n"
        + "DNS configuration (for service-specific queries)\n"
        + "\n"
        + "resolver #1\n"
        + "  domain   : corp.example\n"
        + "  nameserver[0] : 10.8.0.2\n"
        + "  flags    : Supplemental, Service-specific\n";

    [FactOnNonMacOS]
    public void ParsesTheEmptyDnsServersSentence()
    {
        MacDnsConfigurator.ParseDnsServers("There aren't any DNS Servers set on Wi-Fi.\n").ShouldBeEmpty();
        MacDnsConfigurator.ParseDnsServers("1.1.1.1\n8.8.8.8\n").ShouldBe(new[] { "1.1.1.1", "8.8.8.8" });
        MacDnsConfigurator.ParseDnsServers(null).ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void CarriesTheNetworkServiceThroughTheAppliedPlan()
    {
        var value = MacDnsConfigurator.FormatPreviousManager("Thunderbolt Bridge");
        value.ShouldBe("networksetup:Thunderbolt Bridge");

        MacDnsConfigurator.TryParsePreviousManager(value, out var service).ShouldBeTrue();
        service.ShouldBe("Thunderbolt Bridge");

        // A manager name written by another platform is not mistaken for a service.
        MacDnsConfigurator.TryParsePreviousManager("systemd-resolved", out _).ShouldBeFalse();
        MacDnsConfigurator.TryParsePreviousManager("networksetup:", out _).ShouldBeFalse();
        MacDnsConfigurator.TryParsePreviousManager(null, out _).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void ResolverFilePathsCannotEscapeTheResolverDirectory()
    {
        MacDnsConfigurator.ResolverFilePath("corp.example").ShouldBe("/etc/resolver/corp.example");

        // A wildcard domain is expressed as the bare suffix: resolver(5) names files by domain.
        MacDnsConfigurator.ResolverFilePath("*.corp.example").ShouldBe("/etc/resolver/corp.example");

        // Path traversal is refused outright rather than sanitised.
        MacDnsConfigurator.IsSafeResolverDomain("../../etc/passwd").ShouldBeFalse();
        MacDnsConfigurator.IsSafeResolverDomain("corp/example").ShouldBeFalse();
        MacDnsConfigurator.IsSafeResolverDomain("corp\\example").ShouldBeFalse();
        MacDnsConfigurator.IsSafeResolverDomain("corp..example").ShouldBeFalse();
        MacDnsConfigurator.IsSafeResolverDomain(" ").ShouldBeFalse();
        Should.Throw<ArgumentException>(() => MacDnsConfigurator.ResolverFilePath("../evil"));
    }

    [FactOnNonMacOS]
    public void RendersAResolverFileWithTheMarkerAndTheDocumentedPortForm()
    {
        var servers = new[]
        {
            new DnsServerEntry { Address = "10.0.0.17" },
            new DnsServerEntry { Address = "10.0.0.18", Port = 5353 },
            new DnsServerEntry { Address = "2001:db8::1" },
            new DnsServerEntry { Address = "10.0.0.19" },
        };

        var rendered = MacDnsConfigurator.RenderResolverFile("corp.example", servers);

        rendered.ShouldStartWith(MacDnsConfigurator.ResolverFileMarker);
        rendered.ShouldContain("nameserver 10.0.0.17\n");

        // resolver(5): a non-standard port is written as a trailing dot followed by the port.
        rendered.ShouldContain("nameserver 10.0.0.18.5353\n");
        rendered.ShouldContain("nameserver 2001:db8::1\n");

        // MAXNS is three: the fourth server must not be listed.
        rendered.ShouldNotContain("10.0.0.19");

        MacDnsConfigurator.ContainsOwnedMarker(rendered).ShouldBeTrue();
        MacDnsConfigurator.ContainsOwnedMarker("nameserver 1.1.1.1\n").ShouldBeFalse();
        MacDnsConfigurator.ContainsOwnedMarker(null).ShouldBeFalse();
    }

    [FactOnNonMacOS]
    public void ParsesScutilDnsIntoSectionsAndFlags()
    {
        var resolvers = MacDnsConfigurator.ParseScutilDns(ScutilOutput);

        resolvers.Count.ShouldBe(3);

        var primary = resolvers[0];
        primary.Section.ShouldBe("DNS configuration");
        primary.NameServers.ShouldBe(new[] { "192.0.2.1" });
        primary.InterfaceName.ShouldBe("en0");
        primary.IsScoped.ShouldBeFalse();

        var scoped = resolvers[1];
        scoped.Section.ShouldBe("DNS configuration (for scoped queries)");
        scoped.IsScoped.ShouldBeTrue();
        scoped.InterfaceName.ShouldBe("utun3");

        var supplemental = resolvers[2];
        supplemental.Domain.ShouldBe("corp.example");
        supplemental.IsSupplemental.ShouldBeTrue();
        supplemental.IsServiceSpecific.ShouldBeTrue();

        // The search-domain line is not a nameserver.
        primary.NameServers.ShouldNotContain("lan");
        MacDnsConfigurator.ParseScutilDns(null).ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void ParsesTheInterfaceOutOfIfIndex()
    {
        MacDnsConfigurator.ParseInterfaceFromIfIndex("14 (en0)").ShouldBe("en0");
        MacDnsConfigurator.ParseInterfaceFromIfIndex("21 (utun3)").ShouldBe("utun3");
        MacDnsConfigurator.ParseInterfaceFromIfIndex("14").ShouldBeNull();
        MacDnsConfigurator.ParseInterfaceFromIfIndex(null).ShouldBeNull();
    }
}

/// <summary>Tests for the pure utun parsers and resolution rules.</summary>
public sealed class MacTunDeviceManagerPureTests
{
    private const string InterfaceList =
        "lo0 gif0 stf0 en0 en1 en2 bridge0 ap1 utun0 utun3 awdl0 llw0 utun12\n";

    private const string IfconfigOutput =
        "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
        + "\tinet 169.254.10.2 --> 169.254.10.1 netmask 0xfffffffc\n"
        + "\tinet6 fe80::1%utun3 prefixlen 64 scopeid 0x10\n"
        + "\tnd6 options=201<PERFORMNUD,DAD>\n";

    [FactOnNonMacOS]
    public void ListsOnlyUtunDevicesInNumericOrder()
    {
        var names = MacTunDeviceManager.ParseInterfaceList(InterfaceList);

        // Numeric, not lexicographic: utun12 comes after utun3.
        names.ShouldBe(new[] { "utun0", "utun3", "utun12" });
        MacTunDeviceManager.ParseInterfaceList(null).ShouldBeEmpty();
        MacTunDeviceManager.ParseInterfaceList("en0 lo0\n").ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public void ParsesIfconfigAddressesWithoutThePeerAddressOrZoneSuffix()
    {
        var addresses = MacTunDeviceManager.ParseIfconfigAddresses("utun3", IfconfigOutput);

        // The peer address after '-->' belongs to the other end of the point-to-point link, and the
        // %utun3 zone suffix is not part of the address.
        addresses.ShouldBe(new[] { "169.254.10.2/30", "fe80::1/64" });
        MacTunDeviceManager.ParseIfconfigAddresses("utun3", null).ShouldBeEmpty();
    }

    [TheoryOnNonMacOS]
    [InlineData("0xfffffffc", 30)]
    [InlineData("0xffffffff", 32)]
    [InlineData("0xffffff00", 24)]
    [InlineData("0x80000000", 1)]
    [InlineData("0x0", 0)]
    [InlineData("nonsense", -1)]
    public void ConvertsHexNetmasksToPrefixLengths(string netmask, int expected)
    {
        MacTunDeviceManager.PrefixLengthFromHexNetmask(netmask).ShouldBe(expected);
    }

    [FactOnNonMacOS]
    public void ResolutionPrefersTheRequestedNameThenTheOnlyCandidate()
    {
        var observations = new[]
        {
            new TunnelInterfaceObservation("utun0", new[] { "10.9.9.9/32" }),
            new TunnelInterfaceObservation("utun3", new[] { "169.254.10.2/30" }),
        };

        MacTunDeviceManager.ChooseTunnelInterface(observations, "utun3", null).ShouldBe("utun3");

        // With exactly one candidate there is nothing to disambiguate.
        MacTunDeviceManager.ChooseTunnelInterface(
            new[] { observations[0] }, "utun7", null).ShouldBe("utun0");
    }

    [FactOnNonMacOS]
    public void ResolutionIdentifiesTheTunnelByItsPointToPointAddress()
    {
        var observations = new[]
        {
            new TunnelInterfaceObservation("utun0", new[] { "10.9.9.9/32" }),
            new TunnelInterfaceObservation("utun3", new[] { "169.254.10.2/30" }),
        };

        var expected = CidrBlock.Parse(MacTunDeviceManager.DefaultTunnelAddressPrefix);

        MacTunDeviceManager.ChooseTunnelInterface(observations, preferredName: null, expected)
            .ShouldBe("utun3");
    }

    [FactOnNonMacOS]
    public void ResolutionRefusesToGuessWhenItIsAmbiguous()
    {
        var observations = new[]
        {
            new TunnelInterfaceObservation("utun0", new[] { "10.9.9.9/32" }),
            new TunnelInterfaceObservation("utun3", new[] { "10.10.10.10/32" }),
        };

        // Two utun devices, neither carrying the address MyVpn's tunnel should have. Picking one would
        // point the Kill Switch, the routes and DNS at another product's device.
        MacTunDeviceManager.ChooseTunnelInterface(
                observations, preferredName: null, CidrBlock.Parse(MacTunDeviceManager.DefaultTunnelAddressPrefix))
            .ShouldBeNull();

        MacTunDeviceManager.ChooseTunnelInterface(
                Array.Empty<TunnelInterfaceObservation>(), "utun0", null)
            .ShouldBeNull();
    }

    [FactOnNonMacOS]
    public void ValidatesInterfaceNames()
    {
        MacTunDeviceManager.TryGetSafeInterfaceName("utun0", out var safe).ShouldBeTrue();
        safe.ShouldBe("utun0");

        foreach (var bad in new[] { "-utun0", ".utun0", "utun 0", "utun0\n", "en0;rm", string.Empty, null })
        {
            MacTunDeviceManager.TryGetSafeInterfaceName(bad, out _).ShouldBeFalse(bad ?? "(null)");
        }

        Should.Throw<ArgumentException>(() => MacTunDeviceManager.ValidateInterfaceName("utun0; rm -rf /"));
    }
}

/// <summary>
/// Tests for the emergency cleanup manager.
/// </summary>
/// <remarks>
/// The property that matters most is that every step is attempted even when an earlier one fails: a
/// cleanup that stops at the first error is exactly the situation the user is trying to escape. The
/// collaborators here are scripted, so the test runs anywhere.
/// </remarks>
public sealed class MacNetworkStateManagerTests
{
    private readonly ITestOutputHelper _output;

    public MacNetworkStateManagerTests(ITestOutputHelper output) => _output = output;

    [FactOnNonMacOS]
    public async Task CleanupAttemptsEveryStepEvenWhenAnEarlierOneFails()
    {
        var proxy = new StubSystemProxy
        {
            OnReset = () => throw new InvalidOperationException("networksetup exploded"),
        };

        var dns = new StubDns
        {
            RemoveAllResult = Result.Fail(new MyVpnError(
                ErrorCodes.DnsRestoreFailed, "error.dns.restore_failed", ErrorSeverity.Critical, "resolver stuck")),
        };

        var killSwitch = new StubKillSwitch
        {
            RemoveResult = KillSwitchApplyResult.Failed(new MyVpnError(
                ErrorCodes.KillSwitchRemoveFailed,
                "error.killswitch.remove_failed",
                ErrorSeverity.Critical,
                "pfctl said no")),
        };

        var routes = new StubRoutes();
        var manager = new MacNetworkStateManager(
            MacTestData.MacRunner(), killSwitch, routes, dns, proxy, tun: null);

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.FullyClean.ShouldBeFalse();
        report.Steps.Count.ShouldBe(5);

        report.Steps.Select(s => s.Name).ShouldBe(new[]
        {
            MacNetworkStateManager.StepName.Proxy,
            MacNetworkStateManager.StepName.Dns,
            MacNetworkStateManager.StepName.KillSwitch,
            MacNetworkStateManager.StepName.Routes,
            MacNetworkStateManager.StepName.Interface,
        });

        // A throwing step is reported, not propagated.
        report.Steps[0].Succeeded.ShouldBeFalse();
        report.Steps[0].DetailKey.ShouldBe("error.network.cleanup_step_failed");
        report.Steps[0].TechnicalDetail!.ShouldContain("networksetup exploded");

        // The collaborator's own, more specific key wins over the generic step key.
        report.Steps[1].Succeeded.ShouldBeFalse();
        report.Steps[1].DetailKey.ShouldBe("error.dns.restore_failed");

        report.Steps[2].Succeeded.ShouldBeFalse();
        report.Steps[2].DetailKey.ShouldBe("error.killswitch.remove_failed");

        // Every collaborator was still called, which is the point.
        proxy.ResetCalls.ShouldBe(1);
        dns.RemoveAllCalls.ShouldBe(1);
        killSwitch.RemoveCalls.ShouldBe(1);
        routes.RemoveAllCalls.ShouldBe(1);

        foreach (var step in report.Steps)
        {
            _output.WriteLine($"{step.Name}: {step.Succeeded} {step.DetailKey} {step.TechnicalDetail}");
        }
    }

    [FactOnNonMacOS]
    public async Task CleanupIsIdempotentAndFullyCleanWhenEveryStepSucceeds()
    {
        var proxy = new StubSystemProxy();
        var dns = new StubDns();
        var killSwitch = new StubKillSwitch();
        var routes = new StubRoutes();
        var tun = new StubTun();

        var manager = new MacNetworkStateManager(
            MacTestData.MacRunner(), killSwitch, routes, dns, proxy, tun);

        var first = await manager.EmergencyCleanupAsync(CancellationToken.None);
        var second = await manager.EmergencyCleanupAsync(CancellationToken.None);

        first.FullyClean.ShouldBeTrue();
        second.FullyClean.ShouldBeTrue();

        first.Steps.ShouldAllBe(s => s.Succeeded);

        // The four collaborator steps report "completed"; the interface step reports "nothing to do"
        // because this host is not macOS and no utun was probed.
        first.Steps.Take(4).ShouldAllBe(s => s.DetailKey == "cleanup.step.completed");
        first.Steps[4].DetailKey.ShouldBe("cleanup.step.nothing_to_do");

        // Running it twice must be safe: crash recovery cannot know how far a previous attempt got.
        proxy.ResetCalls.ShouldBe(2);
        routes.RemoveAllCalls.ShouldBe(2);
    }

    [FactOnNonMacOS]
    public async Task CleanupWithNullCollaboratorsSucceedsAndSpawnsNothing()
    {
        var runner = MacTestData.MacRunner();

        // The manager must be constructible with nothing but a runner, and it must not throw.
        var manager = new MacNetworkStateManager(runner);
        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.FullyClean.ShouldBeTrue();
        report.Steps.Count.ShouldBe(5);
        report.Steps.ShouldAllBe(s => s.Succeeded);

        // Missing collaborators are "no manager", not a failure: reporting work that does not exist as a
        // failure would send the user chasing a problem they do not have.
        report.Steps.Take(4).ShouldAllBe(s => s.DetailKey == "cleanup.step.no_manager");

        // On this host the interface probe is skipped rather than running ifconfig.
        report.Steps[4].DetailKey.ShouldBe("cleanup.step.nothing_to_do");
        report.Steps[4].TechnicalDetail!.ShouldContain("Not macOS");

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task CleanupReportsCancellationWithoutStoppingTheRemainingSteps()
    {
        var proxy = new StubSystemProxy
        {
            OnReset = () => throw new OperationCanceledException(),
        };

        var routes = new StubRoutes();
        var manager = new MacNetworkStateManager(
            MacTestData.MacRunner(), new StubKillSwitch(), routes, new StubDns(), proxy, new StubTun());

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.Steps[0].Succeeded.ShouldBeFalse();
        report.Steps[0].DetailKey.ShouldBe("error.operation.cancelled");

        // A half-restored network is worse than a delayed one, so the rest still ran.
        routes.RemoveAllCalls.ShouldBe(1);
        report.Steps[4].Succeeded.ShouldBeTrue();
    }

    [FactOnNonMacOS]
    public async Task LeftoverDetectionReportsWhatItCheckedAndNeverThrows()
    {
        var runner = MacTestData.MacRunner();
        var manager = new MacNetworkStateManager(runner);

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.Any.ShouldBeFalse();

        // "Unknown" must never be reported as "clean".
        leftovers.Details.ShouldContain(d => d.Contains("no IKillSwitch is wired"));
        leftovers.Details.ShouldContain(d => d.Contains("no IRouteManager is wired"));
        leftovers.Details.ShouldContain(d => d.Contains("no IDnsConfigurator is wired"));
        leftovers.Details.ShouldContain(d => d.Contains("no ISystemProxy is wired"));

        runner.Calls.ShouldBeEmpty();
    }

    [FactOnNonMacOS]
    public async Task LeftoverDetectionSurfacesEveryArtefactItFinds()
    {
        var killSwitch = new StubKillSwitch
        {
            InspectResult = new KillSwitchState
            {
                IsArmed = true,
                IsDrifted = false,
                OrphanedRules = new[] { "rules from a previous run" },
                MechanismName = "pf",
            },
        };

        var routes = new StubRoutes
        {
            InspectResult = new RouteState
            {
                TunnelRoutesPresent = true,
                BypassRoutesPresent = false,
                OrphanedRoutes = new[] { "0.0.0.0/1 dev utun3" },
            },
        };

        var dns = new StubDns
        {
            InspectResult = new DnsState
            {
                ActiveServers = new[] { "10.8.0.1" },
                InterfaceName = "utun3",
                PlainDnsReachableOutsideTunnel = true,
                PotentialLeaks = new[] { "dns.leak.plaintext_outside_tunnel" },
            },
        };

        var proxy = new StubSystemProxy
        {
            InspectResult = new SystemProxyState
            {
                IsConfigured = true,
                ActiveProxy = "127.0.0.1:10809",
                PointsAtMyVpn = true,
            },
        };

        var manager = new MacNetworkStateManager(
            MacTestData.MacRunner(), killSwitch, routes, dns, proxy, new StubTun());

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.KillSwitchRulesPresent.ShouldBeTrue();
        leftovers.RoutesPresent.ShouldBeTrue();
        leftovers.DnsOverridden.ShouldBeTrue();
        leftovers.SystemProxySet.ShouldBeTrue();
        leftovers.Any.ShouldBeTrue();

        leftovers.Details.ShouldContain(d => d.Contains("rules from a previous run"));
        leftovers.Details.ShouldContain(d => d.Contains("0.0.0.0/1 dev utun3"));
        leftovers.Details.ShouldContain(d => d.Contains("dns.leak.plaintext_outside_tunnel"));
    }

    [FactOnNonMacOS]
    public async Task LeftoverDetectionDoesNotMistakeAUsersOwnProxyForOurs()
    {
        var proxy = new StubSystemProxy
        {
            InspectResult = new SystemProxyState
            {
                IsConfigured = true,
                ActiveProxy = "proxy.corp:3128",
                PointsAtMyVpn = false,
            },
        };

        var manager = new MacNetworkStateManager(
            MacTestData.MacRunner(), null, null, null, proxy, null);

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.SystemProxySet.ShouldBeFalse();
        leftovers.Details.ShouldContain(d => d.Contains("not pointing at MyVpn"));
    }

    // ------------------------------------------------------------------ scripted collaborators

    private sealed class StubKillSwitch : IKillSwitch
    {
        public string MechanismName => "stub";

        public bool IsSupported => false;

        public int RemoveCalls { get; private set; }

        public KillSwitchApplyResult RemoveResult { get; set; } = KillSwitchApplyResult.Ok();

        public KillSwitchState InspectResult { get; set; } = KillSwitchState.Disarmed;

        public Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(KillSwitchApplyResult.Ok());

        public Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
        {
            RemoveCalls++;
            return Task.FromResult(RemoveResult);
        }

        public Task<KillSwitchState> InspectAsync(
            KillSwitchPlan? expected,
            CancellationToken cancellationToken) => Task.FromResult(InspectResult);
    }

    private sealed class StubRoutes : IRouteManager
    {
        public bool IsSupported => false;

        public int RemoveAllCalls { get; private set; }

        public RouteState InspectResult { get; set; } = new()
        {
            TunnelRoutesPresent = false,
            BypassRoutesPresent = false,
        };

        public Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
        {
            RemoveAllCalls++;
            return Task.FromResult(Result.Ok());
        }

        public Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken) =>
            Task.FromResult(InspectResult);

        public Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Result<PhysicalUplink>.Ok(new PhysicalUplink("en0", "192.0.2.1")));
    }

    private sealed class StubDns : IDnsConfigurator
    {
        public bool IsSupported => false;

        public int RemoveAllCalls { get; private set; }

        public Result RemoveAllResult { get; set; } = Result.Ok();

        public DnsState InspectResult { get; set; } = new()
        {
            ActiveServers = Array.Empty<string>(),
            InterfaceName = null,
            PlainDnsReachableOutsideTunnel = false,
        };

        public Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result<DnsPlan>.Ok(plan));

        public Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
        {
            RemoveAllCalls++;
            return Task.FromResult(RemoveAllResult);
        }

        public Task<DnsState> InspectAsync(CancellationToken cancellationToken) =>
            Task.FromResult(InspectResult);
    }

    private sealed class StubSystemProxy : ISystemProxy
    {
        public bool IsSupported => false;

        public int ResetCalls { get; private set; }

        public Action? OnReset { get; set; }

        public SystemProxyState InspectResult { get; set; } = new() { IsConfigured = false };

        public Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Result<SystemProxySnapshot>.Ok(new SystemProxySnapshot()));

        public Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> ResetAsync(CancellationToken cancellationToken)
        {
            ResetCalls++;
            OnReset?.Invoke();
            return Task.FromResult(Result.Ok());
        }

        public Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken) =>
            Task.FromResult(InspectResult);
    }

    private sealed class StubTun : ITunDeviceManager
    {
        public bool IsSupported => false;

        public string DefaultInterfaceName => "utun0";

        public Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<IReadOnlyList<string>> GetAddressesAsync(
            string interfaceName,
            CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
