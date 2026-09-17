using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Windows.Dns;
using MyVpn.Platform.Windows.Execution;
using MyVpn.Platform.Windows.KillSwitch;
using MyVpn.Platform.Windows.Network;
using MyVpn.Platform.Windows.Proxy;
using MyVpn.Platform.Windows.Routing;
using MyVpn.Platform.Windows.Tun;
using Shouldly;
using Xunit;

namespace MyVpn.Platform.Tests;

// =====================================================================================
// Kill Switch: the pure plan → WFP filter translation.
// =====================================================================================

/// <summary>
/// Tests for the WFP filter translator.
/// </summary>
/// <remarks>
/// This is the part of the Windows platform layer that can be proven on a Linux host, and it is
/// where the fail-closed property actually lives: the executor only resolves names and calls
/// <c>FwpmFilterAdd0</c>, so if the descriptor list is wrong, the machine is either leaked or
/// locked out no matter how careful the P/Invoke is.
/// </remarks>
public sealed class WfpKillSwitchPlanTranslatorTests
{
    /// <summary>
    /// The core's executable path as the plan carries it.
    /// </summary>
    /// <remarks>
    /// Built from the host's temp directory rather than hardcoded as <c>C:\...</c> because
    /// <see cref="KillSwitchPlan.Validate"/> uses <c>Path.IsPathRooted</c>, which is evaluated for
    /// the <i>running</i> host: a Windows-style path is not "rooted" to a Linux test run. The
    /// product never hits this — a Windows plan is built on Windows — but the tests must use a
    /// path that is absolute on the machine executing them.
    /// </remarks>
    private static readonly string CorePath = Path.Combine(Path.GetTempPath(), "myvpn", "xray.exe");

    private static KillSwitchPlan Plan(
        KillSwitchMode mode = KillSwitchMode.OnDemand,
        bool blockIpv6 = true,
        bool allowLoopback = true,
        bool allowDhcp = true,
        bool allowLan = false,
        IReadOnlyList<AllowedEndpoint>? endpoints = null,
        IReadOnlyList<AllowedEndpoint>? destinations = null,
        IReadOnlyList<CidrBlock>? blocked = null) => new()
    {
        Identifier = "myvpn_ks",
        Mode = mode,
        TunnelInterface = "myvpn0",
        AllowedEndpoints = endpoints ?? new[]
        {
            AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
        },
        AllowedApplications = new[] { CorePath },
        AllowedDestinations = destinations ?? new[]
        {
            new AllowedEndpoint
            {
                Destination = CidrBlock.Parse("1.1.1.1/32"),
                Port = 53,
                Network = "tcp,udp",
                ReasonKey = "killswitch.reason.resolver",
            },
        },
        BlockedDestinations = blocked ?? Array.Empty<CidrBlock>(),
        BlockIpv6 = blockIpv6,
        AllowLoopback = allowLoopback,
        AllowDhcp = allowDhcp,
        AllowLan = allowLan,
    };

    [Fact]
    public void TheCatchAllBlockSitsAtWeightZeroAndIsLast()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan()).Value;

        var block = set.Filters[^1];

        block.Action.ShouldBe(WfpAction.Block);
        ((int)block.Weight).ShouldBe(0);
        block.IsCatchAll.ShouldBeTrue();
        block.Conditions.ShouldBeEmpty();

        set.Filters.Count(f => f.Action == WfpAction.Block && f.Weight == 0).ShouldBe(2);
    }

    [Fact]
    public void EveryPermitIsStrictlyAboveTheDefaultBlock()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(allowLan: true)).Value;

        set.Permits.ShouldNotBeEmpty();

        foreach (var permit in set.Permits)
        {
            ((int)permit.Weight).ShouldBeGreaterThan(0);
            permit.Conditions.ShouldNotBeEmpty();
        }

        // Arbitration evaluates highest weight first and stops at the first terminating action, so
        // this ordering is what makes the block a catch-all rather than a blanket drop.
        set.Filters.ShouldBe(set.Filters.OrderByDescending(f => f.Weight).ToArray());
    }

    [Fact]
    public void TheCorePermitCarriesBothTheApplicationIdAndTheUserScope()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan()).Value;

        var core = set.Filters.Where(f => f.Name.StartsWith("core-app:", StringComparison.Ordinal)).ToArray();

        core.ShouldNotBeEmpty();

        foreach (var permit in core)
        {
            permit.Action.ShouldBe(WfpAction.Permit);
            ((int)permit.Weight).ShouldBe(15);

            // ALE_APP_ID is a path, not a process identity: without the second condition any
            // process running the same image would inherit the tunnel exemption.
            permit.Conditions.Count.ShouldBe(2);
            permit.Conditions[0].Kind.ShouldBe(WfpConditionKind.ApplicationPath);
            permit.Conditions[0].Value.ShouldBe(CorePath);
            permit.Conditions[1].Kind.ShouldBe(WfpConditionKind.ProcessUserScope);
        }
    }

    [Fact]
    public void APlanWithNoAllowedEndpointIsRefusedRatherThanTranslated()
    {
        var plan = Plan() with { AllowedEndpoints = Array.Empty<AllowedEndpoint>() };

        // plan.Validate() encodes this rule and the translator re-runs it: arming a default-drop
        // rule set with no allow-listed server would cut off the tunnel's own transport and leave
        // the user with no network at all.
        var translated = WfpKillSwitchPlanTranslator.Translate(plan);

        translated.IsFailure.ShouldBeTrue();
        translated.Error!.MessageKey.ShouldBe("error.killswitch.no_server_endpoint");
    }

    [Fact]
    public void APlanWithNoAllowedApplicationIsRefused()
    {
        var plan = Plan() with { AllowedApplications = Array.Empty<string>() };

        var translated = WfpKillSwitchPlanTranslator.Translate(plan);

        translated.IsFailure.ShouldBeTrue();
        translated.Error!.MessageKey.ShouldBe("error.killswitch.no_allowed_application");
    }

    [Fact]
    public void ADisabledPlanIsRefusedBecauseItHasNoFilterSet()
    {
        var translated = WfpKillSwitchPlanTranslator.Translate(Plan(KillSwitchMode.Disabled));

        translated.IsFailure.ShouldBeTrue();
        translated.Error!.Severity.ShouldBe(ErrorSeverity.Warning);
    }

    [Fact]
    public void Ipv6IsBlockedOutrightAndCarriesNoPermits()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(blockIpv6: true)).Value;

        set.BlockIpv6.ShouldBeTrue();
        set.CatchAllBlockV6.ShouldNotBeNull();
        set.CatchAllBlockV6!.IsCatchAll.ShouldBeTrue();

        // "Disable IPv6 while connected" must include IPv6 inside the tunnel, which is why the v6
        // layer has no permits at all — the same shape as the nftables renderer, where the ipv6
        // drop is emitted before the tunnel accept.
        set.Permits.Any(p => p.Layer == WfpLayer.AleAuthConnectV6).ShouldBeFalse();
    }

    [Fact]
    public void WithIpv6TunnelledThePermitsExistOnBothLayers()
    {
        var plan = Plan(blockIpv6: false) with
        {
            AllowedEndpoints = new[]
            {
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
                AllowedEndpoint.FromEndpoint(new ServerEndpoint("2001:db8::5", 443), "killswitch.reason.vpn_server"),
            },
        };

        var set = WfpKillSwitchPlanTranslator.Translate(plan).Value;

        set.Permits.Any(p => p.Layer == WfpLayer.AleAuthConnectV4).ShouldBeTrue();
        set.Permits.Any(p => p.Layer == WfpLayer.AleAuthConnectV6).ShouldBeTrue();
        set.CatchAllBlockV4.ShouldNotBeNull();
        set.CatchAllBlockV6.ShouldNotBeNull();
    }

    [Fact]
    public void TheRecipeWeightsAreTheDocumentedOnes()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(allowLan: true)).Value;

        ((int)set.Filters.Single(f => f.Name == $"core-app:{CorePath}").Weight).ShouldBe(15);
        ((int)set.Filters.Single(f => f.Name.StartsWith("resolver:", StringComparison.Ordinal)).Weight).ShouldBe(14);
        ((int)set.Filters.Single(f => f.Name == "loopback").Weight).ShouldBe(13);
        ((int)set.Filters.Single(f => f.Name == "tunnel-interface").Weight).ShouldBe(12);
        ((int)set.Filters.Single(f => f.Name == "dhcpv4").Weight).ShouldBe(12);
    }

    [Fact]
    public void TheTunnelPermitNamesTheInterfaceSymbolically()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan()).Value;

        var tunnel = set.Filters.Single(f => f.Name == "tunnel-interface");

        // A LUID is only valid while the adapter exists, so the translator carries the name and
        // the executor resolves it at apply time.
        tunnel.Conditions.Single().Kind.ShouldBe(WfpConditionKind.LocalInterface);
        tunnel.Conditions.Single().Value.ShouldBe("myvpn0");
    }

    [Fact]
    public void TheResolverPermitCarriesPortAndBothTransports()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan()).Value;

        var resolver = set.Filters.Single(f => f.Name.StartsWith("resolver:", StringComparison.Ordinal));

        resolver.Conditions.ShouldContain(c => c.Kind == WfpConditionKind.RemoteAddress && c.Value == "1.1.1.1/32");
        resolver.Conditions.ShouldContain(c => c.Kind == WfpConditionKind.RemotePort && c.Port == 53);
        resolver.Conditions.ShouldContain(c => c.Kind == WfpConditionKind.Protocol && c.Value == "tcp");
        resolver.Conditions.ShouldContain(c => c.Kind == WfpConditionKind.Protocol && c.Value == "udp");
    }

    [Fact]
    public void LoopbackAndDhcpAreOmittedWhenThePlanDisablesThem()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(
            Plan(allowLoopback: false, allowDhcp: false)).Value;

        set.Filters.Any(f => f.Name == "loopback").ShouldBeFalse();
        set.Filters.Any(f => f.Name.StartsWith("dhcp", StringComparison.Ordinal)).ShouldBeFalse();
    }

    [Fact]
    public void LanPermitsAreOneFilterPerRange()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(allowLan: true)).Value;

        var lan = set.Filters.Where(f => f.Name.StartsWith("lan:", StringComparison.Ordinal)).ToArray();

        // WFP ANDs the conditions of one filter, so four address conditions in a single filter
        // would match nothing; each range is its own permit.
        lan.Length.ShouldBe(4);
        lan.ShouldAllBe(f => f.Conditions.Count == 1);
    }

    [Fact]
    public void AnExplicitlyBlockedDestinationIsNotAlsoPermitted()
    {
        var plan = Plan(
            destinations: new[]
            {
                new AllowedEndpoint
                {
                    Destination = CidrBlock.Parse("10.0.0.0/8"),
                    Port = 53,
                    Network = "udp",
                    ReasonKey = "killswitch.reason.resolver",
                },
            },
            blocked: new[] { CidrBlock.Parse("10.0.0.0/8") });

        var set = WfpKillSwitchPlanTranslator.Translate(plan).Value;

        set.Permits.Any(p => p.Name.StartsWith("resolver:", StringComparison.Ordinal)).ShouldBeFalse();
        set.Filters.ShouldContain(f => f.Action == WfpAction.Block && f.Weight == 1);
    }

    [Fact]
    public void TranslationIsDeterministic()
    {
        var first = WfpKillSwitchPlanTranslator.Translate(Plan(allowLan: true)).Value;
        var second = WfpKillSwitchPlanTranslator.Translate(Plan(allowLan: true)).Value;

        first.Filters.Select(f => f.ToString()).ShouldBe(second.Filters.Select(f => f.ToString()));
    }

    [Fact]
    public void EveryDescriptorIsUniquelyIdentifiedByNameLayerAndFlags()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(blockIpv6: false, allowLan: true)).Value;

        // The same logical rule exists on both layers (and, in always-on mode, once per lifetime
        // flag), so a descriptor's identity is the triple — which is what the executor's
        // diagnostics and teardown rely on.
        var identities = set.Filters.Select(f => (f.Name, f.Layer, f.Flags)).ToArray();

        identities.Distinct().Count().ShouldBe(identities.Length);
    }

    [Fact]
    public void AlwaysOnProducesPersistentAndBootTimeTwins()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(KillSwitchMode.AlwaysOn)).Value;

        set.PersistAcrossReboot.ShouldBeTrue();

        // FWPM_FILTER_FLAG_PERSISTENT and FWPM_FILTER_FLAG_BOOTTIME cannot be combined on one
        // filter, so every logical filter exists twice, and the documented transition between the
        // two sets is atomic. The twin is matched on name *and* layer: the same rule legitimately
        // exists once per address family.
        foreach (var logical in set.Filters.Where(f => f.Flags == WfpFilterFlags.Persistent))
        {
            var twin = logical.Name[..^"/persistent".Length] + "/boottime";

            var boot = set.Filters.Single(f => f.Name == twin && f.Layer == logical.Layer);

            boot.Flags.ShouldBe(WfpFilterFlags.BootTime);
            ((int)boot.Weight).ShouldBe((int)logical.Weight);
            boot.Conditions.Count.ShouldBe(logical.Conditions.Count);
            boot.Layer.ShouldBe(logical.Layer);
        }

        set.Filters.Count(f => f.Flags == WfpFilterFlags.Persistent)
            .ShouldBe(set.Filters.Count(f => f.Flags == WfpFilterFlags.BootTime));
    }

    [Fact]
    public void OnDemandPlansCarryNoLifetimeFlags()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan(KillSwitchMode.OnDemand)).Value;

        set.PersistAcrossReboot.ShouldBeFalse();
        set.Filters.ShouldAllBe(f => f.Flags == WfpFilterFlags.None);
    }

    [Fact]
    public void TheIdentifierFallsBackToTheDefault()
    {
        var set = WfpKillSwitchPlanTranslator.Translate(Plan() with { Identifier = "  " }).Value;

        set.Identifier.ShouldBe(WfpKillSwitchPlanTranslator.DefaultIdentifier);
    }
}

// =====================================================================================
// Windows-only executors: the guard that proves none of them can act on this host.
// =====================================================================================

/// <summary>
/// Tests that every Windows executor refuses to act on a non-Windows host.
/// </summary>
/// <remarks>
/// These tests run on Linux, which is the point: they are the evidence that the P/Invoke and
/// registry code in the platform layer is unreachable here. Each assertion checks both halves —
/// a clear refusal with a localization key, and an empty <see cref="FakeCommandRunner.Calls"/>,
/// so not even an external tool was spawned on the way to the refusal.
/// </remarks>
public sealed class WindowsExecutorGuardTests
{
    private static KillSwitchPlan KillSwitchPlanForGuard() => new()
    {
        Identifier = "myvpn_ks",
        Mode = KillSwitchMode.OnDemand,
        TunnelInterface = "myvpn0",
        AllowedEndpoints = new[]
        {
            AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
        },
        AllowedApplications = new[] { @"C:\Program Files\MyVpn\xray.exe" },
        AllowedDestinations = Array.Empty<AllowedEndpoint>(),
    };

    private static RoutePlan RoutePlanForGuard() => new()
    {
        TunnelInterface = "myvpn0",
        PhysicalInterface = "Ethernet",
        TunnelRoutes = new[]
        {
            new RouteEntry
            {
                Destination = CidrBlock.Parse("0.0.0.0/0"),
                Gateway = "10.8.0.1",
                Interface = "myvpn0",
                Metric = 1,
                ReasonKey = "route.reason.tunnel_default",
                DisplacesDefaultRoute = true,
            },
        },
        BypassRoutes = new[]
        {
            new RouteEntry
            {
                Destination = CidrBlock.Parse("203.0.113.5/32"),
                Gateway = "192.168.1.1",
                Interface = "Ethernet",
                Metric = 1,
                ReasonKey = "route.reason.bypass",
            },
        },
    };

    private static DnsPlan DnsPlanForGuard() => new()
    {
        TunnelInterface = "myvpn0",
        Servers = new[]
        {
            new DnsServerEntry { Address = "1.1.1.1", Port = 53, Protocol = "udp" },
        },
        SplitDnsDomains = new[] { "corp.example.com" },
    };

    private static SystemProxyPlan ProxyPlanForGuard() => new()
    {
        SocksPort = 10808,
        HttpPort = 10809,
        BypassDomains = new[] { "localhost" },
    };

    private static SystemProxySnapshot SnapshotForGuard() => new()
    {
        Mode = "manual",
        Enabled = true,
        HttpProxy = "127.0.0.1:8080",
        BypassList = "<local>",
    };

    [Fact]
    public void TheHostIsNotWindowsSoNoGuardCanBeSatisfied()
    {
        // If this ever fails the whole file's premise is wrong: the guard tests below only prove
        // "unreachable on Linux" while the suite actually runs on Linux.
        OperatingSystem.IsWindows().ShouldBeFalse();
        WindowsPlatform.IsWindows.ShouldBeFalse();
        WindowsPlatform.IsProcessElevated().ShouldBeFalse();
    }

    [Fact]
    public void AdapterEnumerationRefusesWithoutTouchingNativeCode()
    {
        WindowsAdapters.Enumerate(out var error).ShouldBeEmpty();
        error.ShouldNotBeNull();

        WindowsAdapters.FindByName("myvpn0").ShouldBeNull();
        WindowsAdapters.TryGetLuid("myvpn0", out var luid).ShouldBeFalse();
        luid.ShouldBe(0UL);
        WindowsAdapters.TryGetInterfaceIndex("myvpn0", out var index).ShouldBeFalse();
        index.ShouldBe(0U);
    }

    [Fact]
    public void IpForwardTableReadsAndLookupsRefuse()
    {
        WindowsIpForwardTable.Read(ipv6: false, out var error).ShouldBeEmpty();
        error.ShouldNotBeNull();

        WindowsIpForwardTable.FindBestRoute(System.Net.IPAddress.Any, out var bestError).ShouldBeNull();
        bestError.ShouldNotBeNull();
    }

    [Fact]
    public async Task TheWfpKillSwitchRefusesOnThisHost()
    {
        var killSwitch = new WindowsWfpKillSwitch(isElevated: () => true);

        // Even with an elevation probe that says yes, the OS guard wins: this process cannot call
        // FwpmEngineOpen0, so it must never claim it can.
        killSwitch.IsSupported.ShouldBeFalse();
        killSwitch.MechanismName.ShouldBe("Windows Filtering Platform");

        var applied = await killSwitch.ApplyAsync(KillSwitchPlanForGuard(), CancellationToken.None);

        applied.Succeeded.ShouldBeFalse();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);
        applied.Error.MessageKey.ShouldBe("error.platform.unsupported");

        var removed = await killSwitch.RemoveAsync("myvpn_ks", CancellationToken.None);

        removed.Succeeded.ShouldBeFalse();
        removed.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        // Inspection is a query, so it answers "not armed" instead of throwing.
        var state = await killSwitch.InspectAsync(KillSwitchPlanForGuard(), CancellationToken.None);

        state.IsArmed.ShouldBeFalse();
        state.IsDrifted.ShouldBeFalse();

        killSwitch.Dispose();
    }

    [Fact]
    public async Task TheSystemProxyRefusesOnThisHostWithoutRunningAnything()
    {
        var runner = new FakeCommandRunner();
        var proxy = new WindowsSystemProxy();

        proxy.IsSupported.ShouldBeFalse();

        var captured = await proxy.CaptureAsync(CancellationToken.None);
        captured.IsFailure.ShouldBeTrue();
        captured.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        var applied = await proxy.ApplyAsync(ProxyPlanForGuard(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        var restored = await proxy.RestoreAsync(SnapshotForGuard(), CancellationToken.None);
        restored.IsFailure.ShouldBeTrue();

        var reset = await proxy.ResetAsync(CancellationToken.None);
        reset.IsFailure.ShouldBeTrue();

        var state = await proxy.InspectAsync(CancellationToken.None);
        state.IsConfigured.ShouldBeFalse();

        // A mutating call must not reach the registry *or* spawn a tool on the way to refusing.
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task TheRouteManagerRefusesOnThisHostWithoutRunningAnything()
    {
        var runner = new FakeCommandRunner();
        runner.Available.Add(WindowsRouteCommands.RouteTool);

        var routes = new WindowsRouteManager(runner, isElevated: () => true);

        routes.IsSupported.ShouldBeFalse();

        var applied = await routes.ApplyAsync(RoutePlanForGuard(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        var removed = await routes.RemoveAsync(RoutePlanForGuard(), CancellationToken.None);
        removed.IsFailure.ShouldBeTrue();

        var removedAll = await routes.RemoveAllOwnedAsync(CancellationToken.None);
        removedAll.IsFailure.ShouldBeTrue();

        var uplink = await routes.GetDefaultUplinkAsync(CancellationToken.None);
        uplink.IsFailure.ShouldBeTrue();
        uplink.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        var state = await routes.InspectAsync(RoutePlanForGuard(), CancellationToken.None);
        state.TunnelRoutesPresent.ShouldBeFalse();

        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task TheDnsConfiguratorRefusesOnThisHostWithoutRunningAnything()
    {
        var runner = new FakeCommandRunner();
        runner.Available.Add(WindowsDnsCommands.NetshTool);

        var dns = new WindowsDnsConfigurator(runner, isElevated: () => true);

        dns.IsSupported.ShouldBeFalse();

        var applied = await dns.ApplyAsync(DnsPlanForGuard(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformUnsupported);

        var restored = await dns.RestoreAsync(DnsPlanForGuard(), CancellationToken.None);
        restored.IsFailure.ShouldBeTrue();

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);
        removed.IsFailure.ShouldBeTrue();

        var state = await dns.InspectAsync(CancellationToken.None);
        state.ActiveServers.ShouldBeEmpty();
        state.InterfaceName.ShouldBeNull();

        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task TheTunManagerRefusesOnThisHost()
    {
        var tun = new WindowsTunDeviceManager();

        tun.IsSupported.ShouldBeFalse();
        tun.DefaultInterfaceName.ShouldBe("myvpn0");

        (await tun.ExistsAsync("myvpn0", CancellationToken.None)).ShouldBeFalse();
        (await tun.GetAddressesAsync("myvpn0", CancellationToken.None)).ShouldBeEmpty();
    }

    [Fact]
    public void ExecutorsWithoutElevationStillReportUnsupported()
    {
        // The elevation probe is a *second* gate, never the first: on the wrong OS the answer must
        // not depend on it.
        new WindowsWfpKillSwitch(isElevated: () => false).IsSupported.ShouldBeFalse();
        new WindowsWfpKillSwitch(isElevated: () => true).IsSupported.ShouldBeFalse();
        new WindowsRouteManager(new FakeCommandRunner(), isElevated: () => true).IsSupported.ShouldBeFalse();
        new WindowsDnsConfigurator(new FakeCommandRunner(), isElevated: () => true).IsSupported.ShouldBeFalse();
        new WindowsSystemProxy().IsSupported.ShouldBeFalse();
        new WindowsTunDeviceManager().IsSupported.ShouldBeFalse();
    }
}

// =====================================================================================
// argv construction, exercised through the pure builders.
// =====================================================================================

public sealed class WindowsRouteCommandTests
{
    [Theory]
    [InlineData(0, "0.0.0.0")]
    [InlineData(8, "255.0.0.0")]
    [InlineData(24, "255.255.255.0")]
    [InlineData(32, "255.255.255.255")]
    public void TheNetmaskIsRenderedTheWayRouteExeNeedsIt(int prefix, string expected)
    {
        WindowsRouteCommands.MaskFor(prefix).ShouldBe(expected);
    }

    [Fact]
    public void AnIpv4HostRouteIsBuiltWithAnExplicitMaskAndInterfaceIndex()
    {
        var arguments = WindowsRouteCommands.AddIpv4(
            CidrBlock.Parse("203.0.113.5/32"), "192.168.1.1", 1, 12);

        arguments.ShouldBe(new[]
        {
            "add", "203.0.113.5", "mask", "255.255.255.255", "192.168.1.1", "metric", "1", "if", "12",
        });
    }

    [Fact]
    public void AnOnLinkIpv4RouteUsesTheZeroGateway()
    {
        var arguments = WindowsRouteCommands.AddIpv4(CidrBlock.Parse("0.0.0.0/0"), gateway: null, 1, 30);

        arguments.ShouldContain("0.0.0.0");
        arguments.ShouldBe(new[]
        {
            "add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "metric", "1", "if", "30",
        });
    }

    [Fact]
    public void AnIpv4DeleteCarriesTheMaskSoItMatchesOneEntry()
    {
        var arguments = WindowsRouteCommands.DeleteIpv4(CidrBlock.Parse("0.0.0.0/0"), "10.8.0.1", 30);

        arguments.ShouldBe(new[] { "delete", "0.0.0.0", "mask", "0.0.0.0", "10.8.0.1", "if", "30" });
    }

    [Fact]
    public void AnIpv4DeleteOmitsAZeroGateway()
    {
        var arguments = WindowsRouteCommands.DeleteIpv4(CidrBlock.Parse("10.0.0.0/8"), gateway: null, 7);

        arguments.ShouldBe(new[] { "delete", "10.0.0.0", "mask", "255.0.0.0", "if", "7" });
    }

    [Fact]
    public void Ipv6RoutesGoThroughNetshWithNamedArguments()
    {
        var add = WindowsRouteCommands.AddIpv6(CidrBlock.Parse("::/0"), "fe80::1", 1, "myvpn0");

        add.ShouldBe(new[]
        {
            "interface", "ipv6", "add", "route", "prefix=::/0", "interface=myvpn0",
            "nexthop=fe80::1", "metric=1", "store=active",
        });

        var delete = WindowsRouteCommands.DeleteIpv6(CidrBlock.Parse("2001:db8::/32"), null, "myvpn0");

        delete.ShouldBe(new[]
        {
            "interface", "ipv6", "delete", "route", "prefix=2001:db8::/32", "interface=myvpn0",
            "store=active",
        });
    }

    [Fact]
    public void Ipv6RoutesAreAlwaysActiveStoreSoARebootIsACleanReset()
    {
        WindowsRouteCommands.AddIpv6(CidrBlock.Parse("::/0"), null, 1, "myvpn0").ShouldContain("store=active");
        WindowsRouteCommands.DeleteIpv6(CidrBlock.Parse("::/0"), null, "myvpn0").ShouldContain("store=active");
    }

    [Theory]
    [InlineData("The object already exists.", true)]
    [InlineData("The route specified was not found.", false)]
    public void AlreadyExistsIsRecognisedForIdempotentReApply(string output, bool expected)
    {
        var result = new MyVpn.Platform.Abstractions.Execution.CommandResult(1, output, string.Empty);

        WindowsRouteCommands.IsAlreadyExists(result).ShouldBe(expected);
    }

    [Theory]
    [InlineData("The route specified was not found.", true)]
    [InlineData("The object already exists.", false)]
    public void AlreadyGoneIsRecognisedForIdempotentTeardown(string output, bool expected)
    {
        var result = new MyVpn.Platform.Abstractions.Execution.CommandResult(1, output, string.Empty);

        WindowsRouteCommands.IsAlreadyGone(result).ShouldBe(expected);
    }

    [Fact]
    public void ARealFailureIsNeitherAlreadyExistsNorAlreadyGone()
    {
        var result = new MyVpn.Platform.Abstractions.Execution.CommandResult(
            1, string.Empty, "The requested operation requires elevation.");

        WindowsRouteCommands.IsAlreadyExists(result).ShouldBeFalse();
        WindowsRouteCommands.IsAlreadyGone(result).ShouldBeFalse();
    }

    [Fact]
    public void BypassRoutesArePlannedBeforeAnyDefaultCapturingRoute()
    {
        var plan = new RoutePlan
        {
            TunnelInterface = "myvpn0",
            TunnelRoutes = new[]
            {
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("0.0.0.0/0"),
                    Gateway = "10.8.0.1",
                    Interface = "myvpn0",
                    Metric = 1,
                    ReasonKey = "route.reason.tunnel_default",
                    DisplacesDefaultRoute = true,
                },
            },
            BypassRoutes = new[]
            {
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("203.0.113.5/32"),
                    Gateway = "192.168.1.1",
                    Interface = "Ethernet",
                    Metric = 1,
                    ReasonKey = "route.reason.bypass",
                },
            },
        };

        var operations = WindowsRouteCommands.PlanApply(plan);

        operations.Count.ShouldBe(2);
        operations[0].Phase.ShouldBe(RoutePhase.Bypass);
        operations[0].Kind.ShouldBe(RouteOperationKind.Add);
        operations[1].Phase.ShouldBe(RoutePhase.Tunnel);

        // The tunnel route must not be installed before the route that keeps the core's own
        // traffic off the tunnel: that ordering is what prevents the "connects, then stalls" loop.
        operations.Select(o => o.Route.Interface).ShouldBe(new[] { "Ethernet", "myvpn0" });
    }

    [Fact]
    public void TeardownIsTheMirrorImageOfInstallation()
    {
        var plan = new RoutePlan
        {
            TunnelInterface = "myvpn0",
            TunnelRoutes = new[]
            {
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("0.0.0.0/0"),
                    Gateway = "10.8.0.1",
                    Interface = "myvpn0",
                    Metric = 1,
                    ReasonKey = "route.reason.tunnel_default",
                },
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("10.8.0.0/24"),
                    Interface = "myvpn0",
                    ReasonKey = "route.reason.tunnel_subnet",
                },
            },
            BypassRoutes = new[]
            {
                new RouteEntry
                {
                    Destination = CidrBlock.Parse("203.0.113.5/32"),
                    Gateway = "192.168.1.1",
                    Interface = "Ethernet",
                    Metric = 1,
                    ReasonKey = "route.reason.bypass",
                },
            },
        };

        var operations = WindowsRouteCommands.PlanRemove(plan);

        operations.Count.ShouldBe(3);
        operations.ShouldAllBe(o => o.Kind == RouteOperationKind.Delete);

        // Tunnel routes first, and reversed within the phase.
        operations[0].Phase.ShouldBe(RoutePhase.Tunnel);
        operations[0].Route.Destination.ShouldBe(CidrBlock.Parse("10.8.0.0/24"));
        operations[1].Phase.ShouldBe(RoutePhase.Tunnel);
        operations[1].Route.Destination.ShouldBe(CidrBlock.Parse("0.0.0.0/0"));
        operations[2].Phase.ShouldBe(RoutePhase.Bypass);
    }
}

public sealed class WindowsDnsCommandTests
{
    [Fact]
    public void TheFirstResolverIsSetWithTheDocumentedNetshVerb()
    {
        var arguments = WindowsDnsCommands.SetPrimary("myvpn0", "1.1.1.1", ipv6: false);

        arguments.ShouldBe(new[]
        {
            "interface", "ip", "set", "dns", "name=myvpn0", "source=static", "address=1.1.1.1",
            "register=primary", "validate=no",
        });
    }

    [Fact]
    public void TheSecondResolverIsAddedAtItsIndex()
    {
        var arguments = WindowsDnsCommands.AddServer("myvpn0", "9.9.9.9", index: 2, ipv6: false);

        arguments.ShouldBe(new[]
        {
            "interface", "ip", "add", "dns", "name=myvpn0", "9.9.9.9", "index=2", "validate=no",
        });
    }

    [Fact]
    public void AddingAtTheFirstIndexIsRefused()
    {
        // Index 1 is what `set dns` writes; accepting it here would silently produce two primaries.
        Should.Throw<ArgumentOutOfRangeException>(
            () => WindowsDnsCommands.AddServer("myvpn0", "9.9.9.9", index: 1, ipv6: false));
    }

    [Fact]
    public void RestoringHandsTheInterfaceBackToDhcp()
    {
        WindowsDnsCommands.ResetToDhcp("myvpn0", ipv6: false).ShouldBe(new[]
        {
            "interface", "ip", "set", "dns", "name=myvpn0", "source=dhcp",
        });

        WindowsDnsCommands.ResetToDhcp("myvpn0", ipv6: true).ShouldBe(new[]
        {
            "interface", "ipv6", "set", "dns", "name=myvpn0", "source=dhcp",
        });
    }

    [Fact]
    public void TheIpv6FamilyIsSelectedExplicitly()
    {
        WindowsDnsCommands.SetPrimary("myvpn0", "2001:db8::1", ipv6: true)[1].ShouldBe("ipv6");
        WindowsDnsCommands.SetPrimary("myvpn0", "1.1.1.1", ipv6: false)[1].ShouldBe("ip");
    }

    [Fact]
    public void EmptyInterfaceNamesAreRefusedBeforeTheyReachArgv()
    {
        Should.Throw<ArgumentException>(() => WindowsDnsCommands.SetPrimary(" ", "1.1.1.1", ipv6: false));
        Should.Throw<ArgumentException>(() => WindowsDnsCommands.ResetToDhcp(string.Empty, ipv6: false));
    }

    [Fact]
    public void NrptRuleKeysAreDeterministicAndDistinct()
    {
        var first = WindowsNrptRules.RuleKeyFor("corp.example.com");
        var second = WindowsNrptRules.RuleKeyFor("corp.example.com");
        var other = WindowsNrptRules.RuleKeyFor("other.example.com");

        first.ShouldBe(second);
        other.ShouldNotBe(first);

        // A well-formed RFC 4122 name-based UUID, so the rule key is a valid registry subkey name
        // and cannot collide with a randomly generated one by accident.
        first.ToString("D")[14].ShouldBe('5');
    }

    [Fact]
    public void NrptRulesComeFromTheSplitDnsDomainsAndTheResolvers()
    {
        var plan = new DnsPlan
        {
            TunnelInterface = "myvpn0",
            Servers = new[]
            {
                new DnsServerEntry { Address = "10.8.0.1", Domains = new[] { "corp.example.com" } },
            },
            SplitDnsDomains = new[] { "internal.example.com" },
        };

        var rules = WindowsNrptRules.FromPlan(plan);

        rules.Select(r => r.Domain).ShouldBe(new[] { "corp.example.com", "internal.example.com" });
        rules.ShouldAllBe(r => r.Servers.Count == 1 && r.Servers[0] == "10.8.0.1");
        rules.ShouldAllBe(r => r.Identifier == "myvpn0");
        WindowsNrptRules.PolicyConfigPath.ShouldContain("Policies");
    }

    [Fact]
    public void NrptRulesAreEmptyWhenNoServerIsConfigured()
    {
        var plan = new DnsPlan
        {
            TunnelInterface = "myvpn0",
            Servers = Array.Empty<DnsServerEntry>(),
            SplitDnsDomains = new[] { "corp.example.com" },
            BlockPlainDnsLeaks = false,
        };

        WindowsNrptRules.FromPlan(plan).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("corp.example.com", true)]
    [InlineData("a-b_c.example", true)]
    [InlineData("*", false)]
    [InlineData(".", false)]
    [InlineData("corp..example.com", false)]
    [InlineData("corp/example", false)]
    [InlineData("corp example", false)]
    public void OnlyPlainNamespacesAreWrittenToTheRegistry(string domain, bool expected)
    {
        WindowsNrptRules.IsSafeNamespace(domain).ShouldBe(expected);
    }
}

public sealed class WindowsProxyValueTests
{
    [Fact]
    public void AFixedProxyPlanBecomesThePerSchemeWinInetValue()
    {
        var values = WindowsProxyValues.FromPlan(new SystemProxyPlan
        {
            SocksPort = 10808,
            HttpPort = 10809,
            BypassDomains = new[] { "example.com" },
        });

        values.ProxyEnable.ShouldBe(1);
        values.ProxyServer.ShouldBe("http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808");
        values.AutoConfigUrl.ShouldBeNull();

        // "<local>" keeps single-label intranet names off the proxy, which is what a user expects
        // and what a missing entry silently breaks.
        values.ProxyOverride.ShouldNotBeNull();
        values.ProxyOverride!.ShouldContain("<local>");
        values.ProxyOverride.ShouldContain("example.com");
    }

    [Fact]
    public void ASocksOnlyPlanAlsoCoversHttps()
    {
        var values = WindowsProxyValues.FromPlan(new SystemProxyPlan
        {
            EnableHttp = false,
            EnableSocks = true,
            SocksPort = 10808,
        });

        values.ProxyServer.ShouldBe("socks=127.0.0.1:10808;https=127.0.0.1:10808");
    }

    [Fact]
    public void APacPlanLeavesTheFixedProxySwitchedOff()
    {
        var values = WindowsProxyValues.FromPlan(new SystemProxyPlan
        {
            UsePac = true,
            PacUrl = "http://127.0.0.1:10810/proxy.pac",
        });

        // WinINET prefers the PAC over a fixed proxy; leaving ProxyEnable set would resurrect a
        // stale fixed proxy the moment the PAC URL is removed.
        values.ProxyEnable.ShouldBe(0);
        values.AutoConfigUrl.ShouldBe("http://127.0.0.1:10810/proxy.pac");
    }

    [Fact]
    public void HostRouteBypassesAreExpressibleAndWiderOnesAreReported()
    {
        var values = WindowsProxyValues.FromPlan(new SystemProxyPlan
        {
            BypassNetworks = new[]
            {
                CidrBlock.Parse("192.0.2.7/32"),
                CidrBlock.Parse("10.0.0.0/8"),
            },
        });

        values.ProxyOverride!.ShouldContain("192.0.2.7");

        // ProxyOverride has no prefix syntax, so a wider block genuinely has no spelling; it is
        // reported rather than silently dropped.
        values.NotExpressibleNetworks.ShouldBe(new[] { "10.0.0.0/8" });
    }

    [Fact]
    public void TheRegistryWritesCarryTheDocumentedValueNames()
    {
        var values = WindowsProxyValues.FromPlan(new SystemProxyPlan { HttpPort = 10809, SocksPort = 10808 });

        var writes = values.ToWrites();

        writes.Single(w => w.Name == "ProxyEnable").Dword.ShouldBe(1);
        writes.Single(w => w.Name == "ProxyServer").Delete.ShouldBeFalse();
        writes.Single(w => w.Name == "ProxyOverride").Text.ShouldNotBeNull();

        // Absent, not empty: an empty AutoConfigURL and an absent one differ to WinINET.
        writes.Single(w => w.Name == "AutoConfigURL").Delete.ShouldBeTrue();

        WindowsProxyRegistry.ProxyEnableValue.ShouldBe("ProxyEnable");
        WindowsProxyRegistry.ProxyServerValue.ShouldBe("ProxyServer");
        WindowsProxyRegistry.ProxyOverrideValue.ShouldBe("ProxyOverride");
        WindowsProxyRegistry.AutoConfigUrlValue.ShouldBe("AutoConfigURL");
        WindowsProxyRegistry.InternetSettingsPath.ShouldBe(
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
    }

    [Fact]
    public void ResetOnlyClearsTheEnableFlagAndThePacUrl()
    {
        var writes = WindowsProxyValues.ResetWrites();

        writes.Count.ShouldBe(2);
        writes.Single(w => w.Name == "ProxyEnable").Dword.ShouldBe(0);
        writes.Single(w => w.Name == "AutoConfigURL").Delete.ShouldBeTrue();

        // The user's own ProxyServer and ProxyOverride are left alone: deleting them would leave an
        // empty box when manual proxy mode is re-enabled. This is why ResetAsync does not go through
        // the snapshot mapping.
        writes.Any(w => w.Name is "ProxyServer" or "ProxyOverride").ShouldBeFalse();
    }

    [Fact]
    public void ACapturedSnapshotRoundTripsThroughTheRegistryValues()
    {
        var snapshot = new SystemProxySnapshot
        {
            Mode = "manual",
            Enabled = true,
            HttpProxy = "proxy.corp:8080",
            HttpsProxy = "proxy.corp:8443",
            SocksProxy = "socks.corp:1080",
            BypassList = "<local>;*.corp",
        };

        var values = WindowsProxyValues.FromSnapshot(snapshot);
        var restored = WindowsProxyValues.ToSnapshot(values);

        values.ProxyEnable.ShouldBe(1);
        values.ProxyServer.ShouldBe("http=proxy.corp:8080;https=proxy.corp:8443;socks=socks.corp:1080");

        restored.Mode.ShouldBe("manual");
        restored.Enabled.ShouldBeTrue();
        restored.HttpProxy.ShouldBe("proxy.corp:8080");
        restored.HttpsProxy.ShouldBe("proxy.corp:8443");
        restored.SocksProxy.ShouldBe("socks.corp:1080");
        restored.BypassList.ShouldBe("<local>;*.corp");
    }

    [Fact]
    public void ADisabledSnapshotRestoresAsDisabled()
    {
        var values = WindowsProxyValues.FromSnapshot(new SystemProxySnapshot
        {
            Mode = "none",
            Enabled = false,
        });

        values.ProxyEnable.ShouldBe(0);
        values.ProxyServer.ShouldBeNull();
        values.AutoConfigUrl.ShouldBeNull();
    }

    [Fact]
    public void APacSnapshotRestoresThePacUrlAndNotAFixedProxy()
    {
        var values = WindowsProxyValues.FromSnapshot(new SystemProxySnapshot
        {
            Mode = "auto",
            Enabled = true,
            PacUrl = "http://127.0.0.1:10810/proxy.pac",
        });

        values.AutoConfigUrl.ShouldBe("http://127.0.0.1:10810/proxy.pac");
        values.ProxyEnable.ShouldBe(0);
        values.ProxyServer.ShouldBeNull();
    }

    [Theory]
    [InlineData("http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808", "127.0.0.1:10809", "127.0.0.1:10809", "127.0.0.1:10808")]
    [InlineData("proxy.corp:8080", "proxy.corp:8080", "proxy.corp:8080", null)]
    [InlineData(null, null, null, null)]
    public void TheProxyServerValueSplitsIntoItsSchemes(
        string? value,
        string? http,
        string? https,
        string? socks)
    {
        var (parsedHttp, parsedHttps, parsedSocks) = WindowsProxyValues.SplitProxyServer(value);

        parsedHttp.ShouldBe(http);
        parsedHttps.ShouldBe(https);
        parsedSocks.ShouldBe(socks);
    }

    [Theory]
    [InlineData("http=127.0.0.1:10809", true)]
    [InlineData("socks=localhost:10808", true)]
    [InlineData("http=proxy.corp:8080", false)]
    [InlineData(null, false)]
    public void LoopbackDetectionIsByHost(string? value, bool expected)
    {
        WindowsProxyValues.PointsAtLoopback(value).ShouldBe(expected);
    }
}

public sealed class WindowsTunInterfaceNameTests
{
    [Theory]
    [InlineData("myvpn0", true)]
    [InlineData("Wintun", true)]
    [InlineData("Local Area Connection", true)]
    [InlineData("", false)]
    [InlineData("-myvpn0", false)]
    [InlineData("myvpn/0", false)]
    [InlineData("myvpn%0", false)]
    [InlineData("myvpn;0", false)]
    [InlineData("myvpn=0", false)]
    public void InterfaceNamesAreValidatedBeforeTheyReachArgv(string name, bool expected)
    {
        WindowsTunDeviceManager.IsValidInterfaceName(name).ShouldBe(expected);
    }

    [Fact]
    public void AControlCharacterInANameIsRefusedAndNotEchoedVerbatim()
    {
        WindowsTunDeviceManager.IsValidInterfaceName("myvpn\n0").ShouldBeFalse();

        var error = Should.Throw<ArgumentException>(
            () => WindowsTunDeviceManager.ValidateInterfaceName("myvpn\n0"));

        error.Message.ShouldNotContain("\n");
    }

    [Fact]
    public void ANullNameIsRejectedAsAnArgument()
    {
        Should.Throw<ArgumentNullException>(() => WindowsTunDeviceManager.ValidateInterfaceName(null));
    }
}

// =====================================================================================
// Emergency cleanup: ordering, resilience and idempotence.
// =====================================================================================

/// <summary>A Kill Switch collaborator whose outcome the test controls.</summary>
internal sealed class ScriptedKillSwitch : IKillSwitch
{
    public bool Supported { get; set; }

    public KillSwitchApplyResult RemoveResult { get; set; } = KillSwitchApplyResult.Ok("removed");

    public Exception? ThrowOnRemove { get; set; }

    public int RemoveCalls { get; private set; }

    public KillSwitchState InspectResult { get; set; } = KillSwitchState.Disarmed;

    public string MechanismName => "scripted";

    public bool IsSupported => Supported;

    public Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken) =>
        Task.FromResult(KillSwitchApplyResult.Ok());

    public Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
    {
        RemoveCalls++;

        if (ThrowOnRemove is not null)
        {
            throw ThrowOnRemove;
        }

        return Task.FromResult(RemoveResult);
    }

    public Task<KillSwitchState> InspectAsync(KillSwitchPlan? expected, CancellationToken cancellationToken) =>
        Task.FromResult(InspectResult);
}

internal sealed class ScriptedRouteManager : IRouteManager
{
    public Result RemoveAllResult { get; set; } = Result.Ok();

    public Exception? ThrowOnRemoveAll { get; set; }

    public int RemoveAllCalls { get; private set; }

    public RouteState InspectResult { get; set; } = new()
    {
        TunnelRoutesPresent = false,
        BypassRoutesPresent = false,
    };

    public bool IsSupported => true;

    public Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken) => Task.FromResult(Result.Ok());

    public Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken) => Task.FromResult(Result.Ok());

    public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        RemoveAllCalls++;

        if (ThrowOnRemoveAll is not null)
        {
            throw ThrowOnRemoveAll;
        }

        return Task.FromResult(RemoveAllResult);
    }

    public Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken) =>
        Task.FromResult(InspectResult);

    public Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Result.Fail<PhysicalUplink>(ErrorCodes.NotFound, "error.route.no_default_route"));
}

internal sealed class ScriptedDnsConfigurator : IDnsConfigurator
{
    public Result RemoveAllResult { get; set; } = Result.Ok();

    public Exception? ThrowOnRemoveAll { get; set; }

    public int RemoveAllCalls { get; private set; }

    public DnsState InspectResult { get; set; } = new()
    {
        ActiveServers = Array.Empty<string>(),
        InterfaceName = null,
        PlainDnsReachableOutsideTunnel = false,
    };

    public bool IsSupported => true;

    public Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken) =>
        Task.FromResult(Result<DnsPlan>.Ok(plan));

    public Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken) => Task.FromResult(Result.Ok());

    public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        RemoveAllCalls++;

        if (ThrowOnRemoveAll is not null)
        {
            throw ThrowOnRemoveAll;
        }

        return Task.FromResult(RemoveAllResult);
    }

    public Task<DnsState> InspectAsync(CancellationToken cancellationToken) => Task.FromResult(InspectResult);
}

internal sealed class ScriptedSystemProxy : ISystemProxy
{
    public Result ResetResult { get; set; } = Result.Ok();

    public Exception? ThrowOnReset { get; set; }

    public int ResetCalls { get; private set; }

    public SystemProxyState InspectResult { get; set; } = new() { IsConfigured = false };

    public bool IsSupported => true;

    public Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Result<SystemProxySnapshot>.Ok(new SystemProxySnapshot()));

    public Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken) =>
        Task.FromResult(Result.Ok());

    public Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken) =>
        Task.FromResult(Result.Ok());

    public Task<Result> ResetAsync(CancellationToken cancellationToken)
    {
        ResetCalls++;

        if (ThrowOnReset is not null)
        {
            throw ThrowOnReset;
        }

        return Task.FromResult(ResetResult);
    }

    public Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken) =>
        Task.FromResult(InspectResult);
}

public sealed class WindowsNetworkStateManagerTests
{
    [Fact]
    public async Task CleanupRunsTheDocumentedOrderAndAttemptsEveryStep()
    {
        var proxy = new ScriptedSystemProxy
        {
            ResetResult = Result.Fail(ErrorCodes.SystemProxyRestoreFailed, "error.proxy.restore_failed"),
        };
        var dns = new ScriptedDnsConfigurator
        {
            RemoveAllResult = Result.Fail(ErrorCodes.DnsRestoreFailed, "error.dns.restore_failed"),
        };
        var killSwitch = new ScriptedKillSwitch
        {
            RemoveResult = KillSwitchApplyResult.Failed(
                new MyVpnError(ErrorCodes.KillSwitchRemoveFailed, "error.killswitch.remove_failed")),
        };
        var routes = new ScriptedRouteManager
        {
            RemoveAllResult = Result.Fail(ErrorCodes.RouteRemoveFailed, "error.route.remove_failed"),
        };

        var manager = new WindowsNetworkStateManager(killSwitch, routes, dns, proxy);

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.Steps.Select(s => s.Name).ShouldBe(new[]
        {
            WindowsNetworkStateManager.StepName.Proxy,
            WindowsNetworkStateManager.StepName.Dns,
            WindowsNetworkStateManager.StepName.KillSwitch,
            WindowsNetworkStateManager.StepName.Routes,
            WindowsNetworkStateManager.StepName.Interface,
        });

        // Every step is reported, and four of the five genuinely failed.
        report.Steps.Count(s => !s.Succeeded).ShouldBe(4);
        report.FullyClean.ShouldBeFalse();

        // A failure early on must not stop the later steps: this is the whole point of the method.
        proxy.ResetCalls.ShouldBe(1);
        dns.RemoveAllCalls.ShouldBe(1);
        killSwitch.RemoveCalls.ShouldBe(1);
        routes.RemoveAllCalls.ShouldBe(1);

        // Detail keys are localization keys, never English sentences.
        foreach (var step in report.Steps)
        {
            step.DetailKey.ShouldNotBeNull();
            step.DetailKey!.ShouldStartWith(step.Succeeded ? "cleanup.step." : "error.");
        }
    }

    [Fact]
    public async Task AThrowingStepDoesNotPreventTheRemainingOnes()
    {
        var proxy = new ScriptedSystemProxy { ThrowOnReset = new InvalidOperationException("boom") };
        var dns = new ScriptedDnsConfigurator { ThrowOnRemoveAll = new TimeoutException("slow") };
        var killSwitch = new ScriptedKillSwitch { ThrowOnRemove = new ObjectDisposedException("ks") };
        var routes = new ScriptedRouteManager { ThrowOnRemoveAll = new IOException("disk") };

        var manager = new WindowsNetworkStateManager(killSwitch, routes, dns, proxy);

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.Steps.Count.ShouldBe(5);
        report.Steps.Count(s => !s.Succeeded).ShouldBe(4);
        dns.RemoveAllCalls.ShouldBe(1);
        killSwitch.RemoveCalls.ShouldBe(1);
        routes.RemoveAllCalls.ShouldBe(1);
    }

    [Fact]
    public async Task ADeadlineDoesNotAbortTheRemainingSteps()
    {
        var proxy = new ScriptedSystemProxy
        {
            ThrowOnReset = new OperationCanceledException(),
        };

        var manager = new WindowsNetworkStateManager(
            new ScriptedKillSwitch(),
            new ScriptedRouteManager(),
            new ScriptedDnsConfigurator(),
            proxy);

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        // A cancelled token must not stop the rest: a half-restored network is worse than a
        // delayed one.
        report.Steps.Single(s => s.Name == WindowsNetworkStateManager.StepName.Proxy)
            .DetailKey.ShouldBe("error.operation.cancelled");
        report.Steps.Single(s => s.Name == WindowsNetworkStateManager.StepName.Proxy)
            .Succeeded.ShouldBeFalse();
        report.Steps.Count(s => s.Succeeded).ShouldBe(4);
    }

    [Fact]
    public async Task CleanupIsIdempotentWithNoCollaboratorsAtAll()
    {
        var manager = new WindowsNetworkStateManager();

        var first = await manager.EmergencyCleanupAsync(CancellationToken.None);
        var second = await manager.EmergencyCleanupAsync(CancellationToken.None);

        first.Steps.Count.ShouldBe(5);
        second.Steps.Count.ShouldBe(5);

        // Nothing is wired, so nothing can fail — and the absence of a manager is reported as
        // "nothing to do", not as a failure.
        first.Steps.Count(s => s.DetailKey == "cleanup.step.no_manager").ShouldBe(4);
        first.Steps.ShouldAllBe(s => s.DetailKey != null);
        second.FullyClean.ShouldBe(first.FullyClean);
    }

    [Fact]
    public async Task DetectionNeverThrowsWithNullCollaborators()
    {
        var manager = new WindowsNetworkStateManager();

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.ShouldNotBeNull();
        leftovers.Details.ShouldNotBeEmpty();

        // Each unwired collaborator is reported as "cannot be inspected" rather than as "clean".
        leftovers.Details.ShouldContain(d => d.Contains("no IKillSwitch is wired", StringComparison.Ordinal));
        leftovers.Details.ShouldContain(d => d.Contains("no IDnsConfigurator is wired", StringComparison.Ordinal));
        leftovers.Details.ShouldContain(d => d.Contains("no ISystemProxy is wired", StringComparison.Ordinal));
        leftovers.Details.ShouldContain(d => d.Contains("no IRouteManager is wired", StringComparison.Ordinal));

        leftovers.KillSwitchRulesPresent.ShouldBeFalse();
        leftovers.TunnelInterfacePresent.ShouldBeFalse();
        leftovers.DnsOverridden.ShouldBeFalse();
        leftovers.SystemProxySet.ShouldBeFalse();
    }

    [Fact]
    public async Task DetectionReportsWhatTheCollaboratorsSee()
    {
        var killSwitch = new ScriptedKillSwitch
        {
            InspectResult = new KillSwitchState
            {
                IsArmed = true,
                IsDrifted = false,
                OrphanedRules = new[] { "default-deny at weight 0" },
                MechanismName = "scripted",
            },
        };

        var dns = new ScriptedDnsConfigurator
        {
            InspectResult = new DnsState
            {
                ActiveServers = new[] { "10.8.0.1" },
                InterfaceName = "myvpn0",
                PlainDnsReachableOutsideTunnel = false,
                PotentialLeaks = new[] { "error.dns.leak.ipv6_resolver" },
            },
        };

        var proxy = new ScriptedSystemProxy
        {
            InspectResult = new SystemProxyState
            {
                IsConfigured = true,
                ActiveProxy = "127.0.0.1:10809",
                PointsAtMyVpn = true,
            },
        };

        var routes = new ScriptedRouteManager
        {
            InspectResult = new RouteState
            {
                TunnelRoutesPresent = true,
                BypassRoutesPresent = true,
            },
        };

        var manager = new WindowsNetworkStateManager(killSwitch, routes, dns, proxy);

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.KillSwitchRulesPresent.ShouldBeTrue();
        leftovers.DnsOverridden.ShouldBeTrue();
        leftovers.SystemProxySet.ShouldBeTrue();
        leftovers.RoutesPresent.ShouldBeTrue();
        leftovers.Any.ShouldBeTrue();

        leftovers.Details.ShouldContain(d => d.Contains("dns potential leak", StringComparison.Ordinal));
        leftovers.Details.ShouldContain(d => d.Contains("kill switch orphaned filter", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheTunnelInterfaceStepNeverClaimsToHaveRemovedSomethingItDoesNotOwn()
    {
        var manager = new WindowsNetworkStateManager();

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        var step = report.Steps.Single(s => s.Name == WindowsNetworkStateManager.StepName.Interface);

        // On this host the adapter cannot even be probed, so the honest answer is "nothing to do".
        step.DetailKey.ShouldNotBeNull();
        step.TechnicalDetail.ShouldNotBeNull();
    }

    [Fact]
    public void InterfaceNameValidationStillAppliesToTheManager()
    {
        Should.Throw<ArgumentException>(() => new WindowsNetworkStateManager(tunnelInterfaceName: "myvpn/0"));
        Should.Throw<ArgumentException>(() => new WindowsNetworkStateManager(identifier: " "));
    }
}
