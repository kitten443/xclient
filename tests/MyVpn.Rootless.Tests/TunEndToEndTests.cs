using MyVpn.Rootless.Harness;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Rootless.Tests;

/// <summary>
/// Verifies TUN mode end to end with no privileges on the host.
/// </summary>
/// <remarks>
/// <para>
/// Both ends of the tunnel and the traffic target run inside one throwaway user + network
/// namespace pair, created by <c>unshare</c> and destroyed when the last process in it exits.
/// Nothing here needs root on the host, no external server is contacted and no packet can leave
/// the machine: the "internet" is a veth pair and a dummy interface.
/// </para>
/// <para>
/// The tests in this class skip — they do not fail — when the environment cannot host the
/// scenario: no <c>/dev/net/tun</c>, no user namespaces, no <c>nft</c>, or no core binary in the
/// git-ignored <c>.tools/</c> directory. The pattern is the one already used by
/// <c>NftablesKillSwitchRendererTests</c>: probe, print the reason, return.
/// </para>
/// </remarks>
public sealed class TunEndToEndTests
{
    private readonly ITestOutputHelper _output;

    public TunEndToEndTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The whole tunnel, with the Kill Switch off.
    /// </summary>
    [Fact]
    public async Task TunMode_CarriesTrafficThroughTheTunnel_AndRestoresEverything()
    {
        if (!NetnsHarness.TryPrepare(_output, requiresNft: false, out _))
        {
            return;
        }

        var run = await NetnsHarness.RunAsync(_output, "off");

        if (SkipIfDnsIsNotIsolated(run))
        {
            return;
        }

        AssertTunnelWorked(run);

        // With the Kill Switch disabled no table may exist at any point: a stray ruleset would mean
        // the session applies firewall state the user did not ask for.
        run.Report.Client.NftTableWhileConnected.ShouldBeEmpty();
        run.Report.Client.NftTableAfterDisconnect.ShouldBeEmpty();
    }

    /// <summary>
    /// The same tunnel with <see cref="MyVpn.Core.Domain.KillSwitchMode.OnDemand"/> selected.
    /// </summary>
    /// <remarks>
    /// The Kill Switch is the one part of the design that is supposed to leave state behind while
    /// connected, so it needs both halves of its contract checked in the same run: the table is
    /// there while the tunnel is up, and it is gone the moment the session ends. The tunnel
    /// assertions are repeated because a firewall that blocks the tunnel it is protecting is a
    /// failure that only shows up when traffic is actually sent.
    /// </remarks>
    [Fact]
    public async Task OnDemandKillSwitch_IsArmedWhileConnected_AndRemovedAfterwards()
    {
        if (!NetnsHarness.TryPrepare(_output, requiresNft: true, out _))
        {
            return;
        }

        var run = await NetnsHarness.RunAsync(_output, "on-demand");

        if (SkipIfDnsIsNotIsolated(run))
        {
            return;
        }

        AssertTunnelWorked(run);

        var client = run.Report.Client;

        // Armed: the table exists and carries the renderer's ownership marker, so it is MyVpn's
        // ruleset rather than a table that happens to share the name.
        client.NftTableWhileConnected.ShouldNotBeEmpty();
        client.NftTableWhileConnected.ShouldContain("myvpn: default deny");
        client.NftTableWhileConnected.ShouldContain("oifname \"myvpn0\" accept");

        // The other half of the loop-prevention property: the firewall lets the core reach the
        // server on the uplink, so the bypass route the route manager installed is usable.
        client.NftTableWhileConnected.ShouldContain(
            $"ip daddr {ServerRole.UplinkAddress} meta l4proto {{ tcp, udp }} th dport 8443 accept");

        // Disarmed: the table is gone, which is what makes the restore claim meaningful.
        client.NftTableAfterDisconnect.ShouldBeEmpty();
    }

    /// <summary>
    /// Returns true — and skips the test — when the namespace could not be isolated from the host's
    /// resolver, which is a condition of the machine rather than a fault in the product.
    /// </summary>
    private bool SkipIfDnsIsNotIsolated(ScenarioRun run)
    {
        if (!run.Report.Client.DnsIsolationFailed)
        {
            return false;
        }

        _output.WriteLine($"SKIPPED: {run.Report.Failure}");
        return true;
    }

    /// <summary>
    /// Every assertion the tunnel itself has to satisfy, for either Kill Switch mode.
    /// </summary>
    private void AssertTunnelWorked(ScenarioRun run)
    {
        var report = run.Report;

        // A rig failure is a test bug, not a product failure, and must not be mistaken for one.
        report.Failure.ShouldBeNull();
        report.Completed.ShouldBeTrue();

        var client = report.Client;

        // ---- the far side is a real host, not this namespace -------------------------------
        var farSide = string.Join("\n", report.Server.Addresses);
        farSide.Contains(ServerRole.UplinkAddress, StringComparison.Ordinal)
            .ShouldBeTrue($"the far side should own the uplink address {ServerRole.UplinkAddress}: {farSide}");
        farSide.Contains(ServerRole.TargetAddress, StringComparison.Ordinal)
            .ShouldBeTrue($"the far side should own the traffic target address {ServerRole.TargetAddress}: {farSide}");

        // ---- before the connect -------------------------------------------------------------
        client.InterfacesBeforeConnect.ShouldNotContain(ClientScenario.TunInterface);
        client.UplinkDefaultRoute.ShouldContain("via 10.0.0.1");
        client.RouteToTargetBeforeConnect.ShouldContain("dev cli0");

        // Negative control: the target is reachable without the tunnel, and the source it observes
        // is this namespace's own uplink address. The tunnelled request below is only evidence of
        // the path because this one shows the alternative is available and distinguishable.
        client.DirectRequestStatus.ShouldBe(200);
        client.DirectRequestBody.ShouldContain("TARGET-OK");
        client.DirectRequestBody.ShouldContain($"from {ClientScenario.ClientAddress}");

        // ---- the connect -------------------------------------------------------------------
        client.ConnectSucceeded.ShouldBeTrue(client.ConnectError);

        // 1. The core created the interface and gave it the configured addresses.
        client.TunExistsWhileConnected.ShouldBeTrue();
        client.TunAddresses.ShouldContain(ClientScenario.ExpectedTunAddress);

        // 2. The default route now points at the tunnel, and — the loop-prevention property —
        //    the route to the VPN server is still on the physical uplink.
        client.DefaultRouteWhileConnected.ShouldContain($"dev {ClientScenario.TunInterface}");
        client.RouteToTargetWhileConnected.ShouldContain($"dev {ClientScenario.TunInterface}");
        client.RouteToServerWhileConnected.ShouldContain($"dev {ClientScenario.UplinkInterface}");
        client.RouteToServerWhileConnected.ShouldNotContain(ClientScenario.TunInterface);

        // 3. The resolver was moved to the tunnel and the previous state was recorded.
        client.ResolvConfWhileConnected.ShouldContain("# myvpn: managed resolver configuration");
        client.ResolvConfWhileConnected.ShouldContain("nameserver 1.1.1.1");
        client.ResolvConfWhileConnected.ShouldNotBe(client.ResolvConfBeforeConnect);
        client.DnsRecordedPreviousServers.ShouldContain(ClientScenario.PreexistingResolver);

        // 4. A request that must traverse the tunnel reached the target — and reached it through
        //    the far side's own stack, which is what the source address the target observed says.
        client.TunnelRequestStatus.ShouldBe(200);
        client.TunnelRequestBody.ShouldContain("TARGET-OK");
        client.TunnelRequestBody.ShouldContain($"from {ServerRole.TargetAddress}");
        client.TunnelRequestBody.ShouldNotContain($"from {ClientScenario.ClientAddress}");

        report.Server.ServedRequests.Count(
            line => line.Contains($" {ClientScenario.ClientAddress} GET / HTTP/1.1", StringComparison.Ordinal))
            .ShouldBe(1, "exactly one request may arrive directly from the client namespace");

        report.Server.ServedRequests.Count(
            line => line.Contains($" {ServerRole.TargetAddress} GET / HTTP/1.1", StringComparison.Ordinal))
            .ShouldBe(1, "exactly one request may arrive through the tunnel");

        // ---- after the disconnect ----------------------------------------------------------
        client.DisconnectSucceeded.ShouldBeTrue(client.DisconnectError);

        // 5. The tunnel interface is gone, which is also what removes its routes.
        client.TunExistsAfterDisconnect.ShouldBeFalse();
        client.InterfacesAfterDisconnect.ShouldNotContain(
            name => name.StartsWith("myvpn", StringComparison.Ordinal),
            "no MyVpn interface may survive the session");

        // 6. Routing is back where it started.
        client.DefaultRouteAfterDisconnect.ShouldNotContain("myvpn");
        client.DefaultRouteAfterDisconnect.ShouldContain("via 10.0.0.1");
        client.RouteToTargetAfterDisconnect.ShouldContain("dev cli0");
        client.RouteToServerAfterDisconnect.ShouldContain("dev cli0");

        // 7. The resolver file is byte-for-byte what it was.
        client.ResolvConfAfterDisconnect.ShouldBe(client.ResolvConfBeforeConnect);

        // 8. The core process is gone from this namespace, not merely stopped.
        client.CoreProcessesInNamespaceAfterDisconnect.ShouldBe(0);

        // ---- and the host itself was never involved ----------------------------------------
        run.HostInterfaces.ShouldNotContain(
            name => name.StartsWith("myvpn", StringComparison.Ordinal),
            "no MyVpn interface may appear on the host");

        run.HostDefaultRoute.ShouldNotContain("myvpn");
        run.ProcessesReferencingRun.ShouldBe(
            0,
            "no process from the run — and therefore no namespace — may survive it");

        run.StdErrLines.ShouldNotContain(
            line => line.Contains("harness:", StringComparison.Ordinal),
            "the harness must not report a rig failure");
    }
}
