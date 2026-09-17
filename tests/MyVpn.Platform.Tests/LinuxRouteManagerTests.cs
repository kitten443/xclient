using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Linux.Routing;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>
/// Tests for the Linux route executor.
/// </summary>
/// <remarks>
/// The executor is driven through the shared <see cref="FakeCommandRunner"/>, so every assertion here
/// is about the command line it builds and the order it emits it in. The order is the interesting
/// part: bypass routes keep the core's own connection to the server off the tunnel, and installing or
/// removing them in the wrong order produces the "connects, then immediately stalls" failure that has
/// no error message anywhere.
/// </remarks>
public sealed class LinuxRouteManagerTests
{
    private readonly ITestOutputHelper _output;

    public LinuxRouteManagerTests(ITestOutputHelper output) => _output = output;

    // ------------------------------------------------------------------ helpers

    private static FakeCommandRunner RunnerWithIp()
    {
        var runner = new FakeCommandRunner();
        runner.Available.Add("ip");
        return runner;
    }

    private static LinuxRouteManager Manager(ICommandRunner runner, bool elevated = true) =>
        new(runner, isElevated: () => elevated);

    private static RouteEntry Route(
        string cidr,
        string @interface,
        string? gateway = null,
        int metric = 1,
        bool displaces = false) => new()
    {
        Destination = CidrBlock.Parse(cidr),
        Gateway = gateway,
        Interface = @interface,
        Metric = metric,
        ReasonKey = "route.reason.test",
        DisplacesDefaultRoute = displaces,
    };

    /// <summary>The full-tunnel shape: a default capture plus the uplink host route that protects it.</summary>
    private static RoutePlan FullTunnelPlan(bool displaces = false) => new()
    {
        TunnelInterface = "myvpn0",
        TunnelRoutes = new[] { Route("0.0.0.0/0", "myvpn0", displaces: displaces) },
        BypassRoutes = new[] { Route("203.0.113.7/32", "enp3s0", "192.168.1.1") },
        PhysicalInterface = "enp3s0",
    };

    private static RoutePlan TwoByTwoPlan() => new()
    {
        TunnelInterface = "myvpn0",
        TunnelRoutes = new[] { Route("10.0.0.0/8", "myvpn0"), Route("0.0.0.0/0", "myvpn0") },
        BypassRoutes = new[]
        {
            Route("203.0.113.7/32", "enp3s0", "192.168.1.1"),
            Route("203.0.113.8/32", "enp3s0", "192.168.1.1"),
        },
        PhysicalInterface = "enp3s0",
    };

    private static List<string> Commands(FakeCommandRunner runner) =>
        runner.Calls.Select(call => string.Join(' ', call.Arguments)).ToList();

    private static IEnumerable<int> IndexesOf(IReadOnlyList<string> commands, string fragment) =>
        commands.Select((command, index) => (command, index))
            .Where(pair => pair.command.Contains(fragment, StringComparison.Ordinal))
            .Select(pair => pair.index);

    // ------------------------------------------------------------------ refusal to act

    [Fact]
    public async Task WithoutRootItReportsUnsupportedAndRunsNothing()
    {
        var runner = RunnerWithIp();
        var manager = Manager(runner, elevated: false);

        manager.IsSupported.ShouldBeFalse();

        var applied = await manager.ApplyAsync(FullTunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);
        applied.Error.MessageKey.ShouldBe("error.route.needs_privileges");
        applied.Error.RemediationKey.ShouldBe("privilege.install_helper");

        // Nothing may have been attempted: an unprivileged `ip route add` fails with a confusing
        // "Operation not permitted" that looks like a broken plan rather than a missing helper.
        runner.Calls.ShouldBeEmpty();

        var removed = await manager.RemoveAsync(FullTunnelPlan(), CancellationToken.None);
        removed.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);

        var cleaned = await manager.RemoveAllOwnedAsync(CancellationToken.None);
        cleaned.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);

        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task WithoutTheIpToolItReportsTheMissingPlatformTool()
    {
        var runner = new FakeCommandRunner(); // "ip" is not available
        var manager = Manager(runner);

        manager.IsSupported.ShouldBeFalse();

        var applied = await manager.ApplyAsync(FullTunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);
        applied.Error.MessageKey.ShouldBe("error.route.tool_missing");

        var uplink = await manager.GetDefaultUplinkAsync(CancellationToken.None);
        uplink.IsFailure.ShouldBeTrue();
        uplink.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);

        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public void WithTheToolButNoRootItIsStillUnsupported()
    {
        var runner = RunnerWithIp();
        Manager(runner, elevated: true).IsSupported.ShouldBeTrue();

        var withoutTool = new FakeCommandRunner();
        Manager(withoutTool, elevated: true).IsSupported.ShouldBeFalse();

        var withoutRoot = RunnerWithIp();
        Manager(withoutRoot, elevated: false).IsSupported.ShouldBeFalse();
    }

    [Fact]
    public async Task RejectsAnInvalidPlanWithoutRunningAnything()
    {
        var runner = RunnerWithIp();
        var manager = Manager(runner);

        var noTunnelRoutes = FullTunnelPlan() with { TunnelRoutes = Array.Empty<RouteEntry>() };
        var first = await manager.ApplyAsync(noTunnelRoutes, CancellationToken.None);

        first.IsFailure.ShouldBeTrue();
        first.Error!.MessageKey.ShouldBe("error.route.no_tunnel_routes");

        // A default capture with no uplink host route is the loop the plan validator exists to stop.
        var noBypass = FullTunnelPlan() with { BypassRoutes = Array.Empty<RouteEntry>() };
        var second = await manager.ApplyAsync(noBypass, CancellationToken.None);

        second.IsFailure.ShouldBeTrue();
        second.Error!.MessageKey.ShouldBe("error.route.missing_bypass_route");

        runner.Calls.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ ordering (the loop-prevention property)

    [Fact]
    public async Task InstallsBypassRoutesBeforeAnyRouteThatCapturesTheDefault()
    {
        var runner = RunnerWithIp();
        var manager = Manager(runner);

        var applied = await manager.ApplyAsync(TwoByTwoPlan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);

        // Every invocation is an argv vector for `ip`; there is no shell anywhere.
        runner.Calls.ShouldAllBe(call => call.FileName == "ip");
        var allArguments = runner.Calls.SelectMany(call => call.Arguments).ToList();
        allArguments.ShouldNotContain("sh");
        allArguments.ShouldNotContain("-c");

        commands.ShouldContain("-4 route add 203.0.113.7/32 via 192.168.1.1 dev enp3s0 metric 1");
        commands.ShouldContain("-4 route add default dev myvpn0 metric 1");

        var bypassIndexes = IndexesOf(commands, "203.0.113.").ToList();
        var tunnelIndexes = IndexesOf(commands, "dev myvpn0").ToList();

        bypassIndexes.Count.ShouldBe(2);
        tunnelIndexes.Count.ShouldBe(2);

        // The property under test: both uplink host routes are installed before the first route that
        // can capture the default prefix. Reverse the two loops in ApplyAsync and this fails.
        bypassIndexes.Max().ShouldBeLessThan(tunnelIndexes.Min());

        _output.WriteLine(string.Join(Environment.NewLine, commands));
    }

    [Fact]
    public async Task RemovesTunnelRoutesBeforeBypassRoutes()
    {
        var runner = RunnerWithIp();
        var manager = Manager(runner);

        (await manager.ApplyAsync(TwoByTwoPlan(), CancellationToken.None)).IsSuccess.ShouldBeTrue();
        runner.Calls.Clear();

        var removed = await manager.RemoveAsync(TwoByTwoPlan(), CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);
        commands.ShouldContain("-4 route del default dev myvpn0");
        commands.ShouldContain("-4 route del 203.0.113.7/32 dev enp3s0");

        var tunnelDeletes = IndexesOf(commands, "dev myvpn0").ToList();
        var bypassDeletes = IndexesOf(commands, "203.0.113.").ToList();

        tunnelDeletes.Count.ShouldBe(2);
        bypassDeletes.Count.ShouldBe(2);

        // Teardown is the mirror image of installation: the default-capturing routes go first, so the
        // core's own traffic is never left pointed at a tunnel that is being dismantled.
        tunnelDeletes.Max().ShouldBeLessThan(bypassDeletes.Min());

        _output.WriteLine(string.Join(Environment.NewLine, commands));
    }

    [Fact]
    public async Task AFailedBypassRouteStopsTheApplyBeforeAnythingCapturesTheDefault()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("203.0.113.7/32")
            ? new CommandResult(2, string.Empty, "RTNETLINK answers: Network is unreachable")
            : new CommandResult(0, string.Empty, string.Empty);

        var applied = await Manager(runner).ApplyAsync(FullTunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.RouteAddFailed);
        applied.Error.MessageKey.ShouldBe("error.route.bypass_failed");

        // Fail closed: with the uplink host route missing, a default-capturing route would send the
        // core's own connection into a tunnel that cannot carry it.
        var commands = Commands(runner);
        commands.Any(command => command.Contains("dev myvpn0", StringComparison.Ordinal)).ShouldBeFalse();
    }

    [Fact]
    public async Task SurfacesATunnelRouteFailureWithTheAddFailedKey()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("default")
            ? new CommandResult(2, string.Empty, "RTNETLINK answers: Network is unreachable")
            : new CommandResult(0, string.Empty, string.Empty);

        var applied = await Manager(runner).ApplyAsync(FullTunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.RouteAddFailed);
        applied.Error.MessageKey.ShouldBe("error.route.add_failed");
        applied.Error.Arguments.Keys.ShouldContain("route");
    }

    // ------------------------------------------------------------------ idempotency

    [Fact]
    public async Task TreatsDeletingAMissingRouteAsSuccess()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("del")
            ? new CommandResult(2, string.Empty, "RTNETLINK answers: No such process")
            : new CommandResult(0, string.Empty, string.Empty);

        var removed = await Manager(runner).RemoveAsync(FullTunnelPlan(), CancellationToken.None);

        // Crash recovery depends on this: when the core dies the kernel deletes its interface *and its
        // routes*, so every deletion in the recorded plan legitimately finds nothing left.
        removed.IsSuccess.ShouldBeTrue();
        Commands(runner).Count(command => command.Contains("route del", StringComparison.Ordinal))
            .ShouldBe(2);
    }

    [Fact]
    public async Task TreatsAVanishedTunnelDeviceAsSuccessOnRemoval()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("del")
            ? new CommandResult(1, string.Empty, "Cannot find device \"myvpn0\"")
            : new CommandResult(0, string.Empty, string.Empty);

        (await Manager(runner).RemoveAsync(FullTunnelPlan(), CancellationToken.None))
            .IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task TreatsFileExistsOnAddAsIdempotentSuccess()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("add")
            ? new CommandResult(2, string.Empty, "RTNETLINK answers: File exists")
            : new CommandResult(0, string.Empty, string.Empty);

        var applied = await Manager(runner).ApplyAsync(FullTunnelPlan(), CancellationToken.None);

        // Re-applying a plan (a reconnect, or a second session) must not be reported as a failure.
        applied.IsSuccess.ShouldBeTrue();
    }

    // ------------------------------------------------------------------ displaced default route

    [Fact]
    public async Task CapturesTheDisplacedDefaultBeforeTheChangeAndRestoresItOnRemoval()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-4 route show default",
            new CommandResult(
                0,
                "default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.50 metric 100 \n",
                string.Empty));

        var manager = Manager(runner);
        var plan = FullTunnelPlan(displaces: true);

        var applied = await manager.ApplyAsync(plan, CancellationToken.None);
        applied.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);

        var capture = commands.FindIndex(command => command.Contains("route show default", StringComparison.Ordinal));
        var install = commands.FindIndex(command => command.Contains("route add default", StringComparison.Ordinal));

        capture.ShouldBeGreaterThanOrEqualTo(0);
        install.ShouldBeGreaterThan(capture);

        // Displacing means DELETING the uplink default, not adding a second one. `route replace` cannot
        // do it: Linux distinguishes default routes partly by metric, so "replace ... metric 1" leaves
        // an uplink default at metric 100 in place, and the kernel then prefers whichever metric is
        // lower. It was the metric-0 case that produced a silent full-tunnel failure, but neither
        // metric is safe to leave behind, so the delete is unconditional.
        commands.ShouldContain("-4 route del default via 192.168.1.1 dev enp3s0 metric 100");
        commands.ShouldContain("-4 route add default dev myvpn0 metric 1");
        commands.ShouldNotContain("-4 route replace default dev myvpn0 metric 1");

        // The uplink host route is a plain "add"; the delete must precede the capture.
        commands.ShouldContain("-4 route add 203.0.113.7/32 via 192.168.1.1 dev enp3s0 metric 1");
        commands.FindIndex(command => command.Contains("route del default", StringComparison.Ordinal))
            .ShouldBeLessThan(install);

        runner.Calls.Clear();

        var removed = await manager.RemoveAsync(plan, CancellationToken.None);
        removed.IsSuccess.ShouldBeTrue();

        var afterRemoval = Commands(runner);
        afterRemoval.ShouldContain("-4 route del default dev myvpn0");
        afterRemoval.ShouldContain("-4 route add default via 192.168.1.1 dev enp3s0 metric 100");

        // The restore comes FIRST, before any route is deleted. The gateway of the restored default may
        // be reachable only through one of the routes this teardown removes, and
        // `ip route add default via <gw> dev <uplink>` then fails with "Nexthop has invalid gateway"
        // (verified against a real kernel: exit 2), leaving the host with no default route at all.
        // Doing it first also closes the gap in which the machine has no default: the tunnel's
        // lower-metric default keeps winning until the tunnel route is deleted below.
        var restoreIndex = afterRemoval.FindIndex(
            command => command.Contains("route add default", StringComparison.Ordinal));
        var firstDelete = afterRemoval.FindIndex(
            command => command.Contains("route del", StringComparison.Ordinal));

        restoreIndex.ShouldBeGreaterThanOrEqualTo(0);
        firstDelete.ShouldBeGreaterThan(
            restoreIndex,
            "the displaced default must be restored before anything is deleted");

        _output.WriteLine(string.Join(Environment.NewLine, afterRemoval));
    }

    /// <summary>
    /// The regression test for the silent full-tunnel failure.
    /// </summary>
    /// <remarks>
    /// A bare <c>ip route add default via &lt;gw&gt;</c>, and many static configurations, leave the
    /// uplink default at metric 0. Before this was fixed the manager installed its own default with
    /// "replace" and left the metric-0 route alone; the kernel prefers the lower metric, so every
    /// packet kept leaving by the physical interface while the client reported "connected" — a full
    /// traffic leak on any host without a Kill Switch. Verified against a real kernel in a throwaway
    /// network namespace before and after the change.
    /// </remarks>
    [Fact]
    public async Task DeletesAMetricZeroUplinkDefaultThatWouldOtherwiseWinOverTheTunnel()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-4 route show default",
            new CommandResult(0, "default via 192.168.1.1 dev enp3s0 metric 0 \n", string.Empty));

        var manager = Manager(runner);
        var applied = await manager.ApplyAsync(FullTunnelPlan(displaces: true), CancellationToken.None);
        applied.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);
        var delete = commands.FindIndex(command => command.Contains("route del default", StringComparison.Ordinal));
        var add = commands.FindIndex(command => command.Contains("route add default", StringComparison.Ordinal));

        delete.ShouldBeGreaterThanOrEqualTo(0, "the metric-0 uplink default must be removed");
        commands[delete].ShouldBe("-4 route del default via 192.168.1.1 dev enp3s0 metric 0");
        add.ShouldBeGreaterThan(delete, "the tunnel default must be installed only after the uplink one is gone");
    }

    /// <summary>
    /// A host with no default route at all must still be able to connect.
    /// </summary>
    /// <remarks>
    /// "The kernel answered: there is no default route" is not the same as "the tool could not
    /// answer". With no competing default, the tunnel's own route IS the default and nothing needs
    /// restoring, so refusing here would make a fresh network namespace or an isolated segment
    /// permanently unable to connect. The fail-closed case is covered by
    /// <see cref="RefusesToDisplaceTheDefaultWhenTheToolCannotAnswer"/>.
    /// </remarks>
    [Fact]
    public async Task DisplacesTheDefaultOnAHostThatHasNoneBecauseNothingCanCompete()
    {
        var runner = RunnerWithIp(); // every listing answers, with exit 0 and no output
        var manager = Manager(runner);

        var applied = await manager.ApplyAsync(FullTunnelPlan(displaces: true), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);

        // Nothing was there to delete, and nothing is restored at teardown either.
        commands.ShouldNotContain(command => command.Contains("route del default", StringComparison.Ordinal));
        commands.ShouldContain("-4 route add default dev myvpn0 metric 1");
    }

    /// <summary>
    /// Fail closed when the kernel never said whether a competing default route exists.
    /// </summary>
    /// <remarks>
    /// This is the case that must NOT proceed. If <c>ip route show default</c> fails, a lower-metric
    /// uplink default may still be present, and installing the tunnel's default anyway would leave
    /// traffic leaving by the physical interface with no error anywhere. Refusing is the only safe
    /// answer when there is also no earlier capture to fall back on.
    /// </remarks>
    [Fact]
    public async Task RefusesToDisplaceTheDefaultWhenTheToolCannotAnswer()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => arguments.Contains("show", StringComparer.Ordinal)
            ? new CommandResult(2, string.Empty, "RTNETLINK answers: Operation not permitted")
            : new CommandResult(0, string.Empty, string.Empty);

        var manager = Manager(runner);

        var applied = await manager.ApplyAsync(FullTunnelPlan(displaces: true), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.route.displace_without_capture");
        applied.Error.Severity.ShouldBe(ErrorSeverity.Error);

        var commands = Commands(runner);
        commands.Any(command => command.Contains("route add", StringComparison.Ordinal)).ShouldBeFalse();
        commands.Any(command => command.Contains("route replace", StringComparison.Ordinal)).ShouldBeFalse();
        commands.Any(command => command.Contains("route del", StringComparison.Ordinal)).ShouldBeFalse();
    }

    /// <summary>
    /// A re-apply must not throw away the only record of the route it already took.
    /// </summary>
    /// <remarks>
    /// On the second <c>ApplyAsync</c> the physical default is gone precisely because this manager
    /// removed it, so the probe now answers "none". Discarding the earlier capture there — which the
    /// original "no capture means fail" code did, by failing the whole apply — left teardown unable to
    /// restore the host's route, and a failed reconnect could strand the machine with no default at all.
    /// </remarks>
    [Fact]
    public async Task AReApplyKeepsTheEarlierCaptureSoTeardownCanStillRestoreTheUplink()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-4 route show default",
            new CommandResult(0, "default via 192.168.1.1 dev enp3s0 metric 0 \n", string.Empty));

        var manager = Manager(runner);
        var plan = FullTunnelPlan(displaces: true);

        (await manager.ApplyAsync(plan, CancellationToken.None)).IsSuccess.ShouldBeTrue();

        // The uplink default is gone now: the second apply sees nothing, exactly like a real reconnect.
        runner.Respond("-4 route show default", new CommandResult(0, string.Empty, string.Empty));
        runner.Calls.Clear();

        (await manager.ApplyAsync(plan, CancellationToken.None)).IsSuccess.ShouldBeTrue();

        runner.Calls.Clear();
        var removed = await manager.RemoveAsync(plan, CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();
        Commands(runner).ShouldContain(
            "-4 route add default via 192.168.1.1 dev enp3s0 metric 0",
            "the capture from the first apply is the only thing that can restore the uplink");
    }

    // ------------------------------------------------------------------ discovery

    [Fact]
    public async Task ParsesTheDefaultUplinkFromARealisticRouteLine()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-4 route show default",
            new CommandResult(
                0,
                "default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.50 metric 100 \n",
                string.Empty));

        var uplink = await Manager(runner).GetDefaultUplinkAsync(CancellationToken.None);

        uplink.IsSuccess.ShouldBeTrue();
        uplink.Value.InterfaceName.ShouldBe("enp3s0");
        uplink.Value.GatewayAddress.ShouldBe("192.168.1.1");
        uplink.Value.IsIpv6.ShouldBeFalse();
    }

    [Fact]
    public async Task FallsBackToTheIpv6DefaultWhenThereIsNoIpv4Default()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-6 route show default",
            new CommandResult(0, "default via fe80::1 dev enp3s0 proto ra metric 100 pref medium\n", string.Empty));

        var uplink = await Manager(runner).GetDefaultUplinkAsync(CancellationToken.None);

        uplink.IsSuccess.ShouldBeTrue();
        uplink.Value.InterfaceName.ShouldBe("enp3s0");
        uplink.Value.GatewayAddress.ShouldBe("fe80::1");
        uplink.Value.IsIpv6.ShouldBeTrue();
    }

    [Fact]
    public async Task ReportsNoDefaultRouteAsAFailureRatherThanThrowing()
    {
        var runner = RunnerWithIp();

        var uplink = await Manager(runner).GetDefaultUplinkAsync(CancellationToken.None);

        uplink.IsFailure.ShouldBeTrue();
        uplink.Error!.Code.ShouldBe(ErrorCodes.NotFound);
        uplink.Error.MessageKey.ShouldBe("error.route.no_default_route");

        // Both families are probed before the answer is "there is no default route".
        var commands = Commands(runner);
        commands.ShouldContain("-4 route show default");
        commands.ShouldContain("-6 route show default");
    }

    [Fact]
    public async Task PrefersThePhysicalUplinkOverOurOwnTunnelDefault()
    {
        var runner = RunnerWithIp();
        runner.Respond(
            "-4 route show default",
            new CommandResult(
                0,
                "default dev myvpn0 metric 1 \n"
                + "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100 \n",
                string.Empty));

        var uplink = await Manager(runner).GetDefaultUplinkAsync(CancellationToken.None);

        // Returning the tunnel interface here would build a bypass route that points into the tunnel.
        uplink.Value.InterfaceName.ShouldBe("enp3s0");
        uplink.Value.GatewayAddress.ShouldBe("192.168.1.1");
    }

    // ------------------------------------------------------------------ rendering

    [Fact]
    public async Task RendersIpv6RoutesWithTheIpv6FamilyFlag()
    {
        var runner = RunnerWithIp();
        var plan = new RoutePlan
        {
            TunnelInterface = "myvpn0",
            TunnelRoutes = new[] { Route("2001:db8::/32", "myvpn0") },
            BypassRoutes = new[] { Route("2001:db8:dead::1/128", "enp3s0", "2001:db8::1") },
            PhysicalInterface = "enp3s0",
        };

        (await Manager(runner).ApplyAsync(plan, CancellationToken.None)).IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);

        // `ip route` defaults to IPv4, so the IPv6 family flag is mandatory, not cosmetic.
        commands.ShouldContain("-6 route add 2001:db8:dead::1/128 via 2001:db8::1 dev enp3s0 metric 1");
        commands.ShouldContain("-6 route add 2001:db8::/32 dev myvpn0 metric 1");
    }

    // ------------------------------------------------------------------ inspection

    [Fact]
    public async Task InspectWithANullPlanDoesNotThrowAndReportsWhatItOwns()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => string.Join(' ', arguments) switch
        {
            "-4 route show" => new CommandResult(
                0,
                "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100 \n"
                + "default dev myvpn0 metric 1 \n",
                string.Empty),
            "-6 route show" => new CommandResult(
                0, "fe80::/64 dev myvpn0 proto kernel metric 256 pref medium\n", string.Empty),
            _ => new CommandResult(0, string.Empty, string.Empty),
        };

        var state = await Manager(runner).InspectAsync(null, CancellationToken.None);

        state.TunnelRoutesPresent.ShouldBeTrue();

        // Ownership of a host route on the physical uplink cannot be claimed without a plan.
        state.BypassRoutesPresent.ShouldBeFalse();
        state.DisplacedDefaultRoute.ShouldBeNull();
        state.OrphanedRoutes.Any(route => route.Contains("myvpn0", StringComparison.Ordinal)).ShouldBeTrue();

        // The kernel's own link-local route on the tunnel is not a leftover.
        state.OrphanedRoutes.Any(route => route.Contains("proto kernel", StringComparison.Ordinal))
            .ShouldBeFalse();
    }

    [Fact]
    public async Task InspectMatchesTheExpectedPlanAgainstTheLiveTable()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, _) => new CommandResult(
            0,
            "default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.50 metric 100 \n"
            + "203.0.113.7 via 192.168.1.1 dev enp3s0 metric 1 \n"
            + "default dev myvpn0 metric 1 \n",
            string.Empty);

        var state = await Manager(runner).InspectAsync(FullTunnelPlan(), CancellationToken.None);

        // The /32 host route is printed by `ip` as a bare address; matching must not be textual.
        state.TunnelRoutesPresent.ShouldBeTrue();
        state.BypassRoutesPresent.ShouldBeTrue();
        state.OrphanedRoutes.ShouldBeEmpty();
    }

    [Fact]
    public async Task InspectReportsMissingRoutesAndOrphansAgainstThePlan()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => string.Join(' ', arguments) switch
        {
            "-4 route show" => new CommandResult(
                0,
                "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100 \n"
                + "10.99.0.0/16 dev myvpn0 metric 1 \n",
                string.Empty),
            _ => new CommandResult(0, string.Empty, string.Empty),
        };

        var state = await Manager(runner).InspectAsync(FullTunnelPlan(), CancellationToken.None);

        state.TunnelRoutesPresent.ShouldBeFalse();
        state.BypassRoutesPresent.ShouldBeFalse();
        state.OrphanedRoutes.Count.ShouldBe(1);
        state.OrphanedRoutes[0].ShouldContain("10.99.0.0/16");
    }

    [Fact]
    public async Task InspectWithoutTheToolReportsNothingRatherThanGuessing()
    {
        var runner = new FakeCommandRunner();

        var state = await Manager(runner).InspectAsync(FullTunnelPlan(), CancellationToken.None);

        state.TunnelRoutesPresent.ShouldBeFalse();
        state.BypassRoutesPresent.ShouldBeFalse();
        state.OrphanedRoutes.ShouldBeEmpty();
        runner.Calls.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ plan-free cleanup

    [Fact]
    public async Task RemoveAllOwnedRemovesTunnelRoutesPolicyTableRoutesAndMarkedRules()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => string.Join(' ', arguments) switch
        {
            "-4 route show" => new CommandResult(
                0,
                "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100 \n"
                + "default dev myvpn0 metric 1 \n"
                + "10.0.0.0/8 dev myvpn0 scope link metric 1 \n",
                string.Empty),
            "-6 route show" => new CommandResult(0, "2001:db8::/32 dev myvpn0 metric 1 pref medium\n", string.Empty),
            "-4 route show table 100" => new CommandResult(0, "198.51.100.0/24 dev eth9 metric 50 \n", string.Empty),
            "-6 route show table 100" => new CommandResult(0, string.Empty, string.Empty),
            "rule show" => new CommandResult(
                0,
                "0:\tfrom all lookup local\n"
                + "1000:\tfrom all fwmark 0xca6c/0xca6c lookup 100\n"
                + "32766:\tfrom all lookup main\n",
                string.Empty),

            // The rule was already gone when the panic-clear ran; that must not fail the cleanup.
            "rule del priority 1000" => new CommandResult(
                2, string.Empty, "RTNETLINK answers: No such file or directory"),
            _ => new CommandResult(0, string.Empty, string.Empty),
        };

        var cleaned = await Manager(runner).RemoveAllOwnedAsync(CancellationToken.None);

        cleaned.IsSuccess.ShouldBeTrue();

        var commands = Commands(runner);

        // Ownership comes from the route itself, because a crashed process left no plan behind.
        commands.ShouldContain("-4 route del default dev myvpn0");
        commands.ShouldContain("-4 route del 10.0.0.0/8 dev myvpn0");
        commands.ShouldContain("-6 route del 2001:db8::/32 dev myvpn0");

        // Table 100 is MyVpn's own table, so anything left in it goes too.
        commands.ShouldContain("-4 route del 198.51.100.0/24 dev eth9 table 100");

        // Our mark identifies our policy-routing rules at any priority.
        commands.ShouldContain("rule del priority 1000");

        // The host's own default route and its other rules are none of our business.
        commands.Any(command =>
            command.Contains("del", StringComparison.Ordinal)
            && command.Contains("enp3s0", StringComparison.Ordinal)).ShouldBeFalse();
        commands.Any(command => command.Contains("rule del priority 32766", StringComparison.Ordinal))
            .ShouldBeFalse();

        _output.WriteLine(string.Join(Environment.NewLine, commands));
    }

    [Fact]
    public async Task RemoveAllOwnedTreatsAMissingPolicyTableAsEmpty()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => string.Join(' ', arguments) switch
        {
            // A physical host route: not ours, so it must be left alone.
            "-4 route show" => new CommandResult(
                0, "203.0.113.7 via 192.168.1.1 dev enp3s0 metric 1 \n", string.Empty),

            // `ip route show table 100` exits non-zero while table 100 has never been created.
            // That means the table is empty, which is not a failure to clean up after.
            "-4 route show table 100" or "-6 route show table 100" => new CommandResult(
                2, string.Empty, "Error: ipv6: FIB table does not exist.\nDump terminated"),
            _ => new CommandResult(0, string.Empty, string.Empty),
        };

        (await Manager(runner).RemoveAllOwnedAsync(CancellationToken.None)).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task InspectDoesNotReportKernelRoutesOnTheTunnelAsOrphans()
    {
        var runner = RunnerWithIp();
        runner.Handler = (_, arguments) => string.Join(' ', arguments) switch
        {
            "-4 route show" => new CommandResult(0, "default dev myvpn0 metric 1 \n", string.Empty),
            "-6 route show" => new CommandResult(
                0, "fe80::/64 dev myvpn0 proto kernel metric 256 pref medium\n", string.Empty),
            _ => new CommandResult(0, string.Empty, string.Empty),
        };

        var state = await Manager(runner).InspectAsync(FullTunnelPlan(), CancellationToken.None);

        state.TunnelRoutesPresent.ShouldBeTrue();

        // The kernel creates that link-local route for the interface itself; it is not a leftover and
        // the panic-clear must not try to delete it.
        state.OrphanedRoutes.ShouldBeEmpty();
    }

    [Fact]
    public async Task RemoveAllOwnedWithoutTheToolIsANoOp()
    {
        var runner = new FakeCommandRunner();
        var manager = Manager(runner);

        (await manager.RemoveAllOwnedAsync(CancellationToken.None)).IsSuccess.ShouldBeTrue();
        (await manager.RemoveAsync(FullTunnelPlan(), CancellationToken.None)).IsSuccess.ShouldBeTrue();

        runner.Calls.ShouldBeEmpty();
    }
}
