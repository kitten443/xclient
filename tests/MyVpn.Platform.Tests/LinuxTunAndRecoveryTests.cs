using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Linux.Execution;
using MyVpn.Platform.Linux.Network;
using MyVpn.Platform.Linux.Tun;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>
/// Tests for the Linux TUN observer and the emergency network-recovery manager.
/// </summary>
/// <remarks>
/// The command runner is scripted throughout, so these tests describe the executor's own
/// responsibilities: reading back what the kernel actually holds, refusing names that must not
/// reach argv, and — the property that matters most — attempting every cleanup step even when an
/// earlier one fails. The real-kernel behaviour of the TUN device itself is verified separately by
/// creating a device inside a throwaway network namespace.
/// </remarks>
public sealed class LinuxTunAndRecoveryTests
{
    /// <summary>Output of <c>ip link show myvpn0</c> for an existing device.</summary>
    private const string LinkPresent =
        "3: myvpn0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN "
        + "group default qlen 500\n    link/none ";

    /// <summary>Realistic <c>ip -brief address show dev myvpn0</c> output, IPv4 and link-local IPv6.</summary>
    private const string BriefAddresses =
        "myvpn0           UNKNOWN        10.8.0.2/24 fe80::21b:2cff:fe3d:4e5f/64 \n";

    private readonly ITestOutputHelper _output;

    public LinuxTunAndRecoveryTests(ITestOutputHelper output) => _output = output;

    // ------------------------------------------------------------------ TUN device manager

    [Fact]
    public void IsSupportedMirrorsTheTunDeviceNode()
    {
        var runner = new FakeCommandRunner();
        var manager = new LinuxTunDeviceManager(runner);

        var nodeExists = File.Exists("/dev/net/tun");
        if (!nodeExists)
        {
            _output.WriteLine(
                "/dev/net/tun is absent in this environment; only the negative case can be asserted.");
        }

        manager.IsSupported.ShouldBe(nodeExists);
        manager.DefaultInterfaceName.ShouldBe("myvpn0");

        // Capability reporting must not spawn a process: it is a property getter called from the UI.
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task ExistsAsyncFollowsTheIpLinkExitCode()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(0, LinkPresent, string.Empty));
        runner.Respond("link show ghost0", new CommandResult(1, string.Empty, "Device \"ghost0\" does not exist."));

        var manager = new LinuxTunDeviceManager(runner);

        (await manager.ExistsAsync("myvpn0", CancellationToken.None)).ShouldBeTrue();

        // A missing interface is the normal "not connected yet" case, not an error to throw over.
        (await manager.ExistsAsync("ghost0", CancellationToken.None)).ShouldBeFalse();

        var call = runner.Calls[0];
        call.FileName.ShouldBe("ip");
        call.Arguments.ShouldBe(new[] { "link", "show", "myvpn0" });
    }

    [Fact]
    public async Task GetAddressesParsesTheBriefAddressLayout()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("-brief address show dev myvpn0", new CommandResult(0, BriefAddresses, string.Empty));

        var addresses = await new LinuxTunDeviceManager(runner).GetAddressesAsync("myvpn0", CancellationToken.None);

        // Prefix lengths are kept: the routing layer needs them, and ip reports them.
        addresses.ShouldBe(new[] { "10.8.0.2/24", "fe80::21b:2cff:fe3d:4e5f/64" });

        runner.Calls[0].Arguments.ShouldBe(new[] { "-brief", "address", "show", "dev", "myvpn0" });
    }

    [Fact]
    public async Task GetAddressesAlsoUnderstandsTheDetailedAddressLayout()
    {
        const string detailed =
            "3: myvpn0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN\n"
            + "    link/none \n"
            + "    inet 10.8.0.2/24 brd 10.8.0.255 scope global myvpn0\n"
            + "       valid_lft forever preferred_lft forever\n"
            + "    inet6 fe80::21b:2cff:fe3d:4e5f/64 scope link \n"
            + "       valid_lft forever preferred_lft forever\n";

        var runner = new FakeCommandRunner();
        runner.Respond("-brief address show dev myvpn0", new CommandResult(0, detailed, string.Empty));

        var addresses = await new LinuxTunDeviceManager(runner).GetAddressesAsync("myvpn0", CancellationToken.None);

        // The broadcast address, the scope and the lifetime counters must not leak into the result.
        addresses.ShouldBe(new[] { "10.8.0.2/24", "fe80::21b:2cff:fe3d:4e5f/64" });
    }

    [Fact]
    public async Task GetAddressesReturnsEmptyForAnInterfaceWithoutAddresses()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("-brief address show dev myvpn0", new CommandResult(0, "myvpn0           UNKNOWN \n", string.Empty));

        var addresses = await new LinuxTunDeviceManager(runner).GetAddressesAsync("myvpn0", CancellationToken.None);

        addresses.ShouldBeEmpty();
    }

    [Fact]
    public async Task GetAddressesReturnsEmptyForUnparseableOutputInsteadOfThrowing()
    {
        var manager = new LinuxTunDeviceManager(new FakeCommandRunner());

        // Output that is not about this interface at all.
        var junk = new FakeCommandRunner();
        junk.Respond("-brief address show dev myvpn0", new CommandResult(0, "<garbage>\nnot an address line\n", string.Empty));
        (await new LinuxTunDeviceManager(junk).GetAddressesAsync("myvpn0", CancellationToken.None)).ShouldBeEmpty();

        // A non-zero exit code, which is what a missing interface produces.
        var missing = new FakeCommandRunner();
        missing.Respond("-brief address show dev myvpn0", new CommandResult(1, string.Empty, "Device does not exist."));
        (await new LinuxTunDeviceManager(missing).GetAddressesAsync("myvpn0", CancellationToken.None)).ShouldBeEmpty();

        // Empty and null output must not throw either.
        var empty = new FakeCommandRunner();
        empty.Respond("-brief address show dev myvpn0", new CommandResult(0, string.Empty, string.Empty));
        (await new LinuxTunDeviceManager(empty).GetAddressesAsync("myvpn0", CancellationToken.None)).ShouldBeEmpty();

        var nullOutput = new FakeCommandRunner();
        nullOutput.Respond("-brief address show dev myvpn0", new CommandResult(0, null!, string.Empty));
        (await new LinuxTunDeviceManager(nullOutput).GetAddressesAsync("myvpn0", CancellationToken.None)).ShouldBeEmpty();

        // A name that parsed nothing at all is likewise empty, not an exception.
        (await manager.GetAddressesAsync("ghost0", CancellationToken.None)).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("myvpn0-interface")]  // 17 characters: over IFNAMSIZ - 1
    [InlineData("my vpn0")]           // whitespace
    [InlineData("my\tvpn0")]          // a tab is whitespace too
    [InlineData("my/vpn0")]           // path separator
    [InlineData("eth0:1")]            // ':' is iproute2 alias syntax
    [InlineData("-force")]            // would be read as an option by ip
    [InlineData("myvpn0;reboot")]     // shell metacharacter: no shell exists, but still refused
    [InlineData("myvpn0\nrm")]        // control character
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task InvalidInterfaceNamesAreRejectedBeforeAnyCommandRuns(string? name)
    {
        var runner = new FakeCommandRunner();
        var manager = new LinuxTunDeviceManager(runner);

        await Should.ThrowAsync<ArgumentException>(
            () => manager.ExistsAsync(name!, CancellationToken.None));

        await Should.ThrowAsync<ArgumentException>(
            () => manager.GetAddressesAsync(name!, CancellationToken.None));

        // Nothing may reach argv, so the runner must never have been called at all.
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task AMaximumLengthInterfaceNameIsAccepted()
    {
        const string name = "myvpn0123456789"; // exactly 15 characters, the kernel's limit

        name.Length.ShouldBe(LinuxTunDeviceManager.MaxInterfaceNameLength);
        LinuxTunDeviceManager.IsValidInterfaceName(name).ShouldBeTrue();

        var runner = new FakeCommandRunner();
        runner.Respond($"link show {name}", new CommandResult(0, LinkPresent, string.Empty));

        (await new LinuxTunDeviceManager(runner).ExistsAsync(name, CancellationToken.None)).ShouldBeTrue();

        runner.Calls.ShouldHaveSingleItem();
    }

    // ------------------------------------------------------------------ leftover detection

    [Fact]
    public async Task DetectLeftoversWithNoCollaboratorsReportsWhatItCan()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(1, string.Empty, "Device \"myvpn0\" does not exist."));

        // Constructed with nothing but a runner: every optional collaborator is null.
        var manager = new LinuxNetworkStateManager(runner);

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.TunnelInterfacePresent.ShouldBeFalse();
        leftovers.KillSwitchRulesPresent.ShouldBeFalse();
        leftovers.RoutesPresent.ShouldBeFalse();
        leftovers.DnsOverridden.ShouldBeFalse();
        leftovers.SystemProxySet.ShouldBeFalse();

        // Each unavailable probe has to say so rather than let the caller read "nothing found" as
        // "the machine is clean".
        leftovers.Details.ShouldNotBeEmpty();
        leftovers.Details.ShouldContain(d => d.Contains("kill switch", StringComparison.OrdinalIgnoreCase));
        leftovers.Details.ShouldContain(d => d.Contains("dns", StringComparison.OrdinalIgnoreCase));
        leftovers.Details.ShouldContain(d => d.Contains("proxy", StringComparison.OrdinalIgnoreCase));
        leftovers.Details.ShouldContain(d => d.Contains("routes", StringComparison.OrdinalIgnoreCase));
        leftovers.Details.ShouldContain(d => d.Contains("xray", StringComparison.OrdinalIgnoreCase));

        _output.WriteLine(string.Join("\n", leftovers.Details));
    }

    [Fact]
    public async Task DetectLeftoversReportsEveryArtefactWhenCollaboratorsAreWired()
    {
        var order = new List<string>();
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(0, LinkPresent, string.Empty));
        runner.Respond("-brief address show dev myvpn0", new CommandResult(0, BriefAddresses, string.Empty));
        runner.Respond(
            "route show table all",
            new CommandResult(0, "10.8.0.0/24 dev myvpn0 proto kernel scope link src 10.8.0.2 \n", string.Empty));

        var manager = new LinuxNetworkStateManager(
            runner,
            new StubKillSwitch(armed: true, order),
            new StubRouteManager(tunnelRoutesPresent: true, order),
            new StubDnsConfigurator(new[] { "10.8.0.1" }, "myvpn0", order),
            new StubSystemProxy(configured: true, order));

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.KillSwitchRulesPresent.ShouldBeTrue();
        leftovers.TunnelInterfacePresent.ShouldBeTrue();
        leftovers.RoutesPresent.ShouldBeTrue();
        leftovers.DnsOverridden.ShouldBeTrue();
        leftovers.SystemProxySet.ShouldBeTrue();
        leftovers.Any.ShouldBeTrue();

        // The interface probe reports the addresses it saw, for the diagnostics bundle.
        leftovers.Details.ShouldContain(d => d.Contains("10.8.0.2/24", StringComparison.Ordinal));
        leftovers.Details.ShouldContain(d => d.Contains("dev myvpn0", StringComparison.Ordinal));

        _output.WriteLine(string.Join("\n", leftovers.Details));
    }

    [Fact]
    public async Task DetectLeftoversRecognisesADnsOverrideFromTheResolverAddressAlone()
    {
        var order = new List<string>();
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(0, LinkPresent, string.Empty));
        runner.Respond("-brief address show dev myvpn0", new CommandResult(0, BriefAddresses, string.Empty));

        // No interface name reported, but the resolver is an address hosted on our tunnel.
        var manager = new LinuxNetworkStateManager(
            runner,
            dns: new StubDnsConfigurator(new[] { "10.8.0.2" }, interfaceName: null, order));

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        leftovers.DnsOverridden.ShouldBeTrue();
        leftovers.Details.ShouldContain(d => d.Contains("tunnel_bound=True", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DetectLeftoversSurvivesCollaboratorsThatThrow()
    {
        var order = new List<string>();
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(1, string.Empty, "Device \"myvpn0\" does not exist."));

        var failure = new InvalidOperationException("scripted inspector failure");

        var manager = new LinuxNetworkStateManager(
            runner,
            new StubKillSwitch(armed: false, order) { InspectException = failure },
            new StubRouteManager(tunnelRoutesPresent: false, order) { InspectException = failure },
            new StubDnsConfigurator(Array.Empty<string>(), null, order) { InspectException = failure },
            new StubSystemProxy(configured: false, order) { InspectException = failure });

        var leftovers = await manager.DetectLeftoversAsync(CancellationToken.None);

        // A broken inspector must degrade to "unknown", never take the diagnostics run down.
        leftovers.KillSwitchRulesPresent.ShouldBeFalse();
        leftovers.RoutesPresent.ShouldBeFalse();
        leftovers.DnsOverridden.ShouldBeFalse();
        leftovers.SystemProxySet.ShouldBeFalse();
        leftovers.Details.ShouldContain(d => d.Contains("scripted inspector failure", StringComparison.Ordinal));

        _output.WriteLine(string.Join("\n", leftovers.Details));
    }

    // ------------------------------------------------------------------ emergency cleanup

    [Fact]
    public async Task EmergencyCleanupOnAnAlreadyCleanMachineReportsFullyClean()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("link show myvpn0", new CommandResult(1, string.Empty, "Device \"myvpn0\" does not exist."));

        var report = await new LinuxNetworkStateManager(runner).EmergencyCleanupAsync(CancellationToken.None);

        report.FullyClean.ShouldBeTrue();
        report.Steps.Count.ShouldBe(5);
        report.Steps.ShouldAllBe(s => s.Succeeded);

        // Nothing was mutated: the only command issued was the read-only existence probe.
        var call = runner.Calls.ShouldHaveSingleItem();
        call.Arguments.ShouldBe(new[] { "link", "show", "myvpn0" });

        _output.WriteLine(string.Join("\n", report.Steps.Select(s => $"{s.Name}: {s.DetailKey} — {s.TechnicalDetail}")));
    }

    [Fact]
    public async Task EmergencyCleanupWithNoCollaboratorsStillReportsEveryStep()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);

        var report = await new LinuxNetworkStateManager(runner).EmergencyCleanupAsync(CancellationToken.None);

        report.Steps.Count.ShouldBe(5);
        report.Steps.Select(s => s.Name).ShouldBe(new[] { "proxy", "dns", "kill-switch", "routes", "interface" });
        report.FullyClean.ShouldBeTrue();

        // A step with no collaborator is a completed no-op, not a failure.
        report.Steps.Take(4).ShouldAllBe(s => s.DetailKey == "cleanup.step.no_manager");

        // The interface MyVpn owns was still brought down and deleted.
        order.ShouldBe(new[] { "interface" });
    }

    [Fact]
    public async Task EmergencyCleanupContinuesAfterAFailingStep()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);

        var manager = new LinuxNetworkStateManager(
            runner,
            new StubKillSwitch(armed: true, order) { FailRemove = true },
            new StubRouteManager(tunnelRoutesPresent: true, order),
            new StubDnsConfigurator(new[] { "10.8.0.1" }, "myvpn0", order),
            new StubSystemProxy(configured: true, order));

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        // Every step is still reported, in order.
        report.Steps.Count.ShouldBe(5);
        report.Steps.Select(s => s.Name).ShouldBe(new[] { "proxy", "dns", "kill-switch", "routes", "interface" });

        var failed = report.Steps.Single(s => s.Name == "kill-switch");
        failed.Succeeded.ShouldBeFalse();

        // The collaborator's own localization key is surfaced, never a raw English sentence.
        failed.DetailKey.ShouldBe("error.killswitch.remove_failed");
        failed.TechnicalDetail.ShouldNotBeNullOrWhiteSpace();

        report.FullyClean.ShouldBeFalse();

        // The property that matters most: the failure did not stop anything that came after it,
        // and the steps that ran did so in the documented order.
        order.ShouldBe(new[] { "proxy.reset", "dns.remove", "killswitch.remove", "routes.remove", "interface" });
    }

    [Fact]
    public async Task EmergencyCleanupRunsEveryStepInTheDocumentedOrder()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);

        var manager = new LinuxNetworkStateManager(
            runner,
            new StubKillSwitch(armed: true, order),
            new StubRouteManager(tunnelRoutesPresent: true, order),
            new StubDnsConfigurator(new[] { "10.8.0.1" }, "myvpn0", order),
            new StubSystemProxy(configured: true, order));

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.FullyClean.ShouldBeTrue();
        report.Steps.Select(s => s.Name).ShouldBe(new[] { "proxy", "dns", "kill-switch", "routes", "interface" });
        order.ShouldBe(new[] { "proxy.reset", "dns.remove", "killswitch.remove", "routes.remove", "interface" });

        // The interface is taken down before it is deleted, and the Kill Switch is removed before
        // the routes it protects disappear.
        var ipCommands = runner.Calls
            .Where(c => c.FileName == "ip")
            .Select(c => string.Join(' ', c.Arguments))
            .ToList();

        ipCommands.ShouldContain("link set dev myvpn0 down");
        ipCommands.ShouldContain("link delete dev myvpn0");
        ipCommands.IndexOf("link delete dev myvpn0").ShouldBeGreaterThan(ipCommands.IndexOf("link set dev myvpn0 down"));
    }

    [Fact]
    public async Task EmergencyCleanupIsSafeToRunTwice()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);
        var manager = new LinuxNetworkStateManager(runner);

        var first = await manager.EmergencyCleanupAsync(CancellationToken.None);
        var callsAfterFirstRun = runner.Calls.Count;
        var second = await manager.EmergencyCleanupAsync(CancellationToken.None);

        first.FullyClean.ShouldBeTrue();
        second.FullyClean.ShouldBeTrue();

        // The second run only probed; there was nothing left to delete.
        second.Steps.Single(s => s.Name == "interface").DetailKey.ShouldBe("cleanup.step.nothing_to_do");
        order.ShouldBe(new[] { "interface" });
        runner.Calls.Count.ShouldBe(callsAfterFirstRun + 1);
    }

    [Fact]
    public async Task EmergencyCleanupReportsAFailedInterfaceStepWhenTheDeviceSurvives()
    {
        // The default scripted runner answers every command with exit code 0, i.e. the device never
        // goes away — which is what happens while the Xray core still holds the descriptor.
        var runner = new FakeCommandRunner();

        var report = await new LinuxNetworkStateManager(runner).EmergencyCleanupAsync(CancellationToken.None);

        var step = report.Steps.Single(s => s.Name == "interface");

        // Read-back rather than exit-code trust: a "successful" delete that left the device in
        // place must not be reported as clean.
        step.Succeeded.ShouldBeFalse();
        step.DetailKey.ShouldBe("error.tun.remove_failed");
        step.TechnicalDetail!.ShouldContain("still present");
        report.FullyClean.ShouldBeFalse();
    }

    [Fact]
    public async Task EmergencyCleanupTurnsAThrownExceptionIntoAFailedStepAndKeepsGoing()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);

        var manager = new LinuxNetworkStateManager(
            runner,
            systemProxy: new StubSystemProxy(configured: true, order)
            {
                ResetException = new InvalidOperationException("gsettings vanished"),
            });

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        report.Steps[0].Name.ShouldBe("proxy");
        report.Steps[0].Succeeded.ShouldBeFalse();
        report.Steps[0].DetailKey.ShouldBe("error.network.cleanup_step_failed");
        report.Steps[0].TechnicalDetail!.ShouldContain("gsettings vanished");
        report.FullyClean.ShouldBeFalse();

        // The exception did not stop the remaining steps.
        order.ShouldBe(new[] { "proxy.reset", "interface" });
        report.Steps.Count.ShouldBe(5);
    }

    [Fact]
    public async Task CleanupStepDetailKeysAreLocalizationKeys()
    {
        var order = new List<string>();
        var runner = TunnelRunner(order);

        var manager = new LinuxNetworkStateManager(
            runner,
            new StubKillSwitch(armed: true, order) { FailRemove = true },
            new StubRouteManager(tunnelRoutesPresent: true, order),
            new StubDnsConfigurator(new[] { "10.8.0.1" }, "myvpn0", order),
            new StubSystemProxy(configured: true, order));

        var report = await manager.EmergencyCleanupAsync(CancellationToken.None);

        foreach (var step in report.Steps)
        {
            step.DetailKey.ShouldNotBeNullOrWhiteSpace();
            step.DetailKey!.ShouldMatch(@"^(cleanup|error)\.[a-z0-9_.]+$");
        }

        report.Steps.ShouldContain(s => s.DetailKey == "cleanup.step.completed");
        report.Steps.ShouldContain(s => s.DetailKey == "error.killswitch.remove_failed");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// A runner that behaves like a small kernel: <c>myvpn0</c> exists until it is deleted, and the
    /// interface step is recorded in <paramref name="order"/> when that happens.
    /// </summary>
    private static FakeCommandRunner TunnelRunner(List<string> order, bool present = true, string interfaceName = "myvpn0")
    {
        var exists = present;
        var runner = new FakeCommandRunner();

        runner.Handler = (file, arguments) =>
        {
            if (!string.Equals(file, "ip", StringComparison.Ordinal))
            {
                return new CommandResult(0, string.Empty, string.Empty);
            }

            var command = string.Join(' ', arguments);

            if (command == $"link show {interfaceName}")
            {
                return exists
                    ? new CommandResult(0, LinkPresent, string.Empty)
                    : new CommandResult(1, string.Empty, $"Device \"{interfaceName}\" does not exist.");
            }

            if (command == $"-brief address show dev {interfaceName}")
            {
                return new CommandResult(0, BriefAddresses, string.Empty);
            }

            if (command == $"link delete dev {interfaceName}")
            {
                exists = false;
                order.Add("interface");
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };

        return runner;
    }

    /// <summary>A Kill Switch that records its calls and can be told to fail or throw.</summary>
    private sealed class StubKillSwitch : IKillSwitch
    {
        private readonly bool _armed;
        private readonly List<string> _order;

        public StubKillSwitch(bool armed, List<string> order)
        {
            _armed = armed;
            _order = order;
        }

        public bool FailRemove { get; init; }

        public Exception? InspectException { get; init; }

        public string MechanismName => "nftables";

        public bool IsSupported => true;

        public Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(KillSwitchApplyResult.Ok());

        public Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
        {
            _order.Add("killswitch.remove");

            if (FailRemove)
            {
                return Task.FromResult(KillSwitchApplyResult.Failed(
                    new MyVpnError(
                        ErrorCodes.KillSwitchRemoveFailed,
                        "error.killswitch.remove_failed",
                        ErrorSeverity.Critical,
                        "nftables could not remove the rule set: scripted failure")));
            }

            return Task.FromResult(KillSwitchApplyResult.Ok());
        }

        public Task<KillSwitchState> InspectAsync(KillSwitchPlan? expected, CancellationToken cancellationToken)
        {
            _order.Add("killswitch.inspect");

            if (InspectException is not null)
            {
                throw InspectException;
            }

            return Task.FromResult(new KillSwitchState
            {
                IsArmed = _armed,
                IsDrifted = false,
                MechanismName = MechanismName,
            });
        }
    }

    /// <summary>A route manager that records its calls and can be told to throw.</summary>
    private sealed class StubRouteManager : IRouteManager
    {
        private readonly bool _tunnelRoutesPresent;
        private readonly List<string> _order;

        public StubRouteManager(bool tunnelRoutesPresent, List<string> order)
        {
            _tunnelRoutesPresent = tunnelRoutesPresent;
            _order = order;
        }

        public Exception? InspectException { get; init; }

        public bool IsSupported => true;

        public Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
        {
            _order.Add("routes.remove");
            return Task.FromResult(Result.Ok());
        }

        public Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken)
        {
            _order.Add("routes.inspect");

            if (InspectException is not null)
            {
                throw InspectException;
            }

            return Task.FromResult(new RouteState
            {
                TunnelRoutesPresent = _tunnelRoutesPresent,
                BypassRoutesPresent = false,
            });
        }

        public Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Result<PhysicalUplink>.Ok(new PhysicalUplink("eth0", "192.0.2.1")));
    }

    /// <summary>A DNS configurator that records its calls and can be told to throw.</summary>
    private sealed class StubDnsConfigurator : IDnsConfigurator
    {
        private readonly IReadOnlyList<string> _servers;
        private readonly string? _interfaceName;
        private readonly List<string> _order;

        public StubDnsConfigurator(IReadOnlyList<string> servers, string? interfaceName, List<string> order)
        {
            _servers = servers;
            _interfaceName = interfaceName;
            _order = order;
        }

        public Exception? InspectException { get; init; }

        public bool IsSupported => true;

        public Task<Result> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
        {
            _order.Add("dns.remove");
            return Task.FromResult(Result.Ok());
        }

        public Task<DnsState> InspectAsync(CancellationToken cancellationToken)
        {
            _order.Add("dns.inspect");

            if (InspectException is not null)
            {
                throw InspectException;
            }

            return Task.FromResult(new DnsState
            {
                ActiveServers = _servers,
                InterfaceName = _interfaceName,
                PlainDnsReachableOutsideTunnel = _interfaceName is null,
            });
        }
    }

    /// <summary>A system proxy that records its calls and can be told to fail or throw.</summary>
    private sealed class StubSystemProxy : ISystemProxy
    {
        private readonly bool _configured;
        private readonly List<string> _order;

        public StubSystemProxy(bool configured, List<string> order)
        {
            _configured = configured;
            _order = order;
        }

        public Exception? ResetException { get; init; }

        public Exception? InspectException { get; init; }

        public bool IsSupported => true;

        public Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Result<SystemProxySnapshot>.Ok(new SystemProxySnapshot()));

        public Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Ok());

        public Task<Result> ResetAsync(CancellationToken cancellationToken)
        {
            _order.Add("proxy.reset");

            if (ResetException is not null)
            {
                throw ResetException;
            }

            return Task.FromResult(Result.Ok());
        }

        public Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken)
        {
            _order.Add("proxy.inspect");

            if (InspectException is not null)
            {
                throw InspectException;
            }

            return Task.FromResult(new SystemProxyState
            {
                IsConfigured = _configured,
                ActiveProxy = _configured ? "127.0.0.1:10809" : null,
                PointsAtMyVpn = _configured,
            });
        }
    }
}
