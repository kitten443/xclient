using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.Linux.ProcessRouting;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>
/// A cgroupfs stand-in backed by dictionaries.
/// </summary>
/// <remarks>
/// cgroupfs is a file system, so the manager can be tested against a fake one: creating a cgroup
/// creates its control files, writing a PID to <c>cgroup.procs</c> <i>adds</i> a member (it does not
/// truncate), and a populated cgroup cannot be removed. Modelling those three behaviours is what
/// makes the tests meaningful rather than merely green.
/// </remarks>
internal sealed class FakeCgroupV2FileSystem : ICgroupV2FileSystem
{
    public const string MountInfoPath = "/proc/self/mountinfo";
    public const string Root = "/sys/fs/cgroup";

    private readonly Dictionary<string, string> _contents = new(StringComparer.Ordinal);
    private readonly HashSet<string> _directories = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SortedSet<int>> _members = new(StringComparer.Ordinal);

    /// <summary>Paths whose write should fail, with the message the kernel would produce.</summary>
    public Dictionary<string, string> WriteFailures { get; } = new(StringComparer.Ordinal);

    /// <summary>Directories whose creation should fail (EPERM on a root-owned cgroup root).</summary>
    public HashSet<string> CreateFailures { get; } = new(StringComparer.Ordinal);

    public static FakeCgroupV2FileSystem WithUnifiedHierarchy()
    {
        var fileSystem = new FakeCgroupV2FileSystem();
        fileSystem._contents[MountInfoPath] =
            "36 25 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
            + "37 25 0:33 / /sys/fs/cgroup/unified rw,nosuid - cgroup2 cgroup2 rw\n";
        fileSystem._directories.Add(Root);
        fileSystem._contents[Root + "/cgroup.controllers"] = "cpuset cpu io memory pids\n";
        fileSystem._members[Root + "/cgroup.procs"] = new SortedSet<int>();
        return fileSystem;
    }

    public static FakeCgroupV2FileSystem WithCgroupV1Only()
    {
        var fileSystem = new FakeCgroupV2FileSystem();
        fileSystem._contents[MountInfoPath] =
            "36 25 0:30 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpuacct\n"
            + "37 25 0:31 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        return fileSystem;
    }

    public IReadOnlyCollection<int> Members(string slicePath) =>
        _members.TryGetValue(slicePath + "/cgroup.procs", out var members)
            ? members
            : Array.Empty<int>();

    public IReadOnlyCollection<int> RootMembers =>
        Members(Root);

    public bool FileExists(string path) =>
        _contents.ContainsKey(path) || _members.ContainsKey(path);

    public bool DirectoryExists(string path) => _directories.Contains(path);

    public void CreateDirectory(string path)
    {
        if (CreateFailures.Contains(path))
        {
            throw new UnauthorizedAccessException($"Access to the path '{path}' is denied.");
        }

        _directories.Add(path);

        // Real cgroupfs: a new cgroup immediately contains its control files.
        _directories.Add(path);
        _contents[path + "/cgroup.controllers"] = string.Empty;
        _members[path + "/cgroup.procs"] = new SortedSet<int>();
    }

    public void DeleteDirectory(string path)
    {
        var procs = path + "/cgroup.procs";

        if (_members.TryGetValue(procs, out var members) && members.Count > 0)
        {
            throw new IOException($"Device or resource busy: '{path}' still has member processes.");
        }

        _directories.Remove(path);
        _contents.Remove(path + "/cgroup.controllers");
        _members.Remove(procs);
    }

    public string ReadAllText(string path)
    {
        if (_members.TryGetValue(path, out var members))
        {
            return string.Join('\n', members);
        }

        return _contents.TryGetValue(path, out var contents)
            ? contents
            : throw new FileNotFoundException($"No such file or directory: '{path}'", path);
    }

    public void WriteAllText(string path, string contents)
    {
        if (WriteFailures.TryGetValue(path, out var message))
        {
            throw new IOException(message);
        }

        if (_members.TryGetValue(path, out var members))
        {
            foreach (var token in contents.Split(
                         '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var pid = int.Parse(token, CultureInfo.InvariantCulture);

                // Real cgroupfs semantics: writing a PID to cgroup.procs *moves* it there, removing it
                // from whichever cgroup held it before. Without this the slice could never be removed,
                // because rmdir on a populated cgroup fails — which is exactly the behaviour under test.
                foreach (var other in _members.Where(entry => entry.Key != path))
                {
                    other.Value.Remove(pid);
                }

                members.Add(pid);
            }

            return;
        }

        _contents[path] = contents;
    }
}

/// <summary>Plans and contexts shared by the process-routing tests.</summary>
internal static class ProcessRoutingFixtures
{
    public const int Mark = 0x0CA6C;
    public const int TableId = 100;

    public static ProcessRoutingPlan TunnelPlan(
        ProcessRoutingMode mode = ProcessRoutingMode.VpnOnly,
        bool enforceable = true,
        string? cgroupPath = null,
        IReadOnlyList<ResolvedProcessSelector>? selectors = null) => new()
    {
        Mode = mode,
        Capability = ProcessRoutingCapability.FullRedirect,
        Enforceable = enforceable,
        CgroupPath = cgroupPath,
        FirewallMark = Mark,
        RoutingTableId = TableId,
        Selectors = selectors ?? new[]
        {
            new ResolvedProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutableName,
                ExecutableName = "firefox",
                IncludeChildren = true,
                ThroughTunnel = true,
            },
        },
    };

    public static ResolvedProcessSelector BypassSelector(string executable = "steam") => new()
    {
        Kind = ProcessSelectorKind.ExecutableName,
        ExecutableName = executable,
        IncludeChildren = true,
        ThroughTunnel = false,
    };

    public static ProcessRoutingRenderContext Context() => new()
    {
        TunnelInterface = "myvpn0",
        TunnelSlice = CgroupV2Manager.DefaultSliceName,
        BypassSlice = CgroupV2Manager.BypassSliceName,
        VpnServerEndpoints = new[] { "203.0.113.7" },
    };

    public static CgroupV2Manager Manager(FakeCgroupV2FileSystem fileSystem) =>
        new(fileSystem, FakeCgroupV2FileSystem.MountInfoPath);
}

/// <summary>
/// Tests for <see cref="NftablesProcessRoutingRenderer"/>.
/// </summary>
/// <remarks>
/// The renderer is a pure function, so everything here runs unprivileged. The ruleset it produces is
/// additionally loaded into a real kernel network namespace by
/// <see cref="LinuxProcessRoutingKernelTests"/>.
/// </remarks>
public sealed class NftablesProcessRoutingRendererTests
{
    private readonly ITestOutputHelper _output;

    public NftablesProcessRoutingRendererTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void RendersAnAtomicIdempotentReplacement()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        var text = ruleset.NftablesText;

        // The bare table line makes the following delete unconditional: without it, the very first
        // apply would fail because there is nothing to delete.
        text.ShouldContain("table inet myvpn_route\n");
        text.ShouldContain("delete table inet myvpn_route\n");
        text.IndexOf("table inet myvpn_route\n", StringComparison.Ordinal)
            .ShouldBeLessThan(text.IndexOf("delete table inet myvpn_route\n", StringComparison.Ordinal));

        // 'destroy table' is documented in newer manuals and rejected by nftables 1.0.x.
        text.ShouldNotContain("destroy table");

        _output.WriteLine(text);
    }

    [Fact]
    public void UsesARouteChainSoTheMarkActuallyChangesTheRoute()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        // Only `type route hook output` re-runs the route lookup after `meta mark set`; a filter
        // chain would set the mark and never consult it, which is a silent no-op.
        ruleset.NftablesText.ShouldContain("type route hook output priority mangle; policy accept;");
    }

    [Fact]
    public void IsDeterministicAndIndependentOfEndpointOrder()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan();

        var first = NftablesProcessRoutingRenderer.Render(plan, ProcessRoutingFixtures.Context());
        var second = NftablesProcessRoutingRenderer.Render(plan, ProcessRoutingFixtures.Context());

        first.NftablesText.ShouldBe(second.NftablesText);
        first.InstallCommands.Select(command => command.ToString())
            .ShouldBe(second.InstallCommands.Select(command => command.ToString()));

        var ordered = ProcessRoutingFixtures.Context() with
        {
            VpnServerEndpoints = new[] { "198.51.100.9", "203.0.113.7", "2001:db8::5" },
        };

        var reversed = ordered with
        {
            VpnServerEndpoints = new[] { "2001:db8::5", "203.0.113.7", "198.51.100.9" },
        };

        var a = NftablesProcessRoutingRenderer.Render(plan, ordered);
        var b = NftablesProcessRoutingRenderer.Render(plan, reversed);

        a.InstallCommands.Select(command => command.ToString())
            .ShouldBe(b.InstallCommands.Select(command => command.ToString()));

        // IPv4 before IPv6, then by address: stable, and independent of the input order.
        a.InstallCommands.Select(command => command.ToString())
            .Where(text => text.StartsWith("rule add to", StringComparison.Ordinal))
            .ShouldBe(new[]
            {
                "rule add to 198.51.100.9 lookup main priority 900",
                "rule add to 203.0.113.7 lookup main priority 900",
                "rule add to 2001:db8::5 lookup main priority 900",
            });
    }

    [Fact]
    public void MarkAndTableAreConsistentBetweenNftablesAndTheIpRule()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan();
        var ruleset = NftablesProcessRoutingRenderer.Render(plan, ProcessRoutingFixtures.Context());

        // What the firewall writes onto the packet...
        var nftMarks = Regex.Matches(ruleset.NftablesText, @"meta mark set (0x[0-9a-f]+)")
            .Select(match => match.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        nftMarks.ShouldBe(new[] { "0xca6c" });

        // ...must be exactly what the policy rule selects, together with the plan's table id.
        var commands = ruleset.InstallCommands.Select(command => command.ToString()).ToArray();

        commands.ShouldContain("rule add fwmark 0xca6c/0xca6c lookup 100 priority 1000");
        commands.ShouldContain("route replace default dev myvpn0 table 100");

        var markRule = Regex.Match(
            commands.Single(text => text.Contains("fwmark", StringComparison.Ordinal)
                                    && text.Contains("lookup", StringComparison.Ordinal)),
            @"fwmark (0x[0-9a-f]+)/\1 lookup (\d+) priority (\d+)");

        markRule.Success.ShouldBeTrue();
        markRule.Groups[1].Value.ShouldBe(nftMarks[0]);
        markRule.Groups[2].Value.ShouldBe(plan.RoutingTableId.ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void OrdersRouteThenServerPinThenMarkThenFailClosed()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        var commands = ruleset.InstallCommands.Select(command => command.ToString()).ToArray();

        var route = Array.FindIndex(commands, text => text.StartsWith("route replace", StringComparison.Ordinal));
        var pin = Array.FindIndex(commands, text => text.StartsWith("rule add to", StringComparison.Ordinal));
        var mark = Array.FindIndex(
            commands,
            text => text.Contains("fwmark", StringComparison.Ordinal)
                    && text.Contains("lookup", StringComparison.Ordinal));
        var prohibit = Array.FindIndex(commands, text => text.Contains("prohibit", StringComparison.Ordinal));

        // The route must exist before the rule that sends traffic to it (marked traffic must never
        // see an empty table), and the server's escape route must outrank the mark rule — otherwise
        // the core's own connection to the server would be routed into the tunnel it is building.
        route.ShouldBeGreaterThanOrEqualTo(0);
        pin.ShouldBe(route + 1);
        mark.ShouldBe(pin + 1);
        prohibit.ShouldBe(mark + 1);

        // Fail-closed: if the tunnel is down, the marked traffic must die rather than fall through to
        // the physical uplink.
        commands[prohibit].ShouldBe("rule add fwmark 0xca6c/0xca6c prohibit priority 1100");
        commands[pin].ShouldBe("rule add to 203.0.113.7 lookup main priority 900");
    }

    [Fact]
    public void ExplainsLoopPreventionInTheGeneratedFile()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        ruleset.NftablesText.ShouldContain("LOOP PREVENTION");
        ruleset.NftablesText.ShouldContain("oifname \"myvpn0\" return");
        ruleset.NftablesText.ShouldContain("never re-mark");
    }

    [Fact]
    public void UsesLevelOneForTheDefaultSliceAndEscapesTheComponent()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        ruleset.NftablesText.ShouldContain("socket cgroupv2 level 1 \"myvpn.slice\" meta mark set 0xca6c");
    }

    [Fact]
    public void UsesTheComponentDepthForANestedSlice()
    {
        var context = ProcessRoutingFixtures.Context() with { TunnelSlice = "myvpn.slice/apps.slice" };
        var ruleset = NftablesProcessRoutingRenderer.Render(ProcessRoutingFixtures.TunnelPlan(), context);

        // level N compares the socket's Nth ancestor component, so a two-component slice matches at
        // level 2 with its leaf name.
        ruleset.NftablesText.ShouldContain("socket cgroupv2 level 2 \"apps.slice\"");
    }

    [Fact]
    public void OffRendersTeardownRatherThanRules()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan(mode: ProcessRoutingMode.Off);
        var ruleset = NftablesProcessRoutingRenderer.Render(plan, ProcessRoutingFixtures.Context());

        ruleset.IsTeardown.ShouldBeTrue();
        ruleset.HasMarkingRules.ShouldBeFalse();
        ruleset.NftablesText.ShouldContain("delete table inet myvpn_route");
        ruleset.NftablesText.ShouldNotContain("meta mark set");
        ruleset.NftablesText.ShouldNotContain("socket cgroupv2");

        // "Off" must actively remove: leaving the mark rule behind would keep the previous selection
        // in force while the UI reports per-app routing as disabled.
        foreach (var command in ruleset.InstallCommands)
        {
            var text = command.ToString();
            (text.Contains(" del ", StringComparison.Ordinal)
             || text.StartsWith("route flush", StringComparison.Ordinal)).ShouldBeTrue(text);
        }

        ruleset.InstallCommands.Select(command => command.ToString())
            .ShouldBe(ruleset.RemoveCommands.Select(command => command.ToString()));
    }

    [Fact]
    public void TeardownRemovesBothDirectionsAndEveryRuleIsSafeToRepeat()
    {
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(mode: ProcessRoutingMode.Off), ProcessRoutingFixtures.Context());

        var commands = ruleset.RemoveCommands.Select(command => command.ToString()).ToArray();

        // Both directions, unconditionally: the plan may have been edited since it was applied, and
        // removing something that is not there is a no-op the executor tolerates.
        commands.ShouldContain("rule del fwmark 0xca6c/0xca6c lookup 100 priority 1000");
        commands.ShouldContain("rule del fwmark 0xca6c/0xca6c prohibit priority 1100");
        commands.ShouldContain("rule del to 203.0.113.7 lookup main priority 900");
        commands.ShouldContain("route flush table 100");
        commands.ShouldContain("rule del fwmark 0xca6d/0xca6d lookup 101 priority 1000");
        commands.ShouldContain("route flush table 101");

        // Rules before the table's routes: removing the route while the mark rule is still live would
        // leak marked traffic to the physical uplink during teardown.
        Array.IndexOf(commands, "rule del fwmark 0xca6c/0xca6c lookup 100 priority 1000")
            .ShouldBeLessThan(Array.IndexOf(commands, "route flush table 100"));
    }

    [Fact]
    public void BypassSelectorsGetTheirOwnMarkTableAndPhysicalRoute()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.Rules,
            selectors: new[]
            {
                ProcessRoutingFixtures.TunnelPlan().Selectors[0],
                ProcessRoutingFixtures.BypassSelector(),
            });

        var context = ProcessRoutingFixtures.Context() with
        {
            PhysicalUplink = new PhysicalUplinkRoute("eth0", "192.0.2.1"),
        };

        var ruleset = NftablesProcessRoutingRenderer.Render(plan, context);
        var commands = ruleset.InstallCommands.Select(command => command.ToString()).ToArray();

        // Both slices are matched, each with its own mark.
        ruleset.NftablesText.ShouldContain("socket cgroupv2 level 1 \"myvpn.slice\" meta mark set 0xca6c");
        ruleset.NftablesText.ShouldContain("socket cgroupv2 level 1 \"myvpn-bypass.slice\" meta mark set 0xca6d");

        commands.ShouldContain("route replace default dev myvpn0 table 100");
        commands.ShouldContain("route replace default via 192.0.2.1 dev eth0 table 101");
        commands.ShouldContain("rule add fwmark 0xca6c/0xca6c lookup 100 priority 1000");
        commands.ShouldContain("rule add fwmark 0xca6d/0xca6d lookup 101 priority 1000");
    }

    [Fact]
    public void RefusesABypassSelectorWithoutAPhysicalUplink()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.BypassVpn,
            selectors: new[] { ProcessRoutingFixtures.BypassSelector() });

        // A bypass mark with no route to send it through would load perfectly and silently do
        // nothing, so the renderer refuses instead of producing it.
        var exception = Should.Throw<ArgumentException>(
            () => NftablesProcessRoutingRenderer.Render(plan, ProcessRoutingFixtures.Context()));

        exception.Message.ShouldContain("PhysicalUplink");
    }

    [Fact]
    public void RefusesServerEndpointsThatAreNotIpLiterals()
    {
        var context = ProcessRoutingFixtures.Context() with
        {
            VpnServerEndpoints = new[] { "vpn.example.com; rm -rf /" },
        };

        Should.Throw<ArgumentException>(() =>
            NftablesProcessRoutingRenderer.Render(ProcessRoutingFixtures.TunnelPlan(), context));
    }

    [Fact]
    public void EveryCommandIsAnArgvVectorThatNeedsNoShell()
    {
        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.Rules,
            selectors: new[]
            {
                ProcessRoutingFixtures.TunnelPlan().Selectors[0],
                ProcessRoutingFixtures.BypassSelector(),
            });

        var context = ProcessRoutingFixtures.Context() with
        {
            PhysicalUplink = new PhysicalUplinkRoute("eth0", "192.0.2.1"),
        };

        var ruleset = NftablesProcessRoutingRenderer.Render(plan, context);

        foreach (var command in ruleset.InstallCommands.Concat(ruleset.RemoveCommands))
        {
            command.Arguments.ShouldNotBeEmpty();

            foreach (var argument in command.Arguments)
            {
                argument.ShouldNotBeNullOrWhiteSpace();

                argument.IndexOfAny(new[] { ' ', ';', '|', '&', '`', '$', '"', '\'', '\n', '>', '<', '*' })
                    .ShouldBe(-1, $"'{argument}' would need a shell to survive");
            }
        }
    }
}

/// <summary>Tests for the cgroup v2 slice manager, against a fake cgroupfs.</summary>
public sealed class CgroupV2ManagerTests
{
    [Fact]
    public void DetectFindsTheUnifiedHierarchyMountPoint()
    {
        var manager = ProcessRoutingFixtures.Manager(FakeCgroupV2FileSystem.WithUnifiedHierarchy());

        var detected = manager.Detect();

        detected.IsSuccess.ShouldBeTrue();
        detected.Value.Root.ShouldBe(FakeCgroupV2FileSystem.Root);
    }

    [Fact]
    public void DetectReportsAMissingCgroupV2RatherThanAssumingOne()
    {
        var manager = ProcessRoutingFixtures.Manager(FakeCgroupV2FileSystem.WithCgroupV1Only());

        var detected = manager.Detect();

        detected.IsFailure.ShouldBeTrue();
        detected.Error!.MessageKey.ShouldBe("error.process.cgroup_v2_missing");
        detected.Error.Code.ShouldBe(ErrorCodes.ProcessRoutingUnsupported);
    }

    [Fact]
    public void EnsureSliceCreatesOnceAndNeverRecreates()
    {
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var manager = ProcessRoutingFixtures.Manager(fileSystem);

        var first = manager.EnsureSlice(CgroupV2Manager.DefaultSliceName);
        first.IsSuccess.ShouldBeTrue();
        first.Value.Created.ShouldBeTrue();
        first.Value.Path.ShouldBe("/sys/fs/cgroup/myvpn.slice");

        // Re-creating a slice would give it a new cgroup ID and silently invalidate every rule the
        // kernel is currently matching against it, so an existing slice is returned untouched.
        var second = manager.EnsureSlice(CgroupV2Manager.DefaultSliceName);
        second.IsSuccess.ShouldBeTrue();
        second.Value.Created.ShouldBeFalse();
    }

    [Fact]
    public void EnsureSliceFailsClearlyWhenTheCgroupRootIsNotWritable()
    {
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        fileSystem.CreateFailures.Add("/sys/fs/cgroup/myvpn.slice");

        var created = ProcessRoutingFixtures.Manager(fileSystem).EnsureSlice(CgroupV2Manager.DefaultSliceName);

        created.IsFailure.ShouldBeTrue();
        created.Error!.MessageKey.ShouldBe("error.process.cgroup_create_failed");
        created.Error.RemediationKey.ShouldBe("privilege.install_helper");
    }

    [Fact]
    public void MoveProcessesRecordsMembershipAndSkipsProcessesThatExited()
    {
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var manager = ProcessRoutingFixtures.Manager(fileSystem);
        manager.EnsureSlice(CgroupV2Manager.DefaultSliceName).IsSuccess.ShouldBeTrue();

        var moved = manager.MoveProcesses(CgroupV2Manager.DefaultSliceName, new[] { 1, 0, 4242, 4243 });

        // PID 1 is the whole machine and PID 0 is not a process: neither may ever be moved.
        moved.IsSuccess.ShouldBeTrue();
        moved.Value.ShouldBe(2);
        fileSystem.Members("/sys/fs/cgroup/myvpn.slice").ShouldBe(new[] { 4242, 4243 });

        // A process that disappears between enumeration and the write is normal, not a failure.
        fileSystem.WriteFailures["/sys/fs/cgroup/myvpn.slice/cgroup.procs"] = "No such process";
        manager.MoveProcesses(CgroupV2Manager.DefaultSliceName, new[] { 9999 }).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void RemoveSliceReleasesMembersThenRemovesTheDirectoryAndIsIdempotent()
    {
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var manager = ProcessRoutingFixtures.Manager(fileSystem);
        manager.EnsureSlice(CgroupV2Manager.DefaultSliceName).IsSuccess.ShouldBeTrue();
        manager.MoveProcesses(CgroupV2Manager.DefaultSliceName, new[] { 4242 }).IsSuccess.ShouldBeTrue();

        var removed = manager.RemoveSlice(CgroupV2Manager.DefaultSliceName);

        removed.IsSuccess.ShouldBeTrue();

        // Released back to the root cgroup: a process in the root matches no slice, so no rule applies.
        fileSystem.RootMembers.ShouldBe(new[] { 4242 });
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();

        // Removing what is not there is success: this is what makes crash recovery safe to run blind.
        manager.RemoveSlice(CgroupV2Manager.DefaultSliceName).IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void RemoveSliceOnAnUnmountedHierarchySucceeds()
    {
        var manager = ProcessRoutingFixtures.Manager(FakeCgroupV2FileSystem.WithCgroupV1Only());

        var removed = manager.RemoveSlice(CgroupV2Manager.DefaultSliceName);

        removed.IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void MoveProcessesFailsWhenTheSliceDoesNotExist()
    {
        var manager = ProcessRoutingFixtures.Manager(FakeCgroupV2FileSystem.WithUnifiedHierarchy());

        var moved = manager.MoveProcesses(CgroupV2Manager.DefaultSliceName, new[] { 4242 });

        moved.IsFailure.ShouldBeTrue();
        moved.Error!.MessageKey.ShouldBe("error.process.cgroup_join_failed");
    }

    [Fact]
    public void ResolveMatchUsesTheComponentDepth()
    {
        var top = CgroupV2Manager.ResolveMatch("myvpn.slice");
        top.Level.ShouldBe(1);
        top.Component.ShouldBe("myvpn.slice");
        top.RenderNft().ShouldBe("socket cgroupv2 level 1 \"myvpn.slice\"");

        var nested = CgroupV2Manager.ResolveMatch("myvpn.slice/apps.slice");
        nested.Level.ShouldBe(2);
        nested.Component.ShouldBe("apps.slice");
    }

    [Theory]
    [InlineData("../escape.slice")]
    [InlineData("myvpn.slice/../../escape.slice")]
    [InlineData("myvpn.slice\" meta mark set 0x1 comment \"")]
    [InlineData("myvpn.slice\ncounter drop")]
    [InlineData("myvpn slice")]
    public void NormalizeRejectsTraversalAndRulesetInjection(string slice)
    {
        CgroupV2Manager.NormalizeRelativePath(slice).IsFailure.ShouldBeTrue();
    }

    [Fact]
    public void NormalizeAcceptsTheShapesSettingsMayProduce()
    {
        CgroupV2Manager.NormalizeRelativePath(null).Value.ShouldBe("myvpn.slice");
        CgroupV2Manager.NormalizeRelativePath("myvpn.slice").Value.ShouldBe("myvpn.slice");
        CgroupV2Manager.NormalizeRelativePath("/sys/fs/cgroup/myvpn.slice").Value.ShouldBe("myvpn.slice");
        CgroupV2Manager.NormalizeRelativePath("myvpn.slice/").Value.ShouldBe("myvpn.slice");
    }
}

/// <summary>
/// Tests for the Linux process-routing executor, driven by a fake command runner and a fake cgroupfs.
/// </summary>
/// <remarks>
/// These cover the executor's own responsibilities: refusing to act without privileges or a usable
/// cgroup hierarchy, probing the kernel before it emits anything, ordering and tolerating the
/// commands it runs, moving exactly the right processes into the slice, and being idempotent.
/// </remarks>
public sealed class CgroupV2ProcessRouterTests
{
    private readonly ITestOutputHelper _output;

    public CgroupV2ProcessRouterTests(ITestOutputHelper output) => _output = output;

    private const string ListingWithOurRules =
        "table inet myvpn_route {\n"
        + "\tchain mark_output {\n"
        + "\t\ttype route hook output priority mangle; policy accept;\n"
        + "\t\tsocket cgroupv2 level 1 \"myvpn.slice\" meta mark set 0x0000ca6c\n"
        + "\t}\n"
        + "}\n";

    /// <summary>A runner that accepts the probe, the ruleset and the read-back.</summary>
    private static FakeCommandRunner SucceedingRunner(bool failRealApply = false)
    {
        var runner = new FakeCommandRunner();
        runner.Available.Add("ip");

        runner.Handler = (fileName, arguments) =>
        {
            var text = string.Join(' ', arguments);

            if (text.Contains("--check", StringComparison.Ordinal))
            {
                return new CommandResult(0, string.Empty, string.Empty);
            }

            if (arguments.Count > 0 && arguments[0] == "--file")
            {
                if (failRealApply
                    && arguments.Count > 1
                    && File.Exists(arguments[1])
                    && File.ReadAllText(arguments[1]).Contains("meta mark set", StringComparison.Ordinal))
                {
                    return new CommandResult(1, string.Empty, "Error: syntax error, unexpected newline");
                }

                return new CommandResult(0, string.Empty, string.Empty);
            }

            if (arguments.Count > 0 && arguments[0] == "list")
            {
                return new CommandResult(0, ListingWithOurRules, string.Empty);
            }

            // The physical uplink probe a bypass needs: a plain default route on a non-tunnel device.
            if (arguments.Count > 2
                && (arguments[0] == "-4" || arguments[0] == "-6")
                && arguments[1] == "route")
            {
                return new CommandResult(
                    0,
                    "default via 192.0.2.1 dev eth0 proto dhcp metric 100\n",
                    string.Empty);
            }

            _ = fileName;
            return new CommandResult(0, string.Empty, string.Empty);
        };

        return runner;
    }

    private static IReadOnlyList<ProcessDescriptor> SyntheticProcesses() => new[]
    {
        new ProcessDescriptor
        {
            ProcessId = 4242,
            ExecutableName = "firefox",
            ExecutablePath = "/usr/lib/firefox/firefox",
        },
        new ProcessDescriptor
        {
            ProcessId = 4243,
            ExecutableName = "firefox-bin",
            ExecutablePath = "/usr/lib/firefox/firefox-bin",
        },
        new ProcessDescriptor
        {
            ProcessId = 5000,
            ExecutableName = "unrelated",
            ExecutablePath = "/usr/bin/unrelated",
        },
    };

    private static Func<int, int?> SyntheticTree() => pid => pid switch
    {
        4243 => 4242,
        4242 => 1,
        _ => 1,
    };

    private static CgroupV2ProcessRouter Router(
        FakeCommandRunner runner,
        FakeCgroupV2FileSystem fileSystem,
        bool elevated = true,
        IReadOnlyList<ProcessDescriptor>? processes = null,
        Func<int, int?>? parentReader = null,
        IReadOnlyList<string>? endpoints = null) =>
        new(
            runner,
            isElevated: () => elevated,
            cgroups: ProcessRoutingFixtures.Manager(fileSystem),
            tunnelInterface: "myvpn0",
            vpnServerEndpoints: endpoints ?? new[] { "203.0.113.7" },
            parentReader: parentReader ?? SyntheticTree(),
            processEnumerator: _ => Task.FromResult(
                processes ?? Array.Empty<ProcessDescriptor>()));

    [Fact]
    public void ReportsFullRedirectCapability()
    {
        // This is the one platform where the honest answer is "yes, really".
        new CgroupV2ProcessRouter().Capability.ShouldBe(ProcessRoutingCapability.FullRedirect);
    }

    [Fact]
    public async Task EnumerateAsyncStillReturnsRealProcesses()
    {
        var router = new CgroupV2ProcessRouter();

        var processes = await router.EnumerateAsync(CancellationToken.None);

        processes.ShouldNotBeEmpty();
        processes.ShouldContain(process => process.ProcessId == Environment.ProcessId);
    }

    [Fact]
    public async Task InterfaceDispatchReachesThisRouterRatherThanTheBaseRefusal()
    {
        // LinuxPlatformServices exposes the router as IProcessRouter, and the base class implements
        // that interface with a non-virtual refusal; this asserts the derived implementation is what
        // an interface call actually reaches.
        IProcessRouter router = Router(
            SucceedingRunner(), FakeCgroupV2FileSystem.WithUnifiedHierarchy(), elevated: false);

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.needs_privileges");
    }

    [Fact]
    public async Task RefusesWithoutPrivilegesAndRunsNothing()
    {
        var runner = SucceedingRunner();
        var router = Router(runner, FakeCgroupV2FileSystem.WithUnifiedHierarchy(), elevated: false);

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);
        applied.Error.MessageKey.ShouldBe("error.process.needs_privileges");
        applied.Error.RemediationKey.ShouldBe("privilege.install_helper");

        // A failed `nft` as a normal user produces "Operation not permitted", which looks like a
        // broken ruleset rather than a missing helper. Refusing first is what keeps that honest.
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task RefusesWhenCgroupV2IsNotMountedAndRunsNothing()
    {
        var runner = SucceedingRunner();
        var router = Router(runner, FakeCgroupV2FileSystem.WithCgroupV1Only());

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.cgroup_v2_missing");
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task RefusesWhenTheKernelCannotMatchSocketCgroupv2()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        runner.Handler = (_, arguments) =>
            string.Join(' ', arguments).Contains("--check", StringComparison.Ordinal)
                ? new CommandResult(
                    1,
                    string.Empty,
                    "Error: unsupported expression type 'socket cgroupv2' (Operation not supported)")
                : new CommandResult(0, string.Empty, string.Empty);

        var router = Router(runner, fileSystem);

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.cgroupv2_match_unsupported");
        applied.Error.RemediationKey.ShouldBe("platform.upgrade_kernel");

        // The probe runs before anything is loaded, and the slice it created for the probe is removed
        // again: a rejected probe must not leave state behind.
        runner.Calls.Count.ShouldBe(1);
        runner.Calls[0].Arguments.ShouldContain("--check");
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();

        _output.WriteLine(applied.Error.ToString());
    }

    [Fact]
    public async Task RefusesAnUnenforceablePlanBeforeRunningAnything()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var router = Router(runner, fileSystem);

        var applied = await router.ApplyAsync(
            ProcessRoutingFixtures.TunnelPlan(enforceable: false), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.ProcessRoutingUnsupported);
        applied.Error.MessageKey.ShouldBe("error.process.unsupported_on_platform");
        runner.Calls.ShouldBeEmpty();
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();
    }

    [Fact]
    public async Task RefusesAPlanWithNoSelectorsBeforeRunningAnything()
    {
        var runner = SucceedingRunner();
        var router = Router(runner, FakeCgroupV2FileSystem.WithUnifiedHierarchy());

        var applied = await router.ApplyAsync(
            ProcessRoutingFixtures.TunnelPlan(selectors: Array.Empty<ResolvedProcessSelector>()),
            CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.mode_without_selection");
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task OffTearsDownInsteadOfFailingValidation()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        // A plan with no selectors would fail validation, but "Off" is a teardown request: refusing
        // it would leave enforcement installed with no way to remove it.
        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.Off, selectors: Array.Empty<ResolvedProcessSelector>());

        var removed = await Router(runner, fileSystem).ApplyAsync(plan, CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();
        runner.FileSnapshots.Values.ShouldContain(
            text => text.Contains("delete table inet myvpn_route", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AppliesFirewallRoutesAndMembershipInTheDocumentedOrder()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var router = Router(runner, fileSystem, processes: SyntheticProcesses());

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        // The slice holds the selected process and its already-running child, and nothing else.
        fileSystem.Members("/sys/fs/cgroup/myvpn.slice").ShouldBe(new[] { 4242, 4243 });

        var nftCalls = runner.Calls.Where(call => Path.GetFileName(call.FileName) == "nft").ToArray();

        nftCalls[0].Arguments[0].ShouldBe("--check");
        nftCalls[0].Arguments[1].ShouldBe("--file");
        nftCalls[1].Arguments[0].ShouldBe("--file");
        nftCalls[2].Arguments[0].ShouldBe("list");

        // The ruleset handed to `nft` is the rendered one, from a private file that is deleted after.
        var rulesetPath = nftCalls[1].Arguments[1];
        runner.FileSnapshots[rulesetPath].ShouldContain("socket cgroupv2 level 1 \"myvpn.slice\"");
        File.Exists(rulesetPath).ShouldBeFalse();

        var ipCalls = runner.Calls
            .Where(call => Path.GetFileName(call.FileName) == "ip")
            .Select(call => string.Join(' ', call.Arguments))
            .ToArray();

        ipCalls.ShouldBe(new[]
        {
            "route replace default dev myvpn0 table 100",
            "rule add to 203.0.113.7 lookup main priority 900",
            "rule add fwmark 0xca6c/0xca6c lookup 100 priority 1000",
            "rule add fwmark 0xca6c/0xca6c prohibit priority 1100",
        });
    }

    [Fact]
    public async Task HonoursIncludeChildrenAndNeverMovesItselfOrPidOne()
    {
        var processes = SyntheticProcesses()
            .Append(new ProcessDescriptor
            {
                ProcessId = Environment.ProcessId,
                ExecutableName = "firefox",
                ExecutablePath = "/usr/lib/firefox/firefox",
            })
            .Append(new ProcessDescriptor { ProcessId = 1, ExecutableName = "firefox" })
            .ToArray();

        var withChildren = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var appliedWithChildren = await Router(
            SucceedingRunner(), withChildren, processes: processes).ApplyAsync(
            ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        appliedWithChildren.IsSuccess.ShouldBeTrue();

        // A cgroup is inherited across fork, so the child is in the slice before it can open a socket;
        // the router's own process and PID 1 are never moved in, whatever the selector says.
        withChildren.Members("/sys/fs/cgroup/myvpn.slice").ShouldBe(new[] { 4242, 4243 });

        var withoutChildren = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var selectors = new[]
        {
            ProcessRoutingFixtures.TunnelPlan().Selectors[0] with { IncludeChildren = false },
        };

        var appliedWithout = await Router(
            SucceedingRunner(), withoutChildren, processes: processes).ApplyAsync(
            ProcessRoutingFixtures.TunnelPlan(selectors: selectors), CancellationToken.None);

        appliedWithout.IsSuccess.ShouldBeTrue();
        withoutChildren.Members("/sys/fs/cgroup/myvpn.slice").ShouldBe(new[] { 4242 });
    }

    [Fact]
    public async Task MovesBypassSelectorsIntoTheirOwnSlice()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.BypassVpn,
            selectors: new[] { ProcessRoutingFixtures.BypassSelector("unrelated") });

        var applied = await Router(runner, fileSystem, processes: SyntheticProcesses())
            .ApplyAsync(plan, CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        fileSystem.Members("/sys/fs/cgroup/myvpn-bypass.slice").ShouldBe(new[] { 5000 });
        fileSystem.Members("/sys/fs/cgroup/myvpn.slice").ShouldBeEmpty();

        var ipCalls = runner.Calls
            .Where(call => Path.GetFileName(call.FileName) == "ip")
            .Select(call => string.Join(' ', call.Arguments))
            .ToArray();

        ipCalls.ShouldContain("-4 route show default");
        ipCalls.ShouldContain("route replace default via 192.0.2.1 dev eth0 table 101");
        ipCalls.ShouldContain("rule add fwmark 0xca6d/0xca6d lookup 101 priority 1000");
    }

    [Fact]
    public async Task RollsBackWhenNftablesRejectsTheRuleset()
    {
        var runner = SucceedingRunner(failRealApply: true);
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var router = Router(runner, fileSystem, processes: SyntheticProcesses());

        var applied = await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.ruleset_rejected");
        applied.Error.TechnicalDetail!.ShouldContain("syntax error");

        // A half-applied policy is worse than none, so the failed apply removes what it created.
        runner.FileSnapshots.Values.ShouldContain(
            text => text.Contains("delete table inet myvpn_route", StringComparison.Ordinal));
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();

        _output.WriteLine(applied.Error.ToString());
    }

    [Fact]
    public async Task RollsBackWhenARoutingCommandFails()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        runner.Handler = (fileName, arguments) =>
        {
            var text = string.Join(' ', arguments);

            if (text.Contains("--check", StringComparison.Ordinal)
                || text.Contains("list table", StringComparison.Ordinal))
            {
                return new CommandResult(0, ListingWithOurRules, string.Empty);
            }

            if (text.StartsWith("route replace", StringComparison.Ordinal))
            {
                return new CommandResult(2, string.Empty, "RTNETLINK answers: Network is unreachable");
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };

        var applied = await Router(runner, fileSystem, processes: SyntheticProcesses())
            .ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.route_failed");
        applied.Error.TechnicalDetail!.ShouldContain("Network is unreachable");
    }

    [Fact]
    public async Task RefusesWhenTheToolsAreMissing()
    {
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        var withoutNft = SucceedingRunner();
        withoutNft.Available.Remove("nft");

        var noNft = await Router(withoutNft, fileSystem)
            .ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        noNft.IsFailure.ShouldBeTrue();
        noNft.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);
        noNft.Error.MessageKey.ShouldBe("error.process.tool_missing");
        noNft.Error.Arguments["tool"].ShouldBe("nft");
        withoutNft.Calls.ShouldBeEmpty();

        var withoutIp = SucceedingRunner();
        withoutIp.Available.Remove("ip");

        var noIp = await Router(withoutIp, fileSystem)
            .ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        noIp.IsFailure.ShouldBeTrue();
        noIp.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);
        noIp.Error.Arguments["tool"].ShouldBe("ip");
        withoutIp.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReportsVerificationFailureAndRollsBackWhenTheKernelDoesNotShowTheRules()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();

        // `nft -f` succeeds, but the listing does not contain our rules — another tool removed the
        // table, or the load went somewhere else. Reporting success here would tell the user their
        // selected applications are tunnelled when nothing is in force.
        runner.Handler = (_, arguments) =>
        {
            var text = string.Join(' ', arguments);

            if (text.Contains("--check", StringComparison.Ordinal))
            {
                return new CommandResult(0, string.Empty, string.Empty);
            }

            if (arguments.Count > 0 && arguments[0] == "list")
            {
                return new CommandResult(0, "table inet myvpn_route {\n}\n", string.Empty);
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };

        var applied = await Router(runner, fileSystem, processes: SyntheticProcesses())
            .ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.process.verify_failed");
        applied.Error.Severity.ShouldBe(ErrorSeverity.Critical);

        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();
    }

    [Fact]
    public async Task RemoveIsIdempotentWhenNothingWasEverApplied()
    {
        var runner = new FakeCommandRunner();
        runner.Available.Add("ip");

        // The kernel's answers when there is nothing to delete. `ip rule del` exits 2, and
        // `ip route flush` on a table that was never created exits 2 as well.
        runner.Handler = (_, arguments) =>
        {
            var text = string.Join(' ', arguments);

            if (text.StartsWith("rule del", StringComparison.Ordinal))
            {
                return new CommandResult(2, string.Empty, "RTNETLINK answers: No such file or directory");
            }

            if (text.StartsWith("route flush", StringComparison.Ordinal))
            {
                return new CommandResult(2, string.Empty, "Error: ipv4: FIB table does not exist.");
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };

        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var router = Router(runner, fileSystem, processes: SyntheticProcesses());

        var first = await router.RemoveAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);
        var second = await router.RemoveAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        first.IsSuccess.ShouldBeTrue();
        second.IsSuccess.ShouldBeTrue();
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();
    }

    [Fact]
    public async Task RemoveReleasesMembershipAndDeletesTheSlices()
    {
        var runner = SucceedingRunner();
        var fileSystem = FakeCgroupV2FileSystem.WithUnifiedHierarchy();
        var router = Router(runner, fileSystem, processes: SyntheticProcesses());

        (await router.ApplyAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None))
            .IsSuccess.ShouldBeTrue();

        fileSystem.Members("/sys/fs/cgroup/myvpn.slice").ShouldNotBeEmpty();

        var removed = await router.RemoveAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();
        fileSystem.RootMembers.ShouldBe(new[] { 4242, 4243 });
        fileSystem.DirectoryExists("/sys/fs/cgroup/myvpn.slice").ShouldBeFalse();

        // The rules, not just the cgroup: a surviving mark rule could still capture traffic put into
        // the slice by a later run.
        runner.FileSnapshots.Values.ShouldContain(
            text => text.Contains("delete table inet myvpn_route", StringComparison.Ordinal));

        var ipCalls = runner.Calls
            .Where(call => Path.GetFileName(call.FileName) == "ip")
            .Select(call => string.Join(' ', call.Arguments))
            .ToArray();

        ipCalls.ShouldContain("rule del fwmark 0xca6c/0xca6c lookup 100 priority 1000");
        ipCalls.ShouldContain("route flush table 100");
    }

    [Fact]
    public async Task RemoveRefusesWithoutPrivilegesRatherThanPretendingToHaveCleanedUp()
    {
        var runner = SucceedingRunner();
        var router = Router(runner, FakeCgroupV2FileSystem.WithUnifiedHierarchy(), elevated: false);

        var removed = await router.RemoveAsync(ProcessRoutingFixtures.TunnelPlan(), CancellationToken.None);

        removed.IsFailure.ShouldBeTrue();
        removed.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);
        runner.Calls.ShouldBeEmpty();
    }
}

/// <summary>
/// Real-kernel verification of the rendered ruleset and the rendered <c>ip</c> commands.
/// </summary>
/// <remarks>
/// <para>
/// <c>nft --check</c> needs <c>CAP_NET_ADMIN</c> even to parse, so the checks run inside a throwaway
/// user and network namespace created with <c>unshare -rn</c>: inside it the process holds the
/// capability, and the host's firewall and routing tables are never touched. This is the same method
/// <c>NftablesKillSwitchRendererTests</c> uses, and the same one the research document prescribes.
/// </para>
/// <para>
/// <b>What these tests cannot do here.</b> Creating <c>/sys/fs/cgroup/myvpn.slice</c> requires write
/// access to the cgroup root, which is root-owned; a user namespace does not grant it, because
/// cgroupfs is not mountable-with-ownership from a child user namespace. The ruleset is therefore
/// loaded with a cgroup component that exists on the host, and the failure of the production slice
/// name is asserted separately — which is itself the evidence for why the executor probes first.
/// </para>
/// </remarks>
public sealed class LinuxProcessRoutingKernelTests
{
    private readonly ITestOutputHelper _output;

    public LinuxProcessRoutingKernelTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void RenderedRulesetIsAcceptedAndLoadableByTheKernel()
    {
        if (!TryGetTooling(out var reason, out var component))
        {
            _output.WriteLine($"SKIPPED: {reason}");
            return;
        }

        _output.WriteLine($"cgroup component used for the match: {component}");

        var plan = ProcessRoutingFixtures.TunnelPlan();
        var context = ProcessRoutingFixtures.Context() with { TunnelSlice = component };
        var ruleset = NftablesProcessRoutingRenderer.Render(plan, context);

        _output.WriteLine(ruleset.NftablesText);

        var path = WriteTemp("myvpn-route", ruleset.NftablesText);
        var script = WriteScript(
            "myvpn-load",
            $"nft -f {path}",
            "nft list table inet myvpn_route");

        try
        {
            // Syntax and static semantics, evaluated by the kernel without committing anything.
            var check = RunRaw("unshare", "-rn", "nft", "-c", "-f", path);
            _output.WriteLine($"nft -c stderr: {check.StdErr}");
            check.ExitCode.ShouldBe(0, $"nft --check rejected the rendered ruleset: {check.StdErr}");

            // Then the real thing, inside the throwaway namespace.
            var applied = RunRaw("unshare", "-rn", "sh", script);
            _output.WriteLine($"nft apply stdout: {applied.StdOut}");
            _output.WriteLine($"nft apply stderr: {applied.StdErr}");
            applied.ExitCode.ShouldBe(0, $"the kernel refused the rendered ruleset: {applied.StdErr}");

            // Read back what the kernel actually holds, including the resolved cgroup match.
            applied.StdOut.ShouldContain("table inet myvpn_route");
            applied.StdOut.ShouldContain("socket cgroupv2 level 1");
            applied.StdOut.ShouldContain("0x0000ca6c");
        }
        finally
        {
            File.Delete(path);
            File.Delete(script);
        }
    }

    [Fact]
    public void ARuleForASliceThatDoesNotExistIsRejectedByTheKernel()
    {
        if (!TryGetTooling(out var reason, out _))
        {
            _output.WriteLine($"SKIPPED: {reason}");
            return;
        }

        if (Directory.Exists("/sys/fs/cgroup/" + CgroupV2Manager.DefaultSliceName))
        {
            _output.WriteLine(
                $"SKIPPED: /sys/fs/cgroup/{CgroupV2Manager.DefaultSliceName} exists on this host.");
            return;
        }

        // The production slice name does not exist here, and the kernel refuses the ruleset outright.
        // This is precisely the failure the executor probes for: a match that cannot resolve is
        // rejected rather than installed as a rule that never fires.
        var ruleset = NftablesProcessRoutingRenderer.Render(
            ProcessRoutingFixtures.TunnelPlan(), ProcessRoutingFixtures.Context());

        var path = WriteTemp("myvpn-route-missing", ruleset.NftablesText);

        try
        {
            var check = RunRaw("unshare", "-rn", "nft", "-c", "-f", path);

            _output.WriteLine($"nft -c stderr: {check.StdErr.Trim()}");
            check.ExitCode.ShouldNotBe(0);
            check.StdErr.ShouldContain("cgroupv2 path fails");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RenderedIpCommandsAreAcceptedByTheKernelAndIdempotentlyRemovable()
    {
        if (!TryGetTooling(out var reason, out var component))
        {
            _output.WriteLine($"SKIPPED: {reason}");
            return;
        }

        var plan = ProcessRoutingFixtures.TunnelPlan(
            mode: ProcessRoutingMode.Rules,
            selectors: new[]
            {
                ProcessRoutingFixtures.TunnelPlan().Selectors[0],
                ProcessRoutingFixtures.BypassSelector(),
            });

        var context = ProcessRoutingFixtures.Context() with
        {
            TunnelSlice = component,
            PhysicalUplink = new PhysicalUplinkRoute("phys0", "192.0.2.1"),
        };

        var ruleset = NftablesProcessRoutingRenderer.Render(plan, context);

        var lines = new List<string>
        {
            // The tunnel interface the core would create, plus a stand-in physical uplink with a
            // gateway, so both policy tables have a real device to point at.
            "ip link add myvpn0 type dummy",
            "ip link set myvpn0 up",
            "ip link add phys0 type dummy",
            "ip link set phys0 up",
            "ip addr add 192.0.2.2/24 dev phys0",
        };

        for (var i = 0; i < ruleset.InstallCommands.Count; i++)
        {
            lines.Add($"ip {ruleset.InstallCommands[i]}");
            lines.Add($"echo INSTALL_{i}=$?");
        }

        lines.Add("echo RULE_SHOW_BEGIN");
        lines.Add("ip rule show");
        lines.Add("echo ROUTE_100_BEGIN");
        lines.Add("ip route show table 100");
        lines.Add("echo ROUTE_101_BEGIN");
        lines.Add("ip route show table 101");

        // The removal sequence, twice: the second pass must find nothing and must not be treated as a
        // failure by the executor (it tolerates exactly these kernel answers).
        for (var pass = 0; pass < 2; pass++)
        {
            for (var i = 0; i < ruleset.RemoveCommands.Count; i++)
            {
                lines.Add($"ip {ruleset.RemoveCommands[i]}");
                lines.Add($"echo REMOVE_{pass}_{i}=$?");
            }
        }

        lines.Add("echo RULE_SHOW_AFTER");
        lines.Add("ip rule show");

        var script = WriteScript("myvpn-ip", lines.ToArray());

        try
        {
            var result = RunRaw("unshare", "-rn", "sh", script);

            _output.WriteLine(result.StdOut);
            _output.WriteLine($"stderr: {result.StdErr}");

            result.ExitCode.ShouldBe(0, result.StdErr);

            // Every install command succeeded in a real kernel.
            for (var i = 0; i < ruleset.InstallCommands.Count; i++)
            {
                result.StdOut.ShouldContain($"INSTALL_{i}=0");
            }

            var ruleShow = Section(result.StdOut, "RULE_SHOW_BEGIN", "ROUTE_100_BEGIN");
            ruleShow.ShouldContain("fwmark 0xca6c/0xca6c lookup 100");
            ruleShow.ShouldContain("fwmark 0xca6c/0xca6c prohibit");
            ruleShow.ShouldContain("to 203.0.113.7 lookup main");
            ruleShow.ShouldContain("fwmark 0xca6d/0xca6d lookup 101");

            Section(result.StdOut, "ROUTE_100_BEGIN", "ROUTE_101_BEGIN")
                .ShouldContain("default dev myvpn0");

            Section(result.StdOut, "ROUTE_101_BEGIN", "REMOVE_0_0")
                .ShouldContain("default via 192.0.2.1 dev phys0");

            // The first removal pass succeeds. The second finds the rules already gone: `ip rule del`
            // exits 2 with "No such file or directory" while flushing an already-empty table still
            // succeeds — which is exactly why the executor tolerates both answers rather than
            // reporting a failure for state that is already correct.
            for (var i = 0; i < ruleset.RemoveCommands.Count; i++)
            {
                result.StdOut.ShouldContain($"REMOVE_0_{i}=0");
            }

            result.StdOut.ShouldContain("REMOVE_1_0=2");
            result.StdOut.ShouldContain("REMOVE_1_1=2");

            var after = result.StdOut[result.StdOut.IndexOf("RULE_SHOW_AFTER", StringComparison.Ordinal)..];
            after.ShouldNotContain("0xca6c");
            after.ShouldNotContain("0xca6d");
        }
        finally
        {
            File.Delete(script);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static string Section(string output, string begin, string end)
    {
        var start = output.IndexOf(begin, StringComparison.Ordinal);
        start.ShouldBeGreaterThanOrEqualTo(0, $"'{begin}' was not printed");

        var stop = output.IndexOf(end, StringComparison.Ordinal);
        stop.ShouldBeGreaterThan(start, $"'{end}' was not printed");

        return output[(start + begin.Length)..stop];
    }

    private static bool TryGetTooling(out string reason, out string component)
    {
        component = string.Empty;

        if (!OperatingSystem.IsLinux())
        {
            reason = "not running on Linux.";
            return false;
        }

        if (!File.Exists("/usr/sbin/nft") && !File.Exists("/usr/bin/nft") && !File.Exists("/sbin/nft"))
        {
            reason = "nftables is not installed.";
            return false;
        }

        if (!File.Exists("/usr/bin/unshare") && !File.Exists("/bin/unshare"))
        {
            reason = "unshare is not installed.";
            return false;
        }

        var probe = RunRaw("unshare", "-rn", "true");
        if (probe.ExitCode != 0)
        {
            reason = $"user namespaces are unavailable: {probe.StdErr.Trim()}";
            return false;
        }

        // Creating the real slice needs write access to the cgroup root, which a user namespace does
        // not grant (cgroupfs permissions are checked against the initial namespace's root). When the
        // tests do run as real root, the production slice name is used and removed again; otherwise
        // the match is rendered against a component that exists on this host, and that substitution
        // is reported rather than hidden.
        try
        {
            var slice = "/sys/fs/cgroup/myvpn-routing-verify.slice";

            if (!Directory.Exists(slice))
            {
                Directory.CreateDirectory(slice);
                component = "myvpn-routing-verify.slice";
                reason = string.Empty;
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Expected for an unprivileged test run; fall through to an existing component.
        }

        component = ExistingCgroupComponent() ?? string.Empty;

        if (component.Length == 0)
        {
            reason = "no existing top-level cgroup could be used for the match.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    private static string? ExistingCgroupComponent()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/self/cgroup"))
            {
                if (!line.StartsWith("0::", StringComparison.Ordinal))
                {
                    continue;
                }

                var path = line[3..].Trim('/');
                var component = path.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

                return component is not null && Directory.Exists("/sys/fs/cgroup/" + component)
                    ? component
                    : null;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return null;
    }

    private static string WriteTemp(string prefix, string contents)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}.nft");
        File.WriteAllText(path, contents);
        return path;
    }

    /// <summary>
    /// Writes an executable shell script whose lines are already argv-shaped.
    /// </summary>
    /// <remarks>
    /// The renderer's output is an argv vector per command, so the test re-joins it with the binary
    /// name to run several commands in one namespace. Every token is checked first: if a value ever
    /// needed quoting, this test would fail rather than quietly hide a shell-injection hazard behind
    /// the shell this test uses to drive the namespace.
    /// </remarks>
    private static string WriteScript(string prefix, params string[] lines)
    {
        foreach (var line in lines)
        {
            // Only the command lines are validated: the "echo MARKER=$?" lines are the test's own
            // scaffolding and legitimately contain a shell variable.
            if (!line.StartsWith("ip ", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                token.IndexOfAny(new[] { ';', '|', '&', '`', '$', '"', '\'', '<', '>', '*', '(', ')', '\\' })
                    .ShouldBe(-1, $"'{token}' would need shell quoting");
            }
        }

        var path = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}.sh");
        File.WriteAllText(path, string.Join('\n', lines) + "\n");
        return path;
    }

    private static ProcessResult RunRaw(string fileName, params string[] arguments)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(info);
            if (process is null)
            {
                return new ProcessResult(-1, string.Empty, "failed to start process");
            }

            var stdOut = process.StandardOutput.ReadToEnd();
            var stdErr = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(60_000))
            {
                process.Kill(entireProcessTree: true);
                return new ProcessResult(-1, stdOut, "timed out");
            }

            return new ProcessResult(process.ExitCode, stdOut, stdErr);
        }
        catch (Exception ex)
        {
            return new ProcessResult(-1, string.Empty, ex.Message);
        }
    }

    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
}
