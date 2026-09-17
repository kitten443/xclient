using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Linux.Execution;
using MyVpn.Platform.Linux.KillSwitch;
using MyVpn.Platform.Linux.Proxy;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>A command runner that records its calls and returns scripted results.</summary>
internal sealed class FakeCommandRunner : ICommandRunner
{
    private readonly Dictionary<string, CommandResult> _responses = new(StringComparer.Ordinal);

    public List<(string FileName, string[] Arguments)> Calls { get; } = new();

    public HashSet<string> Available { get; } = new(StringComparer.Ordinal) { "nft", "gsettings" };

    /// <summary>Captures files as they were at invocation time, before any cleanup runs.</summary>
    public Dictionary<string, string> FileSnapshots { get; } = new(StringComparer.Ordinal);

    public Func<string, IReadOnlyList<string>, CommandResult>? Handler { get; set; }

    public void Respond(string key, CommandResult result) => _responses[key] = result;

    public Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        Calls.Add((fileName, arguments.ToArray()));

        // Snapshot any file the command was handed, so a test can assert on its content even
        // though the implementation deletes it in a finally block.
        foreach (var argument in arguments)
        {
            if (File.Exists(argument))
            {
                FileSnapshots[argument] = File.ReadAllText(argument);
            }
        }

        if (Handler is not null)
        {
            return Task.FromResult(Handler(fileName, arguments));
        }

        var key = string.Join(' ', arguments);
        return Task.FromResult(_responses.TryGetValue(key, out var result)
            ? result
            : new CommandResult(0, string.Empty, string.Empty));
    }

    public bool Exists(string fileName) => Available.Contains(fileName);
}

/// <summary>Tests for the nftables Kill Switch executor.</summary>
/// <remarks>
/// The rule-set text is covered separately by <c>NftablesKillSwitchRendererTests</c>, which also
/// installs it into a real kernel network namespace. These tests cover the executor's own
/// responsibilities: refusing to act without privileges or tooling, building the command line
/// safely, and reporting what the kernel actually holds.
/// </remarks>
public sealed class NftablesKillSwitchTests
{
    private readonly ITestOutputHelper _output;

    public NftablesKillSwitchTests(ITestOutputHelper output) => _output = output;

    private static KillSwitchPlan Plan(KillSwitchMode mode = KillSwitchMode.OnDemand) => new()
    {
        Identifier = NftablesKillSwitchRenderer.TableName,
        Mode = mode,
        TunnelInterface = "myvpn0",
        AllowedEndpoints = new[]
        {
            AllowedEndpoint.FromEndpoint(new ServerEndpoint("203.0.113.5", 443), "killswitch.reason.vpn_server"),
        },
        AllowedApplications = new[] { "/usr/lib/myvpn/xray" },
        AllowedDestinations = Array.Empty<AllowedEndpoint>(),
        AllowLan = true,
    };

    [Fact]
    public async Task ReportsUnsupportedWhenNotElevated()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => false);

        killSwitch.IsSupported.ShouldBeFalse();

        var applied = await killSwitch.ApplyAsync(Plan(), CancellationToken.None);

        applied.Succeeded.ShouldBeFalse();
        applied.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);
        applied.Error.RemediationKey.ShouldBe("privilege.install_helper");

        // It must not have tried: a failed `nft` invocation as a normal user produces a confusing
        // "Operation not permitted" that looks like a broken rule set rather than a missing helper.
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReportsUnsupportedWhenNftIsMissing()
    {
        var runner = new FakeCommandRunner();
        runner.Available.Remove("nft");

        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);

        killSwitch.IsSupported.ShouldBeFalse();

        var applied = await killSwitch.ApplyAsync(Plan(), CancellationToken.None);

        applied.Succeeded.ShouldBeFalse();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);
    }

    [Fact]
    public async Task RefusesToArmAPlanWithoutAServerEndpoint()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);

        // A default-deny rule set with no allowed server would cut the tunnel off entirely.
        var plan = Plan() with { AllowedEndpoints = Array.Empty<AllowedEndpoint>() };

        var applied = await killSwitch.ApplyAsync(plan, CancellationToken.None);

        applied.Succeeded.ShouldBeFalse();
        applied.Error!.MessageKey.ShouldBe("error.killswitch.no_server_endpoint");
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task AppliesTheRenderedRulesetFromAPrivateTemporaryFileAndRemovesIt()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);

        var applied = await killSwitch.ApplyAsync(Plan(), CancellationToken.None);

        applied.Succeeded.ShouldBeTrue();

        // Exactly one call, passed as an argv vector with no shell involved.
        var call = runner.Calls.ShouldHaveSingleItem();
        call.FileName.ShouldBe("nft");
        call.Arguments.Length.ShouldBe(2);
        call.Arguments[0].ShouldBe("--file");

        var path = call.Arguments[1];
        path.ShouldEndWith(".nft");

        runner.FileSnapshots.ShouldContainKey(path);
        var rendered = runner.FileSnapshots[path];

        rendered.ShouldContain("table inet myvpn_ks");
        rendered.ShouldContain("myvpn: default deny");
        rendered.ShouldContain("203.0.113.5");

        // The temporary file must not survive: it is cleaned up in a finally block.
        File.Exists(path).ShouldBeFalse();
    }

    [Fact]
    public async Task SurfacesThePlatformErrorWhenNftRejectsTheRuleset()
    {
        var runner = new FakeCommandRunner
        {
            Handler = (_, _) => new CommandResult(1, string.Empty, "syntax error, unexpected newline"),
        };

        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);
        var applied = await killSwitch.ApplyAsync(Plan(), CancellationToken.None);

        applied.Succeeded.ShouldBeFalse();
        applied.Error!.Code.ShouldBe(ErrorCodes.KillSwitchApplyFailed);
        applied.Error.TechnicalDetail!.ShouldContain("syntax error");
        _output.WriteLine(applied.Error.ToString());
    }

    [Fact]
    public async Task DisabledModeRemovesRatherThanArms()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);

        var applied = await killSwitch.ApplyAsync(Plan(KillSwitchMode.Disabled), CancellationToken.None);

        applied.Succeeded.ShouldBeTrue();

        var rendered = runner.FileSnapshots.Values.ShouldHaveSingleItem();
        rendered.ShouldNotContain("policy drop");
    }

    [Fact]
    public async Task ReportsNotArmedWhenTheTableIsAbsent()
    {
        var runner = new FakeCommandRunner
        {
            Handler = (_, _) => new CommandResult(1, string.Empty, "No such file or directory"),
        };

        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);
        var state = await killSwitch.InspectAsync(Plan(), CancellationToken.None);

        state.IsArmed.ShouldBeFalse();
        state.IsDrifted.ShouldBeFalse();
    }

    [Fact]
    public async Task ReportsArmedWhenOurMarkerIsPresent()
    {
        var runner = new FakeCommandRunner
        {
            Handler = (_, _) => new CommandResult(0,
                "table inet myvpn_ks {\n\tcounter drop comment \"myvpn: default deny\"\n}", string.Empty),
        };

        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);
        var state = await killSwitch.InspectAsync(Plan(), CancellationToken.None);

        state.IsArmed.ShouldBeTrue();
        state.IsDrifted.ShouldBeFalse();
        state.OrphanedRules.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReportsDriftWhenASameNamedTableIsNotOurs()
    {
        // A same-named table without our marker means another tool owns it or a previous apply was
        // truncated. Reporting "armed" here would tell the user they are protected when they are
        // not, which is the worst possible answer.
        var runner = new FakeCommandRunner
        {
            Handler = (_, _) => new CommandResult(0, "table inet myvpn_ks {\n}", string.Empty),
        };

        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);
        var state = await killSwitch.InspectAsync(Plan(), CancellationToken.None);

        state.IsArmed.ShouldBeFalse();
        state.IsDrifted.ShouldBeTrue();
        state.OrphanedRules.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task InspectReportsDisarmedWithoutPrivilegesRatherThanGuessing()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => false);

        var state = await killSwitch.InspectAsync(Plan(), CancellationToken.None);

        state.IsArmed.ShouldBeFalse();
        runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task RemoveUsesTheIdempotentTeardownScript()
    {
        var runner = new FakeCommandRunner();
        var killSwitch = new NftablesKillSwitch(runner, isElevated: () => true);

        var removed = await killSwitch.RemoveAsync("myvpn_ks", CancellationToken.None);

        removed.Succeeded.ShouldBeTrue();

        var rendered = runner.FileSnapshots.Values.ShouldHaveSingleItem();
        rendered.ShouldContain("delete table inet myvpn_ks");

        // Idempotent by construction, which is what makes crash recovery safe to run blind.
        rendered.ShouldContain("table inet myvpn_ks\n");
    }
}

/// <summary>Tests for the GSettings system-proxy executor.</summary>
public sealed class LinuxSystemProxyTests
{
    private static SystemProxyPlan Plan() => new()
    {
        SocksPort = 10808,
        HttpPort = 10809,
        EnableSocks = true,
        EnableHttp = true,
        BypassDomains = new[] { "example.internal" },
    };

    [Fact]
    public void IsSupportedMirrorsThePresenceOfGsettings()
    {
        var withTool = new LinuxSystemProxy(new FakeCommandRunner());
        withTool.IsSupported.ShouldBeTrue();

        var runner = new FakeCommandRunner();
        runner.Available.Remove("gsettings");
        new LinuxSystemProxy(runner).IsSupported.ShouldBeFalse();
    }

    [Fact]
    public async Task CaptureReadsAndUnquotesTheCurrentConfiguration()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("get org.gnome.system.proxy mode", new CommandResult(0, "'manual'\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy autoconfig-url", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http host", new CommandResult(0, "'proxy.corp'\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http port", new CommandResult(0, "3128\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.https host", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.https port", new CommandResult(0, "0\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks host", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks port", new CommandResult(0, "0\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy ignore-hosts", new CommandResult(0, "['localhost']\n", string.Empty));

        var captured = await new LinuxSystemProxy(runner).CaptureAsync(CancellationToken.None);

        captured.IsSuccess.ShouldBeTrue();
        captured.Value.Mode.ShouldBe("manual");
        captured.Value.Enabled.ShouldBeTrue();
        captured.Value.HttpProxy.ShouldBe("proxy.corp:3128");
    }

    [Fact]
    public async Task CaptureFailsClearlyWhenTheSchemaIsUnavailable()
    {
        var runner = new FakeCommandRunner
        {
            Handler = (_, _) => new CommandResult(1, string.Empty, "No such schema 'org.gnome.system.proxy'"),
        };

        var captured = await new LinuxSystemProxy(runner).CaptureAsync(CancellationToken.None);

        captured.IsFailure.ShouldBeTrue();
        captured.Error!.Code.ShouldBe(ErrorCodes.SystemProxySetFailed);
    }

    [Fact]
    public async Task ApplyWritesModeHostsPortsAndABypassListContainingLoopback()
    {
        var runner = new FakeCommandRunner();
        var proxy = new LinuxSystemProxy(runner);

        var applied = await proxy.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var writes = runner.Calls.Select(c => string.Join(' ', c.Arguments)).ToArray();

        writes.ShouldContain("set org.gnome.system.proxy mode manual");
        writes.ShouldContain("set org.gnome.system.proxy.http host 127.0.0.1");
        writes.ShouldContain("set org.gnome.system.proxy.http port 10809");
        writes.ShouldContain("set org.gnome.system.proxy.socks host 127.0.0.1");
        writes.ShouldContain("set org.gnome.system.proxy.socks port 10808");

        // Loopback must be present in the bypass list: proxying a request to our own inbound back
        // through the proxy is a loop, and it breaks the connection verification.
        var bypass = runner.Calls.Single(c => c.Arguments.Length > 2 && c.Arguments[2] == "ignore-hosts");
        bypass.Arguments[3].ShouldContain("'localhost'");
        bypass.Arguments[3].ShouldContain("'127.0.0.0/8'");
        bypass.Arguments[3].ShouldContain("'example.internal'");

        // Mode is written last so the desktop never points at a half-configured proxy.
        writes[^1].ShouldBe("set org.gnome.system.proxy mode manual");
    }

    [Fact]
    public async Task ApplyUsesPacModeWhenRequested()
    {
        var runner = new FakeCommandRunner();
        var proxy = new LinuxSystemProxy(runner);

        var plan = Plan() with { UsePac = true, PacUrl = "https://example.com/proxy.pac" };
        var applied = await proxy.ApplyAsync(plan, CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var writes = runner.Calls.Select(c => string.Join(' ', c.Arguments)).ToArray();
        writes.ShouldContain("set org.gnome.system.proxy autoconfig-url https://example.com/proxy.pac");
        writes.ShouldContain("set org.gnome.system.proxy mode auto");
    }

    [Fact]
    public async Task RestoreWritesBackTheCapturedModeAndEndpoints()
    {
        var runner = new FakeCommandRunner();
        var proxy = new LinuxSystemProxy(runner);

        var snapshot = new SystemProxySnapshot
        {
            Mode = "auto",
            Enabled = true,
            PacUrl = "https://corp.example/proxy.pac",
            HttpProxy = "proxy.corp:3128",
            BypassList = "['localhost']",
        };

        var restored = await proxy.RestoreAsync(snapshot, CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();

        var writes = runner.Calls.Select(c => string.Join(' ', c.Arguments)).ToArray();

        // The original PAC mode is restored, not flattened to "manual": losing a corporate PAC
        // configuration would leave the machine unable to reach anything after the VPN exits.
        writes.ShouldContain("set org.gnome.system.proxy mode auto");
        writes.ShouldContain("set org.gnome.system.proxy autoconfig-url https://corp.example/proxy.pac");
        writes.ShouldContain("set org.gnome.system.proxy.http host proxy.corp");
        writes.ShouldContain("set org.gnome.system.proxy.http port 3128");
    }

    [Fact]
    public async Task InspectRecognisesALoopbackProxyAndIgnoresEmptyHosts()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("get org.gnome.system.proxy mode", new CommandResult(0, "'manual'\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy autoconfig-url", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http host", new CommandResult(0, "'127.0.0.1'\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http port", new CommandResult(0, "10809\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks host", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks port", new CommandResult(0, "0\n", string.Empty));

        var state = await new LinuxSystemProxy(runner).InspectAsync(CancellationToken.None);

        state.IsConfigured.ShouldBeTrue();
        state.ActiveProxy.ShouldBe("127.0.0.1:10809");
        state.PointsAtMyVpn.ShouldBeTrue();
    }

    [Fact]
    public async Task InspectReportsNothingConfiguredWhenModeIsNone()
    {
        var runner = new FakeCommandRunner();
        runner.Respond("get org.gnome.system.proxy mode", new CommandResult(0, "'none'\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy autoconfig-url", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http host", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.http port", new CommandResult(0, "0\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks host", new CommandResult(0, "''\n", string.Empty));
        runner.Respond("get org.gnome.system.proxy.socks port", new CommandResult(0, "0\n", string.Empty));

        var state = await new LinuxSystemProxy(runner).InspectAsync(CancellationToken.None);

        state.IsConfigured.ShouldBeFalse();
        state.ActiveProxy.ShouldBeNull();
    }
}
