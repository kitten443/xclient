using System.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Linux.Dns;
using MyVpn.Platform.Abstractions.Execution;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>A throwaway directory tree, so no test ever touches the real /etc or /run.</summary>
internal sealed class DnsTestTree : IDisposable
{
    public DnsTestTree()
    {
        Root = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"myvpn-dns-{Guid.NewGuid():N}");

        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string Path(params string[] parts) =>
        System.IO.Path.Combine(new[] { Root }.Concat(parts).ToArray());

    public string WriteResolvConf(string content)
    {
        var path = Path("etc", "resolv.conf");
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leftover temp tree is harmless.
        }
    }
}

/// <summary>
/// Tests for the Linux DNS executor.
/// </summary>
/// <remarks>
/// This container has no systemd-resolved, no resolvconf and no GSettings schemas, so every backend
/// below is exercised through <see cref="FakeCommandRunner"/> and a temporary resolv.conf. That
/// covers the decision logic — which is where the leak-shaped bugs live — but it is <i>not</i> a
/// real-backend verification: nothing here proves that a real <c>resolvectl</c> or a real
/// <c>resolvconf</c> accepts these command lines. That has to be checked on a real machine.
/// </remarks>
public sealed class LinuxDnsConfiguratorTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly DnsTestTree _tree = new();
    private readonly FakeCommandRunner _runner = new();

    public LinuxDnsConfiguratorTests(ITestOutputHelper output) => _output = output;

    public void Dispose() => _tree.Dispose();

    private static DnsPlan Plan(params string[] servers) => new()
    {
        TunnelInterface = "myvpn0",
        Servers = servers.Length == 0
            ? new[] { new DnsServerEntry { Address = "10.8.0.1" } }
            : servers.Select(s => new DnsServerEntry { Address = s }).ToArray(),
    };

    /// <summary>Builds an executor whose entire filesystem surface lives in the temp tree.</summary>
    private LinuxDnsConfigurator Create(
        bool elevated = true,
        bool resolvConfFile = true,
        bool resolvConfState = true)
    {
        var resolvConfPath = _tree.Path("etc", "resolv.conf");
        if (resolvConfFile)
        {
            if (!File.Exists(resolvConfPath))
            {
                _tree.WriteResolvConf("nameserver 192.168.1.1\nsearch lan\n");
            }
        }
        else if (File.Exists(resolvConfPath))
        {
            File.Delete(resolvConfPath);
        }

        if (resolvConfState)
        {
            Directory.CreateDirectory(_tree.Path("resolvconf-state", "interfaces"));
        }

        return new LinuxDnsConfigurator(
            _runner,
            () => elevated,
            resolvConfPath,
            _tree.Path("resolvconf-state"),
            _tree.Path("myvpn-state"));
    }

    /// <summary>Scripts a resolvectl whose service answers and whose read-back shows the given links.</summary>
    private void ScriptSystemd(string? readBack = "Link 7 (myvpn0): 10.8.0.1")
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (fileName, arguments) =>
        {
            if (fileName != "resolvectl")
            {
                return new CommandResult(0, string.Empty, string.Empty);
            }

            var joined = string.Join(' ', arguments);

            if (joined == "status")
            {
                return new CommandResult(0, "systemd-resolved is active\n", string.Empty);
            }

            return joined == "dns"
                ? new CommandResult(0, readBack ?? string.Empty, string.Empty)
                : new CommandResult(0, string.Empty, string.Empty);
        };
    }

    /// <summary>Scripts a resolvconf whose update regenerates resolv.conf the way the tool would.</summary>
    private void ScriptResolvConf(string regenerated)
    {
        _runner.Available.Add("resolvconf");
        _runner.Handler = (fileName, arguments) =>
        {
            if (fileName == "resolvconf" && arguments.Count == 1 && arguments[0] == "-u")
            {
                File.WriteAllText(_tree.Path("etc", "resolv.conf"), regenerated);
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };
    }

    private string[] Argv() =>
        _runner.Calls.Select(c => $"{c.FileName} {string.Join(' ', c.Arguments)}".Trim()).ToArray();

    private string ResolvConfText() => File.ReadAllText(_tree.Path("etc", "resolv.conf"));

    // ------------------------------------------------------------------ privileges

    [Fact]
    public async Task WithoutPrivilegesNothingIsRunAtAll()
    {
        _runner.Available.Add("resolvectl");

        var dns = Create(elevated: false);

        // Reporting "supported" without privileges would let the session believe DNS was pinned and
        // fail only after the tunnel was already up.
        dns.IsSupported.ShouldBeFalse();

        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);
        applied.Error.RemediationKey.ShouldBe("privilege.install_helper");

        var restored = await dns.RestoreAsync(Plan(), CancellationToken.None);
        restored.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);
        removed.Error!.Code.ShouldBe(ErrorCodes.PrivilegeDenied);

        // Not one command: a failed `resolvectl` as a normal user produces a confusing bus error
        // that looks like a broken configuration rather than a missing helper.
        _runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public void IsSupportedReflectsWhetherAnyBackendExists()
    {
        // A regular /etc/resolv.conf is a (last-resort) backend.
        Create().IsSupported.ShouldBeTrue();

        // resolvectl counts even without a writable resolv.conf.
        var withResolvectl = new FakeCommandRunner { Available = { "resolvectl" } };
        new LinuxDnsConfigurator(
            withResolvectl, () => true, _tree.Path("etc", "absent.conf"),
            _tree.Path("resolvconf-state"), _tree.Path("myvpn-state")).IsSupported.ShouldBeTrue();

        // No tool and no file: nothing to drive.
        Create(resolvConfFile: false).IsSupported.ShouldBeFalse();
    }

    // ------------------------------------------------------------------ backend selection

    [Fact]
    public async Task SelectsSystemdResolvedOnlyWhenResolvectlAnswers()
    {
        ScriptSystemd();

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        dns.Backend.ShouldBe(LinuxDnsBackend.SystemdResolved);
        dns.BackendName.ShouldBe("systemd-resolved");

        // The probe is a real command, and it is the first thing that runs.
        _runner.Calls[0].FileName.ShouldBe("resolvectl");
        _runner.Calls[0].Arguments.ShouldBe(new[] { "status" });
    }

    [Fact]
    public async Task FallsThroughToResolvconfWhenResolvectlExistsButFails()
    {
        // The Debian and Arch-with-resolved-disabled scenario, and the highest-value test here: a
        // resolvectl-only implementation exits zero, changes nothing, and the queries keep going to
        // the physical link's resolver. It must fall through instead.
        _runner.Available.Add("resolvectl");
        _runner.Available.Add("resolvconf");
        ScriptResolvConf("nameserver 10.8.0.1\n");

        _runner.Handler = (fileName, arguments) =>
        {
            if (fileName == "resolvectl")
            {
                return new CommandResult(
                    1, string.Empty, "Failed to connect to bus: No such file or directory");
            }

            if (fileName == "resolvconf" && arguments.Count == 1 && arguments[0] == "-u")
            {
                File.WriteAllText(_tree.Path("etc", "resolv.conf"), "nameserver 10.8.0.1\n");
            }

            return new CommandResult(0, string.Empty, string.Empty);
        };

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        dns.Backend.ShouldBe(LinuxDnsBackend.ResolvConf);

        // resolvectl was probed, then abandoned: it was never used to configure anything.
        Argv().ShouldContain("resolvectl status");
        Argv().ShouldNotContain("resolvectl dns myvpn0 10.8.0.1");

        // The interface-scoped record is the thing that was actually installed.
        var record = _tree.Path("resolvconf-state", "interfaces", "myvpn0.myvpn");
        File.Exists(record).ShouldBeTrue();
        File.ReadAllText(record).ShouldContain("nameserver 10.8.0.1");

        Argv().ShouldContain("resolvconf -u");

        // The real observable effect is the libc-visible file, which the read-back confirms.
        ResolvConfText().ShouldContain("nameserver 10.8.0.1");
    }

    [Fact]
    public async Task FallsThroughToDirectResolvConfWhenNoToolCanBeUsed()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) =>
            new CommandResult(1, string.Empty, "Failed to connect to bus: No such file or directory");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        dns.Backend.ShouldBe(LinuxDnsBackend.DirectResolvConf);

        var text = ResolvConfText();
        text.ShouldContain(LinuxDnsConfigurator.ManagedMarker);
        text.ShouldContain("nameserver 10.8.0.1");
        text.ShouldContain("search lan");

        // The original is backed up before anything is written, so a crash is recoverable.
        var backup = _tree.Path("myvpn-state", "resolv.conf.backup");
        File.ReadAllText(backup).ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    [Fact]
    public async Task RefusesWhenNoBackendExistsRatherThanPretending()
    {
        var dns = Create(resolvConfFile: false);

        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.PlatformToolMissing);
        applied.Error.MessageKey.ShouldBe("error.dns.no_backend");
        _runner.Calls.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ plan validation

    [Fact]
    public async Task RejectsANonIpResolverBeforeRunningAnything()
    {
        ScriptSystemd();

        var dns = Create();
        var plan = Plan("dns.example.com");

        var applied = await dns.ApplyAsync(plan, CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.dns.server_not_ip");
        _runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task AnEmptyResolverListIsANoOp()
    {
        ScriptSystemd();

        var dns = Create();
        var plan = Plan() with { Servers = Array.Empty<DnsServerEntry>(), BlockPlainDnsLeaks = false };

        var applied = await dns.ApplyAsync(plan, CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        _runner.Calls.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ systemd-resolved argv

    [Fact]
    public async Task SystemdPathUsesTheDocumentedArgv()
    {
        ScriptSystemd("Link 7 (myvpn0): 10.8.0.1 2001:db8::53");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan("10.8.0.1", "2001:db8::53"), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var argv = Argv();
        argv.ShouldContain("resolvectl dns myvpn0 10.8.0.1 2001:db8::53");

        // `~.` is the catch-all routing domain: without it the physical link keeps answering every
        // name the tunnel link does not explicitly own.
        argv.ShouldContain("resolvectl domain myvpn0 ~.");

        // Per-link resolvers are not enough; the tunnel link has to own the default route.
        argv.ShouldContain("resolvectl default-route myvpn0 yes");

        _output.WriteLine(string.Join("\n", argv));
    }

    [Fact]
    public async Task SystemdPathUsesSplitDnsDomainsInsteadOfTheCatchAll()
    {
        ScriptSystemd();

        var dns = Create();
        var plan = Plan() with { SplitDnsDomains = new[] { "corp.example.com", "internal.test" } };

        var applied = await dns.ApplyAsync(plan, CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        var argv = Argv();
        argv.ShouldContain("resolvectl domain myvpn0 ~corp.example.com ~internal.test");
        argv.ShouldNotContain("resolvectl domain myvpn0 ~.");
    }

    [Fact]
    public async Task SystemdPathCarriesANonDefaultPort()
    {
        ScriptSystemd();

        var dns = Create();
        var plan = Plan() with
        {
            Servers = new[] { new DnsServerEntry { Address = "10.8.0.1", Port = 5353 } },
        };

        var applied = await dns.ApplyAsync(plan, CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        // resolvectl is the only one of the three backends that can express a port at all.
        Argv().ShouldContain("resolvectl dns myvpn0 10.8.0.1:5353");
    }

    // ------------------------------------------------------------------ resolvconf

    [Fact]
    public async Task ResolvconfRecordIsInterfaceScoped()
    {
        ScriptResolvConf("nameserver 10.8.0.1\n");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();
        dns.Backend.ShouldBe(LinuxDnsBackend.ResolvConf);

        // `<iface>.myvpn` is what makes the record ours: NetworkManager and dhclient cannot clobber
        // it, and `-d <iface>.myvpn` removes exactly our entry.
        File.Exists(_tree.Path("resolvconf-state", "interfaces", "myvpn0.myvpn")).ShouldBeTrue();

        // resolvconf takes its record only on stdin and has no file argument, and this runner has no
        // stdin, so `-a` is deliberately never invoked: it would read whatever the process happens
        // to have on stdin and register an empty record while exiting zero.
        Argv().ShouldNotContain(a => a.StartsWith("resolvconf -a", StringComparison.Ordinal));
        Argv().ShouldContain("resolvconf -u");

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(_tree.Path("resolvconf-state", "interfaces", "myvpn0.myvpn"));
            mode.ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Fact]
    public async Task FileBackendsRefuseAResolverTheyCannotExpress()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) => new CommandResult(1, string.Empty, "Failed to connect to bus");

        var dns = Create();
        var plan = Plan() with
        {
            Servers = new[] { new DnsServerEntry { Address = "10.8.0.1", Port = 5353 } },
        };

        var applied = await dns.ApplyAsync(plan, CancellationToken.None);

        // resolv.conf has no port field: writing it would silently drop the resolver, so this is
        // refused rather than degraded.
        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.dns.resolv_conf_port_unsupported");
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    // ------------------------------------------------------------------ symlinks

    [Fact]
    public async Task ASymlinkedResolvConfIsRefusedRatherThanWrittenThrough()
    {
        // A real symlink, as on Ubuntu and Fedora: /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
        var target = _tree.Path("etc", "stub-resolv.conf");
        Directory.CreateDirectory(_tree.Path("etc"));
        File.WriteAllText(target, "nameserver 127.0.0.53\n");

        var link = _tree.Path("etc", "resolv.conf");
        File.CreateSymbolicLink(link, target);

        var dns = new LinuxDnsConfigurator(
            _runner,
            () => true,
            link,
            _tree.Path("resolvconf-state"),
            _tree.Path("myvpn-state"));

        dns.Backend.ShouldBe(LinuxDnsBackend.Unknown);
        dns.IsSupported.ShouldBeTrue();

        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.DnsConfigureFailed);
        applied.Error.MessageKey.ShouldBe("error.dns.resolv_conf_symlink");

        // Writing through it would have replaced the stub file that systemd-resolved regenerates,
        // and after a crash MyVpn could not tell which of the four resolved modes to put back.
        File.ReadAllText(target).ShouldBe("nameserver 127.0.0.53\n");
        new FileInfo(link).LinkTarget.ShouldNotBeNull();
    }

    // ------------------------------------------------------------------ read-back

    [Fact]
    public async Task ApplyFailsWhenTheServersDidNotTakeEffect()
    {
        // resolvectl exits zero for every command but the link still holds somebody else's server.
        // Trusting the exit code here is exactly how a client reports "protected" while leaking.
        ScriptSystemd("Link 7 (myvpn0): 1.1.1.1");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.Code.ShouldBe(ErrorCodes.DnsConfigureFailed);
        applied.Error.MessageKey.ShouldBe("error.dns.verify_failed");
        applied.Error.TechnicalDetail!.ShouldContain("10.8.0.1");
        applied.Error.TechnicalDetail!.ShouldContain("1.1.1.1");
    }

    [Fact]
    public async Task ApplyFailsWhenTheDnsCommandItselfFails()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, arguments) => string.Join(' ', arguments) == "status"
            ? new CommandResult(0, "active", string.Empty)
            : new CommandResult(1, string.Empty, "Unknown interface myvpn0");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan(), CancellationToken.None);

        applied.IsFailure.ShouldBeTrue();
        applied.Error!.MessageKey.ShouldBe("error.dns.resolvectl_dns_failed");
        applied.Error.TechnicalDetail!.ShouldContain("Unknown interface");
    }

    // ------------------------------------------------------------------ restore

    [Fact]
    public async Task RestoreRevertsTheTunnelLinkAndIsIdempotent()
    {
        ScriptSystemd();
        var dns = Create();

        await dns.ApplyAsync(Plan(), CancellationToken.None);
        _runner.Calls.Clear();

        var restored = await dns.RestoreAsync(Plan(), CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();
        Argv().ShouldContain("resolvectl revert myvpn0");

        // The tunnel link had no resolvers of its own, so `revert` is the documented undo: the link
        // goes back to DHCP-provided DNS, and nothing global was ever mutated.
        Argv().ShouldNotContain(a => a.StartsWith("resolvectl dns myvpn0", StringComparison.Ordinal));

        // Restoring on a machine where nothing was applied must also succeed: the emergency path
        // cannot be allowed to fail just because it ran twice. A fresh process has no record of the
        // backend, so it undoes every mechanism that could hold state for the interface.
        var fresh = Create();
        var second = await fresh.RestoreAsync(Plan(), CancellationToken.None);
        second.IsSuccess.ShouldBeTrue();
        Argv().ShouldContain("resolvectl revert myvpn0");
    }

    [Fact]
    public async Task RestorePutsBackRecordedLinkScopedServersWhenThereWereAny()
    {
        ScriptSystemd();
        var dns = Create();

        await dns.ApplyAsync(Plan(), CancellationToken.None);

        var plan = Plan() with { PreviousServers = new[] { "10.9.0.1" } };
        var restored = await dns.RestoreAsync(plan, CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();
        Argv().ShouldContain("resolvectl dns myvpn0 10.9.0.1");
    }

    [Fact]
    public async Task RestoreOnResolvconfRemovesOnlyOurRecord()
    {
        ScriptResolvConf("nameserver 10.8.0.1\n");
        var dns = Create();

        await dns.ApplyAsync(Plan(), CancellationToken.None);
        _runner.Calls.Clear();

        var restored = await dns.RestoreAsync(Plan(), CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();

        // -f is what makes this idempotent, and the interface-scoped name is what keeps other
        // daemons' records out of it.
        Argv().ShouldContain("resolvconf -f -d myvpn0.myvpn");
        File.Exists(_tree.Path("resolvconf-state", "interfaces", "myvpn0.myvpn")).ShouldBeFalse();
    }

    [Fact]
    public async Task RestoreOnDirectResolvConfPutsTheOriginalFileBack()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) => new CommandResult(1, string.Empty, "Failed to connect to bus");

        var dns = Create();
        await dns.ApplyAsync(Plan(), CancellationToken.None);
        ResolvConfText().ShouldContain(LinuxDnsConfigurator.ManagedMarker);

        var restored = await dns.RestoreAsync(Plan(), CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();

        // Byte-for-byte, including the search domain MyVpn does not otherwise model.
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");

        // The backup is consumed, so a second restore is a genuine no-op rather than a replay.
        File.Exists(_tree.Path("myvpn-state", "resolv.conf.backup")).ShouldBeFalse();
        (await dns.RestoreAsync(Plan(), CancellationToken.None)).IsSuccess.ShouldBeTrue();
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    // ------------------------------------------------------------------ blind cleanup

    [Fact]
    public async Task RemoveAllOwnedRevertsEveryBackendThatIsPresent()
    {
        _runner.Available.Add("resolvectl");
        _runner.Available.Add("resolvconf");
        _runner.Handler = (fileName, arguments) =>
            fileName == "resolvectl" && string.Join(' ', arguments) == "dns"
                ? new CommandResult(0, "Link 7 (myvpn0): 10.8.0.1\nLink 2 (eth0): 192.168.1.1\n", string.Empty)
                : new CommandResult(0, string.Empty, string.Empty);

        var dns = Create();

        // A record that survived a crash, in the tool's own state directory.
        File.WriteAllText(
            _tree.Path("resolvconf-state", "interfaces", "myvpn0.myvpn"),
            "nameserver 10.8.0.1\n");

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();

        var argv = Argv();

        // Our tunnel link is reverted, found by the project's own naming convention rather than by a
        // remembered plan — which is what makes this safe to run blind after a crash.
        argv.ShouldContain("resolvectl revert myvpn0");

        // eth0 is somebody else's link: not touched.
        argv.ShouldNotContain(a => a.Contains("revert eth0", StringComparison.Ordinal));

        argv.ShouldContain("resolvconf -f -d myvpn0.myvpn");
    }

    [Fact]
    public async Task RemoveAllOwnedSkipsALinkThatNoLongerExists()
    {
        ScriptSystemd();
        var dns = Create();

        // Apply remembers the tunnel interface; then the TUN disappears, as it does when Xray dies.
        await dns.ApplyAsync(Plan(), CancellationToken.None);
        _runner.Calls.Clear();

        _runner.Handler = (_, arguments) => string.Join(' ', arguments) == "dns"
            ? new CommandResult(0, "Link 2 (eth0): 192.168.1.1\n", string.Empty)
            : new CommandResult(0, string.Empty, string.Empty);

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);

        // The per-link configuration died with the link, so reverting it would only manufacture a
        // failure on a machine that is already clean.
        removed.IsSuccess.ShouldBeTrue();
        Argv().ShouldNotContain(a => a.StartsWith("resolvectl revert", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RemoveAllOwnedSucceedsWhenNothingIsOwned()
    {
        var dns = Create(resolvConfFile: false);

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);

        // Idempotent by construction: reporting failure here would leave the session unable to reach
        // a clean state after an emergency teardown.
        removed.IsSuccess.ShouldBeTrue();
        _runner.Calls.ShouldBeEmpty();
    }

    [Fact]
    public async Task RemoveAllOwnedRestoresADirectlyWrittenResolvConf()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) => new CommandResult(1, string.Empty, "Failed to connect to bus");

        var dns = Create();
        await dns.ApplyAsync(Plan(), CancellationToken.None);
        ResolvConfText().ShouldContain(LinuxDnsConfigurator.ManagedMarker);

        // A different process instance, which is what an emergency cleanup after a crash looks like.
        var blind = new LinuxDnsConfigurator(
            _runner,
            () => true,
            _tree.Path("etc", "resolv.conf"),
            _tree.Path("resolvconf-state"),
            _tree.Path("myvpn-state"));

        var removed = await blind.RemoveAllOwnedAsync(CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    [Fact]
    public async Task RemoveAllOwnedLeavesAForeignResolvConfAlone()
    {
        var dns = Create();

        var removed = await dns.RemoveAllOwnedAsync(CancellationToken.None);

        removed.IsSuccess.ShouldBeTrue();

        // No marker, so the file is not ours and must not be rewritten even though it is a regular
        // file the direct backend could have written.
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    // ------------------------------------------------------------------ inspect

    [Fact]
    public async Task InspectReportsLeakKeysRatherThanProse()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, arguments) => string.Join(' ', arguments) == "dns"
            ? new CommandResult(0, "Link 7 (myvpn0): 10.8.0.1 2001:db8::53\n", string.Empty)
            : new CommandResult(0, "active", string.Empty);

        // A plain resolver outside the tunnel, visible to libc.
        _tree.WriteResolvConf("nameserver 8.8.8.8\n");

        var state = await Create().InspectAsync(CancellationToken.None);

        state.InterfaceName.ShouldBe("myvpn0");
        state.ActiveServers.ShouldBe(new[] { "10.8.0.1", "2001:db8::53" });
        state.HasIpv6Resolver.ShouldBeTrue();
        state.PlainDnsReachableOutsideTunnel.ShouldBeTrue();

        state.PotentialLeaks.ShouldContain("error.dns.leak.ipv6_resolver");
        state.PotentialLeaks.ShouldContain("error.dns.leak.plain_resolver_present");

        // Localization keys only: never a raw English sentence.
        state.PotentialLeaks.ShouldAllBe(k => k.StartsWith("error.dns.", StringComparison.Ordinal));
        state.PotentialLeaks.ShouldAllBe(k => k.All(IsLocalizationKeyChar));
    }

    private static bool IsLocalizationKeyChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '.' or '_';

    private static bool IsIpLiteral(string value) => IPAddress.TryParse(value, out var parsed) && parsed is not null;

    [Fact]
    public async Task InspectFallsBackToTheLibcVisibleResolversWhenNoTunnelLinkIsConfigured()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, arguments) => string.Join(' ', arguments) == "dns"
            ? new CommandResult(0, "Link 2 (eth0): 192.168.1.1\n", string.Empty)
            : new CommandResult(0, "active", string.Empty);

        var dns = Create();
        var state = await dns.InspectAsync(CancellationToken.None);

        // Nothing of ours is live, so the honest answer is what libc would actually read (the local
        // stub, 192.168.1.1 in the temp tree) rather than an empty list.
        state.ActiveServers.ShouldBe(new[] { "192.168.1.1" });
        state.InterfaceName.ShouldBeNull();
        state.HasIpv6Resolver.ShouldBeFalse();
        dns.Backend.ShouldBe(LinuxDnsBackend.SystemdResolved);
    }

    [Fact]
    public async Task InspectReportsAMissingBackendAsAPotentialLeak()
    {
        var dns = Create(resolvConfFile: false);

        var state = await dns.InspectAsync(CancellationToken.None);

        state.ActiveServers.ShouldBeEmpty();
        state.InterfaceName.ShouldBeNull();
        state.PlainDnsReachableOutsideTunnel.ShouldBeFalse();
        state.PotentialLeaks.ShouldContain("error.dns.leak.backend_unknown");
    }

    [Fact]
    public async Task InspectTreatsACaptiveStubAsNoPlainResolver()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, arguments) => string.Join(' ', arguments) == "dns"
            ? new CommandResult(0, "Link 7 (myvpn0): 10.8.0.1\n", string.Empty)
            : new CommandResult(0, "active", string.Empty);

        // The stub address on Ubuntu and Fedora is a local socket, not a resolver outside the tunnel.
        _tree.WriteResolvConf("nameserver 127.0.0.53\noptions edns0 trust-ad\n");

        var state = await Create().InspectAsync(CancellationToken.None);

        state.PlainDnsReachableOutsideTunnel.ShouldBeFalse();
        state.PotentialLeaks.ShouldNotContain("error.dns.leak.plain_resolver_present");
        state.ActiveServers.ShouldBe(new[] { "10.8.0.1" });
    }

    // ------------------------------------------------------------------ captured state

    [Fact]
    public async Task ApplyRecordsThePreviousStateSoACallerCanPersistIt()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) => new CommandResult(1, string.Empty, "Failed to connect to bus");

        var dns = Create();
        await dns.ApplyAsync(Plan(), CancellationToken.None);

        dns.RecordedPreviousManager.ShouldBe("resolv.conf");
        dns.RecordedPreviousServers.ShouldBe(new[] { "192.168.1.1" });

        // DnsPlan is immutable and ApplyAsync returns no value, so the captured state is offered as
        // a copy for the caller to keep.
        var merged = dns.MergeRecordedState(Plan());
        merged.PreviousServers.ShouldBe(new[] { "192.168.1.1" });
        merged.PreviousManager.ShouldBe("resolv.conf");
    }

    [Fact]
    public async Task ACrashRestoreUsesTheStateRecordedInThePlan()
    {
        _runner.Available.Add("resolvectl");
        _runner.Handler = (_, _) => new CommandResult(1, string.Empty, "Failed to connect to bus");

        var dns = Create();
        await dns.ApplyAsync(Plan(), CancellationToken.None);

        var persisted = dns.MergeRecordedState(Plan());

        // A new process, given only the persisted plan, restores the captured configuration.
        var restarted = new LinuxDnsConfigurator(
            _runner,
            () => true,
            _tree.Path("etc", "resolv.conf"),
            _tree.Path("resolvconf-state"),
            _tree.Path("myvpn-state"));

        var restored = await restarted.RestoreAsync(persisted, CancellationToken.None);

        restored.IsSuccess.ShouldBeTrue();
        ResolvConfText().ShouldBe("nameserver 192.168.1.1\nsearch lan\n");
    }

    [Fact]
    public async Task AnIpv6OnlyResolverIsAppliedAndReportedBack()
    {
        ScriptSystemd("Link 7 (myvpn0): 2001:db8::53");

        var dns = Create();
        var applied = await dns.ApplyAsync(Plan("2001:db8::53"), CancellationToken.None);

        applied.IsSuccess.ShouldBeTrue();

        // A bare IPv6 literal must not be mistaken for the `address:port` form while parsing back.
        var state = await dns.InspectAsync(CancellationToken.None);
        state.ActiveServers.ShouldBe(new[] { "2001:db8::53" });
        state.ActiveServers.ShouldAllBe(s => IsIpLiteral(s));
        state.HasIpv6Resolver.ShouldBeTrue();
        state.PotentialLeaks.ShouldContain("error.dns.leak.ipv6_resolver");
    }
}
