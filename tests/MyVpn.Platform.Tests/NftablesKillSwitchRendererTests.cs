using System.Diagnostics;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Linux.KillSwitch;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Platform.Tests;

/// <summary>
/// Tests for the nftables Kill Switch renderer.
/// </summary>
/// <remarks>
/// Two layers of verification:
/// <list type="number">
/// <item><description>Pure assertions on the generated text, which run anywhere.</description></item>
/// <item><description>
/// A real load test inside a throwaway user+network namespace via <c>unshare -rn</c>. This
/// is what makes the suite meaningful: it proves the ruleset is accepted by the kernel, not
/// merely that it looks right. It is skipped gracefully when the environment does not
/// permit user namespaces.
/// </description></item>
/// </list>
/// </remarks>
public sealed class NftablesKillSwitchRendererTests
{
    private readonly ITestOutputHelper _output;

    public NftablesKillSwitchRendererTests(ITestOutputHelper output) => _output = output;

    private static KillSwitchPlan SamplePlan(
        bool blockIpv6 = true,
        bool allowLan = true,
        IReadOnlyList<ServerEndpoint>? endpoints = null) => new()
    {
        Identifier = NftablesKillSwitchRenderer.TableName,
        Mode = KillSwitchMode.OnDemand,
        TunnelInterface = "myvpn0",
        AllowedEndpoints = (endpoints ?? new[] { new ServerEndpoint("203.0.113.5", 443) })
            .Select(e => AllowedEndpoint.FromEndpoint(e, "killswitch.reason.vpn_server"))
            .ToArray(),
        AllowedApplications = new[] { "/usr/lib/myvpn/xray" },
        AllowedDestinations = new[]
        {
            new AllowedEndpoint
            {
                Destination = CidrBlock.Parse("1.1.1.1/32"),
                Port = 53,
                ReasonKey = "killswitch.reason.resolver",
            },
        },
        BlockIpv6 = blockIpv6,
        AllowLan = allowLan,
    };

    [Fact]
    public void RendersIdempotentAtomicReplacement()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan());

        // The bare table line must precede the delete, otherwise deleting a missing table
        // fails on first run.
        ruleset.ShouldContain("table inet myvpn_ks\n");
        ruleset.ShouldContain("delete table inet myvpn_ks\n");

        var tableIndex = ruleset.IndexOf("table inet myvpn_ks\n", StringComparison.Ordinal);
        var deleteIndex = ruleset.IndexOf("delete table inet myvpn_ks\n", StringComparison.Ordinal);
        deleteIndex.ShouldBeGreaterThan(tableIndex);

        // 'destroy' is rejected by nftables 1.0.x despite newer man pages documenting it.
        ruleset.ShouldNotContain("destroy table");
    }

    [Fact]
    public void UsesSingleBodyDropPolicyOnAllChains()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan());

        ruleset.ShouldContain("type filter hook output priority 100; policy drop;");
        ruleset.ShouldContain("type filter hook input priority 100; policy drop;");
        ruleset.ShouldContain("type filter hook forward priority 100; policy drop;");
    }

    /// <summary>
    /// Regression test for a real bug found while building this renderer.
    /// </summary>
    /// <remarks>
    /// nftables joins statements on one line with a logical AND, so
    /// <c>tcp dport 443 udp dport 443 accept</c> describes a packet that is simultaneously
    /// TCP and UDP. That rule never matches, so the server would never be reachable and the
    /// tunnel would never come up. Multiple protocols must be a single set match.
    /// </remarks>
    [Fact]
    public void ExpressedMultipleProtocolsAsOneSetMatchNotConjunction()
    {
        var plan = SamplePlan();
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);

        ruleset.ShouldContain("ip daddr 203.0.113.5 meta l4proto { tcp, udp } th dport 443 accept");

        // The broken form: two port matches ANDed together.
        ruleset.ShouldNotContain("tcp dport 443 udp dport 443");
        ruleset.ShouldNotContain("udp dport 443 tcp dport 443");
    }

    [Fact]
    public void SingleProtocolUsesDirectMatch()
    {
        var endpoint = new AllowedEndpoint
        {
            Destination = CidrBlock.Parse("203.0.113.9/32"),
            Port = 8443,
            Network = "tcp",
            ReasonKey = "killswitch.reason.vpn_server",
        };

        var plan = SamplePlan() with { AllowedEndpoints = new[] { endpoint } };
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);

        ruleset.ShouldContain("ip daddr 203.0.113.9 tcp dport 8443 accept");

        // Scoped to this port: the resolver rule elsewhere in the same ruleset legitimately
        // uses a set match because it covers both protocols.
        ruleset.ShouldNotContain("th dport 8443");
    }

    [Fact]
    public void BlocksIpv6BeforeTunnelAcceptSoIpv6CannotRideTheTunnel()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan(blockIpv6: true));

        var ipv6Drop = ruleset.IndexOf("meta nfproto ipv6 counter drop", StringComparison.Ordinal);
        var tunnelAccept = ruleset.IndexOf("oifname \"myvpn0\" accept", StringComparison.Ordinal);

        ipv6Drop.ShouldBeGreaterThanOrEqualTo(0);
        tunnelAccept.ShouldBeGreaterThanOrEqualTo(0);

        // Ordering is the security property: if the tunnel accept came first, IPv6 would be
        // permitted through the tunnel even though the user chose to disable IPv6.
        ipv6Drop.ShouldBeLessThan(tunnelAccept);
    }

    [Fact]
    public void OmitsIpv6DropWhenFullTunnelIpv6Selected()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan(blockIpv6: false));
        ruleset.ShouldNotContain("meta nfproto ipv6 counter drop");
    }

    [Fact]
    public void AlwaysEndsOutputChainWithCountingDefaultDeny()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan());
        ruleset.ShouldContain("counter drop comment \"myvpn: default deny\"");
    }

    [Fact]
    public void AllowsLoopbackTunnelAndEstablishedBeforeDenying()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan());

        ruleset.ShouldContain("oifname \"lo\" accept comment \"myvpn: loopback\"");
        ruleset.ShouldContain("ct state established,related accept");
    }

    [Fact]
    public void AllowsDhcpSoTheInterfaceKeepsItsAddress()
    {
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(SamplePlan());
        ruleset.ShouldContain("udp sport 67-68 accept");
        ruleset.ShouldContain("udp dport 67-68 accept");
    }

    [Fact]
    public void DisabledModeRendersTeardownNotABlockingRuleset()
    {
        var plan = SamplePlan() with { Mode = KillSwitchMode.Disabled };
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);

        ruleset.ShouldNotContain("policy drop");
        ruleset.ShouldContain("delete table inet myvpn_ks");
    }

    [Fact]
    public void EscapesInterfaceNameSoItCannotInjectRulesetSyntax()
    {
        var plan = SamplePlan() with { TunnelInterface = "evil\"\n    counter accept\n" };
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);

        // The injected newline and quote must not produce an extra statement line, and the
        // quote must come out escaped so the string terminates exactly where intended.
        ruleset.ShouldNotContain("\n    counter accept\n");
        ruleset.ShouldContain(@"oifname ""evil\""");
    }

    [Fact]
    public void BlockedDestinationsAreRenderedDeterministically()
    {
        var plan = SamplePlan() with
        {
            BlockedDestinations = new[]
            {
                CidrBlock.Parse("192.168.0.0/16"),
                CidrBlock.Parse("10.0.0.0/8"),
                CidrBlock.Parse("2001:db8::/32"),
            },
        };

        var first = NftablesKillSwitchRenderer.RenderInstall(plan);
        var second = NftablesKillSwitchRenderer.RenderInstall(plan);

        first.ShouldBe(second);

        var index10 = first.IndexOf("ip daddr 10.0.0.0/8", StringComparison.Ordinal);
        var index192 = first.IndexOf("ip daddr 192.168.0.0/16", StringComparison.Ordinal);
        var indexV6 = first.IndexOf("ip6 daddr 2001:db8::/32", StringComparison.Ordinal);

        index10.ShouldBeLessThan(index192);
        index192.ShouldBeLessThan(indexV6);
    }

    [Fact]
    public void ReferencedInterfacesListsTunnelAndLoopback()
    {
        var names = NftablesKillSwitchRenderer.ReferencedInterfaces(SamplePlan());
        names.ShouldContain("myvpn0");
        names.ShouldContain("lo");
    }

    // ------------------------------------------------------------------ kernel acceptance

    [Fact]
    public void GeneratedRulesetIsAcceptedAndLoadableByTheKernel()
    {
        var available = TryGetTooling(out var reason);
        if (!available)
        {
            _output.WriteLine($"SKIPPED: {reason}");
            return;
        }

        var plan = SamplePlan();
        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);
        var path = Path.Combine(Path.GetTempPath(), $"myvpn-test-{Guid.NewGuid():N}.nft");

        try
        {
            File.WriteAllText(path, ruleset);

            // Check syntax, then actually install it inside a throwaway netns. The netns is
            // discarded when the process exits, so nothing on the host is modified.
            var check = RunInNamespace($"nft -c -f {path}");
            _output.WriteLine($"nft -c stdout: {check.StdOut}");
            _output.WriteLine($"nft -c stderr: {check.StdErr}");
            check.ExitCode.ShouldBe(0, $"nft --check rejected the generated ruleset: {check.StdErr}");

            var apply = RunInNamespace($"nft -f {path} && nft list table inet myvpn_ks");
            _output.WriteLine($"nft apply stderr: {apply.StdErr}");
            apply.ExitCode.ShouldBe(0, $"the kernel refused the ruleset: {apply.StdErr}");

            apply.StdOut.ShouldContain("table inet myvpn_ks");
            apply.StdOut.ShouldContain("myvpn: default deny");
            apply.StdOut.ShouldContain("myvpn: vpn server");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RemoveRulesetIsIdempotentAndAcceptedByTheKernel()
    {
        var available = TryGetTooling(out var reason);
        if (!available)
        {
            _output.WriteLine($"SKIPPED: {reason}");
            return;
        }

        var remove = NftablesKillSwitchRenderer.RenderRemove();
        var path = Path.Combine(Path.GetTempPath(), $"myvpn-remove-{Guid.NewGuid():N}.nft");

        try
        {
            File.WriteAllText(path, remove);

            // Applying removal when nothing is installed must succeed, then again.
            var result = RunInNamespace($"nft -f {path} && nft -f {path} && echo IDEMPOTENT_OK");
            _output.WriteLine($"stderr: {result.StdErr}");
            result.ExitCode.ShouldBe(0, result.StdErr);
            result.StdOut.ShouldContain("IDEMPOTENT_OK");
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static bool TryGetTooling(out string reason)
    {
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

        // Probe: unprivileged user namespaces may be disabled by policy.
        var probe = RunRaw("unshare", "-rn", "true");
        if (probe.ExitCode != 0)
        {
            reason = $"user namespaces are unavailable: {probe.StdErr.Trim()}";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Runs a shell command inside a throwaway user+network namespace.
    /// </summary>
    /// <remarks>
    /// <c>unshare -rn</c> maps the caller to root inside a fresh user namespace and creates a
    /// fresh network namespace. Inside it the process holds <c>CAP_NET_ADMIN</c>, which is
    /// what <c>nft</c> needs even for a syntax check, while the host's ruleset is completely
    /// untouched.
    /// </remarks>
    private static ProcessResult RunInNamespace(string command) =>
        RunRaw("unshare", "-rn", "sh", "-c", command);

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

            if (!process.WaitForExit(30_000))
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
