using System.Reflection;
using Shouldly;
using Xunit;

namespace MyVpn.Platform.Tests;

/// <summary>
/// Guards the guard: every test that describes the Windows or macOS executors must carry the
/// host-platform attribute that skips it on that platform, and that attribute must actually
/// skip.
/// </summary>
/// <remarks>
/// <para>
/// This exists because the failure it prevents is invisible on the development host. The
/// Windows and macOS suites assert the executors' <em>refusal</em> path, which is the branch
/// taken when <c>OperatingSystem.IsWindows()</c> / <c>IsMacOS()</c> is false. On the matching
/// CI runner those guards open, so a bare <c>[Fact]</c> there does two wrong things at once:
/// it fails, because "IsSupported is false" is no longer true, and before failing it reaches
/// live kernel state — WFP filters, WinINet proxy settings, PF anchors, the system resolver.
/// </para>
/// <para>
/// A convention that lives only in a code review does not survive contact with the next
/// contributor, so it is asserted here. The rule is name-based on purpose: it covers classes
/// that do not exist yet, without anyone having to remember to update a list.
/// </para>
/// </remarks>
public sealed class HostPlatformGuardPolicyTests
{
    /// <summary>Class-name fragments that mean "this suite describes the Windows executors".</summary>
    private static readonly string[] WindowsFragments = { "Windows", "Wfp" };

    /// <summary>Class-name fragments that mean "this suite describes the macOS executors".</summary>
    private static readonly string[] MacFragments = { "Mac", "Pf", "Networksetup" };

    [Fact]
    public void EveryWindowsSuiteTestSkipsOnWindowsAndEveryMacSuiteTestSkipsOnMacOS()
    {
        var assembly = typeof(HostPlatformGuardPolicyTests).Assembly;

        var windows = new List<string>();
        var mac = new List<string>();
        var unguarded = new List<string>();

        foreach (var type in assembly.GetTypes())
        {
            if (type.Namespace != typeof(HostPlatformGuardPolicyTests).Namespace)
            {
                continue;
            }

            var isWindows = WindowsFragments.Any(f => type.Name.Contains(f, StringComparison.Ordinal));
            var isMac = !isWindows && MacFragments.Any(f => type.Name.Contains(f, StringComparison.Ordinal));

            if (!isWindows && !isMac)
            {
                continue;
            }

            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance))
            {
                var fact = method.GetCustomAttribute<FactAttribute>();
                if (fact is null)
                {
                    continue;
                }

                var where = $"{type.Name}.{method.Name}";

                if (isWindows)
                {
                    windows.Add(where);
                    if (fact is not FactOnNonWindowsAttribute and not TheoryOnNonWindowsAttribute)
                    {
                        unguarded.Add($"{where} (expected [FactOnNonWindows] / [TheoryOnNonWindows])");
                    }
                }
                else
                {
                    mac.Add(where);
                    if (fact is not FactOnNonMacOSAttribute and not TheoryOnNonMacOSAttribute)
                    {
                        unguarded.Add($"{where} (expected [FactOnNonMacOS] / [TheoryOnNonMacOS])");
                    }
                }
            }
        }

        // The rule is only meaningful if it matched something. A rename that silently emptied
        // these lists would otherwise turn this test into a vacuous pass -- the exact failure
        // mode this project's README refuses to accept from the integration leg.
        windows.ShouldNotBeEmpty("no Windows-platform test classes were discovered by the name rule");
        mac.ShouldNotBeEmpty("no macOS-platform test classes were discovered by the name rule");

        unguarded.ShouldBeEmpty(
            "these tests would run on their own platform, where they reach live OS state instead of "
            + "the refusal path they assert: " + string.Join(", ", unguarded));
    }

    [Fact]
    public void TheGuardSkipsOnItsOwnPlatformAndRunsEverywhereElse()
    {
        // Both branches are checked as a pure function of the host, so this is verified on any
        // machine rather than only on the two platforms the guard exists for.
        HostPlatformGuard.ForWindowsSuite(hostIsWindows: true).ShouldBe(HostPlatformGuard.WindowsSkipReason);
        HostPlatformGuard.ForWindowsSuite(hostIsWindows: false).ShouldBeNull();

        HostPlatformGuard.ForMacSuite(hostIsMacOS: true).ShouldBe(HostPlatformGuard.MacSkipReason);
        HostPlatformGuard.ForMacSuite(hostIsMacOS: false).ShouldBeNull();

        // The reason is the part a maintainer reads when a suite silently stops running, so it
        // must say why and where the real verification lives.
        HostPlatformGuard.WindowsSkipReason.ShouldContain("README");
        HostPlatformGuard.MacSkipReason.ShouldContain("README");
        HostPlatformGuard.WindowsSkipReason.Length.ShouldBeGreaterThan(80);
        HostPlatformGuard.MacSkipReason.Length.ShouldBeGreaterThan(80);
    }

    [Fact]
    public void TheAttributesAreRealXunitAttributesSoTheMethodsStayDiscoverable()
    {
        // A custom attribute that did not derive from FactAttribute/TheoryAttribute would make
        // xunit skip the method entirely -- silently, and without even a skip count to notice.
        typeof(FactOnNonWindowsAttribute).IsSubclassOf(typeof(FactAttribute)).ShouldBeTrue();
        typeof(TheoryOnNonWindowsAttribute).IsSubclassOf(typeof(TheoryAttribute)).ShouldBeTrue();
        typeof(FactOnNonMacOSAttribute).IsSubclassOf(typeof(FactAttribute)).ShouldBeTrue();
        typeof(TheoryOnNonMacOSAttribute).IsSubclassOf(typeof(TheoryAttribute)).ShouldBeTrue();

        // And they must construct without throwing on this host, leaving this host's own suites
        // unskipped: they run here, which is what keeps the coverage real.
        new FactOnNonWindowsAttribute().Skip.ShouldBe(
            HostPlatformGuard.ForWindowsSuite(OperatingSystem.IsWindows()));
        new TheoryOnNonWindowsAttribute().Skip.ShouldBe(
            HostPlatformGuard.ForWindowsSuite(OperatingSystem.IsWindows()));
        new FactOnNonMacOSAttribute().Skip.ShouldBe(
            HostPlatformGuard.ForMacSuite(OperatingSystem.IsMacOS()));
        new TheoryOnNonMacOSAttribute().Skip.ShouldBe(
            HostPlatformGuard.ForMacSuite(OperatingSystem.IsMacOS()));
    }
}
