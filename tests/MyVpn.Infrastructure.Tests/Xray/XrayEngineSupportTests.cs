using MyVpn.Core.Xray;
using MyVpn.Infrastructure.Xray;
using Shouldly;
using Xunit;

namespace MyVpn.Infrastructure.Tests.Xray;

/// <summary>Tests for core binary discovery.</summary>
/// <remarks>
/// The locator searches <em>directories</em> and joins the platform binary name onto each one with
/// <see cref="Path.Combine"/>, which uses the host's separator. These tests therefore build every
/// fixture path the same way instead of writing POSIX paths as literals: a hard-coded
/// <c>"/app/xray/xray"</c> compiles and passes on Linux but never matches on Windows, where the
/// locator correctly produces <c>\app\xray\xray</c>. The failure that produced was misleading —
/// four tests reporting "binary not found" for a locator that was working exactly as designed —
/// so the expectations are now separator-agnostic by construction rather than by luck.
/// </remarks>
public sealed class XrayBinaryLocatorTests
{
    /// <summary>A directory, built the way the locator builds its search list.</summary>
    private static string Dir(params string[] parts) => Path.Combine(parts);

    /// <summary>The core file inside a directory, named the way the locator names it.</summary>
    private static string Bin(string directory, bool isWindows = false) =>
        Path.Combine(directory, XrayBinaryLocator.BinaryName(isWindows));

    /// <summary>
    /// What <c>Locate</c> reports for a candidate: it returns an absolute path, so a comparison
    /// against a relative or partially-rooted literal would be a different string on Windows.
    /// </summary>
    private static string Resolved(string path) => Path.GetFullPath(path);

    private static ResultLike Locate(
        string? userPath,
        string baseDir,
        IReadOnlyList<string> presentFiles,
        IReadOnlyList<string>? nonExecutable = null,
        bool isWindows = false)
    {
        var files = new HashSet<string>(presentFiles, StringComparer.Ordinal);
        var bad = new HashSet<string>(nonExecutable ?? Array.Empty<string>(), StringComparer.Ordinal);

        var result = XrayBinaryLocator.Locate(
            userSelectedPath: userPath,
            applicationBaseDirectory: baseDir,
            packageManagerDirectories: null,
            isWindows: isWindows,
            fileExists: files.Contains,
            isExecutable: isWindows ? null : path => !bad.Contains(path));

        return new ResultLike(result.IsSuccess, result.IsSuccess ? result.Value.AbsolutePath : null, result.Error);
    }

    private sealed record ResultLike(bool IsSuccess, string? Path, MyVpn.Core.Results.MyVpnError? Error);

    [Fact]
    public void FindsABundledCoreBeforeTheSystemPath()
    {
        var bundled = Bin(Dir("/app", "xray"));
        var result = Locate(null, "/app", new[] { bundled, Bin("/usr/bin") });

        result.IsSuccess.ShouldBeTrue();
        result.Path.ShouldBe(Resolved(bundled));
    }

    [Fact]
    public void PrefersTheUserSelectedCoreOverTheBundledOne()
    {
        var selected = Bin("/custom");
        var result = Locate(selected, "/app", new[] { Bin(Dir("/app", "xray")), selected });

        result.IsSuccess.ShouldBeTrue();
        result.Path.ShouldBe(Resolved(selected));
    }

    [Fact]
    public void FallsBackToTheSystemPathWhenNothingIsBundled()
    {
        var system = Bin("/usr/bin");
        var result = Locate(null, "/app", new[] { system });

        result.IsSuccess.ShouldBeTrue();
        result.Path.ShouldBe(Resolved(system));
    }

    [Fact]
    public void ReportsNotExecutableRatherThanNotPermitted()
    {
        // The binary exists but lost its executable bit, which is what happens when a tarball is
        // extracted without permissions preserved. The predicate is injected, so this exercises the
        // locator's ordering and diagnosis on any host; production passes null on Windows, where
        // the executable bit does not exist.
        var stripped = Bin(Dir("/app", "xray"));
        var result = Locate(null, "/app", new[] { stripped }, nonExecutable: new[] { stripped });

        result.IsSuccess.ShouldBeFalse();
        result.Error!.Code.ShouldBe(MyVpn.Core.Results.ErrorCodes.XrayBinaryNotExecutable);
        result.Error.RemediationKey.ShouldBe("xray.select_binary");
    }

    [Fact]
    public void ReportsNotFoundWhenNothingIsPresent()
    {
        var result = Locate(null, "/app", Array.Empty<string>());

        result.IsSuccess.ShouldBeFalse();
        result.Error!.Code.ShouldBe(MyVpn.Core.Results.ErrorCodes.XrayBinaryNotFound);
    }

    [Fact]
    public void ReportsTheSelectedPathWhenTheUserPathIsWrong()
    {
        var result = Locate("/custom/xray", "/app", Array.Empty<string>());

        result.IsSuccess.ShouldBeFalse();
        result.Error!.MessageKey.ShouldBe("error.xray.binary_not_found_at_path");
    }

    [Fact]
    public void UsesThePlatformBinaryName()
    {
        XrayBinaryLocator.BinaryName(isWindows: true).ShouldBe("xray.exe");
        XrayBinaryLocator.BinaryName(isWindows: false).ShouldBe("xray");
    }

    [Fact]
    public void WindowsSearchOrderOmitsUnixDirectories()
    {
        var order = XrayBinaryLocator.BuildSearchOrder(null, "/app", Array.Empty<string>(), isWindows: true);

        order.ShouldNotContain(o => o.Directory == "/usr/bin");
        order.ShouldNotContain(o => o.Directory == "/usr/lib/xray");
    }

    [Fact]
    public void UnixSearchOrderPutsTheBundledDirectoryFirstWhenNoUserSelectionExists()
    {
        var order = XrayBinaryLocator.BuildSearchOrder(null, "/app", Array.Empty<string>(), isWindows: false);

        order[0].Directory.ShouldBe(Path.Combine("/app", "xray"));
        order[0].Source.ShouldBe(XrayBinarySource.Bundled);
        order.ShouldContain(o => o.Directory == "/usr/bin");
    }
}

/// <summary>Tests for the restart-rate policy.</summary>
public sealed class RestartLimiterTests
{
    [Fact]
    public void AllowsRestartsUpToTheLimitThenBlocks()
    {
        var now = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var limiter = new RestartLimiter(3, TimeSpan.FromMinutes(1), () => now);

        for (var i = 0; i < 3; i++)
        {
            limiter.CanRestart().ShouldBeTrue($"attempt {i + 1} should be allowed");
            limiter.RecordAttempt();
        }

        limiter.CanRestart().ShouldBeFalse();
        limiter.AttemptsInWindow.ShouldBe(3);
    }

    [Fact]
    public void AllowsAgainOnceTheWindowSlidesPastTheOldestAttempt()
    {
        var now = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var limiter = new RestartLimiter(2, TimeSpan.FromSeconds(30), () => now);

        limiter.RecordAttempt();
        limiter.RecordAttempt();
        limiter.CanRestart().ShouldBeFalse();

        // One second before expiry: still blocked.
        now = now.AddSeconds(29);
        limiter.CanRestart().ShouldBeFalse();

        // Past the window: allowed again.
        now = now.AddSeconds(2);
        limiter.CanRestart().ShouldBeTrue();
    }

    [Fact]
    public void ResetClearsTheWindow()
    {
        var now = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var limiter = new RestartLimiter(1, TimeSpan.FromMinutes(5), () => now);

        limiter.RecordAttempt();
        limiter.CanRestart().ShouldBeFalse();

        limiter.Reset();
        limiter.CanRestart().ShouldBeTrue();
        limiter.AttemptsInWindow.ShouldBe(0);
    }

    [Fact]
    public void ReportsWaitTimeWhenBlocked()
    {
        var now = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var limiter = new RestartLimiter(1, TimeSpan.FromSeconds(60), () => now);

        limiter.RecordAttempt();
        var wait = limiter.TimeUntilNextAllowed();

        wait.ShouldBeGreaterThan(TimeSpan.Zero);
        wait.ShouldBeLessThanOrEqualTo(TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void ZeroLimitBlocksEveryRestart()
    {
        var limiter = new RestartLimiter(0, TimeSpan.FromMinutes(1));
        limiter.CanRestart().ShouldBeFalse();
    }

    [Fact]
    public void DescribeSummarisesTheWindow()
    {
        var limiter = new RestartLimiter(5, TimeSpan.FromSeconds(90));
        limiter.RecordAttempt();

        limiter.Describe().ShouldContain("1/5");
        limiter.Describe().ShouldContain("90");
    }
}

/// <summary>Tests for exit-code interpretation — the crash-loop guard.</summary>
public sealed class XrayTestRunInterpreterTests
{
    [Fact]
    public void ExitZeroMeansTheConfigurationIsValid()
    {
        var result = XrayTestRunInterpreter.Interpret(0, string.Empty);

        result.IsValid.ShouldBeTrue();
        result.IsConfigurationError.ShouldBeFalse();
    }

    [Fact]
    public void ExitTwentyThreeIsAConfigurationError()
    {
        var result = XrayTestRunInterpreter.Interpret(23, "failed to open geosite.dat");

        result.IsValid.ShouldBeFalse();
        result.IsConfigurationError.ShouldBeTrue();
        result.MessageKey.ShouldBe("error.xray.config_rejected_by_core");
        result.Diagnostic.ShouldBe("failed to open geosite.dat");
    }

    [Fact]
    public void AnyOtherExitCodeIsNotReportedAsAConfigurationError()
    {
        // A missing shared library or an unsupported flag is a pre-flight failure, not a config
        // problem. Conflating them sends the user hunting in the wrong place.
        var result = XrayTestRunInterpreter.Interpret(127, "cannot execute binary file");

        result.IsValid.ShouldBeFalse();
        result.IsConfigurationError.ShouldBeFalse();
        result.MessageKey.ShouldBe("error.xray.preflight_failed");
    }

    [Fact]
    public void DiagnosticKeepsOnlyTheLastMeaningfulLine()
    {
        var stderr = "Xray 26.9.9 started\nreading config\ncommon/geodata: failed to open geoip.dat\n";

        var result = XrayTestRunInterpreter.Interpret(23, stderr);

        result.Diagnostic.ShouldBe("common/geodata: failed to open geoip.dat");
    }

    [Fact]
    public void DiagnosticIsNullForEmptyStderr()
    {
        XrayTestRunInterpreter.Interpret(23, null).Diagnostic.ShouldBeNull();
        XrayTestRunInterpreter.Interpret(23, "   \n  ").Diagnostic.ShouldBeNull();
    }

    [Fact]
    public void DiagnosticIsBoundedInLength()
    {
        var huge = new string('x', 2000);
        var result = XrayTestRunInterpreter.Interpret(23, huge);

        result.Diagnostic!.Length.ShouldBeLessThanOrEqualTo(501);
    }

    [Theory]
    [InlineData(0, false, XrayStopReason.UnexpectedExit)]
    [InlineData(23, false, XrayStopReason.InvalidConfiguration)]
    [InlineData(2, false, XrayStopReason.Crash)]
    [InlineData(1, false, XrayStopReason.Crash)]
    [InlineData(143, true, XrayStopReason.Requested)]
    [InlineData(137, true, XrayStopReason.ForcedShutdown)]
    public void ClassifiesExitsSoTheSupervisorCanDecide(int exitCode, bool stopRequested, XrayStopReason expected)
    {
        XrayTestRunInterpreter.ClassifyExit(exitCode, stopRequested).ShouldBe(expected);
    }

    [Fact]
    public void InvalidConfigurationIsTerminalRegardlessOfVersion()
    {
        var result = XrayTestRunInterpreter.Interpret(23, "bad config", new XrayVersion(26, 9, 9));

        result.IsConfigurationError.ShouldBeTrue();
        result.RemediationKey.ShouldBe("diagnostics.run");
    }
}
