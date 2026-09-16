using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using MyVpn.Core.Diagnostics;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.Diagnostics;
using MyVpn.Infrastructure.Geo;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Infrastructure.Tests.Diagnostics;

/// <summary>
/// Tests for the diagnostic runner.
/// </summary>
/// <remarks>
/// The property under test throughout is isolation: a diagnostics screen that fails, hangs, or
/// hides the other results is worse than no diagnostics at all, because it removes the user's
/// only route to understanding what is broken.
/// </remarks>
public sealed class DiagnosticRunnerTests
{
    private readonly ITestOutputHelper _output;

    public DiagnosticRunnerTests(ITestOutputHelper output) => _output = output;

    private static DiagnosticContext Context() => new() { Settings = new AppSettings() };

    private static DiagnosticRunner Runner(params IDiagnosticCheck[] checks) =>
        new(checks, NullLogger<DiagnosticRunner>.Instance, checkTimeout: TimeSpan.FromMilliseconds(500));

    private sealed class FakeCheck : IDiagnosticCheck
    {
        private readonly Func<DiagnosticCheckResult> _produce;

        public FakeCheck(
            string id,
            int order = 0,
            bool applicable = true,
            Func<DiagnosticCheckResult>? produce = null)
        {
            Id = id;
            Order = order;
            Applicable = applicable;
            _produce = produce ?? (() => DiagnosticCheckResult.Ok(id, $"check.{id}"));
        }

        public string Id { get; }

        public string TitleKey => $"check.{Id}";

        public int Order { get; }

        public string SkipReasonKey => $"skip.{Id}";

        public bool Applicable { get; }

        public bool IsApplicable(DiagnosticContext context) => Applicable;

        public Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken) =>
            Task.FromResult(_produce());
    }

    private sealed class ThrowingCheck : IDiagnosticCheck
    {
        public string Id => "throwing";

        public string TitleKey => "check.throwing";

        public int Order => 50;

        public string SkipReasonKey => "skip.throwing";

        public bool IsApplicable(DiagnosticContext context) => true;

        public Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("check exploded");
    }

    private sealed class HangingCheck : IDiagnosticCheck
    {
        public string Id => "hanging";

        public string TitleKey => "check.hanging";

        public int Order => 60;

        public string SkipReasonKey => "skip.hanging";

        public bool IsApplicable(DiagnosticContext context) => true;

        public async Task<DiagnosticCheckResult> RunAsync(DiagnosticContext context, CancellationToken cancellationToken)
        {
            // Deliberately ignores the token and outlives the budget.
            await Task.Delay(TimeSpan.FromSeconds(30), CancellationToken.None);
            return DiagnosticCheckResult.Ok(Id, TitleKey);
        }
    }

    [Fact]
    public async Task RunsChecksInDeclaredOrder()
    {
        var report = await Runner(
                new FakeCheck("third", order: 30),
                new FakeCheck("first", order: 10),
                new FakeCheck("second", order: 20))
            .RunAsync(Context(), CancellationToken.None);

        report.Checks.Select(c => c.Id).ShouldBe(new[] { "first", "second", "third" });
        report.Overall.ShouldBe(DiagnosticStatus.Success);
    }

    [Fact]
    public async Task MarksInapplicableChecksAsSkippedWithTheirReason()
    {
        var report = await Runner(new FakeCheck("nope", applicable: false))
            .RunAsync(Context(), CancellationToken.None);

        var check = report.Checks.Single();
        check.Status.ShouldBe(DiagnosticStatus.Skipped);
        check.MessageKey.ShouldBe("skip.nope");

        // A skipped check must not colour the overall verdict.
        report.Overall.ShouldBe(DiagnosticStatus.Success);
    }

    [Fact]
    public async Task AThrowingCheckDoesNotPreventTheOthersFromReporting()
    {
        var report = await Runner(
                new FakeCheck("good", order: 10),
                new ThrowingCheck(),
                new FakeCheck("alsogood", order: 20))
            .RunAsync(Context(), CancellationToken.None);

        report.Checks.Count.ShouldBe(3);
        report.Checks.Single(c => c.Id == "good").Status.ShouldBe(DiagnosticStatus.Success);
        report.Checks.Single(c => c.Id == "alsogood").Status.ShouldBe(DiagnosticStatus.Success);

        var thrown = report.Checks.Single(c => c.Id == "throwing");
        thrown.Status.ShouldBe(DiagnosticStatus.Error);
        thrown.MessageKey.ShouldBe("diagnostics.error.check_failed");
        thrown.TechnicalDetail.ShouldNotBeNull();
        thrown.TechnicalDetail!.ShouldContain("check exploded");
    }

    [Fact]
    public async Task AHangingCheckIsTimedOutRatherThanHangingTheReport()
    {
        var report = await Runner(new HangingCheck(), new FakeCheck("quick"))
            .RunAsync(Context(), CancellationToken.None);

        report.Checks.Single(c => c.Id == "hanging").Status.ShouldBe(DiagnosticStatus.Error);
        report.Checks.Single(c => c.Id == "hanging").MessageKey.ShouldBe("diagnostics.error.check_timeout");

        // The healthy check still reported.
        report.Checks.Single(c => c.Id == "quick").Status.ShouldBe(DiagnosticStatus.Success);
    }

    [Fact]
    public async Task OverallIsTheWorstStatusPresent()
    {
        var allGood = await Runner(new FakeCheck("a")).RunAsync(Context(), CancellationToken.None);
        allGood.Overall.ShouldBe(DiagnosticStatus.Success);

        var withWarning = await Runner(
                new FakeCheck("a"),
                new FakeCheck("b", produce: () => DiagnosticCheckResult.Warning("b", "check.b", "warn.key")))
            .RunAsync(Context(), CancellationToken.None);
        withWarning.Overall.ShouldBe(DiagnosticStatus.Warning);

        var withError = await Runner(
                new FakeCheck("b", produce: () => DiagnosticCheckResult.Warning("b", "check.b", "warn.key")),
                new FakeCheck("c", produce: () => DiagnosticCheckResult.Error("c", "check.c", "error.key")))
            .RunAsync(Context(), CancellationToken.None);
        withError.Overall.ShouldBe(DiagnosticStatus.Error);
    }

    [Fact]
    public async Task CountsAndProblemsAreReported()
    {
        var report = await Runner(
                new FakeCheck("ok", order: 10),
                new FakeCheck("warn", order: 20, produce: () => DiagnosticCheckResult.Warning("warn", "t", "w")),
                new FakeCheck("err", order: 30, produce: () => DiagnosticCheckResult.Error("err", "t", "e")))
            .RunAsync(Context(), CancellationToken.None);

        report.ErrorCount.ShouldBe(1);
        report.WarningCount.ShouldBe(1);
        report.HasErrors.ShouldBeTrue();
        report.Problems.Select(p => p.Id).ShouldBe(new[] { "warn", "err" });
    }

    [Fact]
    public async Task AnEmptyCheckSetIsReportedAsSkippedRatherThanSuccess()
    {
        var report = await Runner().RunAsync(Context(), CancellationToken.None);

        // Nothing verified is not the same as everything fine.
        report.Overall.ShouldBe(DiagnosticStatus.Skipped);
    }

    [Fact]
    public async Task SummaryEmitsMessageKeysRatherThanInventedEnglish()
    {
        var report = await Runner(new FakeCheck(
                "err",
                produce: () => DiagnosticCheckResult.Error("err", "check.err", "error.geodata.missing", "detail text")))
            .RunAsync(Context(), CancellationToken.None);

        var summary = report.ToPlainTextSummary();

        summary.ShouldContain("error.geodata.missing");
        summary.ShouldContain("detail text");
        summary.ShouldContain("err");
        _output.WriteLine(summary);
    }

    [Fact]
    public void DefaultCheckSetCoversTheRequiredAreas()
    {
        var ids = DiagnosticRunner.CreateDefaultChecks().Select(c => c.Id).ToArray();

        // The required areas from the specification.
        ids.ShouldContain("core-binary");
        ids.ShouldContain("geodata");
        ids.ShouldContain("core-process");
        ids.ShouldContain("tun-interface");
        ids.ShouldContain("kill-switch");
        ids.ShouldContain("dns");
        ids.ShouldContain("system-proxy");
        ids.ShouldContain("server-reachability");
    }

    [Fact]
    public void DefaultChecksHaveDistinctIdsAndSensibleOrder()
    {
        var checks = DiagnosticRunner.CreateDefaultChecks().ToArray();

        checks.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count().ShouldBe(checks.Length);
        checks.Select(c => c.Order).ShouldBe(checks.Select(c => c.Order).OrderBy(o => o));
    }
}

/// <summary>Tests for the geo data diagnostic check, using a real manager and real fixtures.</summary>
public sealed class GeoDataDiagnosticCheckTests : IDisposable
{
    private readonly string _root;

    public GeoDataDiagnosticCheckTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "myvpn-diag-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort.
        }
    }

    private GeoDataManager CreateManager(string? seed = null) => new(
        new GeoDataOptions
        {
            AssetDirectory = Path.Combine(_root, "geodata"),
            SeedDirectory = seed,
            BackupDirectory = Path.Combine(_root, "backup"),
            ManifestPath = Path.Combine(_root, "manifest.json"),
        },
        NullLogger<GeoDataManager>.Instance);

    private static byte[] BuildValidAsset(int entries = 200, int padding = 40)
    {
        using var buffer = new MemoryStream();

        for (var i = 0; i < entries; i++)
        {
            using var entry = new MemoryStream();
            WriteField(entry, 1, Encoding.ASCII.GetBytes($"c{i}"));
            WriteField(entry, 9, new byte[padding]);
            WriteField(buffer, 1, entry.ToArray());
        }

        return buffer.ToArray();
    }

    private static void WriteField(Stream stream, int fieldNumber, byte[] payload)
    {
        WriteVarint(stream, (ulong)((fieldNumber << 3) | 2));
        WriteVarint(stream, (ulong)payload.Length);
        stream.Write(payload, 0, payload.Length);
    }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80)
        {
            stream.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }

        stream.WriteByte((byte)value);
    }

    private static void WriteAsset(string directory, GeoAssetKind kind, byte[] content)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, kind.FileName()), content);
    }

    [Fact]
    public async Task ReportsErrorWithAnActionableMessageWhenAssetsAreMissing()
    {
        var context = new DiagnosticContext
        {
            Settings = new AppSettings(),
            GeoData = CreateManager(),
        };

        var result = await new GeoDataDiagnosticCheck().RunAsync(context, CancellationToken.None);

        result.Status.ShouldBe(DiagnosticStatus.Error);
        result.MessageKey.ShouldBe("error.geodata.missing");

        // The plain-language fix must be offered, not just the failure.
        result.RemediationKey.ShouldBe("geodata.repair");
        result.Evidence.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task ReportsSuccessWithEntryCountsForHealthyAssets()
    {
        var assets = Path.Combine(_root, "geodata");

        // Both fixtures must clear the 4096-byte plausibility floor; an entry is roughly 49 bytes.
        WriteAsset(assets, GeoAssetKind.GeoIp, BuildValidAsset(entries: 120));
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidAsset(entries: 150));

        var context = new DiagnosticContext
        {
            Settings = new AppSettings(),
            GeoData = CreateManager(),
        };

        var result = await new GeoDataDiagnosticCheck().RunAsync(context, CancellationToken.None);

        result.Status.ShouldBe(DiagnosticStatus.Success);
        result.TechnicalDetail.ShouldNotBeNull();
        result.TechnicalDetail!.ShouldContain("120");
        result.TechnicalDetail.ShouldContain("150");
    }

    [Fact]
    public async Task ReportsCorruptContentAsAnError()
    {
        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, Encoding.UTF8.GetBytes("<html>" + new string('x', 6000)));
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidAsset());

        var context = new DiagnosticContext
        {
            Settings = new AppSettings(),
            GeoData = CreateManager(),
        };

        var result = await new GeoDataDiagnosticCheck().RunAsync(context, CancellationToken.None);

        result.Status.ShouldBe(DiagnosticStatus.Error);
        result.MessageKey.ShouldNotBeNull();
        result.MessageKey!.ShouldStartWith("error.geodata.");
    }

    [Fact]
    public void IsInapplicableWithoutAGeoDataManager()
    {
        var check = new GeoDataDiagnosticCheck();
        check.IsApplicable(new DiagnosticContext { Settings = new AppSettings() }).ShouldBeFalse();
    }
}
