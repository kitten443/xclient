using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Infrastructure.Geo;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Infrastructure.Tests;

/// <summary>
/// Tests for geo data management, including the regression guards for the v2rayN issue #9765
/// class of failure.
/// </summary>
/// <remarks>
/// These are real file-system tests using real protobuf fixtures, because the whole point of
/// this component is that "the file exists" is not the same as "the file is usable" and
/// "the path is absolute" is not the same as "the path reached the child process".
/// </remarks>
public sealed class GeoDataManagerTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _root;

    public GeoDataManagerTests(ITestOutputHelper output)
    {
        _output = output;
        _root = Path.Combine(Path.GetTempPath(), "myvpn-geo-tests", Guid.NewGuid().ToString("N"));
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
            // Temp cleanup is best effort.
        }
    }

    // ---------------------------------------------------------------- fixtures

    /// <summary>
    /// Builds a structurally valid geo data file: a protobuf message whose repeated field 1
    /// is a set of entries, each carrying a printable code in its own field 1.
    /// </summary>
    /// <remarks>
    /// Padding is added as an unknown field inside each entry, which keeps the fixture above
    /// <see cref="GeoAssetValidator.MinimumPlausibleSizeBytes"/> and simultaneously exercises
    /// the forward-compatibility path where unknown fields must be skipped, not rejected.
    /// The padding is deliberately generous so that even a 100-entry fixture clears the
    /// 4096-byte plausibility floor.
    /// </remarks>
    private static byte[] BuildValidGeoAsset(int entryCount = 200, int padding = 40)
    {
        using var buffer = new MemoryStream();

        for (var i = 0; i < entryCount; i++)
        {
            var entry = BuildEntry($"c{i}", padding);
            WriteLengthDelimited(buffer, fieldNumber: 1, entry);
        }

        return buffer.ToArray();
    }

    private static byte[] BuildEntry(string code, int padding)
    {
        using var entry = new MemoryStream();

        // field 1, wire type 2: the code string.
        WriteLengthDelimited(entry, fieldNumber: 1, Encoding.ASCII.GetBytes(code));

        if (padding > 0)
        {
            // field 9, wire type 2: an unknown field that must be skipped.
            WriteLengthDelimited(entry, fieldNumber: 9, new byte[padding]);
        }

        return entry.ToArray();
    }

    private static void WriteLengthDelimited(Stream stream, int fieldNumber, byte[] payload)
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

    private GeoDataManager CreateManager(string? seedDirectory = null, string? assetDirectory = null)
    {
        var assets = assetDirectory ?? Path.Combine(_root, "geodata");
        return new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = assets,
                SeedDirectory = seedDirectory,
                BackupDirectory = Path.Combine(_root, "backup"),
                ManifestPath = Path.Combine(_root, "geodata-manifest.json"),
            },
            NullLogger<GeoDataManager>.Instance);
    }

    private void WriteAsset(string directory, GeoAssetKind kind, byte[] content)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, kind.FileName()), content);
    }

    // ---------------------------------------------------------------- validation

    [Fact]
    public async Task ReportsMissingAssetsWhenNothingIsPresent()
    {
        var manager = CreateManager();
        var status = await manager.InspectAsync(CancellationToken.None);

        status.AllUsable.ShouldBeFalse();
        status.GeoIp.Health.ShouldBe(GeoAssetHealth.Missing);
        status.GeoSite.Health.ShouldBe(GeoAssetHealth.Missing);
        status.RequiresRepair.ShouldBeTrue();
        status.GeoIp.MessageKey.ShouldBe("error.geodata.missing");

        // Availability drives the config builder: with no assets, geo rules must be omitted.
        status.Availability.All.ShouldBeFalse();
    }

    [Fact]
    public async Task ReportsZeroByteFileAsEmptyNotValid()
    {
        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, Array.Empty<byte>());
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var status = await CreateManager().InspectAsync(CancellationToken.None);

        status.GeoIp.Health.ShouldBe(GeoAssetHealth.Empty);
        status.GeoIp.IsUsable.ShouldBeFalse();
        status.GeoSite.IsUsable.ShouldBeTrue();

        // Independence matters: a broken geoip must not invalidate a good geosite.
        status.AnyUsable.ShouldBeTrue();
        status.Availability.GeoSiteAvailable.ShouldBeTrue();
        status.Availability.GeoIpAvailable.ShouldBeFalse();
    }

    [Fact]
    public async Task ReportsHtmlErrorPageSavedAsDatAsCorrupt()
    {
        // The captive-portal / mirror-error case: an existence check and a size check both
        // pass, but the content is an HTML page.
        var html = Encoding.UTF8.GetBytes(
            "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>"
            + new string('x', 5000)
            + "</body></html>");

        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, html);
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var status = await CreateManager().InspectAsync(CancellationToken.None);

        status.GeoIp.IsUsable.ShouldBeFalse();
        status.GeoIp.Health.ShouldBe(GeoAssetHealth.Corrupt);
        status.GeoIp.FailureDetail.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task ReportsTruncatedFileAsCorrupt()
    {
        // Truncate to a length that is still above the plausibility minimum, so the failure
        // is genuinely a structural truncation rather than a size rejection.
        var valid = BuildValidGeoAsset(entryCount: 500);
        valid.Length.ShouldBeGreaterThan((int)GeoAssetValidator.MinimumPlausibleSizeBytes * 2);
        var truncated = valid[..(valid.Length * 3 / 4)];

        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, truncated);
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var status = await CreateManager().InspectAsync(CancellationToken.None);

        status.GeoIp.IsUsable.ShouldBeFalse();
        status.GeoIp.Health.ShouldBe(GeoAssetHealth.Corrupt);
        status.GeoIp.FailureDetail!.ShouldContain("truncated", Case.Insensitive);
    }

    [Fact]
    public async Task ReportsImplausiblySmallFileAsInvalid()
    {
        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, Encoding.ASCII.GetBytes("not really geo data"));
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var status = await CreateManager().InspectAsync(CancellationToken.None);

        status.GeoIp.IsUsable.ShouldBeFalse();
        status.GeoIp.Health.ShouldBeOneOf(GeoAssetHealth.TooSmall, GeoAssetHealth.Corrupt);
    }

    [Fact]
    public async Task DetectsChecksumMismatchAgainstRecordedManifest()
    {
        var assets = Path.Combine(_root, "geodata");
        var manager = CreateManager();

        WriteAsset(assets, GeoAssetKind.GeoIp, BuildValidGeoAsset(entryCount: 100));
        var install = await manager.InstallAsync(
            GeoAssetKind.GeoIp, new MemoryStream(BuildValidGeoAsset(entryCount: 100)),
            null, "v1", null, CancellationToken.None);
        install.IsSuccess.ShouldBeTrue();

        // Replace the file behind the manager's back with different, still-valid content.
        WriteAsset(assets, GeoAssetKind.GeoIp, BuildValidGeoAsset(entryCount: 150));
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var status = await manager.InspectAsync(CancellationToken.None);

        // Structurally usable but not the recorded generation: a warning, not a hard failure,
        // because the asset can still be used and refusing to connect would be worse.
        status.GeoIp.Health.ShouldBe(GeoAssetHealth.ChecksumMismatch);
        status.GeoIp.IsUsable.ShouldBeFalse();
        status.GeoIp.ErrorCode.ShouldBe(ErrorCodes.GeoAssetChecksumMismatch);
    }

    [Fact]
    public async Task RejectsNonAbsoluteAssetDirectoryAsCritical()
    {
        var manager = new GeoDataManager(
            new GeoDataOptions
            {
                // A relative directory changes meaning with the working directory, which is
                // exactly the trap this guard exists for.
                AssetDirectory = "relative/geodata",
                BackupDirectory = Path.Combine(_root, "backup"),
                ManifestPath = Path.Combine(_root, "manifest.json"),
            },
            NullLogger<GeoDataManager>.Instance);

        var status = await manager.InspectAsync(CancellationToken.None);

        status.IsAssetDirectoryAbsolute.ShouldBeFalse();
        status.RequiresRepair.ShouldBeTrue();
        status.GeoIp.Health.ShouldBe(GeoAssetHealth.PathNotAbsolute);

        var error = status.ToWorstError();
        error.ShouldNotBeNull();
        error!.Severity.ShouldBe(ErrorSeverity.Critical);
        error.Code.ShouldBe(ErrorCodes.GeoAssetPathNotAbsolute);
    }

    // ---------------------------------------------------------------- atomic install

    [Fact]
    public async Task InstallsAssetAtomicallyAndRecordsProvenance()
    {
        var manager = CreateManager();
        var content = BuildValidGeoAsset(entryCount: 250);

        var result = await manager.InstallAsync(
            GeoAssetKind.GeoIp,
            new MemoryStream(content),
            expectedSha256: null,
            version: "v26.9.9",
            sourceUrl: "https://example.invalid/geoip.dat",
            CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        result.Value.IsUsable.ShouldBeTrue();
        result.Value.EntryCount.ShouldBe(250);
        result.Value.Version.ShouldBe("v26.9.9");

        // No temporary staging file may be left behind.
        File.Exists(Path.Combine(manager.AssetDirectory, "geoip.dat.download")).ShouldBeFalse();
        File.Exists(Path.Combine(manager.AssetDirectory, "geoip.dat")).ShouldBeTrue();

        var status = await manager.InspectAsync(CancellationToken.None);
        status.GeoIp.IsUsable.ShouldBeTrue();
        status.GeoIp.Sha256.ShouldBe(result.Value.Sha256);
        status.GeoIp.Version.ShouldBe("v26.9.9");
    }

    [Fact]
    public async Task RejectsContentWithWrongChecksumAndLeavesExistingAssetIntact()
    {
        var manager = CreateManager();
        var good = BuildValidGeoAsset(entryCount: 120);

        (await manager.InstallAsync(GeoAssetKind.GeoIp, new MemoryStream(good), null, "good", null,
            CancellationToken.None)).IsSuccess.ShouldBeTrue();

        var before = await manager.InspectAsync(CancellationToken.None);

        // Also plant a valid geosite so the status is otherwise healthy.
        await manager.InstallAsync(GeoAssetKind.GeoSite, new MemoryStream(BuildValidGeoAsset()), null,
            "g", null, CancellationToken.None);

        // Now attempt an update whose declared checksum does not match the payload.
        var badUpdate = BuildValidGeoAsset(entryCount: 999);
        var result = await manager.InstallAsync(
            GeoAssetKind.GeoIp,
            new MemoryStream(badUpdate),
            expectedSha256: new string('a', 64),
            version: "evil",
            sourceUrl: null,
            CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.GeoAssetChecksumMismatch);

        // The pre-existing, good asset must be completely untouched.
        var after = await manager.InspectAsync(CancellationToken.None);
        after.GeoIp.Sha256.ShouldBe(before.GeoIp.Sha256);
        after.GeoIp.IsUsable.ShouldBeTrue();
        after.GeoIp.Version.ShouldBe("good");

        File.Exists(Path.Combine(manager.AssetDirectory, "geoip.dat.download")).ShouldBeFalse();
    }

    [Fact]
    public async Task RejectsStructurallyInvalidUpdateAndKeepsPreviousGeneration()
    {
        var manager = CreateManager();
        var good = BuildValidGeoAsset(entryCount: 120);
        await manager.InstallAsync(GeoAssetKind.GeoIp, new MemoryStream(good), null, "good", null,
            CancellationToken.None);
        await manager.InstallAsync(GeoAssetKind.GeoSite, new MemoryStream(BuildValidGeoAsset()), null,
            "g", null, CancellationToken.None);

        var before = await manager.InspectAsync(CancellationToken.None);

        // Valid size, invalid structure: must be caught before it becomes live.
        var html = Encoding.UTF8.GetBytes("<html>" + new string('y', 6000) + "</html>");
        var result = await manager.InstallAsync(GeoAssetKind.GeoIp, new MemoryStream(html), null,
            "bad", null, CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBeOneOf(ErrorCodes.GeoAssetCorrupt, ErrorCodes.GeoAssetEmpty);

        var after = await manager.InspectAsync(CancellationToken.None);
        after.GeoIp.Sha256.ShouldBe(before.GeoIp.Sha256);
        after.GeoIp.IsUsable.ShouldBeTrue();
    }

    [Fact]
    public async Task RollsBackToPreviousGeneration()
    {
        var manager = CreateManager();
        await manager.InstallAsync(GeoAssetKind.GeoIp, new MemoryStream(BuildValidGeoAsset(100)), null,
            "v1", null, CancellationToken.None);
        await manager.InstallAsync(GeoAssetKind.GeoSite, new MemoryStream(BuildValidGeoAsset()), null,
            "s1", null, CancellationToken.None);

        var v1 = await manager.InspectAsync(CancellationToken.None);

        await manager.InstallAsync(GeoAssetKind.GeoIp, new MemoryStream(BuildValidGeoAsset(300)), null,
            "v2", null, CancellationToken.None);

        var v2 = await manager.InspectAsync(CancellationToken.None);
        v2.GeoIp.EntryCount.ShouldBe(300);

        var rollback = await manager.RollbackAsync(GeoAssetKind.GeoIp, CancellationToken.None);
        rollback.IsSuccess.ShouldBeTrue();

        var restored = await manager.InspectAsync(CancellationToken.None);
        restored.GeoIp.IsUsable.ShouldBeTrue();
        restored.GeoIp.Sha256.ShouldBe(v1.GeoIp.Sha256);
    }

    [Fact]
    public async Task RollbackWithoutBackupFailsWithClearError()
    {
        var result = await CreateManager().RollbackAsync(GeoAssetKind.GeoIp, CancellationToken.None);

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.GeoAssetRollbackFailed);
    }

    [Fact]
    public async Task RepairReseedsFromTheInstallationSeedDirectory()
    {
        var seed = Path.Combine(_root, "seed");
        WriteAsset(seed, GeoAssetKind.GeoIp, BuildValidGeoAsset(180));
        WriteAsset(seed, GeoAssetKind.GeoSite, BuildValidGeoAsset(90));

        var manager = CreateManager(seedDirectory: seed);

        // Nothing in the working directory yet; inspection should already fall back to the seed.
        var before = await manager.InspectAsync(CancellationToken.None);
        before.AllUsable.ShouldBeTrue();
        before.ResolvedFrom.ShouldBe("seed");

        // Now corrupt a working copy and repair.
        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, Encoding.UTF8.GetBytes("<html>" + new string('z', 6000)));

        var corrupted = await manager.InspectAsync(CancellationToken.None);
        corrupted.GeoIp.IsUsable.ShouldBeFalse();

        var repaired = await manager.RepairAsync(CancellationToken.None);

        repaired.GeoIp.IsUsable.ShouldBeTrue();
        repaired.GeoIp.EntryCount.ShouldBe(180);
    }

    [Fact]
    public async Task RepairOnAHealthyInstallationIsANoOp()
    {
        var seed = Path.Combine(_root, "seed");
        WriteAsset(seed, GeoAssetKind.GeoIp, BuildValidGeoAsset());
        WriteAsset(seed, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var manager = CreateManager(seedDirectory: seed);
        var before = await manager.InspectAsync(CancellationToken.None);
        var after = await manager.RepairAsync(CancellationToken.None);

        before.AllUsable.ShouldBeTrue();
        after.AllUsable.ShouldBeTrue();
    }

    // ---------------------------------------------------------------- issue #9765 guards

    [Fact]
    public void ExportsAssetDirectoryAsAnAbsolutePath()
    {
        var manager = CreateManager();
        var environment = manager.BuildXrayEnvironment();

        environment.ContainsKey(GeoDataConstants.AssetLocationEnvironmentVariable).ShouldBeTrue();

        var value = environment[GeoDataConstants.AssetLocationEnvironmentVariable];
        Path.IsPathRooted(value).ShouldBeTrue();
        value.ShouldBe(manager.AssetDirectory);

        // Normalisation must survive a path containing spaces and non-ASCII characters, which
        // is common on Windows and under a macOS user directory.
        var awkward = Path.Combine(_root, "My Vpn Äärend", "geodata");
        var awkwardManager = CreateManager(assetDirectory: awkward);
        Path.IsPathRooted(awkwardManager.BuildXrayEnvironment()[
            GeoDataConstants.AssetLocationEnvironmentVariable]).ShouldBeTrue();
    }

    /// <summary>
    /// Reproduces the exact issue #9765 mechanism and proves the guard catches it.
    /// </summary>
    /// <remarks>
    /// Upstream, the asset directory was computed correctly and was absolute, but the value
    /// never reached the elevated Xray process because the launcher built the child with an
    /// empty environment (and <c>sudo</c>'s <c>env_reset</c> would have removed it anyway).
    /// Xray then fell back to its own default, the directory containing its executable, and
    /// failed to find the assets.
    /// </remarks>
    [Fact]
    public void Issue9765ReproductionIsDetectedByThePrelaunchAssertion()
    {
        var assetDirectory = Path.Combine(_root, "state", "geodata");
        WriteAsset(assetDirectory, GeoAssetKind.GeoIp, BuildValidGeoAsset());
        WriteAsset(assetDirectory, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        // The binary lives somewhere else entirely, as it does in a package install or an
        // app bundle. Its directory has no geo data.
        var binDirectory = Path.Combine(_root, "opt", "myvpn", "bin");
        Directory.CreateDirectory(binDirectory);
        var executable = Path.Combine(binDirectory, "xray");

        // Case 1 — normal operation: the environment variable is delivered, so Xray resolves
        // the directory MyVpn validated.
        var healthy = XrayAssetResolution.VerifyConsistency(
            intendedDirectory: assetDirectory,
            executablePath: executable,
            fileExists: File.Exists,
            isWindows: false);
        healthy.Succeeded.ShouldBeTrue();
        healthy.Directory.ShouldBe(assetDirectory);

        // Case 2 — the #9765 defect: the variable is dropped, so Xray falls back to the
        // executable's directory and finds nothing there. This must be reported before launch
        // rather than surfacing as an opaque error from inside Xray.
        var dropped = XrayAssetResolution.Resolve(
            XrayAssetResolution.BuildCandidateList(
                configuredDirectory: null,
                executableDirectory: binDirectory,
                isWindows: false),
            fileExists: File.Exists);

        dropped.Succeeded.ShouldBeFalse();
        dropped.MessageKey.ShouldBe("error.geodata.not_found_anywhere");
        dropped.TechnicalDetail!.ShouldContain(binDirectory);
    }

    [Fact]
    public void PrelaunchAssertionReportsMismatchWhenXrayWouldResolveADifferentDirectory()
    {
        // MyVpn intends an empty directory, but a later candidate in Xray's search order has
        // usable assets, so Xray would silently use a directory MyVpn never validated.
        var intended = Path.Combine(_root, "intended-empty");
        Directory.CreateDirectory(intended);

        var executableDirectory = Path.Combine(_root, "exe-dir");
        WriteAsset(executableDirectory, GeoAssetKind.GeoIp, BuildValidGeoAsset());
        WriteAsset(executableDirectory, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var resolution = XrayAssetResolution.VerifyConsistency(
            intendedDirectory: intended,
            executablePath: Path.Combine(executableDirectory, "xray"),
            fileExists: File.Exists,
            isWindows: false);

        resolution.Succeeded.ShouldBeTrue();
        resolution.Directory.ShouldBe(executableDirectory);
        resolution.MessageKey.ShouldBe("error.geodata.resolution_mismatch");
    }

    [Fact]
    public void VerifyBeforeLaunchSucceedsWhenTheWorkingCopyIsValid()
    {
        var assets = Path.Combine(_root, "geodata");
        WriteAsset(assets, GeoAssetKind.GeoIp, BuildValidGeoAsset());
        WriteAsset(assets, GeoAssetKind.GeoSite, BuildValidGeoAsset());

        var manager = CreateManager(assetDirectory: assets);
        var executable = Path.Combine(assets, "xray");

        var result = manager.VerifyBeforeLaunch(executable);
        result.IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void VerifyBeforeLaunchFailsWithAnActionableErrorWhenAssetsAreAbsent()
    {
        var manager = CreateManager();
        var result = manager.VerifyBeforeLaunch(Path.Combine(_root, "nowhere", "xray"));

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.GeoAssetMissing);
        result.Error.RemediationKey.ShouldBe("geodata.repair");
        _output.WriteLine(result.Error.ToString());
    }

    // ---------------------------------------------------------------- resolution ordering

    [Fact]
    public void CandidateOrderMatchesXraysDocumentedThenActualLookup()
    {
        var candidates = XrayAssetResolution.BuildCandidateList("/custom/dir", "/exe/dir", isWindows: false);

        candidates[0].ShouldBe("/custom/dir");
        candidates[1].ShouldBe("/exe/dir");
        candidates.ShouldContain("/usr/local/share/xray");
        candidates.ShouldContain("/usr/share/xray");
        candidates.ShouldContain("/opt/share/xray");
    }

    [Fact]
    public void WindowsCandidateListOmitsUnixSystemDirectories()
    {
        var candidates = XrayAssetResolution.BuildCandidateList(null, @"C:\myvpn\bin", isWindows: true);

        candidates.ShouldNotContain("/usr/share/xray");
        candidates.Count.ShouldBe(1);
    }

    [Fact]
    public void CandidateListDeduplicatesPreservingOrder()
    {
        var candidates = XrayAssetResolution.BuildCandidateList("/same", "/same", isWindows: false);
        candidates.Count(c => c == "/same").ShouldBe(1);
    }

    [Fact]
    public void ResolutionRequiresBothAssetsByDefault()
    {
        var directory = Path.Combine(_root, "only-geoip");
        WriteAsset(directory, GeoAssetKind.GeoIp, BuildValidGeoAsset());

        var resolution = XrayAssetResolution.Resolve(
            new[] { directory },
            fileExists: File.Exists);

        resolution.Succeeded.ShouldBeFalse();
        resolution.MissingFiles.ShouldContain("geosite.dat");
    }

    [Fact]
    public void ResolutionCanRequireASingleAsset()
    {
        var directory = Path.Combine(_root, "only-geoip-2");
        WriteAsset(directory, GeoAssetKind.GeoIp, BuildValidGeoAsset());

        var resolution = XrayAssetResolution.Resolve(
            new[] { directory },
            fileExists: File.Exists,
            requiredKinds: new[] { GeoAssetKind.GeoIp });

        resolution.Succeeded.ShouldBeTrue();
        resolution.Directory.ShouldBe(directory);
    }
}
