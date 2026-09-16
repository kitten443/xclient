using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;

namespace MyVpn.Infrastructure.Geo;

/// <summary>Where geo data lives and how it is seeded.</summary>
public sealed record GeoDataOptions
{
    /// <summary>
    /// Writable working directory that will be exported as <c>XRAY_LOCATION_ASSET</c>.
    /// </summary>
    public required string AssetDirectory { get; init; }

    /// <summary>
    /// Read-only seed directory shipped with the installation (package path, app-bundle
    /// resources, AppImage mount). Used to populate or repair the working copy.
    /// </summary>
    public string? SeedDirectory { get; init; }

    /// <summary>Directory holding the previous known-good generation.</summary>
    public required string BackupDirectory { get; init; }

    /// <summary>Path of the checksum manifest.</summary>
    public required string ManifestPath { get; init; }

    /// <summary>Extra directories to search when the working copy is absent.</summary>
    public IReadOnlyList<string> AdditionalSearchDirectories { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Largest asset MyVpn will read into memory to validate. Geo files are a few megabytes;
    /// this bound exists so a corrupt or hostile file cannot exhaust memory.
    /// </summary>
    public long MaxValidationBytes { get; init; } = 256L * 1024 * 1024;
}

/// <summary>A recorded, known-good asset generation.</summary>
public sealed record GeoAssetManifestEntry
{
    public required string FileName { get; init; }

    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }

    public string? Version { get; init; }

    public string? SourceUrl { get; init; }

    public int EntryCount { get; init; }

    public DateTimeOffset RecordedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>On-disk checksum manifest.</summary>
public sealed record GeoAssetManifest
{
    public int SchemaVersion { get; init; } = 1;

    public Dictionary<string, GeoAssetManifestEntry> Assets { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsEmpty => Assets.Count == 0;
}

/// <summary>
/// Owns geo data for the lifetime of the installation: resolution, validation, atomic
/// update, rollback and repair.
/// </summary>
/// <remarks>
/// <para>
/// This component is the direct answer to v2rayN issue #9765, plus the broader failure class
/// it belongs to. Its design rules:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Absolute paths, resolved once.</b> <see cref="AssetDirectory"/> is normalised to a
/// rooted absolute path at construction. A non-absolute value is reported as a Critical
/// health problem rather than silently coerced, because a relative
/// <c>XRAY_LOCATION_ASSET</c> changes meaning with the process working directory.
/// </description></item>
/// <item><description>
/// <b>Content validation, not existence checks.</b> A geo file that is present but
/// truncated, zero-filled, or actually an HTML error page from a captive portal passes an
/// existence and size check. <see cref="GeoAssetValidator"/> walks the protobuf structure,
/// so those cases are caught here rather than inside Xray.
/// </description></item>
/// <item><description>
/// <b>Independent per-asset state.</b> <c>geoip.dat</c> and <c>geosite.dat</c> are validated,
/// updated and rolled back separately, so a failure in one never invalidates the other.
/// </description></item>
/// <item><description>
/// <b>Atomic replacement with rollback.</b> Downloads land in a temporary file on the same
/// filesystem, are verified and structurally validated there, and only then replace the
/// target by rename. The previous generation is kept, so a bad update is reversible.
/// </description></item>
/// <item><description>
/// <b>Corrupt geo data must not break the connection.</b> Nothing here throws on bad data;
/// problems are reported through <see cref="GeoDataStatus"/>, and the config builder
/// consults <see cref="GeoDataStatus.Availability"/> so that a missing asset causes geo
/// rules to be omitted and flagged, not the core to fail.
/// </description></item>
/// </list>
/// </remarks>
public sealed class GeoDataManager
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly GeoDataOptions _options;
    private readonly ILogger<GeoDataManager> _logger;

    public GeoDataManager(GeoDataOptions options, ILogger<GeoDataManager> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _logger = logger;

        // Decide absoluteness BEFORE normalising. Path.GetFullPath would happily resolve a
        // relative value against the current working directory, which would make the guard
        // useless: the whole point is to refuse a path whose meaning depends on the working
        // directory, not to silently pick one interpretation.
        IsAssetDirectoryAbsolute = Path.IsPathRooted(options.AssetDirectory);
        AssetDirectory = IsAssetDirectoryAbsolute
            ? NormalizeDirectory(options.AssetDirectory)
            : options.AssetDirectory ?? string.Empty;
    }

    /// <summary>Absolute asset directory, exported as <c>XRAY_LOCATION_ASSET</c>.</summary>
    public string AssetDirectory { get; }

    /// <summary>True when the configured directory is a usable absolute path.</summary>
    public bool IsAssetDirectoryAbsolute { get; }

    /// <summary>Inspects both assets and reports per-asset health.</summary>
    public async Task<GeoDataStatus> InspectAsync(CancellationToken cancellationToken)
    {
        var manifest = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
        var writable = await IsDirectoryWritableAsync(cancellationToken).ConfigureAwait(false);
        var hasBackup = Directory.Exists(_options.BackupDirectory)
                        && AssetFileNames()
                            .Any(name => File.Exists(Path.Combine(_options.BackupDirectory, name)));

        var geoIp = await ValidateAssetAsync(GeoAssetKind.GeoIp, manifest, cancellationToken)
            .ConfigureAwait(false);
        var geoSite = await ValidateAssetAsync(GeoAssetKind.GeoSite, manifest, cancellationToken)
            .ConfigureAwait(false);

        return new GeoDataStatus
        {
            AssetDirectory = AssetDirectory,
            IsAssetDirectoryAbsolute = IsAssetDirectoryAbsolute,
            IsAssetDirectoryWritable = writable,
            GeoIp = geoIp.ToInfo(),
            GeoSite = geoSite.ToInfo(),
            ResolvedFrom = ResolveProvenance(),
            HasBackupGeneration = hasBackup,
        };
    }

    /// <summary>
    /// Installs a new asset generation atomically.
    /// </summary>
    /// <param name="kind">Which asset is being replaced.</param>
    /// <param name="content">The candidate file content.</param>
    /// <param name="expectedSha256">Expected lowercase hex digest, when the source publishes one.</param>
    /// <param name="version">Upstream version/tag, recorded in the manifest.</param>
    /// <param name="sourceUrl">Where the content came from, recorded for provenance.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// The ordering is the whole point: verify and validate in a temporary file first, back
    /// up the current generation, and only then rename into place. Nothing touches the live
    /// asset until the replacement is known to be good, so a failed or interrupted update
    /// leaves the installation exactly as it was.
    /// </remarks>
    public async Task<Result<GeoAssetStatus>> InstallAsync(
        GeoAssetKind kind,
        Stream content,
        string? expectedSha256,
        string? version,
        string? sourceUrl,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (!IsAssetDirectoryAbsolute)
        {
            return Result<GeoAssetStatus>.Fail(new MyVpnError(
                ErrorCodes.GeoAssetPathNotAbsolute,
                "error.geodata.path_not_absolute",
                ErrorSeverity.Critical,
                $"Refusing to install into a non-absolute asset directory: '{AssetDirectory}'."));
        }

        try
        {
            Directory.CreateDirectory(AssetDirectory);
            Directory.CreateDirectory(_options.BackupDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<GeoAssetStatus>.Fail(new MyVpnError(
                ErrorCodes.GeoAssetDirectoryNotWritable,
                "error.geodata.directory_not_writable",
                ErrorSeverity.Error,
                $"Cannot create the asset directory '{AssetDirectory}': {ex.Message}"));
        }

        var targetPath = Path.Combine(AssetDirectory, kind.FileName());
        var tempPath = targetPath + GeoDataConstants.TemporaryFileSuffix;
        var backupPath = Path.Combine(_options.BackupDirectory, kind.FileName());

        try
        {
            // 1. Stage into a temporary file on the SAME filesystem, so the later rename is atomic.
            long size;
            string sha256;

            await using (var temp = new FileStream(
                tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                using var hasher = SHA256.Create();

                // Dispose the CryptoStream (ending its scope) before reading the digest and the
                // length, so both are final rather than partially flushed.
                await using (var cryptoStream = new CryptoStream(temp, hasher, CryptoStreamMode.Write, leaveOpen: true))
                {
                    await content.CopyToAsync(cryptoStream, cancellationToken).ConfigureAwait(false);
                    await cryptoStream.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
                }

                size = temp.Length;
                sha256 = Convert.ToHexString(hasher.Hash!).ToLowerInvariant();
            }

            // 2. Verify the checksum before trusting the bytes.
            if (!string.IsNullOrWhiteSpace(expectedSha256))
            {
                var expected = expectedSha256.Trim().ToLowerInvariant();
                if (!string.Equals(expected, sha256, StringComparison.Ordinal))
                {
                    TryDelete(tempPath);

                    return Result<GeoAssetStatus>.Fail(new MyVpnError(
                        ErrorCodes.GeoAssetChecksumMismatch,
                        "error.geodata.checksum_mismatch",
                        ErrorSeverity.Error,
                        $"{kind.FileName()} checksum mismatch: expected {expected}, computed {sha256}.")
                        .WithArgs(("file", kind.FileName()), ("expected", expected), ("actual", sha256)));
                }
            }

            // 3. Validate the structure in the temporary file, before it becomes live.
            var validation = await ValidateFileAsync(tempPath, kind, size, cancellationToken).ConfigureAwait(false);
            if (!validation.IsValid)
            {
                TryDelete(tempPath);

                var (health, code, messageKey) = GeoAssetInfo.MapValidationFailure(
                    kind, validation.FailureCode ?? "corrupt");

                return Result<GeoAssetStatus>.Fail(new MyVpnError(
                    code,
                    messageKey,
                    GeoAssetInfo.SeverityFor(health),
                    validation.FailureDetail,
                    "geodata.repair"));
            }

            // 4. Preserve the current generation so the update is reversible.
            if (File.Exists(targetPath))
            {
                File.Copy(targetPath, backupPath, overwrite: true);
            }

            // 5. Atomic publish.
            File.Move(tempPath, targetPath, overwrite: true);

            _logger.LogInformation(
                "Installed {Kind} {File}: {Size} bytes, sha256 {Hash}, {Entries} entries.",
                kind,
                kind.FileName(),
                size,
                sha256,
                validation.EntryCount);

            // 6. Record provenance.
            var manifest = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
            manifest.Assets[kind.FileName()] = new GeoAssetManifestEntry
            {
                FileName = kind.FileName(),
                Sha256 = sha256,
                SizeBytes = size,
                Version = version,
                SourceUrl = sourceUrl,
                EntryCount = validation.EntryCount,
            };

            await SaveManifestAsync(manifest, cancellationToken).ConfigureAwait(false);

            return Result<GeoAssetStatus>.Ok(new GeoAssetStatus(kind, validation, sha256, size, version, sourceUrl));
        }
        catch (OperationCanceledException)
        {
            TryDelete(tempPath);
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tempPath);

            return Result<GeoAssetStatus>.Fail(new MyVpnError(
                ErrorCodes.GeoAssetInstallFailed,
                "error.geodata.install_failed",
                ErrorSeverity.Error,
                $"Failed to install {kind.FileName()}: {ex.Message}"));
        }
    }

    /// <summary>Restores the previous generation for one asset.</summary>
    public async Task<Result<GeoAssetStatus>> RollbackAsync(
        GeoAssetKind kind,
        CancellationToken cancellationToken)
    {
        var backupPath = Path.Combine(_options.BackupDirectory, kind.FileName());
        if (!File.Exists(backupPath))
        {
            return Result<GeoAssetStatus>.Fail(new MyVpnError(
                ErrorCodes.GeoAssetRollbackFailed,
                "error.geodata.no_backup",
                ErrorSeverity.Warning,
                $"No backup generation exists for {kind.FileName()}."));
        }

        var targetPath = Path.Combine(AssetDirectory, kind.FileName());
        var tempPath = targetPath + GeoDataConstants.TemporaryFileSuffix;

        try
        {
            // Restore through a temporary file + rename so a crash mid-restore cannot leave a
            // half-written asset in place.
            File.Copy(backupPath, tempPath, overwrite: true);

            var info = new FileInfo(tempPath);
            var validation = await ValidateFileAsync(tempPath, kind, info.Length, cancellationToken)
                .ConfigureAwait(false);

            if (!validation.IsValid)
            {
                TryDelete(tempPath);

                return Result<GeoAssetStatus>.Fail(new MyVpnError(
                    ErrorCodes.GeoAssetRollbackFailed,
                    "error.geodata.backup_corrupt",
                    ErrorSeverity.Error,
                    $"The backup generation of {kind.FileName()} is itself invalid."));
            }

            File.Move(tempPath, targetPath, overwrite: true);

            var sha256 = await ComputeSha256Async(targetPath, cancellationToken).ConfigureAwait(false);

            // Record the restored generation. Without this the manifest would still describe
            // the failed update, so the very next inspection would report the freshly restored
            // file as a checksum mismatch and the rollback would look like it had not worked.
            var manifest = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
            manifest.Assets[kind.FileName()] = new GeoAssetManifestEntry
            {
                FileName = kind.FileName(),
                Sha256 = sha256,
                SizeBytes = info.Length,
                Version = "rollback",
                EntryCount = validation.EntryCount,
            };

            await SaveManifestAsync(manifest, cancellationToken).ConfigureAwait(false);

            _logger.LogWarning("Rolled back {Kind} to the previous generation.", kind);

            return Result<GeoAssetStatus>.Ok(
                new GeoAssetStatus(kind, validation, sha256, info.Length, "rollback", null));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tempPath);

            return Result<GeoAssetStatus>.Fail(new MyVpnError(
                ErrorCodes.GeoAssetRollbackFailed,
                "error.geodata.rollback_failed",
                ErrorSeverity.Error,
                $"Rollback of {kind.FileName()} failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Best-effort repair: re-seeds the working copy from the installation's read-only seed,
    /// falls back to the backup generation, and reports whatever remains broken.
    /// </summary>
    /// <remarks>
    /// This backs the "repair" button. It never throws and never leaves the installation
    /// worse off: each asset is repaired independently and the returned status describes the
    /// real state afterwards, so the UI can tell the user honestly whether the repair worked.
    /// </remarks>
    public async Task<GeoDataStatus> RepairAsync(CancellationToken cancellationToken)
    {
        var status = await InspectAsync(cancellationToken).ConfigureAwait(false);

        if (status.AllUsable && status.IsAssetDirectoryAbsolute)
        {
            return status;
        }

        foreach (var asset in status.ProblemAssets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var repaired = await TryReseedFromSourceAsync(asset.Kind, cancellationToken).ConfigureAwait(false);
            if (repaired.IsSuccess)
            {
                _logger.LogInformation("Repaired {Kind} by re-seeding.", asset.Kind);
                continue;
            }

            var rolledBack = await RollbackAsync(asset.Kind, cancellationToken).ConfigureAwait(false);
            if (rolledBack.IsSuccess)
            {
                _logger.LogInformation("Repaired {Kind} from the backup generation.", asset.Kind);
                continue;
            }

            _logger.LogWarning(
                "Could not repair {Kind}: {Reseed}; {Rollback}",
                asset.Kind,
                repaired.Error?.Code,
                rolledBack.Error?.Code);
        }

        return await InspectAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the environment for the Xray child process.
    /// </summary>
    /// <remarks>
    /// This is the primary fix for issue #9765. The value is always absolute. The caller must
    /// pass this dictionary to the child process explicitly and must launch Xray by argv, not
    /// through a shell: a shell wrapper, or an elevated launcher that resets the environment,
    /// is precisely how the variable gets lost. The same directory is additionally written
    /// into the generated config's root <c>env</c> object as a second, independent channel.
    /// </remarks>
    public IReadOnlyDictionary<string, string> BuildXrayEnvironment()
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [GeoDataConstants.AssetLocationEnvironmentVariable] = AssetDirectory,
        };

        return environment;
    }

    /// <summary>
    /// Asserts, before launching the core, that Xray will resolve the same asset directory
    /// MyVpn validated.
    /// </summary>
    public Result VerifyBeforeLaunch(string executablePath)
    {
        var resolution = XrayAssetResolution.VerifyConsistency(
            intendedDirectory: AssetDirectory,
            executablePath: executablePath,
            fileExists: File.Exists,
            isWindows: OperatingSystem.IsWindows());

        if (resolution.Succeeded)
        {
            return Result.Ok();
        }

        return Result.Fail(new MyVpnError(
            ErrorCodes.GeoAssetMissing,
            resolution.MessageKey ?? "error.geodata.not_found_anywhere",
            ErrorSeverity.Error,
            resolution.TechnicalDetail,
            "geodata.repair"));
    }

    // ------------------------------------------------------------------ internals

    private async Task<GeoAssetStatus> ValidateAssetAsync(
        GeoAssetKind kind,
        GeoAssetManifest manifest,
        CancellationToken cancellationToken)
    {
        if (!IsAssetDirectoryAbsolute)
        {
            return new GeoAssetStatus(
                kind,
                GeoAssetValidationResult.Invalid("path_not_absolute", $"Asset directory is not absolute: '{AssetDirectory}'."),
                null,
                0,
                null,
                null)
            {
                Health = GeoAssetHealth.PathNotAbsolute,
                ErrorCode = ErrorCodes.GeoAssetPathNotAbsolute,
                MessageKey = "error.geodata.path_not_absolute",
                RemediationKey = "geodata.repair",
            };
        }

        var path = Path.Combine(AssetDirectory, kind.FileName());

        // Fall back to the seed / search directories when the working copy is absent, so a
        // fresh install with bundled assets works without a download.
        if (!File.Exists(path))
        {
            var fallback = FindFallback(kind);
            if (fallback is not null)
            {
                _logger.LogInformation(
                    "{File} is not in the working directory; using the bundled copy at {Fallback}.",
                    kind.FileName(),
                    fallback);

                path = fallback;
            }
            else
            {
                return new GeoAssetStatus(
                    kind,
                    GeoAssetValidationResult.Invalid("missing", $"{kind.FileName()} not found at '{path}'."),
                    null,
                    0,
                    null,
                    null)
                {
                    Health = GeoAssetHealth.Missing,
                    ErrorCode = ErrorCodes.GeoAssetMissing,
                    MessageKey = "error.geodata.missing",
                    RemediationKey = "geodata.repair",
                    AbsolutePath = path,
                };
            }
        }

        try
        {
            var info = new FileInfo(path);
            var validation = await ValidateFileAsync(path, kind, info.Length, cancellationToken)
                .ConfigureAwait(false);
            var sha256 = validation.IsValid || info.Length > 0
                ? await ComputeSha256Async(path, cancellationToken).ConfigureAwait(false)
                : null;

            var manifestEntry = manifest.Assets.GetValueOrDefault(kind.FileName());

            // A checksum mismatch is a warning rather than an error: the content is
            // structurally sound and usable, but it is not the generation we recorded, which
            // is worth telling the user about (a partial write, a mirror serving a stale file).
            if (manifestEntry is not null && sha256 is not null
                && !string.Equals(manifestEntry.Sha256, sha256, StringComparison.Ordinal))
            {
                _logger.LogWarning(
                    "{File} does not match the recorded checksum (recorded {Recorded}, actual {Actual}).",
                    kind.FileName(),
                    manifestEntry.Sha256,
                    sha256);

                return new GeoAssetStatus(kind, validation, sha256, info.Length, manifestEntry.Version,
                    manifestEntry.SourceUrl)
                {
                    Health = GeoAssetHealth.ChecksumMismatch,
                    ErrorCode = ErrorCodes.GeoAssetChecksumMismatch,
                    MessageKey = "error.geodata.checksum_mismatch",
                    RemediationKey = "geodata.repair",
                    AbsolutePath = path,
                    FailureDetail = $"Recorded {manifestEntry.Sha256}, actual {sha256}.",
                };
            }

            return new GeoAssetStatus(kind, validation, sha256, info.Length,
                manifestEntry?.Version, manifestEntry?.SourceUrl)
            {
                Health = validation.IsValid
                    ? GeoAssetHealth.Valid

                    // Preserve the specific diagnosis (empty / too small / truncated / wrong
                    // format) instead of collapsing every structural failure to "corrupt":
                    // the difference is what makes the repair message actionable.
                    : GeoAssetInfo.MapValidationFailure(kind, validation.FailureCode ?? "corrupt").Health,
                ErrorCode = validation.IsValid
                    ? null
                    : GeoAssetInfo.MapValidationFailure(kind, validation.FailureCode ?? "corrupt").ErrorCode,
                MessageKey = validation.IsValid
                    ? null
                    : GeoAssetInfo.MapValidationFailure(kind, validation.FailureCode ?? "corrupt").MessageKey,
                RemediationKey = validation.IsValid ? null : "geodata.repair",
                AbsolutePath = path,
                FailureDetail = validation.FailureDetail,
            };
        }
        catch (UnauthorizedAccessException ex)
        {
            return new GeoAssetStatus(
                kind,
                GeoAssetValidationResult.Invalid("unreadable", ex.Message),
                null,
                0,
                null,
                null)
            {
                Health = GeoAssetHealth.Unreadable,
                ErrorCode = ErrorCodes.GeoAssetUnreadable,
                MessageKey = "error.geodata.unreadable",
                RemediationKey = "geodata.repair",
                AbsolutePath = path,
                FailureDetail = ex.Message,
            };
        }
        catch (IOException ex)
        {
            return new GeoAssetStatus(
                kind,
                GeoAssetValidationResult.Invalid("unreadable", ex.Message),
                null,
                0,
                null,
                null)
            {
                Health = GeoAssetHealth.Unreadable,
                ErrorCode = ErrorCodes.GeoAssetUnreadable,
                MessageKey = "error.geodata.unreadable",
                RemediationKey = "geodata.repair",
                AbsolutePath = path,
                FailureDetail = ex.Message,
            };
        }
    }

    private async Task<GeoAssetValidationResult> ValidateFileAsync(
        string path,
        GeoAssetKind kind,
        long size,
        CancellationToken cancellationToken)
    {
        if (size == 0)
        {
            return GeoAssetValidationResult.Invalid("empty", $"{kind.FileName()} is zero bytes.");
        }

        if (size > _options.MaxValidationBytes)
        {
            return GeoAssetValidationResult.Invalid(
                "too_large",
                $"{kind.FileName()} is {size} bytes, above the {_options.MaxValidationBytes}-byte validation bound.");
        }

        if (!GeoAssetValidator.HasPlausibleSize(size))
        {
            return GeoAssetValidationResult.Invalid(
                "too_small",
                $"{kind.FileName()} is {size} bytes, below the {GeoAssetValidator.MinimumPlausibleSizeBytes}-byte minimum.");
        }

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return GeoAssetValidator.Validate(kind, bytes);
    }

    private string? FindFallback(GeoAssetKind kind)
    {
        var candidates = new List<string>();

        if (!string.IsNullOrWhiteSpace(_options.SeedDirectory))
        {
            candidates.Add(_options.SeedDirectory!);
        }

        candidates.AddRange(_options.AdditionalSearchDirectories);

        if (!OperatingSystem.IsWindows())
        {
            candidates.AddRange(XrayAssetResolution.UnixSystemDirectories);
        }

        var fileName = kind.FileName();
        foreach (var directory in candidates)
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }

            var path = Path.Combine(directory, fileName);
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    private async Task<Result> TryReseedFromSourceAsync(GeoAssetKind kind, CancellationToken cancellationToken)
    {
        var source = FindFallback(kind);
        if (source is null)
        {
            return Result.Fail(ErrorCodes.GeoAssetMissing, "error.geodata.no_seed_available");
        }

        try
        {
            await using var stream = File.OpenRead(source);
            var result = await InstallAsync(kind, stream, null, "seed", source, cancellationToken)
                .ConfigureAwait(false);

            return result.IsSuccess ? Result.Ok() : Result.Fail(result.Error!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.GeoAssetInstallFailed,
                "error.geodata.install_failed",
                ErrorSeverity.Warning,
                ex.Message));
        }
    }

    private string? ResolveProvenance()
    {
        if (Directory.Exists(AssetDirectory)
            && Directory.EnumerateFiles(AssetDirectory, "*.dat").Any())
        {
            return "working-copy";
        }

        if (!string.IsNullOrWhiteSpace(_options.SeedDirectory) && Directory.Exists(_options.SeedDirectory))
        {
            return "seed";
        }

        return "none";
    }

    private async Task<bool> IsDirectoryWritableAsync(CancellationToken cancellationToken)
    {
        if (!IsAssetDirectoryAbsolute)
        {
            return false;
        }

        try
        {
            Directory.CreateDirectory(AssetDirectory);

            var probe = Path.Combine(AssetDirectory, ".myvpn-write-probe");
            await File.WriteAllTextAsync(probe, string.Empty, cancellationToken).ConfigureAwait(false);
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task<GeoAssetManifest> LoadManifestAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(_options.ManifestPath))
            {
                return new GeoAssetManifest();
            }

            await using var stream = File.OpenRead(_options.ManifestPath);
            var manifest = await JsonSerializer
                .DeserializeAsync<GeoAssetManifest>(stream, ManifestJsonOptions, cancellationToken)
                .ConfigureAwait(false);

            return manifest ?? new GeoAssetManifest();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A corrupt manifest must never block startup: the worst case is that we lose the
            // recorded checksums, and the assets are still validated structurally.
            _logger.LogWarning(ex, "Could not read the geo data manifest; continuing without recorded checksums.");
            return new GeoAssetManifest();
        }
    }

    private async Task SaveManifestAsync(GeoAssetManifest manifest, CancellationToken cancellationToken)
    {
        try
        {
            var directory = Path.GetDirectoryName(_options.ManifestPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Write via a temporary file so an interrupted save cannot corrupt the manifest.
            var temp = _options.ManifestPath + ".tmp";
            await using (var stream = File.Create(temp))
            {
                await JsonSerializer.SerializeAsync(stream, manifest, ManifestJsonOptions, cancellationToken)
                    .ConfigureAwait(false);
            }

            File.Move(temp, _options.ManifestPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not persist the geo data manifest.");
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);

        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string NormalizeDirectory(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return string.Empty;
        }

        try
        {
            // GetFullPath also removes trailing separators and resolves '..', so the value
            // stored here is the single canonical form used everywhere else.
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return directory;
        }
    }

    private static IEnumerable<string> AssetFileNames() => new[]
    {
        GeoAssetKind.GeoIp.FileName(),
        GeoAssetKind.GeoSite.FileName(),
    };

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: a leftover temporary file is harmless and is overwritten next time.
        }
    }
}

/// <summary>Per-asset status produced by validation and installation.</summary>
public sealed record GeoAssetStatus
{
    public GeoAssetStatus(
        GeoAssetKind kind,
        GeoAssetValidationResult validation,
        string? sha256,
        long sizeBytes,
        string? version,
        string? sourceUrl)
    {
        Kind = kind;
        Validation = validation;
        Sha256 = sha256;
        SizeBytes = sizeBytes;
        Version = version;
        SourceUrl = sourceUrl;

        AbsolutePath = string.Empty;
        Health = validation.IsValid ? GeoAssetHealth.Valid : GeoAssetHealth.Corrupt;
    }

    public GeoAssetKind Kind { get; init; }

    public GeoAssetValidationResult Validation { get; init; }

    public string? Sha256 { get; init; }

    public long SizeBytes { get; init; }

    public string? Version { get; init; }

    public string? SourceUrl { get; init; }

    public string AbsolutePath { get; init; }

    public GeoAssetHealth Health { get; init; }

    public string? ErrorCode { get; init; }

    public string? MessageKey { get; init; }

    public string? RemediationKey { get; init; }

    public string? FailureDetail { get; init; }

    /// <summary>Number of geo entries decoded during validation.</summary>
    public int EntryCount => Validation.EntryCount;

    public bool IsUsable => Health == GeoAssetHealth.Valid;

    /// <summary>Projects this status onto the Core model consumed by the config builder.</summary>
    public GeoAssetInfo ToInfo() => new()
    {
        Kind = Kind,
        AbsolutePath = AbsolutePath,
        Health = Health,
        SizeBytes = SizeBytes,
        Sha256 = Sha256,
        EntryCount = Validation.EntryCount,
        SampleCodes = Validation.SampleCodes,
        SourceUrl = SourceUrl,
        Version = Version,
        ErrorCode = ErrorCode,
        MessageKey = MessageKey,
        RemediationKey = RemediationKey,
        FailureDetail = FailureDetail ?? Validation.FailureDetail,
    };

    /// <summary>Builds a structured error describing this asset's problem, if any.</summary>
    public MyVpnError? ToError()
    {
        if (IsUsable)
        {
            return null;
        }

        var (health, code, messageKey) = GeoAssetInfo.MapValidationFailure(Kind, Validation.FailureCode ?? "corrupt");

        return new MyVpnError(
            ErrorCode ?? code,
            MessageKey ?? messageKey,
            GeoAssetInfo.SeverityFor(Health),
            FailureDetail ?? Validation.FailureDetail,
            RemediationKey ?? "geodata.repair");
    }
}
