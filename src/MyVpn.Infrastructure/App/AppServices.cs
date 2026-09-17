using MyVpn.Application.Abstractions;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;

namespace MyVpn.Infrastructure.App;

/// <summary>
/// Per-user filesystem layout.
/// </summary>
/// <remarks>
/// Everything writable lives under one per-user root, and the geo data gets a writable working
/// copy there rather than being used in place. That split matters for the packaged cases: an
/// AppImage mount, a macOS app bundle and <c>/usr/share</c> are all read-only, so an updater that
/// tried to write next to the binary would fail — or worse, appear to succeed on one platform and
/// not another.
/// </remarks>
public sealed class AppPaths : IAppPaths
{
    public const string AppFolderName = "myvpn";

    /// <param name="rootOverride">
    /// Explicit root, used by tests and by portable mode. When <c>null</c>, the platform's
    /// per-user data directory is used.
    /// </param>
    public AppPaths(string? rootOverride = null, string? seedGeoDataDirectory = null)
    {
        var root = rootOverride ?? DefaultRoot();

        StateDirectory = root;
        ConfigDirectory = Path.Combine(root, "config");
        LogDirectory = Path.Combine(root, "logs");
        GeoDataDirectory = Path.Combine(root, GeoDataConstants.DefaultAssetDirectoryName);
        GeoBackupDirectory = Path.Combine(root, GeoDataConstants.BackupDirectoryName);
        GeoManifestPath = Path.Combine(root, "geodata-manifest.json");
        ActiveConfigPath = Path.Combine(ConfigDirectory, "active-config.json");

        SeedGeoDataDirectory = seedGeoDataDirectory ?? DefaultSeedDirectory();
    }

    public string StateDirectory { get; }

    public string ConfigDirectory { get; }

    public string LogDirectory { get; }

    public string GeoDataDirectory { get; }

    public string GeoBackupDirectory { get; }

    public string GeoManifestPath { get; }

    public string ActiveConfigPath { get; }

    public string? SeedGeoDataDirectory { get; }

    /// <summary>Creates every directory the application writes to.</summary>
    public void EnsureCreated()
    {
        foreach (var directory in new[] { StateDirectory, ConfigDirectory, LogDirectory, GeoDataDirectory, GeoBackupDirectory })
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static string DefaultRoot()
    {
        // LocalApplicationData maps to ~/.local/share on Linux, ~/Library/Application Support on
        // macOS and %LOCALAPPDATA% on Windows, which is the correct per-user location on each.
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        if (string.IsNullOrEmpty(local))
        {
            local = Path.Combine(Path.GetTempPath(), AppFolderName);
        }

        return Path.Combine(local, AppFolderName);
    }

    private static string? DefaultSeedDirectory()
    {
        // Allows a package to point at a read-only bundled copy without MyVpn guessing.
        var configured = Environment.GetEnvironmentVariable("MYVPN_GEO_SEED");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        // A core unpacked next to the application ships geo data alongside its binary.
        var beside = Path.Combine(AppContext.BaseDirectory, "xray");
        return Directory.Exists(beside) ? beside : null;
    }
}

/// <summary>
/// Writes files atomically.
/// </summary>
/// <remarks>
/// A half-written configuration is worse than a missing one: the core fails to parse it and
/// reports a syntax error at a line the user never wrote. Staging to a temporary file on the same
/// filesystem and renaming into place means a reader sees either the old file or the new one,
/// never a mixture — and rename is atomic on POSIX and on Windows.
/// </remarks>
public sealed class AtomicConfigFileStore : IConfigFileStore
{
    public async Task<Result> WriteAtomicAsync(
        string path,
        string content,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(content);

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // The temporary file must be a sibling: a rename across filesystems is a copy, which
            // is neither atomic nor safe against a crash mid-write.
            var temp = path + ".tmp";

            await File.WriteAllTextAsync(temp, content, cancellationToken).ConfigureAwait(false);

            // Restrict the config before it becomes readable under its final name: it contains
            // server addresses and credentials.
            TryRestrictPermissions(temp);

            File.Move(temp, path, overwrite: true);
            return Result.Ok();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.ConfigWriteFailed,
                "error.config.write_failed",
                ErrorSeverity.Error,
                $"Could not write '{path}': {ex.Message}"));
        }
    }

    public async Task<Result<string>> ReadAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var content = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            return Result<string>.Ok(content);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<string>.Fail(new MyVpnError(
                ErrorCodes.ConfigWriteFailed, "error.config.file_missing", ErrorSeverity.Error,
                $"Could not read '{path}': {ex.Message}"));
        }
    }

    public Task<Result> DeleteAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return Task.FromResult(Result.Ok());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(Result.Fail(new MyVpnError(
                ErrorCodes.ConfigWriteFailed, "error.config.write_failed", ErrorSeverity.Warning,
                $"Could not delete '{path}': {ex.Message}")));
        }
    }

    public bool Exists(string path) => File.Exists(path);

    private static void TryRestrictPermissions(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows ACLs are inherited from the per-user profile directory; no change needed.
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best effort: the file still lives under the user's own data directory.
        }
    }
}
