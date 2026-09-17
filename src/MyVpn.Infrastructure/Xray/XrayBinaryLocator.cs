using MyVpn.Core.Results;

namespace MyVpn.Infrastructure.Xray;

/// <summary>Where the core binary was found.</summary>
public enum XrayBinarySource
{
    /// <summary>Not found anywhere.</summary>
    NotFound = 0,

    /// <summary>Explicitly selected by the user.</summary>
    UserSelected = 1,

    /// <summary>Bundled with the MyVpn installation.</summary>
    Bundled = 2,

    /// <summary>Found on the system PATH.</summary>
    SystemPath = 3,

    /// <summary>Found in a package-manager location.</summary>
    PackageManager = 4,
}

/// <summary>A located core binary.</summary>
public sealed record XrayBinary
{
    public required string AbsolutePath { get; init; }

    public required XrayBinarySource Source { get; init; }

    /// <summary>Directories that were searched, for diagnostics.</summary>
    public IReadOnlyList<string> SearchedPaths { get; init; } = Array.Empty<string>();

    public bool IsFound => Source != XrayBinarySource.NotFound;
}

/// <summary>
/// Locates the Xray-core binary.
/// </summary>
/// <remarks>
/// <para>
/// Existence is not sufficient. A file can be present but not executable (a tarball extracted
/// without the mode bit, a Windows download that lost its ACL, a binary quarantined by macOS
/// Gatekeeper), and the resulting failure from <see cref="System.Diagnostics.Process.Start"/> is
/// opaque. This locator therefore checks the executable bit on Unix so the user gets "the core
/// is not executable" rather than "permission denied" from deep inside the runtime.
/// </para>
/// <para>
/// The logic is pure apart from injected predicates, so every search-order branch is
/// unit-testable without installing anything.
/// </para>
/// </remarks>
public static class XrayBinaryLocator
{
    /// <summary>Binary file name for the platform.</summary>
    public static string BinaryName(bool isWindows) => isWindows ? "xray.exe" : "xray";

    /// <summary>
    /// Returns the search order as absolute directory candidates, most specific first.
    /// </summary>
    /// <remarks>
    /// The user's explicit choice always wins. The bundled copy comes next, because a client
    /// that ships a known-good core should not be silently downgraded by whatever happens to
    /// be earlier on the PATH. Package-manager locations come last.
    /// </remarks>
    public static IReadOnlyList<(string Directory, XrayBinarySource Source)> BuildSearchOrder(
        string? userSelectedPath,
        string applicationBaseDirectory,
        IReadOnlyList<string> packageManagerDirectories,
        bool isWindows)
    {
        var candidates = new List<(string, XrayBinarySource)>();

        if (!string.IsNullOrWhiteSpace(userSelectedPath))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(userSelectedPath));
            if (!string.IsNullOrEmpty(directory))
            {
                candidates.Add((directory, XrayBinarySource.UserSelected));
            }
        }

        candidates.Add((Path.Combine(applicationBaseDirectory, "xray"), XrayBinarySource.Bundled));
        candidates.Add((Path.Combine(applicationBaseDirectory, "core"), XrayBinarySource.Bundled));

        if (!isWindows)
        {
            // A package install puts the data under /usr/share and the binary in /usr/bin;
            // /usr/lib/myvpn is where a bundled core lives for an FHS-compliant build.
            candidates.Add(("/usr/lib/myvpn", XrayBinarySource.PackageManager));
            candidates.Add(("/usr/lib/xray", XrayBinarySource.PackageManager));
            candidates.Add(("/usr/local/bin", XrayBinarySource.PackageManager));
            candidates.Add(("/usr/bin", XrayBinarySource.PackageManager));
            candidates.Add(("/opt/xray", XrayBinarySource.PackageManager));
        }
        else
        {
            candidates.Add((
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Xray"),
                XrayBinarySource.PackageManager));
        }

        foreach (var directory in packageManagerDirectories)
        {
            if (!string.IsNullOrWhiteSpace(directory))
            {
                candidates.Add((directory, XrayBinarySource.PackageManager));
            }
        }

        return candidates;
    }

    /// <summary>
    /// Resolves the binary, or explains precisely why it could not.
    /// </summary>
    /// <param name="userSelectedPath">Explicit user selection, if any.</param>
    /// <param name="applicationBaseDirectory">MyVpn's own directory (usually <c>AppContext.BaseDirectory</c>).</param>
    /// <param name="packageManagerDirectories">Additional directories to consider.</param>
    /// <param name="isWindows">Platform flag; injected for testing.</param>
    /// <param name="fileExists">Existence predicate.</param>
    /// <param name="isExecutable">
    /// Executable-bit predicate. Pass <c>null</c> on platforms where the concept does not apply.
    /// </param>
    public static Result<XrayBinary> Locate(
        string? userSelectedPath,
        string applicationBaseDirectory,
        IReadOnlyList<string>? packageManagerDirectories = null,
        bool isWindows = false,
        Func<string, bool>? fileExists = null,
        Func<string, bool>? isExecutable = null)
    {
        fileExists ??= File.Exists;
        packageManagerDirectories ??= Array.Empty<string>();

        var binaryName = BinaryName(isWindows);
        var searched = new List<string>();
        var notExecutable = new List<string>();

        // An explicit selection is honoured as a FILE before anything else. The convention below --
        // take the directory, join the platform binary name -- exists to FIND a core, and applying it
        // to a path the user typed silently discards the file they chose: `--core /opt/xray/xray-26.9.9`
        // would look for /opt/xray/xray and report "no core binary at the selected path" while the
        // binary sat right there, next to it. That is the least debuggable failure a "point me at your
        // core" flag can produce, because the path in the message is the one the user just confirmed
        // exists. Falling through to the convention when the exact path is absent, or present but not
        // executable, keeps every existing behaviour intact.
        if (!string.IsNullOrWhiteSpace(userSelectedPath))
        {
            var selected = Path.GetFullPath(userSelectedPath);
            searched.Add(selected);

            if (fileExists(selected))
            {
                if (isExecutable is null || isExecutable(selected))
                {
                    return Result<XrayBinary>.Ok(new XrayBinary
                    {
                        AbsolutePath = selected,
                        Source = XrayBinarySource.UserSelected,
                        SearchedPaths = searched,
                    });
                }

                // Present but unusable. Recorded rather than returned so that the diagnostics below
                // still name it if nothing else in the search order works out.
                notExecutable.Add(selected);
            }
        }

        foreach (var (directory, source) in BuildSearchOrder(
                     userSelectedPath, applicationBaseDirectory, packageManagerDirectories, isWindows))
        {
            var path = Path.Combine(directory, binaryName);
            searched.Add(path);

            if (!fileExists(path))
            {
                continue;
            }

            if (isExecutable is not null && !isExecutable(path))
            {
                notExecutable.Add(path);
                continue;
            }

            return Result<XrayBinary>.Ok(new XrayBinary
            {
                AbsolutePath = Path.GetFullPath(path),
                Source = source,
                SearchedPaths = searched,
            });
        }

        // Report the most specific, actionable diagnosis available.
        if (notExecutable.Count > 0)
        {
            return Result<XrayBinary>.Fail(new MyVpnError(
                ErrorCodes.XrayBinaryNotExecutable,
                "error.xray.binary_not_executable",
                ErrorSeverity.Error,
                $"Found the core at {notExecutable[0]} but it is not executable. On Unix, restore "
                + "the executable bit (chmod +x); on macOS, check whether Gatekeeper quarantined it.",
                "xray.select_binary")
                .WithArg("path", notExecutable[0]));
        }

        if (!string.IsNullOrWhiteSpace(userSelectedPath))
        {
            return Result<XrayBinary>.Fail(new MyVpnError(
                ErrorCodes.XrayBinaryNotFound,
                "error.xray.binary_not_found_at_path",
                ErrorSeverity.Error,
                $"No core binary at the selected path '{userSelectedPath}' (looked for {binaryName}).",
                "xray.select_binary")
                .WithArg("path", userSelectedPath));
        }

        return Result<XrayBinary>.Fail(new MyVpnError(
            ErrorCodes.XrayBinaryNotFound,
            "error.xray.binary_not_found",
            ErrorSeverity.Error,
            $"No '{binaryName}' found. Searched: {string.Join(", ", searched)}.",
            "xray.select_binary"));
    }

    /// <summary>Reads the executable bit without following into a full file read.</summary>
    public static bool IsExecutableOnUnix(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows has no executable bit; the extension convention is all there is.
            return true;
        }

        try
        {
            var mode = File.GetUnixFileMode(path);
            const UnixFileMode executeBits =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

            return (mode & executeBits) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
