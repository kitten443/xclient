using System.Globalization;
using System.Text;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Linux.ProcessRouting;

/// <summary>
/// The small slice of file-system behaviour the cgroup manager needs.
/// </summary>
/// <remarks>
/// cgroupfs is a file system, not an ioctl interface: creating a cgroup is <c>mkdir</c>, moving a
/// process in is a write to <c>cgroup.procs</c>, and destroying it is <c>rmdir</c>. Behind this
/// interface those operations can be pointed at an ordinary directory in a unit test, which is what
/// makes the manager testable on a machine where the test process is not root and the real cgroup
/// root is read-only.
/// </remarks>
public interface ICgroupV2FileSystem
{
    bool FileExists(string path);

    bool DirectoryExists(string path);

    void CreateDirectory(string path);

    void DeleteDirectory(string path);

    string ReadAllText(string path);

    void WriteAllText(string path, string contents);
}

/// <summary>The real cgroupfs / procfs implementation.</summary>
public sealed class PhysicalCgroupV2FileSystem : ICgroupV2FileSystem
{
    public bool FileExists(string path) => File.Exists(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public void DeleteDirectory(string path) => Directory.Delete(path);

    public string ReadAllText(string path) => File.ReadAllText(path);

    public void WriteAllText(string path, string contents) => File.WriteAllText(path, contents);
}

/// <summary>A mounted cgroup v2 (unified) hierarchy.</summary>
/// <param name="Root">Mount point, normally <c>/sys/fs/cgroup</c>.</param>
public sealed record CgroupV2Mount(string Root);

/// <summary>A cgroup directory MyVpn owns.</summary>
/// <param name="Name">Path relative to the cgroup root, e.g. <c>myvpn.slice</c>.</param>
/// <param name="Path">Absolute path, e.g. <c>/sys/fs/cgroup/myvpn.slice</c>.</param>
/// <param name="Created">
/// True when this call created the directory. Used so a failed apply removes only what it made, and
/// never destroys a slice an already-installed ruleset is matching against.
/// </param>
public sealed record CgroupSlice(string Name, string Path, bool Created);

/// <summary>The nftables match that identifies a slice's sockets.</summary>
/// <param name="Level">Ancestor level: 1 is the first path component under the cgroup root.</param>
/// <param name="Component">The path component that level must equal.</param>
/// <remarks>
/// <c>socket cgroupv2 level N "component"</c> matches the <b>Nth path component</b> of the socket's
/// cgroup, so level 1 with a top-level slice matches that slice's entire subtree — and keeps matching
/// it as children are created beneath it. That is the property this whole feature rests on.
/// </remarks>
public sealed record CgroupMatch(int Level, string Component)
{
    /// <summary>Renders the match as it must appear inside an nftables rule.</summary>
    public string RenderNft() =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"socket cgroupv2 level {Level} \"{Escape(Component)}\"");

    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
             .Replace("\"", "\\\"", StringComparison.Ordinal)
             .Replace("\n", string.Empty, StringComparison.Ordinal)
             .Replace("\r", string.Empty, StringComparison.Ordinal);
}

/// <summary>
/// Creates and manages the cgroup v2 slice that selects processes for routing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a cgroup at all.</b> nftables can match a socket's cgroup (<c>socket cgroupv2</c>), which is
/// inherited across <c>fork</c>/<c>exec</c> and covers every thread of a process. Selection by cgroup
/// is therefore the only Linux mechanism that can attach a routing decision to an arbitrary
/// third-party application without modifying it (see <c>docs/research/07-linux-networking.md</c> §2.3).
/// </para>
/// <para>
/// <b>The staleness hazard, and how it is handled.</b> The match resolves the slice to a numeric
/// cgroup ID when the ruleset is loaded; it does not re-resolve a path at packet time. A ruleset for a
/// cgroup that does not exist yet is rejected outright, and if the cgroup is destroyed and re-created
/// it receives a <i>new</i> ID and the installed rules silently stop matching. Two consequences
/// follow, and both are load-bearing:
/// </para>
/// <list type="number">
/// <item><description>
/// <see cref="EnsureSlice"/> never deletes and re-creates an existing slice. Re-creating it would
/// invalidate whatever the kernel is currently matching against.
/// </description></item>
/// <item><description>
/// The caller must re-apply the ruleset after any event that can recreate the slice — a restart, a
/// fresh boot, or systemd replacing the cgroup — and re-run the membership pass after the selected
/// applications are (re)started. <c>CgroupV2ProcessRouter.ApplyAsync</c> is idempotent for exactly
/// that reason.
/// </description></item>
/// </list>
/// <para>
/// <b>Privilege.</b> Creating <c>/sys/fs/cgroup/myvpn.slice</c> requires write access to the cgroup
/// root, which is root-owned. Controller delegation is <i>not</i> what is needed here — a plain
/// directory and its <c>cgroup.procs</c> are — but an unprivileged client still cannot create one
/// there, which is one of the reasons this feature belongs to the privileged helper.
/// </para>
/// </remarks>
public sealed class CgroupV2Manager
{
    /// <summary>Where a unified hierarchy is normally mounted.</summary>
    public const string DefaultMountPoint = "/sys/fs/cgroup";

    /// <summary>Mount table used to detect the unified hierarchy.</summary>
    public const string DefaultMountInfoPath = "/proc/self/mountinfo";

    /// <summary>Slice holding processes that must use the tunnel.</summary>
    public const string DefaultSliceName = "myvpn.slice";

    /// <summary>
    /// Joins paths inside the cgroup2 virtual filesystem.
    /// </summary>
    /// <remarks>
    /// These are not host paths. Every access goes through the file-system abstraction whose keys are
    /// Linux paths on whatever operating system this code is compiled and unit-tested on, and the
    /// separator in that namespace is always <c>/</c>. <c>Path.Combine</c>
    /// would inject the host's separator, which is <c>/</c> on Linux only by accident — the tests that
    /// exercise this class on a Windows runner proved that by reporting every path as missing.
    /// </remarks>
    private static string Join(string left, string right) => left.TrimEnd('/') + '/' + right;

    /// <summary>Slice holding processes that must bypass the tunnel.</summary>
    public const string BypassSliceName = "myvpn-bypass.slice";

    private const string ControllersFileName = "cgroup.controllers";
    private const string ProcsFileName = "cgroup.procs";

    private readonly ICgroupV2FileSystem _fileSystem;
    private readonly string _mountInfoPath;

    public CgroupV2Manager(
        ICgroupV2FileSystem? fileSystem = null,
        string mountInfoPath = DefaultMountInfoPath)
    {
        _fileSystem = fileSystem ?? new PhysicalCgroupV2FileSystem();
        _mountInfoPath = mountInfoPath;
    }

    /// <summary>
    /// Detects a mounted cgroup v2 unified hierarchy.
    /// </summary>
    /// <remarks>
    /// <c>/sys/fs/cgroup/cgroup.controllers</c> existing is the kernel documentation's own test for
    /// "cgroup v2 is in use": the file exists on the root of a unified hierarchy and nowhere in a
    /// cgroup v1 world. A host booted with <c>systemd.unified_cgroup_hierarchy=0</c>, or a kernel
    /// older than 4.5, has no cgroup2 mount at all and is reported as unsupported rather than being
    /// handed a ruleset that can never match.
    /// </remarks>
    public Result<CgroupV2Mount> Detect()
    {
        string mountInfo;

        try
        {
            mountInfo = _fileSystem.ReadAllText(_mountInfoPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<CgroupV2Mount>.Fail(CgroupV2Missing(
                $"'{_mountInfoPath}' could not be read: {ex.Message}"));
        }

        var root = FindCgroup2MountPoint(mountInfo);

        if (root is null)
        {
            return Result<CgroupV2Mount>.Fail(CgroupV2Missing(
                $"no cgroup2 entry was found in '{_mountInfoPath}'. A unified cgroup v2 hierarchy is "
                + "required for 'socket cgroupv2' matching; this host is using cgroup v1 or has none."));
        }

        if (!_fileSystem.FileExists(Join(root, ControllersFileName)))
        {
            return Result<CgroupV2Mount>.Fail(new MyVpnError(
                ErrorCodes.ProcessRoutingUnsupported,
                "error.process.cgroup_v2_not_unified",
                ErrorSeverity.Error,
                $"cgroup2 is mounted at '{root}' but '{ControllersFileName}' is absent, so this is not "
                + "the unified hierarchy root the nftables match needs.",
                "platform.enable_cgroup_v2"));
        }

        return Result<CgroupV2Mount>.Ok(new CgroupV2Mount(root));
    }

    /// <summary>
    /// Creates the slice if it does not exist and returns it.
    /// </summary>
    /// <remarks>
    /// Idempotent by design, and deliberately non-destructive: an existing slice is returned
    /// untouched. Deleting and re-creating it would change its cgroup ID and silently invalidate any
    /// ruleset already loaded against it.
    /// </remarks>
    public Result<CgroupSlice> EnsureSlice(string sliceName)
    {
        var mount = Detect();
        if (mount.IsFailure)
        {
            return Result<CgroupSlice>.Fail(mount.Error!);
        }

        var relative = NormalizeRelativePath(sliceName);
        if (relative.IsFailure)
        {
            return Result<CgroupSlice>.Fail(relative.Error!);
        }

        var full = Join(mount.Value.Root, relative.Value);
        var procs = Join(full, ProcsFileName);

        if (_fileSystem.DirectoryExists(full) && _fileSystem.FileExists(procs))
        {
            return Result<CgroupSlice>.Ok(new CgroupSlice(relative.Value, full, Created: false));
        }

        try
        {
            _fileSystem.CreateDirectory(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<CgroupSlice>.Fail(CreateFailed(full, relative.Value, ex.Message));
        }

        if (!_fileSystem.FileExists(procs))
        {
            // A directory that is not a cgroup: this happens when the mount point is not really a
            // unified hierarchy, or when something else owns the name. Reporting it now is what stops
            // a ruleset from being installed that could never resolve.
            return Result<CgroupSlice>.Fail(CreateFailed(full, relative.Value, $"'{procs}' did not appear"));
        }

        return Result<CgroupSlice>.Ok(new CgroupSlice(relative.Value, full, Created: true));
    }

    /// <summary>
    /// Moves thread groups into the slice by writing their TGIDs to <c>cgroup.procs</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Writing a PID moves the whole thread group, so a multi-threaded application is covered by one
    /// write. A process that exits between enumeration and the write is normal and is skipped;
    /// anything else is reported.
    /// </para>
    /// <para>
    /// <b>Existing sockets keep their old cgroup.</b> The nftables match is evaluated per socket
    /// against the cgroup the socket was created in, so a process moved after it already opened
    /// connections keeps those connections on the old route until they are re-established. Launching
    /// the application inside the slice (<c>systemd-run --slice=</c>) avoids that window entirely and
    /// is the preferred way to place a process; this method exists for processes already running.
    /// </para>
    /// </remarks>
    public Result<int> MoveProcesses(string sliceName, IEnumerable<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);

        var mount = Detect();
        if (mount.IsFailure)
        {
            return Result<int>.Fail(mount.Error!);
        }

        var relative = NormalizeRelativePath(sliceName);
        if (relative.IsFailure)
        {
            return Result<int>.Fail(relative.Error!);
        }

        var procs = Join(Join(mount.Value.Root, relative.Value), ProcsFileName);
        if (!_fileSystem.FileExists(procs))
        {
            return Result<int>.Fail(JoinFailed(relative.Value, $"'{procs}' does not exist"));
        }

        var moved = 0;

        foreach (var pid in processIds)
        {
            // PID 1 owns every other process on the host; moving it into the slice would route the
            // entire machine, and PID 0 is not a process at all.
            if (pid <= 1)
            {
                continue;
            }

            var written = TryWrite(rootProcs: procs, pid, out var detail);

            if (written is null)
            {
                return Result<int>.Fail(JoinFailed(relative.Value, detail!));
            }

            if (written.Value)
            {
                moved++;
            }
        }

        return Result<int>.Ok(moved);
    }

    /// <summary>Reads the PIDs currently in the slice; an absent slice reads as empty.</summary>
    public Result<IReadOnlyList<int>> ReadMemberPids(string sliceName)
    {
        var mount = Detect();
        if (mount.IsFailure)
        {
            return Result<IReadOnlyList<int>>.Fail(mount.Error!);
        }

        var relative = NormalizeRelativePath(sliceName);
        if (relative.IsFailure)
        {
            return Result<IReadOnlyList<int>>.Fail(relative.Error!);
        }

        var procs = Join(Join(mount.Value.Root, relative.Value), ProcsFileName);
        if (!_fileSystem.FileExists(procs))
        {
            return Result<IReadOnlyList<int>>.Ok(Array.Empty<int>());
        }

        try
        {
            var pids = new List<int>();

            foreach (var token in _fileSystem.ReadAllText(procs)
                         .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                {
                    pids.Add(pid);
                }
            }

            return Result<IReadOnlyList<int>>.Ok(pids);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<IReadOnlyList<int>>.Fail(MembersUnreadable(relative.Value, ex.Message));
        }
    }

    /// <summary>
    /// Moves the slice's members back to the cgroup root, which is the "release" operation: a process
    /// in the root cgroup matches no slice and therefore no marking rule.
    /// </summary>
    public Result<int> ReleaseMembers(string sliceName)
    {
        var mount = Detect();
        if (mount.IsFailure)
        {
            return Result<int>.Fail(mount.Error!);
        }

        var relative = NormalizeRelativePath(sliceName);
        if (relative.IsFailure)
        {
            return Result<int>.Fail(relative.Error!);
        }

        return ReleaseMembers(mount.Value, relative.Value);
    }

    /// <summary>
    /// Moves every member of the slice back to the cgroup root and deletes the slice.
    /// </summary>
    /// <remarks>
    /// Idempotent: removing a slice that was never created succeeds — including on a host with no
    /// unified hierarchy at all, where nothing could have been applied in the first place. Members are
    /// released before the directory is removed because a populated cgroup cannot be removed at all.
    /// </remarks>
    public Result RemoveSlice(string sliceName)
    {
        var mount = Detect();
        if (mount.IsFailure)
        {
            // There is no hierarchy to remove anything from, so the desired end state already holds.
            // Reporting a failure here would make teardown and crash recovery fail on exactly the
            // hosts where there is nothing to clean up.
            return Result.Ok();
        }

        var relative = NormalizeRelativePath(sliceName);
        if (relative.IsFailure)
        {
            return Result.Fail(relative.Error!);
        }

        var full = Join(mount.Value.Root, relative.Value);

        if (!_fileSystem.DirectoryExists(full))
        {
            // Never applied, or already removed: nothing to do, and saying so keeps teardown and
            // crash recovery from reporting a false failure.
            return Result.Ok();
        }

        var released = ReleaseMembers(mount.Value, relative.Value);
        if (released.IsFailure)
        {
            return Result.Fail(released.Error!);
        }

        try
        {
            _fileSystem.DeleteDirectory(full);
            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return IsAlreadyGone(ex.Message)
                ? Result.Ok()
                : Result.Fail(RemoveFailed(relative.Value, ex.Message));
        }
    }

    /// <summary>
    /// Converts a slice path into the nftables match that selects it.
    /// </summary>
    /// <remarks>
    /// The level is the number of path components and the component is the last one, because
    /// <c>level N</c> compares the socket's Nth component. A single-component slice (the shape MyVpn
    /// creates, e.g. <c>myvpn.slice</c>) matches at level 1, which is the whole subtree and is
    /// unambiguous. A nested path matches at its depth, where the component must be unique among
    /// siblings at that level: <c>level 2 "apps.slice"</c> also matches <c>other.slice/apps.slice</c>.
    /// MyVpn therefore keeps its slices directly under the cgroup root.
    /// </remarks>
    public static CgroupMatch ResolveMatch(string sliceName)
    {
        var relative = NormalizeRelativePath(sliceName);

        if (relative.IsFailure)
        {
            throw new ArgumentException(
                relative.Error!.TechnicalDetail ?? relative.Error.MessageKey,
                nameof(sliceName));
        }

        var components = relative.Value.Split('/', StringSplitOptions.RemoveEmptyEntries);

        return new CgroupMatch(components.Length, components[^1]);
    }

    /// <summary>
    /// Validates and normalizes a slice path supplied by settings.
    /// </summary>
    /// <remarks>
    /// The value reaches an nftables string and a file-system path, so it is constrained here rather
    /// than trusted: no absolute paths other than under the cgroup root, no <c>..</c>, and only
    /// characters that occur in systemd unit names. The renderer escapes as well; this is the second,
    /// earlier line of defence.
    /// </remarks>
    public static Result<string> NormalizeRelativePath(string? sliceName)
    {
        var value = string.IsNullOrWhiteSpace(sliceName) ? DefaultSliceName : sliceName.Trim();

        if (value.StartsWith(DefaultMountPoint + "/", StringComparison.Ordinal))
        {
            // A plan may legitimately carry the absolute path it was shown in the UI.
            value = value[(DefaultMountPoint.Length + 1)..];
        }

        value = value.Trim('/');

        if (value.Length == 0 || value.Length > 255)
        {
            return Result<string>.Fail(PathInvalid(sliceName, "it is empty or implausibly long"));
        }

        var components = value.Split('/', StringSplitOptions.RemoveEmptyEntries);

        foreach (var component in components)
        {
            if (component is "." or "..")
            {
                return Result<string>.Fail(PathInvalid(sliceName, "it contains a relative path component"));
            }

            if (!component.All(IsAllowedSliceCharacter))
            {
                return Result<string>.Fail(PathInvalid(
                    sliceName,
                    $"the component '{component}' contains characters that are not valid in a cgroup name"));
            }
        }

        return Result<string>.Ok(string.Join('/', components));
    }

    /// <summary>True when a slice name is structurally acceptable.</summary>
    public static bool IsValidPath(string? sliceName) => NormalizeRelativePath(sliceName).IsSuccess;

    // ------------------------------------------------------------------ internals

    private Result<int> ReleaseMembers(CgroupV2Mount mount, string relative)
    {
        var members = ReadMemberPids(relative);
        if (members.IsFailure)
        {
            return Result<int>.Fail(members.Error!);
        }

        if (members.Value.Count == 0)
        {
            return Result<int>.Ok(0);
        }

        var rootProcs = Join(mount.Root, ProcsFileName);
        var released = 0;

        foreach (var pid in members.Value)
        {
            if (pid <= 1)
            {
                continue;
            }

            var written = TryWrite(rootProcs, pid, out var detail);

            if (written is null)
            {
                return Result<int>.Fail(ReleaseFailed(relative, detail!));
            }

            if (written.Value)
            {
                released++;
            }
        }

        if (released == 0)
        {
            // Nothing could be released: the cgroup is still populated and rmdir would fail.
            return Result<int>.Fail(ReleaseFailed(
                relative,
                "no member process could be moved back to the root cgroup"));
        }

        return Result<int>.Ok(released);
    }

    /// <summary>
    /// Writes one PID, mapping "the process is already gone" to <c>false</c> and a real refusal to
    /// <c>null</c> with a detail string.
    /// </summary>
    private bool? TryWrite(string rootProcs, int pid, out string? detail)
    {
        detail = null;

        try
        {
            _fileSystem.WriteAllText(rootProcs, pid.ToString(CultureInfo.InvariantCulture) + "\n");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (IsNoSuchProcess(ex.Message))
            {
                // The process exited while we were working: the kernel has already removed it from
                // whatever cgroup it was in, so this is the desired end state, not a failure.
                return false;
            }

            detail = $"pid {pid}: {ex.Message}";
            return null;
        }
    }

    /// <summary>
    /// Extracts the cgroup2 mount point from <c>mountinfo</c>.
    /// </summary>
    /// <remarks>
    /// A mountinfo line is
    /// <c>36 25 0:32 / /sys/fs/cgroup rw,... - cgroup2 cgroup2 rw,nsdelegate</c>: the fifth field is
    /// the mount point and the file-system type follows the space-delimited <c>-</c> separator. The
    /// optional-fields section can contain dashes of its own, so the separator is located as a token
    /// rather than by splitting on the first dash.
    /// </remarks>
    private static string? FindCgroup2MountPoint(string mountInfo)
    {
        foreach (var line in mountInfo.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(" - ", StringComparison.Ordinal);
            if (separator < 0)
            {
                continue;
            }

            var fields = line[..separator].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 5)
            {
                continue;
            }

            var rest = line[(separator + 3)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (rest.Length == 0 || !string.Equals(rest[0], "cgroup2", StringComparison.Ordinal))
            {
                continue;
            }

            return UnescapeMountField(fields[4]);
        }

        return null;
    }

    /// <summary>mountinfo escapes space, tab, newline and backslash as octal.</summary>
    private static string UnescapeMountField(string value)
    {
        if (!value.Contains('\\'))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        var index = 0;

        while (index < value.Length)
        {
            if (value[index] == '\\' && index + 3 < value.Length
                && int.TryParse(
                    value.AsSpan(index + 1, 3),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var code))
            {
                builder.Append((char)code);
                index += 4;
                continue;
            }

            builder.Append(value[index]);
            index++;
        }

        return builder.ToString();
    }

    private static bool IsAllowedSliceCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or '@' or ':';

    private static bool IsNoSuchProcess(string message) =>
        message.Contains("No such process", StringComparison.OrdinalIgnoreCase);

    private static bool IsAlreadyGone(string message) =>
        IsNoSuchProcess(message)
        || message.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase);

    private static MyVpnError CgroupV2Missing(string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_v2_missing",
            ErrorSeverity.Error,
            "Per-process routing on Linux needs a mounted cgroup v2 (unified) hierarchy, and none was "
            + "found. " + detail,
            "platform.enable_cgroup_v2");

    private static MyVpnError CreateFailed(string path, string slice, string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_create_failed",
            ErrorSeverity.Error,
            $"'{path}' could not be created as a cgroup: {detail}. Creating a slice under the cgroup "
            + "root requires the privileged helper.",
            "privilege.install_helper")
        .WithArg("slice", slice);

    private static MyVpnError JoinFailed(string slice, string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_join_failed",
            ErrorSeverity.Error,
            $"A process could not be moved into '{slice}': {detail}",
            "privilege.install_helper")
        .WithArg("slice", slice);

    private static MyVpnError MembersUnreadable(string slice, string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_members_unreadable",
            ErrorSeverity.Error,
            $"The members of the cgroup slice '{slice}' could not be read: {detail}",
            "network.restore")
        .WithArg("slice", slice);

    private static MyVpnError ReleaseFailed(string slice, string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_release_failed",
            ErrorSeverity.Error,
            $"A process could not be moved out of '{slice}': {detail}",
            "network.restore")
        .WithArg("slice", slice);

    private static MyVpnError RemoveFailed(string slice, string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroup_remove_failed",
            ErrorSeverity.Error,
            $"The cgroup slice '{slice}' could not be removed: {detail}",
            "network.restore")
        .WithArg("slice", slice);

    private static MyVpnError PathInvalid(string? slice, string detail) =>
        new MyVpnError(
            ErrorCodes.InvalidArgument,
            "error.process.cgroup_path_invalid",
            ErrorSeverity.Error,
            $"'{slice}' is not a usable cgroup slice path: {detail}.",
            "process.reconfigure")
        .WithArg("path", slice ?? string.Empty);
}
