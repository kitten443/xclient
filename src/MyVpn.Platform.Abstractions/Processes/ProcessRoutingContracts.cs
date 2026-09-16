using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;

namespace MyVpn.Platform.Abstractions.Processes;

/// <summary>A running process as reported to the UI.</summary>
public sealed record ProcessDescriptor
{
    public required int ProcessId { get; init; }

    /// <summary>Bare executable name, e.g. <c>firefox.exe</c>.</summary>
    public required string ExecutableName { get; init; }

    /// <summary>Absolute path to the executable, when it can be determined.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Owning user, when it can be determined.</summary>
    public string? UserName { get; init; }

    public int? ParentProcessId { get; init; }

    /// <summary>Localization key or literal window title, when available.</summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// True when the path could not be read. This is expected for protected or system
    /// processes on Windows and macOS, and it must be surfaced rather than hidden: a
    /// routing rule cannot be applied to a process we cannot identify.
    /// </summary>
    public bool IsIdentityUnavailable { get; init; }
}

/// <summary>How the platform can actually enforce per-process routing.</summary>
public enum ProcessRoutingCapability
{
    /// <summary>No per-process routing at all.</summary>
    Unsupported = 0,

    /// <summary>
    /// Processes can only be permitted or blocked, not steered into the tunnel. Windows
    /// without a kernel callout driver is in this category: WFP's <c>ALE_APP_ID</c> can
    /// drop an application's traffic, but redirecting it requires
    /// <c>ALE_CONNECT_REDIRECT</c>, which is kernel-mode only.
    /// </summary>
    BlockOnly = 1,

    /// <summary>
    /// Full redirection into the tunnel is available. Linux with cgroups v2 plus policy
    /// routing is in this category.
    /// </summary>
    FullRedirect = 2,

    /// <summary>
    /// Only coarse, user-identifier-based blocking is available; per-application
    /// redirection is not. macOS is in this category: PF's <c>user</c>/<c>group</c> are
    /// match criteria, not routing decisions, and <c>NEAppRule</c> is read-only to the
    /// provider.
    /// </summary>
    UidBlockList = 3,
}

/// <summary>A resolved process selector, ready to be written into platform rules.</summary>
public sealed record ResolvedProcessSelector
{
    public required ProcessSelectorKind Kind { get; init; }

    public string? ExecutableName { get; init; }

    public string? AbsolutePath { get; init; }

    public bool IncludeChildren { get; init; }

    /// <summary>True to route through the tunnel; false to bypass it.</summary>
    public required bool ThroughTunnel { get; init; }
}

/// <summary>
/// The process-routing configuration as data, plus the capability that will enforce it.
/// </summary>
/// <remarks>
/// <see cref="Enforceable"/> is recorded explicitly so that the UI can tell the user the
/// truth: on a platform where only blocking is possible, selecting "route Firefox through
/// the VPN" must produce a clear statement of what will actually happen rather than a
/// silent no-op.
/// </remarks>
public sealed record ProcessRoutingPlan
{
    public required ProcessRoutingMode Mode { get; init; }

    public required ProcessRoutingCapability Capability { get; init; }

    public required IReadOnlyList<ResolvedProcessSelector> Selectors { get; init; }

    public bool TrackChildren { get; init; } = true;

    /// <summary>True when this plan can be enforced as requested on this platform.</summary>
    public required bool Enforceable { get; init; }

    /// <summary>Localization key explaining any reduction from what was requested.</summary>
    public string? DowngradeReasonKey { get; init; }

    /// <summary>cgroup v2 slice path (Linux); <c>null</c> elsewhere.</summary>
    public string? CgroupPath { get; init; }

    public int FirewallMark { get; init; } = 0x0CA6C;

    public int RoutingTableId { get; init; } = 100;

    public Result Validate()
    {
        if (Mode == ProcessRoutingMode.Off)
        {
            return Result.Ok();
        }

        if (Selectors.Count == 0)
        {
            return Result.Fail(ErrorCodes.ProcessRoutingUnsupported, "error.process.mode_without_selection");
        }

        if (!Enforceable)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.ProcessRoutingUnsupported,
                DowngradeReasonKey ?? "error.process.unsupported_on_platform",
                ErrorSeverity.Warning,
                $"Capability is {Capability}; the requested mode {Mode} cannot be enforced as specified."));
        }

        foreach (var selector in Selectors)
        {
            if (selector.Kind is ProcessSelectorKind.ExecutablePath or ProcessSelectorKind.Directory
                && (selector.AbsolutePath is null || !Path.IsPathRooted(selector.AbsolutePath)))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.ProcessRoutingUnsupported,
                    "error.process.path_not_absolute",
                    ErrorSeverity.Error,
                    "Process selectors must use absolute paths; a bare name can be satisfied by a "
                    + "copy of the binary placed anywhere on disk."));
            }
        }

        return Result.Ok();
    }
}

public interface IProcessRouter
{
    ProcessRoutingCapability Capability { get; }

    /// <summary>Enumerates processes for the picker UI.</summary>
    Task<IReadOnlyList<ProcessDescriptor>> EnumerateAsync(CancellationToken cancellationToken);

    Task<Result> ApplyAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken);

    Task<Result> RemoveAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken);
}
