using System.Diagnostics;
using MyVpn.Core.Domain;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;

namespace MyVpn.Platform.Abstractions.Platform;

/// <summary>
/// Reports that no privileged helper is available.
/// </summary>
/// <remarks>
/// The helper service is not implemented yet (see ADR-0005 for the design). Reporting that
/// honestly is the point: an <see cref="IPrivilegedHost"/> that silently pretended to install
/// something would leave the user believing the Kill Switch could be armed when it cannot.
/// </remarks>
public sealed class UnavailablePrivilegedHost : IPrivilegedHost
{
    public Task<PrivilegeStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new PrivilegeStatus
        {
            IsElevated = false,
            HelperAvailable = false,
            HelperVersion = null,
            ErrorCode = ErrorCodes.PrivilegeHelperNotInstalled,
            MessageKey = "error.killswitch.needs_privileges",
            RemediationKey = "privilege.install_helper",
        });

    public Task<Result> InstallAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Result.Fail(NotImplemented()));

    public Task<Result> UninstallAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Result.Fail(NotImplemented()));

    private static MyVpnError NotImplemented() =>
        new MyVpnError(
            ErrorCodes.PrivilegeHelperNotInstalled,
            "error.platform.unsupported",
            ErrorSeverity.Error,
            "The privileged helper service is designed but not implemented in this build. "
            + "See ADR-0005; until it exists, operations that need elevation must be run by a "
            + "process that already has it.",
            "privilege.install_helper");
}

/// <summary>
/// Process enumeration shared by the platform layers.
/// </summary>
/// <remarks>
/// <para>
/// Enumeration is genuinely portable, so it is implemented once. <b>Enforcement is not
/// implemented on any platform</b>, and <see cref="ApplyAsync"/> says so rather than failing
/// silently — the honest capability matrix in ADR-0007 explains why each platform is limited, and
/// a router that accepted a plan and did nothing would be far worse than one that refuses.
/// </para>
/// <para>
/// <see cref="Capability"/> describes what the <i>operating system</i> can do, not what this
/// build does. The distinction matters for the UI: it should be able to tell the user "this is
/// not possible here" separately from "this is not built yet".
/// </para>
/// </remarks>
public abstract class ProcessRouterBase : IProcessRouter
{
    protected ProcessRouterBase(ProcessRoutingCapability capability) => Capability = capability;

    public ProcessRoutingCapability Capability { get; }

    public Task<IReadOnlyList<ProcessDescriptor>> EnumerateAsync(CancellationToken cancellationToken)
    {
        var descriptors = new List<ProcessDescriptor>();

        foreach (var process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var path = TryGetPath(process);

                descriptors.Add(new ProcessDescriptor
                {
                    ProcessId = process.Id,
                    ExecutableName = SafeName(process),
                    ExecutablePath = path,
                    DisplayName = TryGetTitle(process),

                    // A process whose path cannot be read is reported as such rather than
                    // dropped or guessed at: on Windows and macOS this is normal for protected
                    // and system processes, and a routing rule cannot be built from an unknown
                    // identity.
                    IsIdentityUnavailable = path is null,
                });
            }
            catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
            {
                // The process exited between enumeration and inspection. Skipping it is correct.
            }
            finally
            {
                process.Dispose();
            }
        }

        return Task.FromResult<IReadOnlyList<ProcessDescriptor>>(descriptors);
    }

    public Task<Result> ApplyAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Task.FromResult(validation);
        }

        return Task.FromResult(Result.Fail(new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.unsupported_on_platform",
            ErrorSeverity.Error,
            $"Per-process routing is not implemented in this build. The platform capability is "
            + $"{Capability}; see ADR-0007 for what that permits and how it would be enforced.",
            "diagnostics.run")));
    }

    public Task<Result> RemoveAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken) =>
        // Removing what was never applied is genuinely a no-op, and saying so keeps teardown and
        // emergency cleanup from reporting a false failure.
        Task.FromResult(Result.Ok());

    private static string SafeName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            return string.Empty;
        }
    }

    private static string? TryGetPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException
                                      or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? TryGetTitle(Process process)
    {
        try
        {
            return string.IsNullOrWhiteSpace(process.MainWindowTitle) ? null : process.MainWindowTitle;
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }
}
