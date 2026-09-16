using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Processes;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;

namespace MyVpn.Platform.Abstractions.Platform;

public enum PlatformKind
{
    Unknown = 0,
    Windows = 1,
    Linux = 2,
    MacOS = 3,
}

/// <summary>The firewall mechanism a platform will use.</summary>
public enum KillSwitchMechanism
{
    None = 0,

    /// <summary>Windows Filtering Platform, via <c>fwpuclnt.dll</c>.</summary>
    WindowsFilteringPlatform = 1,

    /// <summary>nftables, preferred on Linux.</summary>
    Nftables = 2,

    /// <summary>iptables/ip6tables, used only when nftables is unavailable.</summary>
    IptablesLegacy = 3,

    /// <summary>PF anchors on macOS.</summary>
    PfAnchors = 4,
}

/// <summary>
/// What the current platform can actually do.
/// </summary>
/// <remarks>
/// <para>
/// This record exists so that capability limits are stated once, in code, and consumed by
/// the UI instead of being rediscovered as bug reports. The requirement "do not promise
/// functionality that is technically unreliable" is enforced here: for example macOS
/// reports <see cref="ProcessRoutingCapability.UidBlockList"/>, and Windows reports
/// <see cref="ProcessRoutingCapability.BlockOnly"/>, so neither can present itself as
/// supporting true per-application tunnelling.
/// </para>
/// <para><see cref="Limitations"/> holds localization keys, rendered verbatim in Advanced Mode.</para>
/// </remarks>
public sealed record PlatformCapabilities
{
    public required PlatformKind Kind { get; init; }

    public required bool SupportsTun { get; init; }

    public required bool RequiresElevationForTun { get; init; }

    public required KillSwitchMechanism KillSwitchMechanism { get; init; }

    /// <summary>True when the mechanism can enforce a fail-closed rule set.</summary>
    public required bool SupportsFailClosedKillSwitch { get; init; }

    /// <summary>True when the Kill Switch can survive a reboot without user interaction.</summary>
    public required bool SupportsBootPersistentKillSwitch { get; init; }

    /// <summary>True when IPv6 can be independently blocked by the Kill Switch.</summary>
    public required bool SupportsIpv6KillSwitch { get; init; }

    public required ProcessRoutingCapability ProcessRouting { get; init; }

    public required bool SupportsSystemProxy { get; init; }

    public required bool SupportsSplitDns { get; init; }

    /// <summary>True when the platform notifies DNS changes without polling.</summary>
    public required bool SupportsDnsChangeNotifications { get; init; }

    /// <summary>Localization keys describing platform limitations the user should know.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();

    /// <summary>
    /// True when the UI must describe this platform's Kill Switch as best-effort rather
    /// than guaranteed.
    /// </summary>
    /// <remarks>
    /// Set on macOS. Apple's TN3165 states that the packet filter "is not considered API"
    /// and directs developers to Network Extension instead, so an anchored PF ruleset
    /// works today but carries no compatibility guarantee. Saying so plainly is required
    /// by the project's honesty rule.
    /// </remarks>
    public bool KillSwitchIsBestEffort { get; init; }
}

/// <summary>Result of a privilege pre-flight check.</summary>
public sealed record PrivilegeStatus
{
    public required bool IsElevated { get; init; }

    /// <summary>True when a privileged helper is installed and reachable over IPC.</summary>
    public required bool HelperAvailable { get; init; }

    public required string? HelperVersion { get; init; }

    /// <summary>Capabilities the current process actually holds (Linux <c>CapEff</c>, etc.).</summary>
    public IReadOnlyList<string> HeldCapabilities { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MissingCapabilities { get; init; } = Array.Empty<string>();

    public string? ErrorCode { get; init; }

    public string? MessageKey { get; init; }

    public string? RemediationKey { get; init; }
}

/// <summary>Installation and lifecycle of the privileged helper.</summary>
public interface IPrivilegedHost
{
    Task<PrivilegeStatus> GetStatusAsync(CancellationToken cancellationToken);

    /// <summary>Installs or repairs the helper. Requires elevation and user consent.</summary>
    Task<Result> InstallAsync(CancellationToken cancellationToken);

    Task<Result> UninstallAsync(CancellationToken cancellationToken);
}

/// <summary>The TUN interface's lifecycle.</summary>
public interface ITunDeviceManager
{
    bool IsSupported { get; }

    /// <summary>Default interface name for this platform.</summary>
    string DefaultInterfaceName { get; }

    /// <summary>True when the named interface currently exists.</summary>
    Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken);

    /// <summary>Addresses currently assigned to the interface.</summary>
    Task<IReadOnlyList<string>> GetAddressesAsync(string interfaceName, CancellationToken cancellationToken);
}

/// <summary>
/// Restores the machine to a clean network state.
/// </summary>
/// <remarks>
/// This is the "Restore network" button, and it is a required feature rather than a
/// convenience: if a crash, a power loss or a bug leaves firewall rules, routes or DNS
/// in a broken state, the user must have a single action that gets them back online
/// without editing firewall rules by hand.
/// </remarks>
public interface INetworkStateManager
{
    /// <summary>
    /// Removes every MyVpn-owned artefact: Kill Switch rules, routes, DNS overrides, the
    /// TUN interface and the system proxy.
    /// </summary>
    /// <remarks>
    /// Implementations must be resilient: each step is attempted even if an earlier step
    /// failed, and the aggregate result reports what could not be cleaned. A cleanup that
    /// stops at the first error is exactly the situation the user is trying to escape.
    /// </remarks>
    Task<CleanupReport> EmergencyCleanupAsync(CancellationToken cancellationToken);

    /// <summary>Detects leftovers from a previous run, without changing anything.</summary>
    Task<NetworkLeftovers> DetectLeftoversAsync(CancellationToken cancellationToken);
}

/// <summary>The outcome of an emergency cleanup, step by step.</summary>
public sealed record CleanupReport
{
    public required bool FullyClean { get; init; }

    public IReadOnlyList<CleanupStep> Steps { get; init; } = Array.Empty<CleanupStep>();

    public static CleanupReport FromSteps(IEnumerable<CleanupStep> steps)
    {
        var list = steps.ToArray();
        return new CleanupReport
        {
            FullyClean = list.All(s => s.Succeeded),
            Steps = list,
        };
    }
}

public sealed record CleanupStep(string Name, bool Succeeded, string? DetailKey, string? TechnicalDetail);

/// <summary>Leftover network state found at startup.</summary>
public sealed record NetworkLeftovers
{
    public bool KillSwitchRulesPresent { get; init; }

    public bool TunnelInterfacePresent { get; init; }

    public bool RoutesPresent { get; init; }

    public bool DnsOverridden { get; init; }

    public bool SystemProxySet { get; init; }

    public bool CoreProcessRunning { get; init; }

    public IReadOnlyList<string> Details { get; init; } = Array.Empty<string>();

    public bool Any => KillSwitchRulesPresent || TunnelInterfacePresent || RoutesPresent
                       || DnsOverridden || SystemProxySet || CoreProcessRunning;
}

/// <summary>Everything platform-specific, resolved at runtime.</summary>
public interface IPlatformServices
{
    PlatformCapabilities Capabilities { get; }

    IPrivilegedHost PrivilegedHost { get; }

    IKillSwitch KillSwitch { get; }

    IRouteManager Routes { get; }

    IDnsConfigurator Dns { get; }

    ISystemProxy SystemProxy { get; }

    IProcessRouter ProcessRouter { get; }

    ITunDeviceManager Tun { get; }

    INetworkStateManager NetworkState { get; }

    /// <summary>Path separator used by the platform, for display and validation.</summary>
    string PathSeparator { get; }

    /// <summary>Default location for the Xray binary supplied by a package manager.</summary>
    IReadOnlyList<string> DefaultCoreSearchPaths { get; }
}
