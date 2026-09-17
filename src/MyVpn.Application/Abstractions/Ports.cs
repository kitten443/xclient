using MyVpn.Core.Domain;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;

namespace MyVpn.Application.Abstractions;

/// <summary>
/// Filesystem locations the application works with.
/// </summary>
/// <remarks>
/// A port rather than a static helper because state must live in a per-user writable directory
/// while bundled assets may live in a read-only installation directory — a distinction that
/// differs per platform, per packaging format and per portable mode, and that must be injectable
/// so tests do not touch the real user profile.
/// </remarks>
public interface IAppPaths
{
    /// <summary>Root for everything MyVpn writes.</summary>
    string StateDirectory { get; }

    /// <summary>Where generated core configurations are written.</summary>
    string ConfigDirectory { get; }

    /// <summary>Where the core's own logs and MyVpn's logs go.</summary>
    string LogDirectory { get; }

    /// <summary>Writable working copy of the geo data.</summary>
    string GeoDataDirectory { get; }

    /// <summary>Previous known-good geo generation, used for rollback.</summary>
    string GeoBackupDirectory { get; }

    /// <summary>Checksum manifest for the geo data.</summary>
    string GeoManifestPath { get; }

    /// <summary>Path of the generated configuration for the active session.</summary>
    string ActiveConfigPath { get; }

    /// <summary>Read-only directory the installation ships geo data in, when it ships any.</summary>
    string? SeedGeoDataDirectory { get; }
}

/// <summary>Reads and writes files with the atomicity the caller expects.</summary>
public interface IConfigFileStore
{
    /// <summary>
    /// Writes content so that a crash or a concurrent reader never observes a partial file.
    /// </summary>
    /// <remarks>
    /// Implementations must stage to a temporary file on the same filesystem and rename into
    /// place. A half-written configuration would make the core fail to start with a parse error
    /// that points at a file the user never edited.
    /// </remarks>
    Task<Result> WriteAtomicAsync(string path, string content, CancellationToken cancellationToken);

    Task<Result<string>> ReadAsync(string path, CancellationToken cancellationToken);

    Task<Result> DeleteAsync(string path, CancellationToken cancellationToken);

    bool Exists(string path);
}

/// <summary>
/// Resolves a profile's server to addresses usable in firewall rules and diagnostics.
/// </summary>
/// <remarks>
/// Separated from config generation on purpose. A Kill Switch rule can only pin an IP address,
/// so resolution must complete <i>before</i> a default-deny ruleset is armed; when it fails, the
/// correct behaviour is to refuse to arm rather than to block the user's whole network.
/// </remarks>
public interface IServerEndpointResolver
{
    Task<Result<IReadOnlyList<ServerEndpoint>>> ResolveAsync(
        ServerProfile profile,
        CancellationToken cancellationToken);

    /// <summary>Best-effort reverse lookup for display. Never used for a security decision.</summary>
    Task<string?> DescribeAsync(ServerEndpoint endpoint, CancellationToken cancellationToken);
}

/// <summary>Evidence that traffic actually traverses the tunnel.</summary>
public sealed record ConnectionVerification
{
    /// <summary>The address the outside world saw, as reported by the check endpoint.</summary>
    public required string ExitAddress { get; init; }

    /// <summary>How the check was performed, for diagnostics.</summary>
    public required string Method { get; init; }

    public required TimeSpan Latency { get; init; }

    public DateTimeOffset VerifiedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// The host's own address before the tunnel came up, when it was measured. Equal addresses
    /// mean the traffic did not move and the tunnel is not actually carrying anything.
    /// </summary>
    public string? DirectAddress { get; init; }

    public bool ExitDiffersFromDirect =>
        DirectAddress is not null && !string.Equals(DirectAddress, ExitAddress, StringComparison.Ordinal);
}

/// <summary>
/// Performs a real request through the tunnel.
/// </summary>
/// <remarks>
/// This exists because "the core process is alive" is not evidence that anything works. In TUN
/// mode the core completes TCP handshakes locally and synthesises ICMP replies, so both
/// <c>connect()</c> and <c>ping</c> report success against a dead outbound. The only honest check
/// is to send a request through the tunnel and look at what comes back.
/// </remarks>
public interface IConnectionVerifier
{
    Task<Result<ConnectionVerification>> VerifyAsync(
        TunnelMode mode,
        ProxySettings proxySettings,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    /// <summary>Measures the host's own exit address, for comparison. Best effort.</summary>
    Task<string?> MeasureDirectAddressAsync(TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Provides a bounded health-check budget without scattering magic numbers.</summary>
public static class ConnectionDefaults
{
    public static readonly TimeSpan VerificationTimeout = TimeSpan.FromSeconds(20);

    public static readonly TimeSpan DirectAddressTimeout = TimeSpan.FromSeconds(8);
}

/// <summary>Geo data, as the application layer needs to see it.</summary>
/// <remarks>
/// The application layer must not reference the infrastructure assembly, so this narrow port
/// stands in front of the concrete manager. It exposes exactly what the connect flow needs:
/// per-asset availability (so unavailable geo rules can be omitted rather than failing the
/// connection) and the environment that must reach the core.
/// </remarks>
public interface IGeoDataProvider
{
    Task<GeoDataStatus> InspectAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Makes the exported asset directory actually contain usable assets, seeding it from the
    /// installation copy when the working copy is empty.
    /// </summary>
    /// <remarks>
    /// Inspecting and exporting must agree. Reporting an asset as usable while
    /// <c>XRAY_LOCATION_ASSET</c> points at an empty directory is the issue #9765 failure exactly:
    /// the asset is valid somewhere, and the core is told to look somewhere else.
    /// </remarks>
    Task<GeoDataStatus> EnsureWorkingCopyAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Environment variables that must be set on the core process.
    /// </summary>
    /// <remarks>
    /// Always absolute. Delivering this value is the fix for v2rayN issue #9765, where an
    /// elevated launcher dropped the environment and the core fell back to its own directory.
    /// </remarks>
    IReadOnlyDictionary<string, string> BuildCoreEnvironment();

    /// <summary>Asserts, before launch, that the core will resolve the directory we validated.</summary>
    Result VerifyBeforeLaunch(string executablePath);

    Task<GeoDataStatus> RepairAsync(CancellationToken cancellationToken);
}

public enum CoreState
{
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    RestartLoopBlocked = 4,
    Faulted = 5,
}

/// <summary>Everything needed to launch the core once.</summary>
public sealed record CoreStartRequest
{
    public required string BinaryPath { get; init; }

    public required string ConfigPath { get; init; }

    public required string WorkingDirectory { get; init; }

    /// <summary>Absolute geo asset directory, delivered as an environment variable.</summary>
    public string? AssetDirectory { get; init; }

    public IReadOnlyDictionary<string, string>? Environment { get; init; }
}

public sealed record CoreStatus
{
    public required CoreState State { get; init; }

    public int? ProcessId { get; init; }

    public string? Version { get; init; }

    public string? BinaryPath { get; init; }

    /// <summary>The core's own last words before exiting, when it produced any.</summary>
    public string? LastDiagnostic { get; init; }

    public int RestartCount { get; init; }

    public bool IsRunning => State == CoreState.Running;
}

public sealed record CoreStateChanged(CoreState Previous, CoreState Current, string Reason);

/// <summary>
/// Supervises the core process.
/// </summary>
/// <remarks>
/// Distinct from <see cref="IConnectionVerifier"/>: this reports whether the process is alive,
/// which is necessary but nowhere near sufficient. A live core with a dead outbound is the most
/// common "connected but nothing loads" report, which is why verification is a separate port.
/// </remarks>
public interface ICoreSupervisor
{
    CoreState State { get; }

    event EventHandler<CoreStateChanged>? StateChanged;

    Task<Result> StartAsync(CoreStartRequest request, CancellationToken cancellationToken);

    Task<Result> StopAsync(CancellationToken cancellationToken);

    CoreStatus GetStatus();

    IReadOnlyList<string> GetRecentOutput(int maxLines);
}

/// <summary>Finds and version-checks the core binary.</summary>
public interface ICoreLocator
{
    /// <summary>Resolves the binary, or explains precisely why it could not be found.</summary>
    Result<string> Locate(string? userSelectedPath);

    /// <summary>
    /// Checks the located binary against the version policy for the requested mode.
    /// </summary>
    Task<Result<string>> ProbeVersionAsync(string binaryPath, CancellationToken cancellationToken);
}
