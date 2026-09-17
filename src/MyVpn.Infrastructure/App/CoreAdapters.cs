using MyVpn.Application.Abstractions;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Xray;

namespace MyVpn.Infrastructure.App;

/// <summary>
/// Adapts <see cref="XrayBinaryLocator"/> to the application-layer port.
/// </summary>
/// <remarks>
/// The indirection is not ceremony: it keeps <c>MyVpn.Application</c> free of any dependency on
/// the infrastructure assembly, so a use case can be tested with a fake locator and the search
/// order can change without touching application code.
/// </remarks>
public sealed class CoreLocatorAdapter : ICoreLocator
{
    private readonly XrayEngineManager _engine;

    public CoreLocatorAdapter(XrayEngineManager engine) =>
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));

    public Result<string> Locate(string? userSelectedPath)
    {
        var located = XrayBinaryLocator.Locate(
            userSelectedPath: userSelectedPath,
            applicationBaseDirectory: AppContext.BaseDirectory,
            packageManagerDirectories: null,
            isWindows: OperatingSystem.IsWindows(),
            fileExists: File.Exists,
            isExecutable: XrayBinaryLocator.IsExecutableOnUnix);

        return located.IsSuccess
            ? Result<string>.Ok(located.Value.AbsolutePath)
            : Result<string>.Fail(located.Error!);
    }

    public async Task<Result<string>> ProbeVersionAsync(string binaryPath, CancellationToken cancellationToken)
    {
        var probed = await _engine.ProbeVersionAsync(binaryPath, cancellationToken).ConfigureAwait(false);

        return probed.IsSuccess
            ? Result<string>.Ok(probed.Value.ToString())
            : Result<string>.Fail(probed.Error!);
    }
}

/// <summary>Adapts <see cref="XrayEngineManager"/> to the core-supervisor port.</summary>
public sealed class CoreSupervisorAdapter : ICoreSupervisor
{
    private readonly XrayEngineManager _engine;

    public CoreSupervisorAdapter(XrayEngineManager engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));

        _engine.StateChanged += (_, change) =>
            StateChanged?.Invoke(this, new CoreStateChanged(Map(change.Previous), Map(change.Current), change.Reason));
    }

    public event EventHandler<CoreStateChanged>? StateChanged;

    public CoreState State => Map(_engine.State);

    public Task<Result> StartAsync(CoreStartRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return _engine.StartAsync(new XrayStartRequest
        {
            BinaryPath = request.BinaryPath,
            ConfigPath = request.ConfigPath,
            WorkingDirectory = request.WorkingDirectory,
            AssetDirectory = request.AssetDirectory,
            Environment = request.Environment,
        }, cancellationToken);
    }

    public Task<Result> StopAsync(CancellationToken cancellationToken) => _engine.StopAsync(cancellationToken);

    public CoreStatus GetStatus()
    {
        var status = _engine.GetStatus();

        return new CoreStatus
        {
            State = Map(status.State),
            ProcessId = status.ProcessId,
            Version = status.Version?.ToString(),
            BinaryPath = status.BinaryPath,
            LastDiagnostic = status.LastDiagnostic,
            RestartCount = status.RestartCount,
        };
    }

    public IReadOnlyList<string> GetRecentOutput(int maxLines) => _engine.GetRecentOutput(maxLines);

    private static CoreState Map(XrayEngineState state) => state switch
    {
        XrayEngineState.Stopped => CoreState.Stopped,
        XrayEngineState.Starting => CoreState.Starting,
        XrayEngineState.Running => CoreState.Running,
        XrayEngineState.Stopping => CoreState.Stopping,
        XrayEngineState.RestartLoopBlocked => CoreState.RestartLoopBlocked,
        _ => CoreState.Faulted,
    };
}

/// <summary>Adapts <see cref="GeoDataManager"/> to the geo-data port.</summary>
public sealed class GeoDataProviderAdapter : IGeoDataProvider
{
    private readonly GeoDataManager _manager;

    public GeoDataProviderAdapter(GeoDataManager manager) =>
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));

    public string AssetDirectory => _manager.AssetDirectory;

    public Task<GeoDataStatus> InspectAsync(CancellationToken cancellationToken) =>
        _manager.InspectAsync(cancellationToken);

    public Task<GeoDataStatus> EnsureWorkingCopyAsync(CancellationToken cancellationToken) =>
        _manager.EnsureWorkingCopyAsync(cancellationToken);

    public IReadOnlyDictionary<string, string> BuildCoreEnvironment() => _manager.BuildXrayEnvironment();

    public Result VerifyBeforeLaunch(string executablePath) => _manager.VerifyBeforeLaunch(executablePath);

    public Task<GeoDataStatus> RepairAsync(CancellationToken cancellationToken) =>
        _manager.RepairAsync(cancellationToken);
}
