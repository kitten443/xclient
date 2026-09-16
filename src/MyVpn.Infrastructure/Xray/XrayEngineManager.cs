using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Xray;

namespace MyVpn.Infrastructure.Xray;

public enum XrayEngineState
{
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,

    /// <summary>Restarts exceeded the allowed rate; the engine has given up deliberately.</summary>
    RestartLoopBlocked = 4,

    /// <summary>Start failed for a reason that is not a crash (binary missing, config rejected).</summary>
    Faulted = 5,
}

/// <summary>Everything needed to launch the core once.</summary>
public sealed record XrayStartRequest
{
    /// <summary>Absolute path to the core binary.</summary>
    public required string BinaryPath { get; init; }

    /// <summary>Absolute path to the generated configuration file.</summary>
    public required string ConfigPath { get; init; }

    /// <summary>Working directory. Must exist and be writable; Xray resolves relative paths against it.</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>
    /// Absolute geo asset directory. Injected as <c>XRAY_LOCATION_ASSET</c>.
    /// </summary>
    /// <remarks>
    /// This is the primary fix for issue #9765: the value is set explicitly on the child
    /// process rather than inherited or left to Xray's default. The core is launched by argv
    /// and never through a shell, because a shell wrapper (or an elevated launcher that resets
    /// the environment) is exactly how this variable gets lost.
    /// </remarks>
    public string? AssetDirectory { get; init; }

    /// <summary>Extra environment variables to set on the child process.</summary>
    public IReadOnlyDictionary<string, string>? Environment { get; init; }

    /// <summary>How long to wait for a graceful exit before forcing termination.</summary>
    public TimeSpan GracefulStopTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public XrayEngineOptions Options { get; init; } = new();
}

/// <summary>Supervisor policy.</summary>
public sealed record XrayEngineOptions
{
    /// <summary>Restart the core automatically after an unexpected exit.</summary>
    public bool AutoRestart { get; init; } = true;

    /// <summary>Maximum restarts permitted inside <see cref="RestartWindow"/>.</summary>
    public int MaxRestarts { get; init; } = 5;

    /// <summary>Sliding window for the restart budget.</summary>
    public TimeSpan RestartWindow { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Delay before each restart attempt.</summary>
    public TimeSpan RestartDelay { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Lines of core output retained in memory for diagnostics.</summary>
    public int OutputBufferLines { get; init; } = 2000;

    /// <summary>Run <c>xray run -test</c> before the first start.</summary>
    public bool PreflightEnabled { get; init; } = true;
}

/// <summary>A line of core output.</summary>
public sealed record XrayOutputLine(DateTimeOffset Timestamp, bool IsError, string Text);

public sealed record XrayEngineStateChanged(
    XrayEngineState Previous,
    XrayEngineState Current,
    string Reason,
    XrayStopReason? StopReason = null,
    MyVpnError? Error = null);

/// <summary>Current engine status, for the UI and diagnostics.</summary>
public sealed record XrayEngineStatus
{
    public required XrayEngineState State { get; init; }

    public int? ProcessId { get; init; }

    public XrayVersion? Version { get; init; }

    public string? BinaryPath { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public int RestartCount { get; init; }

    public string RestartLimiterSummary { get; init; } = string.Empty;

    public XrayStopReason? LastStopReason { get; init; }

    /// <summary>The core's own last words before exiting, when it produced any.</summary>
    public string? LastDiagnostic { get; init; }

    public bool IsRunning => State == XrayEngineState.Running;
}

/// <summary>
/// Supervises the Xray-core process.
/// </summary>
/// <remarks>
/// <para>Responsibilities: find and version-check the binary, pre-flight the configuration,
/// start and stop the process, capture output, detect crashes, restart within a bounded rate,
/// and report health.</para>
/// <para><b>Health checks are deliberately not ping- or connect-based.</b> With the native TUN
/// inbound the core completes TCP handshakes locally and synthesises ICMP echo replies, so both
/// <c>connect()</c> succeeding and <c>ping</c> replying are meaningless as liveness signals —
/// they stay "up" even when the outbound is dead. Process liveness plus observed output is the
/// honest signal available without a real proxied request.</para>
/// </remarks>
public sealed class XrayEngineManager : IXrayEngine, IDisposable
{
    private readonly ILogger<XrayEngineManager> _logger;
    private readonly object _gate = new();
    private readonly Queue<XrayOutputLine> _output = new();
    private readonly RestartLimiter _restartLimiter;

    private Process? _process;
    private XrayStartRequest? _lastRequest;
    private XrayEngineState _state = XrayEngineState.Stopped;
    private XrayStopReason? _lastStopReason;
    private string? _lastDiagnostic;
    private int _restartCount;
    private DateTimeOffset? _startedAt;
    private bool _stopRequested;
    private bool _disposed;
    private CancellationTokenSource? _restartCts;

    public XrayEngineManager(ILogger<XrayEngineManager> logger, XrayEngineOptions? options = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? new XrayEngineOptions();
        _restartLimiter = new RestartLimiter(Options.MaxRestarts, Options.RestartWindow);
    }

    public XrayEngineOptions Options { get; }

    public event EventHandler<XrayEngineStateChanged>? StateChanged;

    public event EventHandler<XrayOutputLine>? OutputReceived;

    public XrayEngineState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public XrayEngineStatus GetStatus()
    {
        lock (_gate)
        {
            return new XrayEngineStatus
            {
                State = _state,
                ProcessId = _process is { HasExited: false } p ? p.Id : null,
                Version = _version,
                BinaryPath = _lastRequest?.BinaryPath,
                StartedAt = _startedAt,
                RestartCount = _restartCount,
                RestartLimiterSummary = _restartLimiter.Describe(),
                LastStopReason = _lastStopReason,
                LastDiagnostic = _lastDiagnostic,
            };
        }
    }

    private XrayVersion? _version;

    public IReadOnlyList<string> GetRecentOutput(int maxLines)
    {
        lock (_gate)
        {
            return _output
                .Skip(Math.Max(0, _output.Count - maxLines))
                .Select(line => string.Format(
                    CultureInfo.InvariantCulture,
                    "[{0:HH:mm:ss}] {1}",
                    line.Timestamp,
                    line.Text))
                .ToArray();
        }
    }

    /// <summary>Runs <c>xray version</c> and parses the result.</summary>
    public async Task<Result<XrayVersion>> ProbeVersionAsync(
        string binaryPath,
        CancellationToken cancellationToken)
    {
        var result = await RunCapturedAsync(
            binaryPath,
            new[] { "version" },
            workingDirectory: null,
            environment: null,
            TimeSpan.FromSeconds(15),
            cancellationToken).ConfigureAwait(false);

        if (!result.Started)
        {
            return Result<XrayVersion>.Fail(new MyVpnError(
                ErrorCodes.XrayVersionProbeFailed,
                "error.xray.version_probe_failed",
                ErrorSeverity.Error,
                $"Could not run the core to read its version: {result.FailureDetail}",
                "xray.select_binary"));
        }

        if (!XrayVersion.TryParse(result.StandardOutput, out var version)
            && !XrayVersion.TryParse(result.StandardError, out version))
        {
            return Result<XrayVersion>.Fail(new MyVpnError(
                ErrorCodes.XrayVersionProbeFailed,
                "error.xray.version_unknown",
                ErrorSeverity.Error,
                $"Could not parse a version from the core's output: '{Truncate(result.StandardOutput)}'.",
                "xray.select_binary"));
        }

        lock (_gate)
        {
            _version = version;
        }

        return Result<XrayVersion>.Ok(version);
    }

    /// <summary>
    /// Validates a generated configuration with <c>xray run -test</c>.
    /// </summary>
    /// <remarks>
    /// Running this before the real start is what turns a silent crash loop into a single clear
    /// message. Exit code 23 means the config is rejected, and the supervisor must not retry.
    /// </remarks>
    public async Task<Result<XrayPreflightResult>> PreflightAsync(
        string binaryPath,
        string configPath,
        string? workingDirectory,
        string? assetDirectory,
        CancellationToken cancellationToken)
    {
        var environment = BuildEnvironment(assetDirectory, null);

        var result = await RunCapturedAsync(
            binaryPath,
            new[] { "run", "-test", "-c", configPath },
            workingDirectory,
            environment,
            TimeSpan.FromSeconds(30),
            cancellationToken).ConfigureAwait(false);

        if (!result.Started)
        {
            return Result<XrayPreflightResult>.Fail(new MyVpnError(
                ErrorCodes.XrayStartFailed,
                "error.xray.preflight_failed",
                ErrorSeverity.Error,
                $"Could not run the configuration pre-flight: {result.FailureDetail}"));
        }

        var interpreted = XrayTestRunInterpreter.Interpret(result.ExitCode, result.StandardError, _version);

        if (interpreted.IsValid)
        {
            _logger.LogInformation("Configuration pre-flight succeeded.");
        }
        else
        {
            _logger.LogError(
                "Configuration pre-flight failed (exit {ExitCode}, configError={IsConfigError}): {Diagnostic}",
                interpreted.ExitCode,
                interpreted.IsConfigurationError,
                interpreted.Diagnostic);
        }

        return Result<XrayPreflightResult>.Ok(interpreted);
    }

    /// <summary>Starts the core, pre-flighting the configuration first when enabled.</summary>
    public async Task<Result> StartAsync(XrayStartRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!File.Exists(request.BinaryPath))
        {
            return Fail(XrayEngineState.Faulted, new MyVpnError(
                ErrorCodes.XrayBinaryNotFound,
                "error.xray.binary_not_found",
                ErrorSeverity.Error,
                $"No core binary at '{request.BinaryPath}'."));
        }

        if (!File.Exists(request.ConfigPath))
        {
            return Fail(XrayEngineState.Faulted, new MyVpnError(
                ErrorCodes.ConfigWriteFailed,
                "error.config.file_missing",
                ErrorSeverity.Error,
                $"No configuration file at '{request.ConfigPath}'."));
        }

        // The working directory must exist, otherwise Process.Start throws Win32Exception with a
        // message that mentions neither the directory nor MyVpn.
        if (!Directory.Exists(request.WorkingDirectory))
        {
            try
            {
                Directory.CreateDirectory(request.WorkingDirectory);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Fail(XrayEngineState.Faulted, new MyVpnError(
                    ErrorCodes.XrayStartFailed,
                    "error.xray.working_directory_unavailable",
                    ErrorSeverity.Error,
                    $"Working directory '{request.WorkingDirectory}' is unusable: {ex.Message}"));
            }
        }

        lock (_gate)
        {
            _lastRequest = request;
            _stopRequested = false;
        }

        _restartLimiter.Reset();

        return await StartCoreAsync(request, cancellationToken, isRestart: false).ConfigureAwait(false);
    }

    private async Task<Result> StartCoreAsync(
        XrayStartRequest request,
        CancellationToken cancellationToken,
        bool isRestart)
    {
        // Pre-flight only on the first start: on a restart the config is already known good, and
        // re-testing would just add latency to recovery.
        if (Options.PreflightEnabled && !isRestart)
        {
            var preflight = await PreflightAsync(
                request.BinaryPath,
                request.ConfigPath,
                request.WorkingDirectory,
                request.AssetDirectory,
                cancellationToken).ConfigureAwait(false);

            if (preflight.IsSuccess && !preflight.Value.IsValid)
            {
                var detail = preflight.Value.Diagnostic;

                lock (_gate)
                {
                    _lastDiagnostic = detail;
                }

                // A rejected configuration is terminal. Restarting would reproduce it exactly.
                return Fail(XrayEngineState.Faulted, new MyVpnError(
                    ErrorCodes.ConfigRejectedByCore,
                    preflight.Value.MessageKey ?? "error.xray.config_rejected_by_core",
                    ErrorSeverity.Error,
                    detail,
                    preflight.Value.RemediationKey));
            }
        }

        SetState(XrayEngineState.Starting, isRestart ? "restart" : "start");

        var info = new ProcessStartInfo
        {
            FileName = request.BinaryPath,

            // UseShellExecute = false is mandatory: it is what allows the environment to be set
            // explicitly, and it is what keeps the core off a shell entirely.
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = request.WorkingDirectory,
        };

        // Arguments go through ArgumentList, never a concatenated command line, so no value can
        // introduce additional arguments.
        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(request.ConfigPath);

        foreach (var pair in BuildEnvironment(request.AssetDirectory, request.Environment))
        {
            info.Environment[pair.Key] = pair.Value;
        }

        var process = new Process { StartInfo = info, EnableRaisingEvents = true };
        process.OutputDataReceived += OnOutputDataReceived;
        process.ErrorDataReceived += OnOutputDataReceived;

        // The Exited event carries no exit code, so read it from the process in the handler.
        // Without this subscription an unexpected exit would never be noticed and the engine
        // would report "Running" forever.
        process.Exited += (_, _) =>
        {
            int code;
            try
            {
                code = process.ExitCode;
            }
            catch (InvalidOperationException)
            {
                code = -1;
            }

            OnProcessExited(process, code);
        };

        try
        {
            if (!process.Start())
            {
                process.Dispose();
                return Fail(XrayEngineState.Faulted, new MyVpnError(
                    ErrorCodes.XrayStartFailed,
                    "error.xray.start_failed",
                    ErrorSeverity.Error,
                    "The operating system refused to start the core process."));
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            process.Dispose();

            return Fail(XrayEngineState.Faulted, new MyVpnError(
                ErrorCodes.XrayStartFailed,
                "error.xray.start_failed",
                ErrorSeverity.Error,
                $"Starting the core failed: {ex.Message}",
                "xray.select_binary"));
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        lock (_gate)
        {
            _process = process;
            _startedAt = DateTimeOffset.UtcNow;
            if (isRestart)
            {
                _restartCount++;
            }
        }

        // A short grace period: if the core dies immediately it is almost always a configuration
        // or asset problem, and reporting that now is far more useful than reporting "running"
        // and then "crashed" a moment later.
        var exitedEarly = await Task.Run(
            () => process.WaitForExit(750),
            CancellationToken.None).ConfigureAwait(false);

        if (!exitedEarly)
        {
            SetState(XrayEngineState.Running, "started");
            _logger.LogInformation("Core started with PID {Pid}.", process.Id);
            return Result.Ok();
        }

        var earlyExit = process.ExitCode;
        _logger.LogError("Core exited {Code} during start-up.", earlyExit);

        OnProcessExited(process, earlyExit);

        return Fail(XrayEngineState.Faulted, new MyVpnError(
            ErrorCodes.XrayStoppedUnexpectedly,
            "error.xray.start_failed",
            ErrorSeverity.Error,
            $"The core exited with code {earlyExit} immediately after start. {_lastDiagnostic}".Trim()));
    }

    /// <summary>Stops the core, attempting a graceful shutdown first.</summary>
    public async Task<Result> StopAsync(CancellationToken cancellationToken)
    {
        Process? process;

        lock (_gate)
        {
            process = _process;
            _stopRequested = true;
            _restartCts?.Cancel();
        }

        if (process is null || process.HasExited)
        {
            SetState(XrayEngineState.Stopped, "already-stopped", XrayStopReason.Requested);
            return Result.Ok();
        }

        var timeout = _lastRequest?.GracefulStopTimeout ?? TimeSpan.FromSeconds(5);
        SetState(XrayEngineState.Stopping, "stop-requested");

        if (OperatingSystem.IsWindows())
        {
            // Windows has no SIGTERM analogue for a console process launched without a console
            // group, so a forced kill is the only reliable option. Recorded honestly rather than
            // described as a graceful stop.
            _logger.LogInformation("Forcing core termination (no graceful stop mechanism on Windows).");
            TryKillTree(process);
        }
        else
        {
            SendSignal(process, SigTerm);

            var exited = await Task.Run(
                () => process.WaitForExit((int)timeout.TotalMilliseconds),
                CancellationToken.None).ConfigureAwait(false);

            if (!exited)
            {
                _logger.LogWarning("Core did not exit within {Timeout}s; forcing termination.", timeout.TotalSeconds);
                _lastStopReason = XrayStopReason.ForcedShutdown;
                TryKillTree(process);
            }
        }

        // Give the exit handler a moment to run so the status is consistent when we return.
        await Task.Run(() => process.WaitForExit(2000), CancellationToken.None).ConfigureAwait(false);

        SetState(XrayEngineState.Stopped, "stopped", _lastStopReason ?? XrayStopReason.Requested);
        return Result.Ok();
    }

    private void OnOutputDataReceived(object sender, DataReceivedEventArgs args)
    {
        if (args.Data is null)
        {
            return;
        }

        // Xray writes almost everything to stderr, including routine notices, so the stream is
        // not a reliable severity indicator. Classify by content instead, and keep both.
        var isError = LooksLikeFailure(args.Data);
        var line = new XrayOutputLine(DateTimeOffset.UtcNow, isError, args.Data);

        lock (_gate)
        {
            _output.Enqueue(line);
            while (_output.Count > Options.OutputBufferLines)
            {
                _output.Dequeue();
            }
        }

        OutputReceived?.Invoke(this, line);

        if (isError)
        {
            _logger.LogWarning("core: {Line}", args.Data);
        }
        else
        {
            _logger.LogDebug("core: {Line}", args.Data);
        }
    }

    private void OnProcessExited(object sender, int exitCode)
    {
        if (sender is Process process)
        {
            process.OutputDataReceived -= OnOutputDataReceived;
            process.ErrorDataReceived -= OnOutputDataReceived;
        }

        bool stopRequested;
        lock (_gate)
        {
            stopRequested = _stopRequested;
        }

        var reason = XrayTestRunInterpreter.ClassifyExit(exitCode, stopRequested);

        // The last few lines of output are the most useful diagnosis when the core dies.
        lock (_gate)
        {
            _lastStopReason = reason;
            _lastDiagnostic = _output
                .Skip(Math.Max(0, _output.Count - 5))
                .Select(l => l.Text)
                .LastOrDefault();
        }

        if (stopRequested)
        {
            SetState(XrayEngineState.Stopped, "stopped", reason);
            return;
        }

        _logger.LogError("Core exited unexpectedly with code {Code} ({Reason}).", exitCode, reason);

        if (reason == XrayStopReason.InvalidConfiguration)
        {
            // Terminal by definition; retrying cannot change the outcome.
            SetState(XrayEngineState.Faulted, "config-rejected", reason, new MyVpnError(
                ErrorCodes.ConfigRejectedByCore,
                "error.xray.config_rejected_by_core",
                ErrorSeverity.Error,
                _lastDiagnostic));

            return;
        }

        if (!Options.AutoRestart)
        {
            SetState(XrayEngineState.Faulted, "crash-no-autorestart", reason);
            return;
        }

        if (!_restartLimiter.CanRestart())
        {
            var wait = _restartLimiter.TimeUntilNextAllowed();
            _logger.LogError(
                "Restart budget exhausted ({Summary}); giving up for {Wait}s.",
                _restartLimiter.Describe(),
                wait.TotalSeconds);

            SetState(XrayEngineState.RestartLoopBlocked, "restart-loop", reason, new MyVpnError(
                ErrorCodes.XrayRestartLoopDetected,
                "error.xray.restart_loop_detected",
                ErrorSeverity.Critical,
                $"The core restarted {_restartLimiter.Describe()} and has been stopped to avoid a loop.")
                .WithArg("summary", _restartLimiter.Describe()));

            return;
        }

        _restartLimiter.RecordAttempt();
        ScheduleRestart();
    }

    private void ScheduleRestart()
    {
        XrayStartRequest? request;

        lock (_gate)
        {
            request = _lastRequest;
            _restartCts?.Dispose();
            _restartCts = new CancellationTokenSource();
        }

        if (request is null)
        {
            return;
        }

        var token = _restartCts!.Token;
        SetState(XrayEngineState.Starting, "restart-scheduled");

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(Options.RestartDelay, token).ConfigureAwait(false);

                if (token.IsCancellationRequested)
                {
                    return;
                }

                await StartCoreAsync(request, token, isRestart: true).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Cancelled by an explicit stop; nothing to do.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Restart attempt failed.");
                SetState(XrayEngineState.Faulted, "restart-failed", XrayStopReason.Crash);
            }
        }, token);
    }

    private Result Fail(XrayEngineState state, MyVpnError error)
    {
        SetState(state, "failure", null, error);
        return Result.Fail(error);
    }

    private void SetState(
        XrayEngineState next,
        string reason,
        XrayStopReason? stopReason = null,
        MyVpnError? error = null)
    {
        XrayEngineState previous;

        lock (_gate)
        {
            previous = _state;
            _state = next;
        }

        if (previous != next)
        {
            _logger.LogInformation("Core state {Previous} -> {Next} ({Reason}).", previous, next, reason);
        }

        StateChanged?.Invoke(this, new XrayEngineStateChanged(previous, next, reason, stopReason, error));
    }

    /// <summary>
    /// Builds the child environment.
    /// </summary>
    /// <remarks>
    /// <see cref="ProcessStartInfo.Environment"/> is pre-populated with the parent's environment
    /// when <c>UseShellExecute</c> is false, so adding here augments rather than replaces. The
    /// asset directory is always absolute.
    /// </remarks>
    private static IReadOnlyDictionary<string, string> BuildEnvironment(
        string? assetDirectory,
        IReadOnlyDictionary<string, string>? extra)
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!string.IsNullOrWhiteSpace(assetDirectory))
        {
            environment[GeoDataConstants.AssetLocationEnvironmentVariable] = assetDirectory;
        }

        if (extra is not null)
        {
            foreach (var pair in extra)
            {
                environment[pair.Key] = pair.Value;
            }
        }

        return environment;
    }

    private const int SigTerm = 15;

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int Kill(int pid, int signal);

    private void SendSignal(Process process, int signal)
    {
        try
        {
            _ = Kill(process.Id, signal);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            _logger.LogWarning(ex, "Could not send signal {Signal}; falling back to a forced stop.", signal);
            TryKillTree(process);
        }
    }

    private void TryKillTree(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning(ex, "Failed to kill the core process.");
        }
    }

    private sealed record CapturedRun(
        bool Started,
        int ExitCode,
        string StandardOutput,
        string StandardError,
        string? FailureDetail);

    /// <summary>
    /// Runs a short-lived core command and captures its output.
    /// </summary>
    /// <remarks>
    /// Used for <c>version</c> and <c>run -test</c>. These are bounded by a timeout because a
    /// hung probe would block the connect path indefinitely.
    /// </remarks>
    private async Task<CapturedRun> RunCapturedAsync(
        string binaryPath,
        IReadOnlyList<string> arguments,
        string? workingDirectory,
        IReadOnlyDictionary<string, string>? environment,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo
        {
            FileName = binaryPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        if (!string.IsNullOrWhiteSpace(workingDirectory) && Directory.Exists(workingDirectory))
        {
            info.WorkingDirectory = workingDirectory;
        }

        if (environment is not null)
        {
            foreach (var pair in environment)
            {
                info.Environment[pair.Key] = pair.Value;
            }
        }

        try
        {
            using var process = Process.Start(info);
            if (process is null)
            {
                return new CapturedRun(false, -1, string.Empty, string.Empty, "the process could not be started");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKillTree(process);

                return new CapturedRun(
                    true,
                    -1,
                    string.Empty,
                    string.Empty,
                    $"the command did not finish within {timeout.TotalSeconds:0}s");
            }

            return new CapturedRun(
                true,
                process.ExitCode,
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false),
                null);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            return new CapturedRun(false, -1, string.Empty, string.Empty, ex.Message);
        }
    }

    private static string Truncate(string? value) =>
        value is null ? string.Empty : value.Length <= 120 ? value : value[..120] + "…";

    /// <summary>
    /// Heuristic classification of a core output line.
    /// </summary>
    /// <remarks>
    /// Xray emits routine start-up notices on stderr, so treating "stderr" as "error" would fill
    /// the diagnostics view with false alarms. These markers are the ones that actually precede
    /// a failure to start or a dropped connection.
    /// </remarks>
    private static bool LooksLikeFailure(string text) =>
        text.Contains("failed", StringComparison.OrdinalIgnoreCase)
        || text.Contains("error", StringComparison.OrdinalIgnoreCase)
        || text.Contains("panic", StringComparison.OrdinalIgnoreCase)
        || text.Contains("no such file", StringComparison.OrdinalIgnoreCase)
        || text.Contains("permission denied", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        lock (_gate)
        {
            _restartCts?.Cancel();
            _restartCts?.Dispose();
            _restartCts = null;
        }

        var process = _process;
        if (process is not null)
        {
            process.OutputDataReceived -= OnOutputDataReceived;
            process.ErrorDataReceived -= OnOutputDataReceived;

            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
            {
                // Best effort during disposal.
            }

            process.Dispose();
        }
    }
}

/// <summary>Contract for the engine, so the application layer can depend on the abstraction.</summary>
public interface IXrayEngine
{
    XrayEngineState State { get; }

    event EventHandler<XrayEngineStateChanged>? StateChanged;

    event EventHandler<XrayOutputLine>? OutputReceived;

    Task<Result> StartAsync(XrayStartRequest request, CancellationToken cancellationToken);

    Task<Result> StopAsync(CancellationToken cancellationToken);

    Task<Result<XrayVersion>> ProbeVersionAsync(string binaryPath, CancellationToken cancellationToken);

    Task<Result<XrayPreflightResult>> PreflightAsync(
        string binaryPath,
        string configPath,
        string? workingDirectory,
        string? assetDirectory,
        CancellationToken cancellationToken);

    XrayEngineStatus GetStatus();

    IReadOnlyList<string> GetRecentOutput(int maxLines);
}
