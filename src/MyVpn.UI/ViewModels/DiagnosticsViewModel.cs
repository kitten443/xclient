using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using MyVpn.Core.Diagnostics;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.Diagnostics;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>One rendered diagnostic check.</summary>
public sealed class DiagnosticRow : ObservableObject
{
    private string _title = string.Empty;
    private string _message = string.Empty;
    private string _remediation = string.Empty;
    private string _duration = string.Empty;

    public DiagnosticRow(string checkId)
    {
        CheckId = checkId;
    }

    public string CheckId { get; }

    /// <summary>Localized check name.</summary>
    public string Title
    {
        get => _title;
        private set => SetField(ref _title, value);
    }

    /// <summary>Localized outcome, in plain language.</summary>
    public string Message
    {
        get => _message;
        private set => SetField(ref _message, value);
    }

    /// <summary>Localized suggested fix, when the check offered one.</summary>
    public string Remediation
    {
        get => _remediation;
        private set => SetField(ref _remediation, value);
    }

    public bool HasRemediation => _remediation.Length > 0;

    public DiagnosticStatus Status { get; private set; } = DiagnosticStatus.Skipped;

    public bool IsSuccess => Status == DiagnosticStatus.Success;

    public bool IsProblem => Status is DiagnosticStatus.Warning or DiagnosticStatus.Error;

    /// <summary>How long the check took, so a slow check is visible rather than mysterious.</summary>
    public string Duration
    {
        get => _duration;
        private set => SetField(ref _duration, value);
    }

    /// <summary>Raw technical context. Never the primary explanation.</summary>
    public string TechnicalDetail { get; private set; } = string.Empty;

    public bool HasTechnicalDetail => TechnicalDetail.Length > 0;

    /// <summary>The underlying result, kept so a language switch can re-render the text.</summary>
    public DiagnosticCheckResult Result { get; private set; } =
        DiagnosticCheckResult.Skipped("pending", "diagnostics.skip.not_applicable", "diagnostics.skip.not_applicable");

    public void Apply(DiagnosticCheckResult result, LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(localization);

        Result = result;
        Status = result.Status;
        Title = localization.Get(result.TitleKey);
        Message = result.MessageKey is { } key
            ? Presentation.DescribeKey(localization, key, result.Args)
            : string.Empty;

        Remediation = result.RemediationKey is { } fix ? localization.Get(fix) : string.Empty;
        TechnicalDetail = result.TechnicalDetail ?? string.Empty;
        Duration = DisplayFormat.Milliseconds(result.Duration);

        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(IsSuccess));
        OnPropertyChanged(nameof(IsProblem));
        OnPropertyChanged(nameof(HasRemediation));
        OnPropertyChanged(nameof(HasTechnicalDetail));
    }
}

/// <summary>
/// The diagnostics screen.
/// </summary>
/// <remarks>
/// <para>
/// Wraps <see cref="DiagnosticRunner"/> with the standard check set. The report is only ever the
/// runner's output: this class renders, it does not decide. A check that fails appears as that
/// check failing, which is the entire value of the screen.
/// </para>
/// <para>
/// Nothing runs on open. A diagnostics screen that probes the network as soon as it is shown is a
/// screen that announces the user's presence and costs them time; the run is a button.
/// </para>
/// </remarks>
public sealed class DiagnosticsViewModel : ObservableObject
{
    private readonly DiagnosticRunner _runner;
    private readonly LocalizationService _localization;
    private readonly DiagnosticContextProvider _context;

    private string _summary = string.Empty;
    private string _error = string.Empty;
    private bool _busy;

    public DiagnosticsViewModel(
        DiagnosticRunner runner,
        LocalizationService localization,
        DiagnosticContextProvider context)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));
        _context = context ?? throw new ArgumentNullException(nameof(context));

        _localization.LanguageChanged += (_, _) => Relocalize();

        RunCommand = new AsyncRelayCommand(RunAsync, () => !_busy);
    }

    /// <summary>Runs the whole check set.</summary>
    public IAsyncRelayCommand RunCommand { get; }

    /// <summary>Rendered checks, in the runner's frozen order.</summary>
    public ObservableCollection<DiagnosticRow> Checks { get; } = new();

    public string Heading => _localization.Get("main.diagnostics");

    public string RunLabel => _localization.Get("diagnostics.run");

    public string Summary
    {
        get => _summary;
        private set => SetField(ref _summary, value);
    }

    public string Error
    {
        get => _error;
        private set
        {
            if (SetField(ref _error, value))
            {
                OnPropertyChanged(nameof(HasError));
            }
        }
    }

    public bool HasError => _error.Length > 0;

    /// <summary>True while a run is in flight; the button must not queue a second run.</summary>
    public bool IsBusy
    {
        get => _busy;
        private set
        {
            if (SetField(ref _busy, value))
            {
                RunCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>
    /// Runs every check and renders the report.
    /// </summary>
    /// <remarks>
    /// The runner isolates each check: one that throws or hangs is reported as that check failing
    /// rather than losing the report — which is why a diagnostics screen can afford to run checks
    /// it does not fully trust. This method therefore only has to defend against being run twice.
    /// </remarks>
    public async Task RunAsync()
    {
        if (_busy)
        {
            return;
        }

        IsBusy = true;
        Error = string.Empty;

        try
        {
            var report = await _runner
                .RunAsync(_context.Create(), CancellationToken.None)
                .ConfigureAwait(true);

            Render(report);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The runner is not supposed to throw, but a screen whose job is to explain failures
            // must not itself fail silently.
            Error = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Renders a report. Public so a test can drive the view model without a live run.</summary>
    public void Render(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        Checks.Clear();
        foreach (var check in report.Checks)
        {
            var row = new DiagnosticRow(check.Id);
            row.Apply(check, _localization);
            Checks.Add(row);
        }

        // Counts rather than prose: the catalog has no sentence for "2 errors, 1 warning", and
        // inventing English here is exactly what the localization rule forbids.
        Summary = $"{_localization.Get("main.diagnostics")}: "
            + $"{_localization.Get(OverallKey(report.Overall))} "
            + $"(e={report.ErrorCount} w={report.WarningCount} n={report.Checks.Count})";

        OnPropertyChanged(nameof(Checks));
    }

    /// <summary>Checks the runner will execute, for display before a run.</summary>
    public IReadOnlyList<string> CheckTitles => _runner.Checks
        .Select(check => _localization.Get(check.TitleKey))
        .ToArray();

    private void Relocalize()
    {
        // Re-rendered from each row's stored result: the text is derived state, and a language
        // switch must not leave one row in the old language beside another in the new.
        foreach (var row in Checks)
        {
            row.Apply(row.Result, _localization);
        }

        OnAllPropertiesChanged();
    }

    private static string OverallKey(DiagnosticStatus status) => status switch
    {
        DiagnosticStatus.Success => "status.connected",
        DiagnosticStatus.Warning => "status.degraded",
        DiagnosticStatus.Error => "status.faulted",
        _ => "error.xray.version_unknown",
    };
}

/// <summary>
/// Builds the diagnostic context from the objects the application already holds.
/// </summary>
/// <remarks>
/// <para>
/// Pure assembly: no check runs here, and nothing here touches the network or the firewall. It
/// exists in the UI project because it is the seam between the composed graph and the runner's
/// context type, and the values it collects are the same singletons the session uses — a
/// diagnostic run inspects the objects that are in force, not look-alikes.
/// </para>
/// <para>
/// The core binary path and config path are read from the session's own snapshot and the settings
/// rather than re-derived, so the diagnostics screen and the connect path cannot disagree about
/// which file or which binary is in play.
/// </para>
/// </remarks>
public sealed class DiagnosticContextProvider
{
    private readonly IUserSettingsStore _store;
    private readonly ServerListViewModel _servers;
    private readonly GeoDataManager _geoData;
    private readonly IXrayEngine _engine;
    private readonly IPlatformServices? _platform;

    public DiagnosticContextProvider(
        IUserSettingsStore store,
        ServerListViewModel servers,
        GeoDataManager geoData,
        IXrayEngine engine,
        IPlatformServices? platform = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _servers = servers ?? throw new ArgumentNullException(nameof(servers));
        _geoData = geoData ?? throw new ArgumentNullException(nameof(geoData));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _platform = platform;
    }

    public AppSettings Settings => _store.Settings;

    public DiagnosticContext Create() => new()
    {
        Settings = _store.Settings,
        Profile = _servers.Selected?.Profile,
        CoreBinaryPath = _store.CoreBinaryPath,

        // Left null rather than guessed: the config file only exists while a session is up, and
        // the config check reports "no config" honestly instead of checking a path from a
        // previous run that may since have been deleted.
        ConfigPath = null,
        AssetDirectory = _geoData.AssetDirectory,
        Engine = _engine,
        GeoData = _geoData,
        Platform = _platform,

        // Server reachability is a real outbound probe. It runs because the user asked for
        // diagnostics explicitly by pressing the button, which is the same consent the CLI takes
        // for granted when the flag is passed.
        AllowNetworkChecks = true,
    };
}
