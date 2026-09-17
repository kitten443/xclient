using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>
/// The main screen: it drives <see cref="IVpnSession"/> and renders what the session reports.
/// </summary>
/// <remarks>
/// <para>
/// <b>The view model never calls a privileged API.</b> It holds <see cref="IVpnSession"/> and
/// nothing else that can mutate the machine: no firewall, no routing table, no resolver, no
/// Xray process handle. The single privileged-adjacent act in this project is the composition
/// root choosing a platform factory (see <c>Composition/ServiceCollectionExtensions.cs</c>);
/// everything after that travels through the ports.
/// </para>
/// <para>
/// <b>Everything shown is read from <see cref="ConnectionSnapshot"/>.</b> There is no local
/// notion of "connected": if verification failed, the session returns to
/// <see cref="VpnConnectionState.Disconnected"/> with a <c>LastError</c> and this screen shows
/// exactly that. A reassuring state displayed over a failed verification would be the single
/// most misleading thing the UI could do.
/// </para>
/// <para>
/// <b>Connect and disconnect take seconds to tens of seconds.</b> Both buttons run through
/// <see cref="AsyncRelayCommand"/>, which disables itself for the duration, and
/// <see cref="IsBusy"/> additionally reflects the session's own transitional states. A second
/// click therefore cannot start a second operation; and the session's own refusal
/// (<c>error.session.busy</c>) is displayed rather than raced against, because when it appears
/// the UI is telling the user about a real concurrent operation rather than a cosmetic double
/// click.
/// </para>
/// </remarks>
public sealed class MainWindowViewModel : ObservableObject
{
    private readonly IVpnSession _session;
    private readonly LocalizationService _localization;
    private readonly IUserSettingsStore _store;

    private string _coreVersion = string.Empty;
    private string _exitAddress = string.Empty;
    private string _directAddress = string.Empty;
    private string _trafficMoved = string.Empty;
    private string _latency = string.Empty;
    private string _profileName = string.Empty;
    private string _lastError = string.Empty;
    private bool _advancedMode;
    private ServerEntry? _selectedProfile;
    private CancellationTokenSource? _currentOperation;

    public MainWindowViewModel(
        IVpnSession session,
        IUserSettingsStore store,
        LocalizationService localization,
        ServerListViewModel servers,
        SubscriptionImportViewModel subscription,
        DiagnosticsViewModel diagnostics,
        SettingsViewModel settings)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));
        Servers = servers ?? throw new ArgumentNullException(nameof(servers));
        Subscription = subscription ?? throw new ArgumentNullException(nameof(subscription));
        Diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
        Settings = settings ?? throw new ArgumentNullException(nameof(settings));

        _session.StateChanged += OnSessionStateChanged;
        _session.SnapshotChanged += OnSnapshotChanged;
        _localization.LanguageChanged += OnLanguageChanged;

        // The consent gate's output is only a proposal. This is the one place it can become live
        // configuration, which keeps a provider-influenced value exactly one deliberate step away
        // from the settings the session connects with.
        Subscription.ConsentGiven += OnSubscriptionConsentGiven;

        ToggleConnectionCommand = new AsyncRelayCommand(ToggleConnectionAsync, CanToggleConnection);
        SetLanguageCommand = new RelayCommand<string>(code => _localization.SetLanguage(code));

        Warnings = new ObservableCollection<DetailRow>();
        RebuildDetails();
    }

    // ---- collaborators --------------------------------------------------

    /// <summary>Server selection. Shared with the connect command through <see cref="SelectedProfile"/>.</summary>
    public ServerListViewModel Servers { get; }

    /// <summary>Subscription import, including the consent gate.</summary>
    public SubscriptionImportViewModel Subscription { get; }

    /// <summary>Diagnostics report.</summary>
    public DiagnosticsViewModel Diagnostics { get; }

    /// <summary>Read-only view of the effective settings.</summary>
    public SettingsViewModel Settings { get; }

    // ---- commands --------------------------------------------------------

    /// <summary>Connect or disconnect, depending on the session's real state.</summary>
    public IAsyncRelayCommand ToggleConnectionCommand { get; }

    public IRelayCommand<string> SetLanguageCommand { get; }

    // ---- localized chrome ------------------------------------------------

    public string AppTitle => _localization.Get("app.title");

    public string AppSubtitle => _localization.Get("app.subtitle");

    public string LabelStatus => _localization.Get("main.status");

    public string LabelServer => _localization.Get("main.server");

    public string LabelMode => _localization.Get("main.mode");

    public string LabelKillSwitch => _localization.Get("main.killswitch");

    public string LabelLanguage => _localization.Get("language.label");

    public string LabelPing => _localization.Get("main.ping");

    public string LabelIp => _localization.Get("main.ip");

    public string AdvancedModeLabel => _localization.Get("main.advanced_mode");

    public string ConnectTabLabel => _localization.Get("main.status");

    public string ServersTabLabel => _localization.Get("main.change_server");

    public string SubscriptionTabLabel => _localization.Get("main.update_subscription");

    public string DiagnosticsTabLabel => _localization.Get("main.diagnostics");

    public string SettingsTabLabel => _localization.Get("main.settings");

    public string RefreshLabel => _localization.Get("subscription.retry");

    public string RestoreNetworkLabel => _localization.Get("network.restore");

    public string CurrentLanguageCode => _localization.Language;

    // ---- live state ------------------------------------------------------

    /// <summary>Localized connection status, straight from the session's state.</summary>
    public string StatusText => _localization.Get(StatusKey(_session.State));

    /// <summary>Primary button label. "connecting"/"disconnecting" disable it while it is true.</summary>
    public string ConnectButtonText => _session.State switch
    {
        VpnConnectionState.Connected or VpnConnectionState.Degraded => _localization.Get("main.disconnect"),
        VpnConnectionState.Preparing or VpnConnectionState.Connecting or VpnConnectionState.Reconnecting =>
            _localization.Get("main.connecting"),
        VpnConnectionState.Disconnecting => _localization.Get("main.disconnecting"),
        _ => _localization.Get("main.connect"),
    };

    /// <summary>
    /// True while a connection transition or a user-initiated operation is under way.
    /// </summary>
    /// <remarks>
    /// The OR matters: the state machine alone does not cover the window between the click and
    /// the first transition, and the command's own <c>IsRunning</c> does not cover a transition
    /// started by something other than this button.
    /// </remarks>
    public bool IsBusy => _currentOperation is not null || _session.State.IsTransitional();

    /// <summary>True when the session's own Kill Switch requirement is in force.</summary>
    public bool KillSwitchEngaged => _session.Snapshot.KillSwitchArmed
        || _session.State.RequiresKillSwitch();

    /// <summary>The profile the next connect will use.</summary>
    public ServerEntry? SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            if (SetField(ref _selectedProfile, value))
            {
                _store.Settings = _store.Settings with { SelectedProfileId = value?.Profile.Id };
                OnPropertyChanged(nameof(CanConnect));
                ToggleConnectionCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>False when there is nothing to connect to, so the button explains itself.</summary>
    public bool CanConnect => SelectedProfile is not null;

    /// <summary>Core version reported by the session, or empty when it was never established.</summary>
    public string CoreVersion => _coreVersion;

    /// <summary>The address the outside world saw, when verification ran.</summary>
    public string ExitAddress => _exitAddress;

    /// <summary>The host's own address before the tunnel came up, when it could be measured.</summary>
    public string DirectAddress => _directAddress;

    /// <summary>
    /// Whether traffic actually traversed the tunnel.
    /// </summary>
    /// <remarks>
    /// Three-valued on purpose. A freshly started session, or one connected with verification
    /// skipped, has no evidence either way, and the honest rendering of "no evidence" is the
    /// unknown value — not a tick.
    /// </remarks>
    public string TrafficMoved => _trafficMoved;

    /// <summary>Verification round-trip time, or empty when it was not measured.</summary>
    public string Latency => _latency;

    public ServerEntry? ActiveProfile => _session.Snapshot.ProfileId is { } id
        ? Servers.Find(id)
        : null;

    /// <summary>Localized, severity-prefixed rendering of the session's last error.</summary>
    public string LastError => _lastError;

    public bool HasError => _lastError.Length > 0;

    /// <summary>Localized warnings the session reported for the current or last attempt.</summary>
    public ObservableCollection<DetailRow> Warnings { get; }

    public bool HasWarnings => Warnings.Count > 0;

    public bool AdvancedMode
    {
        get => _advancedMode;
        set
        {
            if (SetField(ref _advancedMode, value))
            {
                _store.Settings = _store.Settings with { AdvancedMode = value };
            }
        }
    }

    /// <summary>Rows shown in the detail table, rebuilt when any value or the language changes.</summary>
    public ObservableCollection<DetailRow> Details { get; } = new();

    // ---- lifecycle -------------------------------------------------------

    /// <summary>
    /// Loads persisted state and the first profile list. Never touches the network.
    /// </summary>
    /// <remarks>
    /// Startup must not resolve the server, fetch a subscription or arm anything: the user has
    /// not asked to connect yet, and a GUI that mutates the machine on launch is
    /// indistinguishable from malware. This only reads local state.
    /// </remarks>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var state = await _store.LoadAsync(cancellationToken).ConfigureAwait(true);

        _advancedMode = state.Settings.AdvancedMode;
        Subscription.Restore(state.SubscriptionUrl);
        Settings.Restore(state.Settings);
        Settings.CoreBinaryPath = state.CoreBinaryPath ?? string.Empty;
        Servers.Restore(state.Profiles);

        var selected = state.Settings.SelectedProfileId is { } id ? Servers.Find(id) : null;
        _selectedProfile = selected ?? Servers.Profiles.FirstOrDefault();

        RebuildDetails();
        OnPropertyChanged(nameof(AdvancedMode));
        OnPropertyChanged(nameof(SelectedProfile));
        OnPropertyChanged(nameof(CanConnect));
        ToggleConnectionCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Records an import the user has accepted, and makes the first profile the active one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the single point at which provider-influenced data becomes live configuration. It
    /// is called only from the consent handler below, after the user has explicitly accepted the
    /// listed changes; the import screen itself cannot reach the store.
    /// </para>
    /// <para>
    /// The subscription URL is stored because it is the user's own input and must survive a
    /// restart. It is never rendered: the import screen shows a masked form, and nothing logs it
    /// (it carries a provider token).
    /// </para>
    /// </remarks>
    public async Task AcceptSubscriptionAsync(
        IReadOnlyList<ServerProfile> profiles,
        string subscriptionUrl,
        AppSettings proposedSettings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(proposedSettings);

        Servers.Restore(profiles);

        // The list resets to the provider's order, so the selection has to be recorded again —
        // otherwise the next launch would silently pick whatever happens to be first rather than
        // what the user is looking at now.
        _selectedProfile = Servers.Profiles.FirstOrDefault();

        var committed = proposedSettings with { SelectedProfileId = _selectedProfile?.Profile.Id };

        _store.Settings = committed;
        _store.Profiles = profiles;
        _store.SubscriptionUrl = subscriptionUrl;
        _store.MarkDirty();

        Settings.Restore(committed);

        await _store.SaveAsync(cancellationToken).ConfigureAwait(true);

        OnPropertyChanged(nameof(SelectedProfile));
        OnPropertyChanged(nameof(CanConnect));
        ToggleConnectionCommand.NotifyCanExecuteChanged();
        RebuildDetails();
    }

    // ---- internals -------------------------------------------------------

    /// <summary>
    /// Persists an import the user consented to.
    /// </summary>
    /// <remarks>
    /// The event arrives on the UI thread and is handled with <c>async void</c>, which is the one
    /// shape an event handler can have. The await is a local file write, not a network call: the
    /// fetch and the parse have already happened, and the only remaining step is recording the
    /// decision. A failure is reported on the connection screen rather than escaping the handler,
    /// which would take the process down.
    /// </remarks>
    private async void OnSubscriptionConsentGiven(object? sender, SubscriptionConsentEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        try
        {
            await AcceptSubscriptionAsync(
                e.Result.Profiles,
                e.Result.SubscriptionUrl,
                e.ProposedSettings).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetError(new Core.Results.MyVpnError(
                Core.Results.ErrorCodes.ConfigWriteFailed,
                "error.config.write_failed",
                Core.Results.ErrorSeverity.Error,
                ex.Message));
        }
    }

    private bool CanToggleConnection()
    {
        if (IsBusy)
        {
            return false;
        }

        return _session.State.IsTunnelUp() || CanConnect;
    }

    private async Task ToggleConnectionAsync()
    {
        // The button is already disabled while an operation runs, so this guard only fires for a
        // command invoked from somewhere the button is not — a keyboard binding, a future tray
        // menu, a test. Refusing here is what makes "one operation at a time" a property of the
        // view model rather than a property of one control's IsEnabled state. The session has its
        // own gate and would return error.session.busy, but reaching it would show the user a
        // spurious warning about a concurrency they cannot see.
        if (IsBusy)
        {
            return;
        }

        // A disconnect is offered whenever the tunnel is up, including Degraded: a user whose
        // health checks are failing must always be able to get out.
        if (_session.State.IsTunnelUp())
        {
            await DisconnectAsync().ConfigureAwait(true);
            return;
        }

        if (SelectedProfile is null)
        {
            // Unreachable through the button (CanExecute is false), but a command invoked from
            // code must not silently no-op.
            _lastError = Presentation.DescribeKey(_localization, "error.server.address_missing");
            OnPropertyChanged(nameof(LastError));
            OnPropertyChanged(nameof(HasError));
            return;
        }

        await ConnectAsync(SelectedProfile).ConfigureAwait(true);
    }

    private async Task ConnectAsync(ServerEntry entry)
    {
        using var operation = BeginOperation();

        _lastError = string.Empty;
        _exitAddress = string.Empty;
        _directAddress = string.Empty;
        _latency = string.Empty;
        _trafficMoved = string.Empty;
        OnPropertyChanged(nameof(LastError));
        OnPropertyChanged(nameof(HasError));
        RebuildDetails();

        var request = new ConnectRequest
        {
            Profile = entry.Profile,
            Settings = _store.Settings,
            CoreBinaryPath = Settings.CoreBinaryPath,
        };

        var result = await _session
            .ConnectAsync(request, operation.Token)
            .ConfigureAwait(true);

        if (result.IsFailure)
        {
            // The session has already rolled back and returned to Disconnected. Reporting the
            // error is the whole point: a failed connect must never leave a reassuring state.
            SetError(result.Error!);
        }

        ApplySnapshot(_session.Snapshot);
    }

    private async Task DisconnectAsync()
    {
        using var operation = BeginOperation();

        var result = await _session
            .DisconnectAsync(operation.Token)
            .ConfigureAwait(true);

        if (result.IsFailure)
        {
            SetError(result.Error!);
        }

        ApplySnapshot(_session.Snapshot);
    }

    /// <summary>
    /// Marks an operation as running, and guarantees it is unmarked however it ends.
    /// </summary>
    /// <remarks>
    /// Disposing the returned scope cancels the token and clears the flag even when the session
    /// throws, so <see cref="IsBusy"/> can never be left stuck true — a stuck "connecting" button
    /// is a state the user cannot escape without restarting the app.
    /// </remarks>
    private OperationScope BeginOperation()
    {
        var cts = new CancellationTokenSource();
        _currentOperation = cts;
        OnPropertyChanged(nameof(IsBusy));
        ToggleConnectionCommand.NotifyCanExecuteChanged();
        return new OperationScope(this, cts);
    }

    private void EndOperation(CancellationTokenSource cts)
    {
        cts.Dispose();
        if (ReferenceEquals(_currentOperation, cts))
        {
            _currentOperation = null;
        }

        OnPropertyChanged(nameof(IsBusy));
        ToggleConnectionCommand.NotifyCanExecuteChanged();
    }

    private void SetError(Core.Results.MyVpnError error)
    {
        _lastError = Presentation.DescribeWithSeverity(_localization, error);
        OnPropertyChanged(nameof(LastError));
        OnPropertyChanged(nameof(HasError));
    }

    private void OnSessionStateChanged(object? sender, VpnStateChange change)
    {
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(ConnectButtonText));
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(KillSwitchEngaged));
        ToggleConnectionCommand.NotifyCanExecuteChanged();
        RebuildDetails();
    }

    private void OnSnapshotChanged(object? sender, ConnectionSnapshot snapshot) => ApplySnapshot(snapshot);

    /// <summary>Copies the session's snapshot into the displayed values.</summary>
    private void ApplySnapshot(ConnectionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        _profileName = snapshot.ProfileName ?? string.Empty;
        _coreVersion = snapshot.CoreVersion ?? string.Empty;

        var verification = snapshot.Verification;
        _exitAddress = verification?.ExitAddress ?? string.Empty;
        _directAddress = verification?.DirectAddress ?? string.Empty;
        _latency = DisplayFormat.Milliseconds(verification?.Latency);

        // No verification means no evidence, which is what the unknown value says. When
        // verification did run, the address comparison is the evidence.
        _trafficMoved = verification is null
            ? _localization.Get(Presentation.UnknownKey)
            : _localization.Get(verification.ExitDiffersFromDirect ? "status.connected" : "status.degraded");

        _lastError = snapshot.LastError is { } error
            ? Presentation.DescribeWithSeverity(_localization, error)
            : string.Empty;

        Warnings.Clear();
        foreach (var warning in snapshot.Warnings)
        {
            Warnings.Add(new DetailRow(warning.Severity.ToString(), Presentation.Describe(_localization, warning)));
        }

        OnPropertyChanged(nameof(CoreVersion));
        OnPropertyChanged(nameof(ExitAddress));
        OnPropertyChanged(nameof(DirectAddress));
        OnPropertyChanged(nameof(TrafficMoved));
        OnPropertyChanged(nameof(Latency));
        OnPropertyChanged(nameof(ServerName));
        OnPropertyChanged(nameof(LastError));
        OnPropertyChanged(nameof(HasError));
        OnPropertyChanged(nameof(HasWarnings));
        OnPropertyChanged(nameof(ActiveProfile));
        OnPropertyChanged(nameof(KillSwitchEngaged));
        RebuildDetails();
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        // The snapshot-derived values were rendered in the previous language, so re-render them
        // from the last snapshot rather than leaving them stale.
        ApplySnapshot(_session.Snapshot);
        OnAllPropertiesChanged();
    }

    private void RebuildDetails()
    {
        // Rows are updated in place against a fixed set, so the table does not flicker during a
        // connect sequence and a language switch changes text rather than identity.
        //
        // Every value here is read from the session or from the stored settings. Nothing is
        // inferred: "unknown" is displayed wherever a fact was not established, and the
        // traffic row is rendered from the snapshot's verification rather than from the state,
        // because the state alone cannot distinguish "the process started" from "the tunnel
        // carries traffic".
        var rows = new (string Label, string Value)[]
        {
            (LabelServer, ServerName),
            (LabelMode, _localization.Get(ModeKey(_store.Settings.TunnelMode))),
            (LabelKillSwitch, _localization.Get(KillSwitchKey(_store.Settings.KillSwitch, KillSwitchEngaged))),
            (_localization.Get("xray.select_binary"), Or(_coreVersion, Unknown)),

            // Latency only means something once verification has run. When it was measured but
            // produced nothing, the explicit "no measurement" value is shown rather than a zero.
            (LabelPing, _latency.Length > 0
                ? _latency
                : _session.State.IsTunnelUp() ? _localization.Get("main.ping_none") : string.Empty),
            (LabelIp, Or(_trafficMoved, Unknown)),

            // The two addresses, each with its own label. These previously borrowed the
            // subscription-metadata vocabulary, which rendered "Profile title" next to an IP
            // address -- readable by nobody.
            (_localization.Get("main.exit_address"), Or(_exitAddress, Unknown)),
            (_localization.Get("main.direct_address"), Or(_directAddress, Unknown)),
        };

        for (var index = 0; index < rows.Length; index++)
        {
            if (index < Details.Count)
            {
                Details[index].Set(rows[index].Label, rows[index].Value);
            }
            else
            {
                Details.Add(new DetailRow(rows[index].Label, rows[index].Value));
            }
        }
    }

    private string Unknown => _localization.Get(Presentation.UnknownKey);

    private string Or(string value, string fallback) => value.Length == 0 ? fallback : value;

    /// <summary>Profile name, or the localized "none selected" placeholder.</summary>
    public string ServerName =>
        _profileName.Length > 0
            ? _profileName
            : SelectedProfile?.DisplayName ?? _localization.Get("main.no_server");

    private static string StatusKey(VpnConnectionState state) => state switch
    {
        VpnConnectionState.Disconnected => "status.disconnected",
        VpnConnectionState.Preparing => "status.preparing",
        VpnConnectionState.Connecting => "status.connecting",
        VpnConnectionState.Connected => "status.connected",
        VpnConnectionState.Degraded => "status.degraded",
        VpnConnectionState.Reconnecting => "status.reconnecting",
        VpnConnectionState.Disconnecting => "status.disconnecting",
        _ => "status.faulted",
    };

    private static string ModeKey(TunnelMode mode) => mode switch
    {
        TunnelMode.Tun => "mode.tun",
        TunnelMode.SystemProxy => "mode.system_proxy",
        _ => "mode.disabled",
    };

    private static string KillSwitchKey(KillSwitchMode mode, bool engaged) => mode switch
    {
        KillSwitchMode.AlwaysOn => "killswitch.always_on",
        KillSwitchMode.OnDemand => engaged ? "killswitch.on_demand" : "killswitch.disabled",
        _ => "killswitch.disabled",
    };

    /// <summary>Scope that unmarks the operation and cancels its token on the way out.</summary>
    private sealed class OperationScope : IDisposable
    {
        private readonly MainWindowViewModel _owner;
        private readonly CancellationTokenSource _cts;

        public OperationScope(MainWindowViewModel owner, CancellationTokenSource cts)
        {
            _owner = owner;
            _cts = cts;
        }

        public CancellationToken Token => _cts.Token;

        public void Dispose() => _owner.EndOperation(_cts);
    }
}
